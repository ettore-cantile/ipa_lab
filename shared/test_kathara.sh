#!/bin/bash
# =============================================================================
# test_kathara.sh  -  Test IPA su Kathara: darmstadt -> frankfurt
# =============================================================================
# NOTA: kathara exec intercetta QUALSIASI argomento "-c" nella riga di comando,
# inclusi quelli destinati a ping, python3, ecc.
# Tutti i comandi con "-c" o con ridirezioni vanno wrappati in uno script
# scritto nel container.  kscript() usa 'cat >' tramite sh -c passato come
# file di input a bash, bypassando la trappola di kathara exec.
# =============================================================================

METHOD=${1:-hardcoded}
MODEL_ID=0
PACKET_COUNT=100
INTERVAL=0.002
WEIGHTS="/shared/weights.json"

# IP e interfaccia di darmstadt->frankfurt da lab.conf:
#   darmstadt[0]="l59"  frankfurt[1]="l59"  => eth0 su darmstadt e' il link diretto
#   10.255.255.17 e' il loopback OSPF di frankfurt (da /etc/hosts del container)
FRANKFURT_IP="10.255.255.17"
INGRESS_IFACE="eth0"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} IPA Kathara Test: darmstadt -> frankfurt  [${METHOD}]${NC}"
echo -e "${GREEN}============================================================${NC}"
echo

# ---------------------------------------------------------------------------
# kscript <node> <remote_path> <content>
# Scrive uno script nel container riga per riga via 'kathara exec <node> sh'
# usando input redirect da process substitution — nessun flag -c a kathara.
# Strategia: passiamo il contenuto come stdin a 'sh' con uno script wrapper
# che usa 'cat >' per scrivere il file.  Funziona su qualsiasi immagine
# Kathara perché usa solo sh/cat, non tee o altri strumenti opzionali.
# ---------------------------------------------------------------------------
kscript() {
    local node="$1"
    local path="$2"
    local content="$3"
    # Encode content to base64 to avoid any quoting/escaping issues
    local b64
    b64=$(printf '%s' "$content" | base64 -w0 2>/dev/null || printf '%s' "$content" | base64)
    # Write via: echo <b64> | base64 -d > <path>  — all via stdin to sh
    kathara exec "$node" sh << WRAPPER
echo '${b64}' | base64 -d > ${path}
chmod +x ${path}
WRAPPER
}

# ---------------------------------------------------------------------------
# STEP 1: Verifica containers
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 1] Checking Kathara containers...${NC}"
if ! kathara linfo 2>/dev/null | grep -q "darmstadt"; then
    echo -e "${RED}[ERROR] Lab not running. Run: kathara lstart${NC}"
    exit 1
fi
echo "  darmstadt: UP"
echo "  frankfurt: UP"
echo

# ---------------------------------------------------------------------------
# STEP 2: Convergenza OSPF — ping diretto via kathara exec
# Nota: kathara exec intercetta solo flag che cominciano con '-'
# passati DIRETTAMENTE a kathara. Il '--' separa gli argomenti di kathara
# da quelli del comando remoto, ma ping con -c viene comunque intercettato.
# Usiamo kscript per scrivere lo script e poi 'bash <path>' per eseguirlo.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2] Waiting for OSPF convergence (frankfurt=${FRANKFURT_IP})...${NC}"

kscript darmstadt /tmp/ping_fkt.sh "#!/bin/sh
ping -c 1 -W 2 ${FRANKFURT_IP} > /dev/null 2>&1 && echo OK || echo FAIL
"

CONVERGED=0
for i in $(seq 1 30); do
    RESULT=$(kathara exec darmstadt bash /tmp/ping_fkt.sh 2>/dev/null | tr -d '\r\n')
    if [ "$RESULT" = "OK" ]; then
        echo "  frankfurt (${FRANKFURT_IP}) reachable — OSPF converged"
        CONVERGED=1
        break
    fi
    echo -n "."
    sleep 1
done

if [ $CONVERGED -eq 0 ]; then
    echo
    echo -e "${RED}  ERROR: frankfurt unreachable after 30s. Check OSPF / kathara lstart.${NC}"
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# STEP 3: Receiver su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Starting IPA receiver on frankfurt...${NC}"

kscript frankfurt /tmp/run_recv.sh "#!/bin/sh
python3 /shared/recv_ipa.py --timeout 60 --count ${PACKET_COUNT} > /tmp/recv_ipa.log 2>&1 &
echo \$! > /tmp/recv_ipa.pid
"
kathara exec frankfurt bash /tmp/run_recv.sh
echo "  recv_ipa.py started (log: /tmp/recv_ipa.log)"
sleep 2
echo

# ---------------------------------------------------------------------------
# STEP 4: Carica pipeline su darmstadt
# --iface eth0: darmstadt[0]=l59 -> eth0 e' il link diretto verso frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Loading pipeline '${METHOD}' on darmstadt (${INGRESS_IFACE})...${NC}"

kscript darmstadt /tmp/run_pipeline.sh "#!/bin/sh
python3 /shared/execute_pipeline.py --method ${METHOD} --iface ${INGRESS_IFACE} --model-id ${MODEL_ID} > /tmp/pipeline.log 2>&1 &
echo \$! > /tmp/pipeline.pid
"
kathara exec darmstadt bash /tmp/run_pipeline.sh
echo "  Pipeline started — waiting 5s for XDP attach..."
sleep 5
echo

# ---------------------------------------------------------------------------
# STEP 5: Popola BPF maps (setup_fwd_table)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Populating BPF maps on darmstadt...${NC}"

kscript darmstadt /tmp/setup_maps.sh "#!/bin/sh
python3 /shared/setup_fwd_table.py --model-id ${MODEL_ID} 2>&1
"
kathara exec darmstadt bash /tmp/setup_maps.sh
echo

# ---------------------------------------------------------------------------
# STEP 6: Invia pacchetti IPA da darmstadt verso frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 6] Sending ${PACKET_COUNT} IPA packets: darmstadt -> frankfurt...${NC}"

kscript darmstadt /tmp/send_ipa.sh "#!/bin/sh
python3 /shared/send_ipa.py --dst ${FRANKFURT_IP} --count ${PACKET_COUNT} --model-id ${MODEL_ID} --weights ${WEIGHTS} --interval ${INTERVAL} 2>&1
"
kathara exec darmstadt bash /tmp/send_ipa.sh
echo

# ---------------------------------------------------------------------------
# STEP 7: Risultati receiver su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7] Results on frankfurt:${NC}"
sleep 2
kathara exec frankfurt cat /tmp/recv_ipa.log 2>/dev/null || echo "  (log not available)"
echo

# ---------------------------------------------------------------------------
# STEP 8: Log pipeline su darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 8] Pipeline log on darmstadt:${NC}"
kathara exec darmstadt cat /tmp/pipeline.log 2>/dev/null || echo "  (no log)"
echo

# ---------------------------------------------------------------------------
# STEP 9: BPF map stats (informational)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] BPF map stats on darmstadt:${NC}"

kscript darmstadt /tmp/bpf_stats.sh "#!/bin/sh
bpftool map show 2>/dev/null | grep -E 'name|entries' || echo '  (no maps loaded)'
"
kathara exec darmstadt bash /tmp/bpf_stats.sh
echo

# ---------------------------------------------------------------------------
# STEP 10: Verifica conteggio pacchetti + TEST PASSED / TEST FAILED
# run_pipeline_test.sh cerca questa stringa esatta nell'output.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 10] Verifying packet counts...${NC}"

kscript frankfurt /tmp/check_recv.sh "#!/bin/sh
LOG=/tmp/recv_ipa.log
if [ ! -f \"\$LOG\" ]; then
    echo 'RECV_COUNT=0'
else
    CNT=\$(grep -c 'recv_ipa' \"\$LOG\" 2>/dev/null || echo 0)
    echo \"RECV_COUNT=\${CNT}\"
fi
"
RECV_LINE=$(kathara exec frankfurt bash /tmp/check_recv.sh 2>/dev/null | tr -d '\r')
RECV_COUNT=$(echo "$RECV_LINE" | grep -oP '(?<=RECV_COUNT=)\d+' 2>/dev/null || echo 0)
[ -z "$RECV_COUNT" ] && RECV_COUNT=0

echo "  Packets sent    : ${PACKET_COUNT}"
echo "  Packets received: ${RECV_COUNT}"

THRESHOLD=$((PACKET_COUNT * 80 / 100))

echo
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} Test complete! Method: ${METHOD}${NC}"
echo -e "${GREEN}============================================================${NC}"

if [ "${RECV_COUNT}" -ge "${THRESHOLD}" ] 2>/dev/null; then
    echo -e "${GREEN}TEST PASSED - received ${RECV_COUNT}/${PACKET_COUNT} packets (>= ${THRESHOLD} threshold)${NC}"
    echo "TEST PASSED"
else
    echo -e "${RED}TEST FAILED - received ${RECV_COUNT}/${PACKET_COUNT} packets (< ${THRESHOLD} threshold)${NC}"
    echo "TEST FAILED"
    exit 1
fi
