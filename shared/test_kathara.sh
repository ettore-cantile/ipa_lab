#!/bin/bash
# =============================================================================
# test_kathara.sh  -  Test IPA su Kathara: darmstadt -> frankfurt
# =============================================================================
# NOTA: kathara exec intercetta QUALSIASI argomento "-c" nella riga di comando,
# inclusi quelli destinati a ping, python3, ecc.
# Tutti i comandi con "-c" o con ridirezioni vanno wrappati in uno script
# scritto nel container via tee e poi eseguito con bash.
# =============================================================================

METHOD=${1:-hardcoded}
MODEL_ID=0
PACKET_COUNT=100
INTERVAL=0.002
WEIGHTS="/shared/weights.json"

# IP di frankfurt ricavato da lab.conf: darmstadt[0]=l59, frankfurt[1]=l59
# -> eth0 di darmstadt e' il link diretto a frankfurt
# L'IP loopback di frankfurt usato da OSPF e' 10.255.255.17 (da /etc/hosts)
FRANKFURT_IP="10.255.255.17"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} IPA Kathara Test: darmstadt -> frankfurt  [${METHOD}]${NC}"
echo -e "${GREEN}============================================================${NC}"
echo

# ---------------------------------------------------------------------------
# kscript <node> <remote_path>
# Legge il body da stdin e lo scrive nel container tramite tee.
# NON usare per comandi con flag -c: kathara li intercetta.
# ---------------------------------------------------------------------------
kscript() {
    local node=$1
    local path=$2
    local body
    body=$(cat)
    printf '%s\n' "$body" | kathara exec "$node" tee "$path" > /dev/null
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
# STEP 2: Convergenza OSPF
# Scriviamo lo script di ping via kscript, poi lo eseguiamo con bash.
# kscript usa tee (nessun flag -c a kathara).
# Il ping usa l'IP loopback di frankfurt (10.255.255.17) noto da lab.conf.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2] Waiting for OSPF convergence (frankfurt=${FRANKFURT_IP})...${NC}"

kscript darmstadt /tmp/ping_frankfurt.sh << PINGSCRIPT
#!/bin/sh
ping -c 1 -W 2 ${FRANKFURT_IP} > /dev/null 2>&1 && echo OK || echo FAIL
PINGSCRIPT

CONVERGED=0
for i in $(seq 1 30); do
    RESULT=$(kathara exec darmstadt bash /tmp/ping_frankfurt.sh 2>/dev/null)
    if echo "$RESULT" | grep -q "OK"; then
        echo "  frankfurt (${FRANKFURT_IP}) reachable"
        CONVERGED=1
        break
    fi
    echo -n "."
    sleep 1
done

if [ $CONVERGED -eq 0 ]; then
    echo
    echo -e "${RED}  ERROR: frankfurt (${FRANKFURT_IP}) unreachable after 30s.${NC}"
    echo -e "${RED}  Verifica: kathara exec darmstadt -- ping frankfurt${NC}"
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# STEP 3: Receiver su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Starting IPA receiver on frankfurt...${NC}"
kscript frankfurt /tmp/run_recv.sh << RECVSCRIPT
#!/bin/sh
python3 /shared/recv_ipa.py --timeout 60 --count ${PACKET_COUNT} > /tmp/recv_ipa.log 2>&1 &
echo \$! > /tmp/recv_ipa.pid
RECVSCRIPT
kathara exec frankfurt bash /tmp/run_recv.sh
echo "  recv_ipa.py started (log: /tmp/recv_ipa.log)"
sleep 2
echo

# ---------------------------------------------------------------------------
# STEP 4: Carica pipeline su darmstadt
# NOTE: --iface eth0 e' il link diretto verso frankfurt (l59 in lab.conf)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Loading pipeline '${METHOD}' on darmstadt (eth0)...${NC}"
kscript darmstadt /tmp/run_pipeline.sh << PIPESCRIPT
#!/bin/sh
python3 /shared/execute_pipeline.py --method ${METHOD} --iface eth0 --model-id ${MODEL_ID} > /tmp/pipeline.log 2>&1 &
echo \$! > /tmp/pipeline.pid
PIPESCRIPT
kathara exec darmstadt bash /tmp/run_pipeline.sh
echo "  Pipeline started - waiting 4s for XDP attach..."
sleep 4
echo

# ---------------------------------------------------------------------------
# STEP 5: Popola BPF maps
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Populating BPF maps on darmstadt...${NC}"
kscript darmstadt /tmp/setup_maps.sh << MAPSCRIPT
#!/bin/sh
python3 /shared/setup_fwd_table.py --model-id ${MODEL_ID}
MAPSCRIPT
kathara exec darmstadt bash /tmp/setup_maps.sh
echo

# ---------------------------------------------------------------------------
# STEP 6: Invia pacchetti IPA da darmstadt verso frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 6] Sending ${PACKET_COUNT} IPA packets: darmstadt -> frankfurt...${NC}"
kscript darmstadt /tmp/send_ipa.sh << SENDSCRIPT
#!/bin/sh
python3 /shared/send_ipa.py --dst frankfurt --count ${PACKET_COUNT} --model-id ${MODEL_ID} --weights ${WEIGHTS} --interval ${INTERVAL}
SENDSCRIPT
kathara exec darmstadt bash /tmp/send_ipa.sh
echo

# ---------------------------------------------------------------------------
# STEP 7: Log receiver su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7] Results on frankfurt:${NC}"
sleep 2
kathara exec frankfurt cat /tmp/recv_ipa.log || echo "  (log not available)"
echo

# ---------------------------------------------------------------------------
# STEP 8: Log pipeline su darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 8] Pipeline log on darmstadt:${NC}"
kathara exec darmstadt cat /tmp/pipeline.log || echo "  (no log)"
echo

# ---------------------------------------------------------------------------
# STEP 9: BPF map stats (informational)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] BPF map stats on darmstadt:${NC}"
kscript darmstadt /tmp/bpf_stats.sh << 'STATSSCRIPT'
#!/bin/sh
bpftool map show 2>/dev/null | grep -E 'name|entries' || echo '  (no maps loaded)'
STATSSCRIPT
kathara exec darmstadt bash /tmp/bpf_stats.sh
echo

# ---------------------------------------------------------------------------
# STEP 10: Verifica conteggio pacchetti + TEST PASSED / TEST FAILED
# run_pipeline_test.sh cerca questa stringa esatta nell'output.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 10] Verifying packet counts...${NC}"
kscript frankfurt /tmp/check_recv.sh << 'CHECKSCRIPT'
#!/bin/sh
LOG=/tmp/recv_ipa.log
if [ ! -f "$LOG" ]; then
    echo "RECV_COUNT=0"
else
    CNT=$(grep -c "Received IPA" "$LOG" 2>/dev/null || echo 0)
    echo "RECV_COUNT=${CNT}"
fi
CHECKSCRIPT
RECV_LINE=$(kathara exec frankfurt bash /tmp/check_recv.sh 2>/dev/null | tr -d '\r')
RECV_COUNT=$(echo "$RECV_LINE" | grep -oP '(?<=RECV_COUNT=)\d+' || echo 0)
echo "  Packets sent    : ${PACKET_COUNT}"
echo "  Packets received: ${RECV_COUNT}"

THRESHOLD=$((PACKET_COUNT * 80 / 100))

echo
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} Test complete! Method: ${METHOD}${NC}"
echo -e "${GREEN}============================================================${NC}"
if [ "${RECV_COUNT:-0}" -ge "${THRESHOLD}" ] 2>/dev/null; then
    echo -e "${GREEN}TEST PASSED - received ${RECV_COUNT}/${PACKET_COUNT} packets (>= ${THRESHOLD} threshold)${NC}"
    echo "TEST PASSED"
else
    echo -e "${RED}TEST FAILED - received ${RECV_COUNT}/${PACKET_COUNT} packets (< ${THRESHOLD} threshold)${NC}"
    echo "TEST FAILED"
    exit 1
fi
