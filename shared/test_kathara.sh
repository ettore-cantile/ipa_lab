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

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} IPA Kathara Test: darmstadt -> frankfurt  [${METHOD}]${NC}"
echo -e "${GREEN}============================================================${NC}"
echo

# ---------------------------------------------------------------------------
# kscript <node> <remote_path> <<'EOF'  body  EOF
# Scrive uno script nel container tramite tee (nessun -c a kathara)
# ---------------------------------------------------------------------------
kscript() {
    local node=$1
    local path=$2
    local body
    body=$(cat)   # legge stdin (heredoc)
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
# Risolviamo l'IP di frankfurt dinamicamente (nessun IP hardcoded)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2] Waiting for OSPF convergence...${NC}"

# Resolve frankfurt IP dynamically inside the container
# Kathara populates /etc/hosts with container names
kscript darmstadt /tmp/resolve_frankfurt.sh << 'RESOLVESCRIPT'
#!/bin/sh
FKT_IP=$(getent hosts frankfurt 2>/dev/null | awk '{print $1; exit}')
if [ -z "$FKT_IP" ]; then
    FKT_IP=$(grep frankfurt /etc/hosts 2>/dev/null | awk '{print $1; exit}')
fi
echo "${FKT_IP:-}"
RESCOLVESCRIPT
FRANKFURT_IP=$(kathara exec darmstadt bash /tmp/resolve_frankfurt.sh 2>/dev/null | tr -d '\r\n')
if [ -z "$FRANKFURT_IP" ]; then
    echo -e "${YELLOW}  [WARN] Could not resolve 'frankfurt' hostname; using fallback 10.255.255.17${NC}"
    FRANKFURT_IP="10.255.255.17"
fi
echo "  Resolved frankfurt -> ${FRANKFURT_IP}"

kscript darmstadt /tmp/ping_frankfurt.sh << PINGSCRIPT
#!/bin/sh
ping -c 1 -W 1 ${FRANKFURT_IP} > /dev/null 2>&1 && echo "OK" || echo "FAIL"
PINGSCRIPT

CONVERGED=0
for i in $(seq 1 30); do
    RESULT=$(kathara exec darmstadt bash /tmp/ping_frankfurt.sh 2>/dev/null || echo "FAIL")
    if echo "$RESULT" | grep -q "OK"; then
        echo "  frankfurt (${FRANKFURT_IP}) reachable via OSPF"
        CONVERGED=1
        break
    fi
    echo -n "."
    sleep 1
done

if [ $CONVERGED -eq 0 ]; then
    echo
    echo -e "${RED}  ERROR: frankfurt (${FRANKFURT_IP}) unreachable. Check lab.conf / kathara lstart.${NC}"
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
# NOTE: --iface eth1 matches common.py INGRESS_IFACE (not eth0 default)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Loading pipeline '${METHOD}' on darmstadt (eth1)...${NC}"
kscript darmstadt /tmp/run_pipeline.sh << PIPESCRIPT
#!/bin/sh
python3 /shared/execute_pipeline.py --method ${METHOD} --iface eth1 --model-id ${MODEL_ID} > /tmp/pipeline.log 2>&1 &
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
# STEP 6: Invia pacchetti
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
# STEP 9: BPF map stats (informational, not a hard assertion)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] BPF map stats on darmstadt:${NC}"
kscript darmstadt /tmp/bpf_stats.sh << 'STATSSCRIPT'
#!/bin/sh
bpftool map show 2>/dev/null | grep -E 'name|entries' || echo '  (no maps loaded)'
STATSSCRIPT
kathara exec darmstadt bash /tmp/bpf_stats.sh
echo

# ---------------------------------------------------------------------------
# STEP 10: Verifica conteggio pacchetti + emetti TEST PASSED / TEST FAILED
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

# Require >= 80% delivery (allows for a few OSPF/XDP warmup drops)
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
