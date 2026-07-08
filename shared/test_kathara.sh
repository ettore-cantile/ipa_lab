#!/bin/bash
# =============================================================================
# test_kathara.sh  —  Test IPA su Kathara: darmstadt → frankfurt
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
# Scriviamo lo script di ping nel container (evita -c intercettato da kathara)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2] Waiting for OSPF convergence...${NC}"

# Scrivi script di ping nel container darmstadt
kscript darmstadt /tmp/ping_frankfurt.sh << 'PINGSCRIPT'
#!/bin/sh
ping -c 1 -W 1 10.255.255.17 > /dev/null 2>&1 && echo "OK" || echo "FAIL"
PINGSCRIPT

kscript darmstadt /tmp/ping_direct.sh << 'PINGSCRIPT'
#!/bin/sh
ping -c 1 -W 1 10.0.0.234 > /dev/null 2>&1 && echo "OK" || echo "FAIL"
PINGSCRIPT

CONVERGED=0
for i in $(seq 1 30); do
    RESULT=$(kathara exec darmstadt bash /tmp/ping_frankfurt.sh 2>/dev/null || echo "FAIL")
    if echo "$RESULT" | grep -q "OK"; then
        echo "  frankfurt (10.255.255.17) reachable via OSPF"
        CONVERGED=1
        break
    fi
    echo -n "."
    sleep 1
done

if [ $CONVERGED -eq 0 ]; then
    echo
    echo -e "${YELLOW}  OSPF not converged, trying direct link 10.0.0.234...${NC}"
    RESULT=$(kathara exec darmstadt bash /tmp/ping_direct.sh 2>/dev/null || echo "FAIL")
    if echo "$RESULT" | grep -q "OK"; then
        echo "  Direct link 10.0.0.234 reachable"
    else
        echo -e "${RED}  ERROR: 10.0.0.234 unreachable. Check lab.conf / kathara lstart.${NC}"
        exit 1
    fi
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
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Loading pipeline '${METHOD}' on darmstadt (eth0)...${NC}"
kscript darmstadt /tmp/run_pipeline.sh << PIPESCRIPT
#!/bin/sh
python3 /shared/execute_pipeline.py --method ${METHOD} --iface eth0 --model-id ${MODEL_ID} > /tmp/pipeline.log 2>&1 &
echo \$! > /tmp/pipeline.pid
PIPESCRIPT
kathara exec darmstadt bash /tmp/run_pipeline.sh
echo "  Pipeline started — waiting 4s for XDP attach..."
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
# STEP 9: BPF map stats
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] BPF map stats on darmstadt:${NC}"
kscript darmstadt /tmp/bpf_stats.sh << 'STATSSCRIPT'
#!/bin/sh
bpftool map show 2>/dev/null | grep -E 'name|entries' || echo '  (no maps loaded)'
STATSSCRIPT
kathara exec darmstadt bash /tmp/bpf_stats.sh
echo

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} Test complete! Method: ${METHOD}${NC}"
echo -e "${GREEN}============================================================${NC}"
