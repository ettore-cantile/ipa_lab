#!/bin/bash
# =============================================================================
# test_kathara.sh  —  Test IPA su Kathara: darmstadt → frankfurt
# =============================================================================
# NOTA IMPORTANTE su kathara exec:
#   - kathara intercetta QUALSIASI argomento "-c", anche dentro sh -c.
#   - Soluzione: scrivere script .sh nel container via 'tee',
#     poi eseguirli con 'bash /tmp/script.sh'.
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
# Helper: scrive uno script nel container e lo esegue
# Usage: krun <node> <script_name> <<'EOF'
#          ...script body...
#        EOF
# ---------------------------------------------------------------------------
kwrite() {
    local node=$1
    local script=$2
    local body=$3
    # Scrivi riga per riga nel container tramite echo (evita -c)
    echo "$body" | while IFS= read -r line; do
        kathara exec "$node" tee -a "/tmp/${script}" <<< "$line" > /dev/null
    done
}

# Funzione piu' semplice: genera script localmente e lo copia con kathara exec
kscript() {
    local node=$1
    local script_path=$2   # path dentro il container
    local content=$3       # contenuto dello script
    # Usa printf per scrivere il file dentro il container
    kathara exec "$node" tee "${script_path}" > /dev/null <<< "${content}"
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
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2] Waiting for OSPF convergence...${NC}"
CONVERGED=0
for i in $(seq 1 30); do
    if kathara exec darmstadt ping -c 1 -W 1 10.255.255.17 > /dev/null 2>&1; then
        echo "  frankfurt (10.255.255.17) reachable"
        CONVERGED=1
        break
    fi
    echo -n "."
    sleep 1
done
if [ $CONVERGED -eq 0 ]; then
    echo
    if ! kathara exec darmstadt ping -c 1 -W 1 10.0.0.234 > /dev/null 2>&1; then
        echo -e "${RED}  ERROR: 10.0.0.234 unreachable.${NC}"
        exit 1
    fi
    echo "  Direct link 10.0.0.234 OK"
fi
echo

# ---------------------------------------------------------------------------
# STEP 3: Receiver su frankfurt
# Scriviamo /tmp/run_recv.sh nel container, poi lo eseguiamo
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Starting IPA receiver on frankfurt...${NC}"
kathara exec frankfurt tee /tmp/run_recv.sh > /dev/null << SCRIPT
#!/bin/sh
python3 /shared/recv_ipa.py --timeout 60 --count ${PACKET_COUNT} > /tmp/recv_ipa.log 2>&1 &
echo \$! > /tmp/recv_ipa.pid
SCRIPT
kathara exec frankfurt bash /tmp/run_recv.sh
echo "  recv_ipa.py started on frankfurt"
sleep 2
echo

# ---------------------------------------------------------------------------
# STEP 4: Carica pipeline su darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Loading pipeline '${METHOD}' on darmstadt (eth0)...${NC}"
kathara exec darmstadt tee /tmp/run_pipeline.sh > /dev/null << SCRIPT
#!/bin/sh
python3 /shared/execute_pipeline.py --method ${METHOD} --iface eth0 --model-id ${MODEL_ID} > /tmp/pipeline.log 2>&1 &
echo \$! > /tmp/pipeline.pid
SCRIPT
kathara exec darmstadt bash /tmp/run_pipeline.sh
echo "  Pipeline started — waiting 4s for XDP attach..."
sleep 4
echo

# ---------------------------------------------------------------------------
# STEP 5: Popola BPF maps su darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Populating BPF maps on darmstadt...${NC}"
kathara exec darmstadt python3 /shared/setup_fwd_table.py --model-id ${MODEL_ID}
echo

# ---------------------------------------------------------------------------
# STEP 6: Invia pacchetti da darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 6] Sending ${PACKET_COUNT} IPA packets: darmstadt -> frankfurt...${NC}"
kathara exec darmstadt python3 /shared/send_ipa.py \
    --dst frankfurt \
    --count ${PACKET_COUNT} \
    --model-id ${MODEL_ID} \
    --weights ${WEIGHTS} \
    --interval ${INTERVAL}
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
kathara exec darmstadt cat /tmp/pipeline.log || echo "  (no log yet)"
echo

# ---------------------------------------------------------------------------
# STEP 9: BPF map stats
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] BPF map stats on darmstadt:${NC}"
kathara exec darmstadt tee /tmp/bpf_stats.sh > /dev/null << SCRIPT
#!/bin/sh
bpftool map show 2>/dev/null | grep -E 'name|entries' || echo '  (no maps loaded)'
SCRIPT
kathara exec darmstadt bash /tmp/bpf_stats.sh
echo

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} Test complete! Method: ${METHOD}${NC}"
echo -e "${GREEN}============================================================${NC}"
