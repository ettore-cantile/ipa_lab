#!/bin/bash
# =============================================================================
# test_kathara.sh  —  Test completo pipeline IPA su Kathara
#                     Scenario: darmstadt → frankfurt
# =============================================================================
#
# TOPOLOGIA:
#   darmstadt (10.255.255.10)
#     eth0 = 10.0.0.233/30  ──── eth1 = 10.0.0.234/30  frankfurt (10.255.255.17)
#     eth1 = 10.0.0.246/30
#     eth2 = 10.0.0.250/30
#
# UTILIZZO (dall'host, dopo kathara lstart):
#   bash shared/test_kathara.sh [hardcoded|template|modular]
#
# REQUISITI:
#   - kathara lstart deve essere già stato eseguito
#   - I container devono avere scapy e bcc installati (vedi Dockerfile)
#
# =============================================================================

set -e

METHOD=${1:-hardcoded}   # hardcoded | template | modular
MODEL_ID=0
PACKET_COUNT=100
INTERVAL=0.002
WEIGHTS="/shared/weights.json"

# Colori output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} IPA Kathara Test: darmstadt -> frankfurt${NC}"
echo -e "${GREEN} Pipeline: ${METHOD}  |  model_id=${MODEL_ID}  |  count=${PACKET_COUNT}${NC}"
echo -e "${GREEN}============================================================${NC}"
echo

# ---------------------------------------------------------------------------
# Helper: esegui comando in un container Kathara
# Sintassi corretta: kathara exec <node> <cmd_string>
# NON usare: kathara exec <node> -- bash -c "..."
# ---------------------------------------------------------------------------
kexec() {
    local node=$1
    shift
    kathara exec "$node" "$@"
}

# ---------------------------------------------------------------------------
# STEP 1: Verifica che i container siano up
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
# STEP 2: Aspetta convergenza OSPF (darmstadt deve pingare frankfurt)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2] Waiting for OSPF convergence (darmstadt -> frankfurt)...${NC}"
CONVERGED=0
for i in $(seq 1 30); do
    if kathara exec darmstadt "ping -c 1 -W 1 10.255.255.17" > /dev/null 2>&1; then
        echo "  OSPF converged — frankfurt (10.255.255.17) reachable"
        CONVERGED=1
        break
    fi
    echo -n "."
    sleep 1
done

if [ $CONVERGED -eq 0 ]; then
    echo
    echo -e "${YELLOW}  WARNING: OSPF not converged yet, trying direct link (10.0.0.234)...${NC}"
    if ! kathara exec darmstadt "ping -c 1 -W 1 10.0.0.234" > /dev/null 2>&1; then
        echo -e "${RED}  ERROR: direct link 10.0.0.234 also unreachable. Check lab.conf.${NC}"
        exit 1
    fi
    echo "  Direct link OK — 10.0.0.234 reachable"
fi
echo

# ---------------------------------------------------------------------------
# STEP 3: Avvia receiver su frankfurt in background
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Starting IPA receiver on frankfurt...${NC}"
kathara exec frankfurt \
    "nohup python3 /shared/recv_ipa.py --timeout 60 --count ${PACKET_COUNT} > /tmp/recv_ipa.log 2>&1 &"
echo "  recv_ipa.py started on frankfurt (log: /tmp/recv_ipa.log)"
sleep 2
echo

# ---------------------------------------------------------------------------
# STEP 4: Carica pipeline eBPF su darmstadt (background)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Loading eBPF pipeline '${METHOD}' on darmstadt (eth0)...${NC}"
kathara exec darmstadt \
    "nohup python3 /shared/execute_pipeline.py --method ${METHOD} --iface eth0 --model-id ${MODEL_ID} > /tmp/pipeline.log 2>&1 &"
echo "  Pipeline started — waiting 4s for XDP attach..."
sleep 4
echo

# ---------------------------------------------------------------------------
# STEP 5: Popola fwd_table e valid_keys su darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Populating BPF maps on darmstadt...${NC}"
kathara exec darmstadt \
    "python3 /shared/setup_fwd_table.py --model-id ${MODEL_ID}"
echo

# ---------------------------------------------------------------------------
# STEP 6: Invia pacchetti IPA da darmstadt a frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 6] Sending ${PACKET_COUNT} IPA packets: darmstadt -> frankfurt...${NC}"
kathara exec darmstadt \
    "python3 /shared/send_ipa.py --dst frankfurt --count ${PACKET_COUNT} --model-id ${MODEL_ID} --weights ${WEIGHTS} --interval ${INTERVAL}"
echo

# ---------------------------------------------------------------------------
# STEP 7: Leggi log dal receiver su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7] Results on frankfurt (recv_ipa.log):${NC}"
sleep 2
kathara exec frankfurt "cat /tmp/recv_ipa.log" || echo "  (log not yet available)"
echo

# ---------------------------------------------------------------------------
# STEP 8: Mostra log pipeline su darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 8] Pipeline log on darmstadt:${NC}"
kathara exec darmstadt "cat /tmp/pipeline.log" || echo "  (no pipeline log yet)"
echo

# ---------------------------------------------------------------------------
# STEP 9: Statistiche BPF maps su darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] BPF map stats on darmstadt:${NC}"
kathara exec darmstadt \
    "bpftool map show 2>/dev/null | grep -E 'name|entries' || echo '  (no maps loaded or bpftool unavailable)'"
echo

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} Test complete! Method: ${METHOD}${NC}"
echo -e "${GREEN} To run all 3 pipelines:${NC}"
echo -e "${GREEN}   bash shared/test_kathara.sh hardcoded${NC}"
echo -e "${GREEN}   bash shared/test_kathara.sh template${NC}"
echo -e "${GREEN}   bash shared/test_kathara.sh modular${NC}"
echo -e "${GREEN}============================================================${NC}"
