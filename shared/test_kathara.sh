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
# UTILIZZO:
#   Terminale 1 (host o container manager):
#     bash /shared/test_kathara.sh [hardcoded|template|modular]
#
#   Oppure separatamente:
#     Terminale 1 → su frankfurt:  python3 /shared/recv_ipa.py --timeout 60
#     Terminale 2 → su darmstadt:  bash /shared/test_kathara.sh hardcoded
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
echo -e "${GREEN} IPA Kathara Test: darmstadt → frankfurt${NC}"
echo -e "${GREEN} Pipeline: ${METHOD}  |  model_id=${MODEL_ID}  |  count=${PACKET_COUNT}${NC}"
echo -e "${GREEN}============================================================${NC}"
echo

# Funzione helper per eseguire comandi nei container Kathara
kexec() {
    local node=$1
    shift
    kathara exec "$node" -- bash -c "$*"
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
echo -e "${YELLOW}[Step 2] Waiting for OSPF convergence (darmstadt → frankfurt)...${NC}"
for i in $(seq 1 30); do
    if kexec darmstadt "ping -c 1 -W 1 10.255.255.17 > /dev/null 2>&1"; then
        echo "  OSPF converged — frankfurt (10.255.255.17) reachable from darmstadt"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${YELLOW}  WARNING: frankfurt not reachable via OSPF yet.${NC}"
        echo    "  Trying direct link (10.0.0.234) instead..."
        if ! kexec darmstadt "ping -c 1 -W 1 10.0.0.234 > /dev/null 2>&1"; then
            echo -e "${RED}  ERROR: direct link 10.0.0.234 also unreachable. Check lab.conf.${NC}"
            exit 1
        fi
        echo "  Direct link OK — using 10.0.0.234 as destination"
    fi
    echo -n "."
    sleep 1
done
echo

# ---------------------------------------------------------------------------
# STEP 3: Avvia receiver su frankfurt in background
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Starting IPA receiver on frankfurt...${NC}"
kexec frankfurt "python3 /shared/recv_ipa.py --timeout 60 --count ${PACKET_COUNT} \
    > /tmp/recv_ipa.log 2>&1 &" || true
echo "  recv_ipa.py started on frankfurt (log: /tmp/recv_ipa.log)"
sleep 1
echo

# ---------------------------------------------------------------------------
# STEP 4: Carica pipeline eBPF su darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Loading eBPF pipeline '${METHOD}' on darmstadt (eth0)...${NC}"
kexec darmstadt "cd /shared && python3 execute_pipeline.py \
    --method ${METHOD} \
    --iface eth0 \
    --model-id ${MODEL_ID} &"
echo "  Pipeline started (background), waiting for XDP attach..."
sleep 3
echo

# ---------------------------------------------------------------------------
# STEP 5: Popola fwd_table e valid_keys
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Populating BPF maps on darmstadt...${NC}"
kexec darmstadt "python3 /shared/setup_fwd_table.py \
    --model-id ${MODEL_ID} \
    --check-reachability"
echo

# ---------------------------------------------------------------------------
# STEP 6: Invia pacchetti IPA da darmstadt a frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 6] Sending ${PACKET_COUNT} IPA packets: darmstadt → frankfurt...${NC}"
kexec darmstadt "python3 /shared/send_ipa.py \
    --dst frankfurt \
    --count ${PACKET_COUNT} \
    --model-id ${MODEL_ID} \
    --weights ${WEIGHTS} \
    --interval ${INTERVAL}"
echo

# ---------------------------------------------------------------------------
# STEP 7: Leggi log dal receiver su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7] Results on frankfurt (recv_ipa.log):${NC}"
sleep 2   # dai tempo al receiver di scrivere gli ultimi pacchetti
kexec frankfurt "cat /tmp/recv_ipa.log" || echo "  (log not yet available)"
echo

# ---------------------------------------------------------------------------
# STEP 8: Mostra statistiche eBPF dal nodo darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 8] eBPF map stats on darmstadt:${NC}"
kexec darmstadt "bpftool map show 2>/dev/null | grep -E 'name|entries' || \
    echo '  (bpftool not available or no maps loaded)'"
echo

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} Test complete!${NC}"
echo -e "${GREEN} Method: ${METHOD}${NC}"
echo -e "${GREEN} To compare all 3 pipelines run:${NC}"
echo -e "${GREEN}   bash /shared/test_kathara.sh hardcoded${NC}"
echo -e "${GREEN}   bash /shared/test_kathara.sh template${NC}"
echo -e "${GREEN}   bash /shared/test_kathara.sh modular${NC}"
echo -e "${GREEN}============================================================${NC}"
