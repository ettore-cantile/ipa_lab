#!/bin/bash
# =============================================================================
# test_kathara.sh  —  Test IPA su Kathara: darmstadt -> frankfurt
#
# Usage: bash shared/test_kathara.sh [hardcoded|template|modular]
#
# Interface mapping (lab.conf + darmstadt.startup):
#   darmstadt[0]="l59" <-> frankfurt[1]="l59"
#     eth0 = 10.0.0.233/30  INGRESS: IPA packets from frankfurt arrive here
#     XDP must be attached to eth0
#   darmstadt[1]="l62" <-> mannheim[0]="l62"
#     eth1 = 10.0.0.246/30  EGRESS toward mannheim
#
# OSPF loopback IPs (from *.startup /etc/hosts):
#   darmstadt  = 10.255.255.10
#   frankfurt  = 10.255.255.17
#
# kathara exec note:
#   kathara exec intercepts '-c' as its own flag and tries to re-invoke
#   itself.  The workaround is --no-deployment-flag=self-execution which
#   disables that behaviour.  All krun() calls use this flag.
# =============================================================================

METHOD=${1:-hardcoded}
MODEL_ID=0
PACKET_COUNT=100
INTERVAL=0.002
WEIGHTS="/shared/weights.json"

FRANKFURT_DIRECT="10.0.0.234"
FRANKFURT_OSPF="10.255.255.17"
FRANKFURT_IP="${FRANKFURT_DIRECT}"

# XDP attaches to eth0 (darmstadt[0]=l59, 10.0.0.233/30, toward frankfurt)
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
# krun NODE CMD
#   Run CMD inside NODE.  Uses --no-deployment-flag=self-execution so that
#   kathara does not intercept the '-c' flag of 'sh -c "..."'.
# ---------------------------------------------------------------------------
krun() {
    local node="$1"
    shift
    kathara exec --no-deployment-flag=self-execution "${node}" -- sh -c "$*"
}

echo -e "${YELLOW}[Step 1] Checking Kathara containers...${NC}"
if ! kathara linfo 2>/dev/null | grep -q "darmstadt"; then
    echo -e "${RED}[ERROR] Lab not running. Run: kathara lstart${NC}"
    exit 1
fi
echo "  darmstadt: UP"
echo "  frankfurt: UP"
echo

# ---------------------------------------------------------------------------
# Step 2a — Direct link check
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2a] Checking direct link darmstadt->frankfurt (${FRANKFURT_DIRECT})...${NC}"
DIRECT_OK=0
for i in $(seq 1 15); do
    RESULT=$(krun darmstadt "ping -c 1 -W 2 ${FRANKFURT_DIRECT} > /dev/null 2>&1 && echo OK || echo FAIL" 2>/dev/null | tr -d '\r\n')
    if [ "${RESULT}" = "OK" ]; then
        echo "  Direct link ${FRANKFURT_DIRECT} reachable — OK"
        DIRECT_OK=1
        break
    fi
    echo -n "."
    sleep 1
done
if [ ${DIRECT_OK} -eq 0 ]; then
    echo
    echo -e "${RED}  ERROR: Direct link ${FRANKFURT_DIRECT} unreachable after 15s.${NC}"
    echo
    echo "  Troubleshooting:"
    echo "    1) kathara exec darmstadt -- ip addr show eth0  (expect 10.0.0.233/30)"
    echo "    2) kathara exec frankfurt  -- ip addr show eth1  (expect 10.0.0.234/30)"
    echo "    3) kathara exec darmstadt -- ping 10.0.0.234    (no -c flag!)"
    echo
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# Step 2b — OSPF convergence (optional)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2b] Checking optional OSPF convergence (${FRANKFURT_OSPF}, up to 30s)...${NC}"
CONVERGED=0
for i in $(seq 1 30); do
    RESULT=$(krun darmstadt "ping -c 1 -W 2 ${FRANKFURT_OSPF} > /dev/null 2>&1 && echo OK || echo FAIL" 2>/dev/null | tr -d '\r\n')
    if [ "${RESULT}" = "OK" ]; then
        echo "  OSPF converged at ${i}s — ${FRANKFURT_OSPF} reachable"
        CONVERGED=1
        FRANKFURT_IP="${FRANKFURT_OSPF}"
        break
    fi
    echo -n "."
    sleep 1
done
if [ ${CONVERGED} -eq 0 ]; then
    echo
    echo "  OSPF not ready — continuing with direct link ${FRANKFURT_DIRECT}"
fi
echo

# ---------------------------------------------------------------------------
# Step 3 — Start IPA receiver on frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Starting IPA receiver on frankfurt...${NC}"
krun frankfurt "python3 /shared/recv_ipa.py --timeout 60 --count ${PACKET_COUNT} > /tmp/recv_ipa.log 2>&1 & echo \$! > /tmp/recv_ipa.pid && echo recv_ipa.py started"
sleep 2
echo

# ---------------------------------------------------------------------------
# Step 4 — Load pipeline on darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Loading pipeline '${METHOD}' on darmstadt (iface=${INGRESS_IFACE})...${NC}"
krun darmstadt "python3 /shared/execute_pipeline.py --method ${METHOD} --iface ${INGRESS_IFACE} --model-id ${MODEL_ID} > /tmp/pipeline.log 2>&1 & echo \$! > /tmp/pipeline.pid && echo Pipeline started"
echo "  Waiting 6s for XDP attach..."
sleep 6
echo

# ---------------------------------------------------------------------------
# Step 5 — Pipeline startup check
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Pipeline startup check:${NC}"
STATUS_LINE=$(krun darmstadt "
if [ ! -f /tmp/pipeline.log ]; then
    echo PIPELINE_STATUS=NOT_STARTED
elif grep -qi 'error\\|traceback\\|exception' /tmp/pipeline.log; then
    echo PIPELINE_STATUS=ERROR
else
    echo PIPELINE_STATUS=OK
fi
" 2>/dev/null | tr -d '\r')
echo "  ${STATUS_LINE}"
if echo "${STATUS_LINE}" | grep -q 'ERROR\|NOT_STARTED'; then
    echo -e "${RED}  Pipeline failed. Full log:${NC}"
    krun darmstadt "cat /tmp/pipeline.log"
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# Step 6 — Send IPA packets
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 6] Sending ${PACKET_COUNT} IPA packets darmstadt -> ${FRANKFURT_IP}...${NC}"
krun darmstadt "python3 /shared/send_ipa.py --dst ${FRANKFURT_IP} --count ${PACKET_COUNT} --model-id ${MODEL_ID} --weights ${WEIGHTS} --interval ${INTERVAL} 2>&1"
echo

# ---------------------------------------------------------------------------
# Step 7 — Receiver log
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7] Receiver log on frankfurt:${NC}"
sleep 2
krun frankfurt "cat /tmp/recv_ipa.log 2>/dev/null || echo log not available"
echo

# ---------------------------------------------------------------------------
# Step 8 — Pipeline log
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 8] Pipeline log on darmstadt:${NC}"
krun darmstadt "cat /tmp/pipeline.log 2>/dev/null || echo no log"
echo

# ---------------------------------------------------------------------------
# Step 9 — BPF map stats
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] BPF map stats on darmstadt:${NC}"
krun darmstadt "bpftool map show 2>/dev/null | grep -E 'name|entries' || echo no maps loaded"
echo

# ---------------------------------------------------------------------------
# Step 10 — Verify packet counts
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 10] Verifying packet counts...${NC}"
RECV_LINE=$(krun frankfurt "
if [ ! -f /tmp/recv_ipa.log ]; then
    echo RECV_COUNT=0
else
    CNT=\$(grep -ci 'received\\|recv\\|packet' /tmp/recv_ipa.log 2>/dev/null || echo 0)
    echo RECV_COUNT=\${CNT}
fi
" 2>/dev/null | grep RECV_COUNT | tr -d '\r')
RECV_COUNT=$(echo "${RECV_LINE}" | grep -oE '[0-9]+$' || echo 0)
[ -z "${RECV_COUNT}" ] && RECV_COUNT=0
THRESHOLD=$((PACKET_COUNT * 80 / 100))

echo "  Packets sent    : ${PACKET_COUNT}"
echo "  Packets received: ${RECV_COUNT}"
echo "  Pass threshold  : ${THRESHOLD} (80%)"
echo
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} Test complete! Method: ${METHOD}${NC}"
echo -e "${GREEN}============================================================${NC}"

if [ "${RECV_COUNT}" -ge "${THRESHOLD}" ] 2>/dev/null; then
    echo -e "${GREEN}TEST PASSED - received ${RECV_COUNT}/${PACKET_COUNT} packets (>= ${THRESHOLD})${NC}"
    echo "TEST PASSED"
else
    echo -e "${RED}TEST FAILED - received ${RECV_COUNT}/${PACKET_COUNT} packets (< ${THRESHOLD})${NC}"
    echo "TEST FAILED"
    exit 1
fi
