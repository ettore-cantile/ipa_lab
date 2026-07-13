#!/usr/bin/env bash
# =============================================================================
# test_kathara_send_recv.sh
# =============================================================================
# Simple send/recv test on Kathara:
#   - launches recv_ipa.py on frankfurt in background
#   - sends N packets from darmstadt with send_ipa.py / test_ipa.py
#   - checks that frankfurt received at least MIN_DELIVERY% of the packets
#   - prints "TEST PASSED" or "TEST FAILED"
#
# Prerequisites:
#   - Kathara lab started (kathara lstart)
#   - eBPF pipeline already loaded on darmstadt (execute_pipeline.py)
#   - /shared mounted on both nodes
#
# Usage:
#   bash shared/test/test_kathara_send_recv.sh [N_PKTS] [METHOD] [MODEL_ID] [SCENARIO]
#   bash shared/test/test_kathara_send_recv.sh 20 hardcoded 42
#   bash shared/test/test_kathara_send_recv.sh 50 template  42
#   bash shared/test/test_kathara_send_recv.sh 50 modular   42
#   bash shared/test/test_kathara_send_recv.sh 20 hardcoded 5 dense
#     (SCENARIO=dense: darmstadt must run method4_hardcoded.py --scenario dense
#      with a model_meta.json declaring n_in/n_out -- see model_meta.py. Every
#      packet carries a real feature vector, not just a header.)
#
# Default: 20 packets, hardcoded method, model_id=42, scenario=sparse
# =============================================================================

set -euo pipefail

N_PKTS="${1:-20}"
METHOD="${2:-hardcoded}"
MODEL_ID="${3:-42}"
SCENARIO="${4:-sparse}"
MIN_DELIVERY=80   # minimum expected packet delivery percentage
RECV_TIMEOUT=30   # recv timeout in seconds
LOG_DIR="/tmp/ipa_test_logs"
RECV_LOG="${LOG_DIR}/recv_ipa_send_recv.log"
COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_YELLOW="\033[1;33m"
NC="\033[0m"

mkdir -p "${LOG_DIR}"

echo -e "${COLOR_YELLOW}=== KATHARA SEND/RECV TEST ===${NC}"
echo "  Packets: ${N_PKTS} | Method: ${METHOD} | model_id: ${MODEL_ID} | scenario: ${SCENARIO}"
echo "  Minimum expected delivery: ${MIN_DELIVERY}%"
echo ""

# ---------------------------------------------------------------------------
# Step 1: check that the Kathara containers are up
# ---------------------------------------------------------------------------
echo "[Step 1] Checking Kathara containers..."
for node in darmstadt frankfurt; do
    if ! kathara exec "${node}" -- echo ok >/dev/null 2>&1; then
        echo -e "${COLOR_RED}[ERROR]${NC} Container '${node}' not responding."
        echo "  Start the lab with: kathara lstart"
        echo "TEST FAILED"
        exit 1
    fi
    echo "  [OK] ${node} up"
done
echo ""

# ---------------------------------------------------------------------------
# Step 2: check that the eBPF pipeline is loaded on darmstadt
# ---------------------------------------------------------------------------
echo "[Step 2] Checking eBPF pipeline on darmstadt..."
if ! kathara exec darmstadt -- bash -c 'bpftool prog list 2>/dev/null | grep -q xdp' 2>/dev/null; then
    echo -e "${COLOR_YELLOW}[WARN]${NC} No XDP program detected on darmstadt."
    echo "  Load the pipeline with:"
    if [ "${SCENARIO}" = "dense" ]; then
        echo "    kathara exec darmstadt -- python3 /shared/methods/method4_hardcoded.py \\"
        echo "        --scenario dense --model-id ${MODEL_ID} \\"
        echo "        --model /shared/test/fixtures/dense_10_4_4_4/model.pt"
    else
        echo "    kathara exec darmstadt -- python3 /shared/execute_pipeline.py --method ${METHOD} --model-id ${MODEL_ID}"
    fi
    echo ""
    # Not blocking: could be an environment without bpftool but with XDP active
else
    echo "  [OK] XDP program active on darmstadt"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3: start recv_ipa.py on frankfurt in background
# ---------------------------------------------------------------------------
echo "[Step 3] Starting recv_ipa.py on frankfurt (timeout=${RECV_TIMEOUT}s)..."
# Write a real script file instead of `kathara exec ... -- bash -c "..."`:
# some kathara-manager versions reject nested `bash -c` invocations inside
# `exec` as a form of self-execution ("Error, the program tried to call
# itself with '-c' argument"). /shared is bind-mounted into the container,
# so a plain script + plain `exec ... -- bash <script>` avoids the -c form.
RECV_RUNNER="/shared/.recv_ipa_runner.sh"
cat > "$(dirname "${BASH_SOURCE[0]}")/../.recv_ipa_runner.sh" <<EOF
#!/usr/bin/env bash
python3 /shared/recv_ipa.py --timeout ${RECV_TIMEOUT} --count ${N_PKTS} \
    > /tmp/recv_ipa_send_recv.log 2>&1
EOF
kathara exec frankfurt -- bash "${RECV_RUNNER}" &
RECV_PID=$!
echo "  recv_ipa.py PID=${RECV_PID} (on host, wraps kathara exec)"
sleep 2  # give the listener time to start
echo ""

# ---------------------------------------------------------------------------
# Step 4: send packets from darmstadt
# ---------------------------------------------------------------------------
echo "[Step 4] Sending ${N_PKTS} IPA packets from darmstadt (scenario=${SCENARIO})..."
if [ "${SCENARIO}" = "dense" ]; then
    kathara exec darmstadt -- python3 /shared/test/test_ipa.py \
        --dest frankfurt \
        --count "${N_PKTS}" \
        --model-id "${MODEL_ID}" \
        --scenario dense \
        --model-meta /shared/test/fixtures/dense_10_4_4_4/model_meta.json \
        --delay 0.05
else
    kathara exec darmstadt -- python3 /shared/test/test_ipa.py \
        --dest frankfurt \
        --count "${N_PKTS}" \
        --model-id "${MODEL_ID}" \
        --delay 0.05
fi
echo ""

# ---------------------------------------------------------------------------
# Step 5: wait for recv_ipa.py to terminate (with timeout)
# ---------------------------------------------------------------------------
echo "[Step 5] Waiting for recv_ipa.py to terminate..."
WAIT_SECS=0
while kill -0 "${RECV_PID}" 2>/dev/null; do
    sleep 1
    WAIT_SECS=$((WAIT_SECS + 1))
    if [ "${WAIT_SECS}" -ge "$((RECV_TIMEOUT + 5))" ]; then
        echo "  [WARN] Timeout waiting for recv_ipa — killing"
        kill "${RECV_PID}" 2>/dev/null || true
        break
    fi
done

# Copy the log from the container
kathara exec frankfurt -- cat /tmp/recv_ipa_send_recv.log > "${RECV_LOG}" 2>/dev/null || true
echo "  Log saved to ${RECV_LOG}"
echo ""

# ---------------------------------------------------------------------------
# Step 6: count received packets and evaluate delivery
# ---------------------------------------------------------------------------
echo "[Step 6] Checking delivery..."
echo "--- recv_ipa output ---"
cat "${RECV_LOG}" 2>/dev/null || echo "  (empty log)"
echo "--- End of output ---"
echo ""

# NOTE: `grep -c` always prints a count (even "0" on no match) but exits 1
# in that case -- `grep -c ... || echo 0` used to run BOTH branches (grep's
# own "0" AND the fallback "0"), producing "0\n0" from the command
# substitution, which broke the arithmetic below. grep -c's own output is
# always a clean single integer (or empty if the file is missing entirely),
# so just default an empty result to 0.
RECEIVED=$(grep -c '\[recv_ipa\] #' "${RECV_LOG}" 2>/dev/null)
RECEIVED=${RECEIVED:-0}
PCT=$(( RECEIVED * 100 / N_PKTS ))

echo "  Sent      : ${N_PKTS}"
echo "  Received  : ${RECEIVED}"
echo "  Delivery  : ${PCT}%  (minimum expected: ${MIN_DELIVERY}%)"
echo ""

# ---------------------------------------------------------------------------
# Step 7: eBPF counters on darmstadt (if available)
# ---------------------------------------------------------------------------
echo "[Step 7] eBPF counters on darmstadt (pkt_stats)..."
kathara exec darmstadt -- bash -c \
    'python3 /shared/execute_pipeline.py --stats 2>/dev/null || \
     python3 -c "
import sys
sys.path.insert(0, \"/shared\")
try:
    from methods.method4_hardcoded import get_stats
    s = get_stats()
    print(f\"  HIT={s.get(\\\"hit\\\",\\"?\\\")}, FAKE={s.get(\\\"fake\\\",\\"?\\\")}, MISS={s.get(\\\"miss\\\",\\"?\\\")}\")
except Exception as e:
    print(f\"  pkt_stats not available: {e}\")
" 2>/dev/null || echo "  pkt_stats: not available (normal outside eBPF kernel)"' || true
echo ""

# ---------------------------------------------------------------------------
# Final verdict
# ---------------------------------------------------------------------------
if [ "${RECEIVED}" -ge 1 ] && [ "${PCT}" -ge "${MIN_DELIVERY}" ]; then
    echo -e "${COLOR_GREEN}TEST PASSED${NC} — ${RECEIVED}/${N_PKTS} packets received (${PCT}%)"
    exit 0
elif [ "${RECEIVED}" -ge 1 ]; then
    echo -e "${COLOR_YELLOW}TEST PARTIAL${NC} — ${RECEIVED}/${N_PKTS} packets received (${PCT}% < ${MIN_DELIVERY}% expected)"
    echo "TEST FAILED"
    exit 1
else
    echo -e "${COLOR_RED}TEST FAILED${NC} — 0 packets received on frankfurt"
    echo "  Possible causes:"
    echo "    - eBPF pipeline not loaded on darmstadt"
    echo "    - Routing not configured (setup_fwd_table.py not run)"
    echo "    - recv_ipa.py did not start in time"
    echo "TEST FAILED"
    exit 1
fi
