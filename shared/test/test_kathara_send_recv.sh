#!/usr/bin/env bash
# =============================================================================
# test_kathara_send_recv.sh
# =============================================================================
# Test semplice send/recv su Kathara:
#   - lancia recv_ipa.py su frankfurt in background
#   - invia N pacchetti da darmstadt con send_ipa.py / test_ipa.py
#   - verifica che frankfurt abbia ricevuto almeno MIN_DELIVERY% dei pacchetti
#   - stampa "TEST PASSED" o "TEST FAILED"
#
# Prerequisiti:
#   - Kathara lab avviato (kathara lstart)
#   - Pipeline eBPF gia' caricata su darmstadt (execute_pipeline.py)
#   - /shared montato in entrambi i nodi
#
# Uso:
#   bash shared/test_kathara_send_recv.sh [N_PKTS] [METHOD] [MODEL_ID]
#   bash shared/test_kathara_send_recv.sh 20 hardcoded 42
#   bash shared/test_kathara_send_recv.sh 50 template  42
#   bash shared/test_kathara_send_recv.sh 50 modular   42
#
# Default: 20 pacchetti, metodo hardcoded, model_id=42
# =============================================================================

set -euo pipefail

N_PKTS="${1:-20}"
METHOD="${2:-hardcoded}"
MODEL_ID="${3:-42}"
MIN_DELIVERY=80   # percentuale minima pacchetti ricevuti
RECV_TIMEOUT=30   # secondi timeout recv
LOG_DIR="/tmp/ipa_test_logs"
RECV_LOG="${LOG_DIR}/recv_ipa_send_recv.log"
COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_YELLOW="\033[1;33m"
NC="\033[0m"

mkdir -p "${LOG_DIR}"

echo -e "${COLOR_YELLOW}=== TEST KATHARA SEND/RECV ===${NC}"
echo "  Pacchetti: ${N_PKTS} | Metodo: ${METHOD} | model_id: ${MODEL_ID}"
echo "  Delivery minima attesa: ${MIN_DELIVERY}%"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Verifica che i container Kathara siano attivi
# ---------------------------------------------------------------------------
echo "[Step 1] Verifica container Kathara..."
for node in darmstadt frankfurt; do
    if ! kathara exec "${node}" -- echo ok >/dev/null 2>&1; then
        echo -e "${COLOR_RED}[ERROR]${NC} Container '${node}' non risponde."
        echo "  Avvia il lab con: kathara lstart"
        echo "TEST FAILED"
        exit 1
    fi
    echo "  [OK] ${node} attivo"
done
echo ""

# ---------------------------------------------------------------------------
# Step 2: Verifica che la pipeline eBPF sia caricata su darmstadt
# ---------------------------------------------------------------------------
echo "[Step 2] Verifica pipeline eBPF su darmstadt..."
if ! kathara exec darmstadt -- bash -c 'bpftool prog list 2>/dev/null | grep -q xdp' 2>/dev/null; then
    echo -e "${COLOR_YELLOW}[WARN]${NC} Nessun programma XDP rilevato su darmstadt."
    echo "  Carica la pipeline con:"
    echo "    kathara exec darmstadt -- python3 /shared/execute_pipeline.py --method ${METHOD} --model-id ${MODEL_ID}"
    echo ""
    # Non blocca: potrebbe essere un ambiente senza bpftool ma con XDP attivo
else
    echo "  [OK] XDP program attivo su darmstadt"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3: Avvia recv_ipa.py su frankfurt in background
# ---------------------------------------------------------------------------
echo "[Step 3] Avvio recv_ipa.py su frankfurt (timeout=${RECV_TIMEOUT}s)..."
kathara exec frankfurt -- bash -c \
    "python3 /shared/recv_ipa.py \
        --timeout ${RECV_TIMEOUT} \
        --count ${N_PKTS} \
        > /tmp/recv_ipa_send_recv.log 2>&1" &
RECV_PID=$!
echo "  recv_ipa.py PID=${RECV_PID} (su host, wraps kathara exec)"
sleep 2  # lascia al listener il tempo di partire
echo ""

# ---------------------------------------------------------------------------
# Step 4: Invia pacchetti da darmstadt
# ---------------------------------------------------------------------------
echo "[Step 4] Invio ${N_PKTS} pacchetti IPA da darmstadt..."
kathara exec darmstadt -- python3 /shared/test_ipa.py \
    --dest frankfurt \
    --count "${N_PKTS}" \
    --model-id "${MODEL_ID}" \
    --delay 0.05
echo ""

# ---------------------------------------------------------------------------
# Step 5: Attendi che recv_ipa.py finisca (con timeout)
# ---------------------------------------------------------------------------
echo "[Step 5] Attesa terminazione recv_ipa.py..."
WAIT_SECS=0
while kill -0 "${RECV_PID}" 2>/dev/null; do
    sleep 1
    WAIT_SECS=$((WAIT_SECS + 1))
    if [ "${WAIT_SECS}" -ge "$((RECV_TIMEOUT + 5))" ]; then
        echo "  [WARN] Timeout attesa recv_ipa — kill"
        kill "${RECV_PID}" 2>/dev/null || true
        break
    fi
done

# Copia il log dal container
kathara exec frankfurt -- cat /tmp/recv_ipa_send_recv.log > "${RECV_LOG}" 2>/dev/null || true
echo "  Log salvato in ${RECV_LOG}"
echo ""

# ---------------------------------------------------------------------------
# Step 6: Conta pacchetti ricevuti e valuta delivery
# ---------------------------------------------------------------------------
echo "[Step 6] Verifica delivery..."
echo "--- Output recv_ipa ---"
cat "${RECV_LOG}" 2>/dev/null || echo "  (log vuoto)"
echo "--- Fine output ---"
echo ""

RECEIVED=$(grep -c '\[recv_ipa\] #' "${RECV_LOG}" 2>/dev/null || echo 0)
PCT=$(( RECEIVED * 100 / N_PKTS ))

echo "  Inviati   : ${N_PKTS}"
echo "  Ricevuti  : ${RECEIVED}"
echo "  Delivery  : ${PCT}%  (minimo atteso: ${MIN_DELIVERY}%)"
echo ""

# ---------------------------------------------------------------------------
# Step 7: Verifica counter eBPF su darmstadt (se disponibile)
# ---------------------------------------------------------------------------
echo "[Step 7] Counter eBPF su darmstadt (pkt_stats)..."
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
    print(f\"  pkt_stats non disponibile: {e}\")
" 2>/dev/null || echo "  pkt_stats: non disponibile (normale fuori da kernel eBPF)"' || true
echo ""

# ---------------------------------------------------------------------------
# Verdetto finale
# ---------------------------------------------------------------------------
if [ "${RECEIVED}" -ge 1 ] && [ "${PCT}" -ge "${MIN_DELIVERY}" ]; then
    echo -e "${COLOR_GREEN}TEST PASSED${NC} — ${RECEIVED}/${N_PKTS} pacchetti ricevuti (${PCT}%)"
    exit 0
elif [ "${RECEIVED}" -ge 1 ]; then
    echo -e "${COLOR_YELLOW}TEST PARTIAL${NC} — ${RECEIVED}/${N_PKTS} pacchetti ricevuti (${PCT}% < ${MIN_DELIVERY}% atteso)"
    echo "TEST FAILED"
    exit 1
else
    echo -e "${COLOR_RED}TEST FAILED${NC} — 0 pacchetti ricevuti su frankfurt"
    echo "  Possibili cause:"
    echo "    - Pipeline eBPF non caricata su darmstadt"
    echo "    - Routing non configurato (setup_fwd_table.py non eseguito)"
    echo "    - recv_ipa.py non partito in tempo"
    echo "TEST FAILED"
    exit 1
fi
