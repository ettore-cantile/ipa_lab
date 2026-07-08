#!/bin/bash
# =============================================================================
# test_kathara.sh  —  Test IPA Pipeline 1 (Hardcoded) su Kathara
#
# Flusso:
#   1. frankfurt carica XDP (Pipeline 1 hardcoded) su eth1 (ingress da darmstadt)
#   2. darmstadt invia 100 pacchetti IPA UDP:9999 con TTL variabile (30-64)
#   3. XDP su frankfurt esegue l'inferenza e sceglie la porta di uscita
#   4. Il test verifica TRUE HIT >= 80% leggendo l'ultima riga di stato
#      stampata dalla pipeline nel suo log (bpftool non e' disponibile
#      nei container di questo lab) e stampa la porta scelta per classe
#
# Usage: bash shared/test_kathara.sh [hardcoded|template|modular]
#
# Nota kathara exec: scrive il comando in shared/_krun_<node>.sh
# (montato come /shared/_krun_<node>.sh nei container) per evitare
# problemi con il flag '-c' e la mancanza di TTY.
# =============================================================================

METHOD=${1:-hardcoded}
MODEL_ID=0
PACKET_COUNT=100
INTERVAL=0.02
WEIGHTS="/shared/weights.json"

# Topologia:
#   darmstadt eth0 = 10.0.0.233/30  (link l59 verso frankfurt eth1)
#   frankfurt eth1 = 10.0.0.234/30  (ingress IPA, XDP attaccato qui)
FRANKFURT_DIRECT="10.0.0.234"
FRANKFURT_OSPF="10.255.255.17"
FRANKFURT_IP="${FRANKFURT_DIRECT}"
FRANKFURT_XDP_IFACE="eth1"      # XDP gira su frankfurt, non su darmstadt

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} IPA Kathara Test: darmstadt -> frankfurt  [${METHOD}]${NC}"
echo -e "${GREEN} Pipeline 1 Hardcoded: XDP su frankfurt/${FRANKFURT_XDP_IFACE}${NC}"
echo -e "${GREEN}============================================================${NC}"
echo

# ---------------------------------------------------------------------------
# krun NODE CMD — scrive CMD in /shared/_krun_NODE.sh ed esegue via kathara
# ---------------------------------------------------------------------------
krun() {
    local node="$1"
    shift
    local cmd="$*"
    local tmpscript="${SCRIPT_DIR}/_krun_${node}.sh"
    printf '#!/bin/bash\n%s\n' "${cmd}" > "${tmpscript}"
    chmod +x "${tmpscript}"
    kathara exec "${node}" -- bash /shared/_krun_${node}.sh 2>&1
    local rc=$?
    rm -f "${tmpscript}"
    return ${rc}
}

# ---------------------------------------------------------------------------
# Step 1 — Verifica container attivi
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 1] Checking Kathara containers...${NC}"
if ! kathara linfo 2>/dev/null | grep -q "darmstadt"; then
    echo -e "${RED}[ERROR] Lab not running. Run: kathara lstart${NC}"
    exit 1
fi
echo "  darmstadt: UP"
echo "  frankfurt:  UP"
echo

# ---------------------------------------------------------------------------
# Step 2a — Link diretto darmstadt -> frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2a] Checking direct link darmstadt -> frankfurt (${FRANKFURT_DIRECT})...${NC}"
DIRECT_OK=0
for i in $(seq 1 15); do
    RESULT=$(krun darmstadt "ping -c 1 -W 2 ${FRANKFURT_DIRECT} > /dev/null 2>&1 && echo OK || echo FAIL" | tr -d '\r\n')
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
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# Step 2a-bis — Verifica che l'interfaccia XDP configurata sia quella VERA
#
# germany50 ha molti link per nodo: il ping riesce comunque (il kernel di
# frankfurt instrada in base all'IP, non al nome interfaccia), ma XDP viene
# agganciato al NOME hardcoded FRANKFURT_XDP_IFACE ("eth1"). Se quel nome
# non corrisponde davvero all'interfaccia collegata a darmstadt, XDP vede
# solo il traffico di un link completamente diverso (altro vicino OSPF) e
# i pacchetti IPA -- pur arrivando fisicamente a frankfurt -- non passano
# mai da li: TRUE HIT=0 senza alcun bug nella pipeline o nel routing.
# Fix: risolvere dinamicamente l'interfaccia reale da ${FRANKFURT_DIRECT}
# invece di fidarsi del nome hardcoded.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2a-bis] Verifying which real interface on frankfurt carries ${FRANKFURT_DIRECT}...${NC}"
ACTUAL_IFACE=$(krun frankfurt "ip -o -4 addr show | grep -F '${FRANKFURT_DIRECT}' | awk '{print \$2}'" | tr -d '\r\n')
echo "  Configured FRANKFURT_XDP_IFACE = ${FRANKFURT_XDP_IFACE}"
echo "  Actual interface holding ${FRANKFURT_DIRECT}  = ${ACTUAL_IFACE:-<not found>}"
if [ -z "${ACTUAL_IFACE}" ]; then
    echo -e "${RED}  ERROR: could not resolve which interface on frankfurt holds ${FRANKFURT_DIRECT}.${NC}"
    echo "TEST FAILED"
    exit 1
fi
if [ "${ACTUAL_IFACE}" != "${FRANKFURT_XDP_IFACE}" ]; then
    echo -e "${YELLOW}  Mismatch detected — overriding FRANKFURT_XDP_IFACE: ${FRANKFURT_XDP_IFACE} -> ${ACTUAL_IFACE}${NC}"
    FRANKFURT_XDP_IFACE="${ACTUAL_IFACE}"
else
    echo "  Match confirmed — XDP will attach to the correct interface."
fi
echo

# ---------------------------------------------------------------------------
# Step 2b — OSPF convergence (opzionale, 30s timeout, SOLO informativo)
#
# Nota: questo check NON deve determinare l'IP usato per il test (Step 6).
# germany50 e' una topologia a 50 nodi: il percorso che OSPF calcola verso
# l'indirizzo di loopback ${FRANKFURT_OSPF} non e' garantito passare per il
# link diretto darmstadt->frankfurt (${FRANKFURT_XDP_IFACE}) -- potrebbe
# instradare altrove se esistono percorsi di costo pari/inferiore. Dato che
# lo scopo del test e' verificare XDP specificamente su
# ${FRANKFURT_XDP_IFACE}, i pacchetti IPA vanno SEMPRE spediti all'IP del
# link diretto (FRANKFURT_IP resta ${FRANKFURT_DIRECT}); questo passo serve
# solo a segnalare lo stato di convergenza OSPF, non a scegliere la
# destinazione. (In precedenza sovrascriveva FRANKFURT_IP con l'indirizzo
# OSPF quando convergeva, causando pacchetti instradati altrove e quindi
# mai visti su eth1 -- TRUE HIT=0 senza alcun bug nella pipeline.)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2b] Checking optional OSPF convergence (${FRANKFURT_OSPF}, up to 30s)...${NC}"
CONVERGED=0
for i in $(seq 1 30); do
    RESULT=$(krun darmstadt "ping -c 1 -W 2 ${FRANKFURT_OSPF} > /dev/null 2>&1 && echo OK || echo FAIL" | tr -d '\r\n')
    if [ "${RESULT}" = "OK" ]; then
        echo "  OSPF converged at ${i}s — ${FRANKFURT_OSPF} reachable (informational only)"
        CONVERGED=1
        break
    fi
    echo -n "."
    sleep 1
done
if [ ${CONVERGED} -eq 0 ]; then
    echo
    echo "  OSPF not ready (informational only, does not affect the test)"
fi
echo "  Using direct link IP ${FRANKFURT_IP} for the actual test (guarantees ingress via ${FRANKFURT_XDP_IFACE})"
echo

# ---------------------------------------------------------------------------
# Step 3 — Carica Pipeline 1 su FRANKFURT (XDP su eth1)
#
# Pulizia preliminare: un'esecuzione precedente di questo script che sia
# uscita per timeout (Step 4) lascia execute_pipeline.py ancora vivo in
# background e/o XDP ancora attaccato su ${FRANKFURT_XDP_IFACE}. Se non
# lo si ripulisce, la nuova compilazione BCC deve competere per la CPU
# con quella vecchia (rendendola ancora piu' lenta) e il nuovo attach XDP
# puo' scontrarsi con quello vecchio. Idempotente: non fa nulla se non
# c'e' niente da pulire.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Loading Pipeline 1 (hardcoded) on frankfurt (iface=${FRANKFURT_XDP_IFACE})...${NC}"
krun frankfurt "pkill -f execute_pipeline.py 2>/dev/null; ip link set dev ${FRANKFURT_XDP_IFACE} xdp off 2>/dev/null; rm -f /tmp/pipeline_frankfurt.log; sleep 1; echo cleaned" > /dev/null
krun frankfurt "nohup python3 /shared/execute_pipeline.py \
    --method ${METHOD} \
    --iface ${FRANKFURT_XDP_IFACE} \
    --model-id ${MODEL_ID} \
    > /tmp/pipeline_frankfurt.log 2>&1 & echo started"
echo

# ---------------------------------------------------------------------------
# Step 4 — Attendi avvio pipeline su frankfurt (polling, non uno sleep fisso)
#
# Nota: un `sleep 8` fisso qui era intermittente — la compilazione BCC del
# programma eBPF (clang -target bpf, con l'intera catena di include del
# kernel) parte da zero ad ogni avvio e il suo tempo e' variabile a
# seconda del carico della macchina: si sono osservati sia ~15s sia oltre
# 40s per lo stesso identico programma. Un timeout di 40s si e' rivelato
# ancora troppo stretto in pratica. Fix: polling fino a 90s sulla stessa
# stringa "XDP attached" gia' usata prima, con uscita immediata su
# errore/traceback (stesso pattern dello Step 2b per OSPF).
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Waiting for pipeline startup on frankfurt (up to 90s)...${NC}"
PIPELINE_READY=0
for i in $(seq 1 90); do
    STATUS_LINE=$(krun frankfurt 'if [ ! -f /tmp/pipeline_frankfurt.log ]; then
    echo PIPELINE_STATUS=NOT_STARTED
elif grep -qi "error\|traceback\|exception" /tmp/pipeline_frankfurt.log; then
    echo PIPELINE_STATUS=ERROR
elif grep -qi "XDP attached" /tmp/pipeline_frankfurt.log; then
    echo PIPELINE_STATUS=OK
else
    echo PIPELINE_STATUS=STARTING
fi' | tr -d '\r')
    if echo "${STATUS_LINE}" | grep -q 'PIPELINE_STATUS=OK'; then
        PIPELINE_READY=1
        echo "  ${STATUS_LINE}  (ready after ${i}s)"
        break
    fi
    if echo "${STATUS_LINE}" | grep -q 'PIPELINE_STATUS=ERROR'; then
        echo
        echo "  ${STATUS_LINE}"
        echo -e "${RED}  Pipeline failed. Full log:${NC}"
        krun frankfurt 'cat /tmp/pipeline_frankfurt.log'
        echo "TEST FAILED"
        exit 1
    fi
    echo -n "."
    sleep 1
done
if [ ${PIPELINE_READY} -eq 0 ]; then
    echo
    echo -e "${RED}  Pipeline did not report 'XDP attached' within 90s. Full log:${NC}"
    krun frankfurt 'cat /tmp/pipeline_frankfurt.log'
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# Step 5 — Stampa egress ifindex table caricata
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Egress ifindex table (from pipeline log):${NC}"
krun frankfurt 'grep -E "cls [0-9]|ifindex" /tmp/pipeline_frankfurt.log 2>/dev/null | head -10'
echo

# ---------------------------------------------------------------------------
# Step 6 — Invia 100 pacchetti IPA da darmstadt con TTL variabile 30-64
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 6] Sending ${PACKET_COUNT} IPA packets from darmstadt -> ${FRANKFURT_IP}${NC}"
echo -e "         TTL range: 30-64 (random per packet), interval=${INTERVAL}s"
krun darmstadt "python3 /shared/send_ipa.py \
    --dst ${FRANKFURT_IP} \
    --count ${PACKET_COUNT} \
    --model-id ${MODEL_ID} \
    --weights ${WEIGHTS} \
    --interval ${INTERVAL} \
    --ttl-min 30 \
    --ttl-max 64"
echo

# ---------------------------------------------------------------------------
# Step 7 — Attendi elaborazione XDP
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7] Waiting 3s for XDP to process packets...${NC}"
sleep 3
echo

# ---------------------------------------------------------------------------
# Step 8 — Leggi le statistiche dal log della pipeline (niente bpftool)
#
# Nota storica: le versioni precedenti di questo step chiamavano `bpftool`
# per leggere pkt_stats/cls_stats direttamente dalle BPF map. bpftool non e'
# installato nei container Kathara di questo lab ("No such file or
# directory: 'bpftool'"), quindi quell'approccio non puo' funzionare qui.
# method4_hardcoded.py pero' stampa gia' ogni secondo una riga di stato
# (TRUE HIT / MISS / DROP / cls0..6 / chosen_port) nel suo stesso log
# (/tmp/pipeline_frankfurt.log) usando `end="\r"` per aggiornarsi in-place:
# ne basta l'ULTIMA occorrenza per avere lo stato piu recente, senza
# bisogno di bpftool ne di un handle BCC separato sul processo in corso.
#
# Nota quoting: il payload Python e' scritto su file via heredoc (non
# passato come stringa 'python3 -c "..."') perche' krun() gia' incapsula
# il comando in un livello di quoting bash; un heredoc con delimitatore
# quotato ('PYEOF') e' scritto letteralmente, senza alcuna espansione,
# quindi qualunque quoting Python al suo interno e' al sicuro.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 8] Reading BPF stats from frankfurt pipeline log:${NC}"
cat > "${SCRIPT_DIR}/_stats_parse.py" <<'PYEOF'
import re

LOG = "/tmp/pipeline_frankfurt.log"
try:
    with open(LOG, "r", errors="replace") as f:
        content = f.read()
except Exception as e:
    print(f"STATS_ERROR: {e}")
    raise SystemExit

# The live status line refreshes in place via '\r', not '\n'.
records = re.split(r"[\r\n]+", content)
pattern = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+chosen_port=(\S+)\s*$"
)

last = None
for line in records:
    m = pattern.match(line)
    if m:
        last = m

if last is None:
    print("STATS_ERROR: no stats line found in pipeline log yet")
    raise SystemExit

hit, miss, drop = int(last.group(1)), int(last.group(2)), int(last.group(3))
cls = [int(last.group(i)) for i in range(4, 11)]
chosen = last.group(11)
total = hit + miss + drop

print(f"HIT_COUNT={hit}")
print(f"MISS_COUNT={miss}")
print(f"DROP_COUNT={drop}")
print(f"TOTAL={total}")
print(f"CHOSEN_PORT={chosen}")
print()
print(f"  TRUE HIT  (redirect) : {hit:>8}  ({100*hit/max(total,1):.1f}%)")
print(f"  MISS      (no cache) : {miss:>8}  ({100*miss/max(total,1):.1f}%)")
print(f"  DROP      (cls 6)    : {drop:>8}  ({100*drop/max(total,1):.1f}%)")
print(f"  TOTAL                : {total:>8}")
print()
print("  Egress port chosen per class (inference output):")
cls_labels = ["eth0", "eth1", "eth2", "eth3", "eth4", "eth5", "DROP"]
cls_total = sum(cls) if any(cls) else 1
for i, cnt in enumerate(cls):
    label = cls_labels[i] if i < len(cls_labels) else f"cls{i}"
    bar = "#" * int(30 * cnt / max(cls_total, 1))
    print(f"    cls {i} -> {label:6s} : {cnt:>6}  {bar}")
PYEOF
STATS_FULL=$(krun frankfurt "python3 /shared/_stats_parse.py")
rm -f "${SCRIPT_DIR}/_stats_parse.py"
if echo "${STATS_FULL}" | grep -q '^STATS_ERROR'; then
    echo "  ${STATS_FULL}"
else
    echo "${STATS_FULL}" | grep -A3 'TRUE HIT'
fi
echo

# ---------------------------------------------------------------------------
# Step 9 — Per-class egress port distribution (dallo stesso parse dello Step 8)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] Per-class egress port distribution on frankfurt:${NC}"
if echo "${STATS_FULL}" | grep -q '^STATS_ERROR'; then
    echo "  (no data — see Step 8)"
else
    echo "${STATS_FULL}" | sed -n '/Egress port/,$p'
fi
echo

# ---------------------------------------------------------------------------
# Step 10 — Pipeline log su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 10] Pipeline log (last 20 lines) on frankfurt:${NC}"
krun frankfurt 'tail -20 /tmp/pipeline_frankfurt.log 2>/dev/null || echo no-log'
echo

# ---------------------------------------------------------------------------
# Step 11 — Verifica finale: TRUE HIT >= 80%  (riusa STATS_FULL dello Step 8,
# nessuna nuova chiamata bpftool/krun necessaria)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 11] Final verdict:${NC}"
HIT_COUNT=$(echo "${STATS_FULL}" | grep '^HIT_COUNT=' | cut -d= -f2 | tr -d '\r')
HIT_COUNT=$(echo "${HIT_COUNT}" | grep -oE '^[0-9]+$' || echo 0)
[ -z "${HIT_COUNT}" ] && HIT_COUNT=0
THRESHOLD=$((PACKET_COUNT * 80 / 100))

echo "  Packets sent    : ${PACKET_COUNT}  (TTL range 30-64)"
echo "  TRUE HIT count  : ${HIT_COUNT}    (inference -> redirect -> no fwd_table)"
echo "  Pass threshold  : ${THRESHOLD}   (80%)"
echo
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} Test complete — Method: ${METHOD} — XDP on frankfurt/${FRANKFURT_XDP_IFACE}${NC}"
echo -e "${GREEN}============================================================${NC}"

if [ "${HIT_COUNT}" -ge "${THRESHOLD}" ] 2>/dev/null; then
    echo -e "${GREEN}TEST PASSED — TRUE HIT=${HIT_COUNT}/${PACKET_COUNT} (>= ${THRESHOLD})${NC}"
    echo "TEST PASSED"
else
    echo -e "${RED}TEST FAILED — TRUE HIT=${HIT_COUNT}/${PACKET_COUNT} (< ${THRESHOLD})${NC}"
    echo "  Possible causes:"
    echo "    - model_cache not populated (check Step 4 log)"
    echo "    - bpf_redirect failed (check ifindex_table in Step 5)"
    echo "    - packets not reaching frankfurt eth1 (check Step 2a)"
    echo "TEST FAILED"
    exit 1
fi
