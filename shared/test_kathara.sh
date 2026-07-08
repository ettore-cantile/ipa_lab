#!/bin/bash
# =============================================================================
# test_kathara.sh  —  Test IPA Pipeline 1 (Hardcoded) su Kathara
#
# Flusso:
#   1. frankfurt carica XDP (Pipeline 1 hardcoded) su eth1 (ingress da darmstadt)
#   2. darmstadt invia 100 pacchetti IPA UDP:9999 con TTL variabile (30-64)
#   3. XDP su frankfurt esegue l'inferenza e sceglie la porta di uscita
#   4. Il test verifica TRUE HIT >= 80% leggendo pkt_stats[0] via bpftool
#      e stampa la porta di uscita scelta per ogni classe
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
# Step 2b — OSPF convergence (opzionale, 30s timeout)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2b] Checking optional OSPF convergence (${FRANKFURT_OSPF}, up to 30s)...${NC}"
CONVERGED=0
for i in $(seq 1 30); do
    RESULT=$(krun darmstadt "ping -c 1 -W 2 ${FRANKFURT_OSPF} > /dev/null 2>&1 && echo OK || echo FAIL" | tr -d '\r\n')
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
    echo "  OSPF not ready — continuing with direct IP ${FRANKFURT_DIRECT}"
fi
echo

# ---------------------------------------------------------------------------
# Step 3 — Carica Pipeline 1 su FRANKFURT (XDP su eth1)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Loading Pipeline 1 (hardcoded) on frankfurt (iface=${FRANKFURT_XDP_IFACE})...${NC}"
krun frankfurt "nohup python3 /shared/execute_pipeline.py \
    --method ${METHOD} \
    --iface ${FRANKFURT_XDP_IFACE} \
    --model-id ${MODEL_ID} \
    > /tmp/pipeline_frankfurt.log 2>&1 & echo started"
echo "  Waiting 8s for XDP attach and model_cache population..."
sleep 8
echo

# ---------------------------------------------------------------------------
# Step 4 — Verifica avvio pipeline su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Pipeline startup check on frankfurt:${NC}"
STATUS_LINE=$(krun frankfurt 'if [ ! -f /tmp/pipeline_frankfurt.log ]; then
    echo PIPELINE_STATUS=NOT_STARTED
elif grep -qi "error\|traceback\|exception" /tmp/pipeline_frankfurt.log; then
    echo PIPELINE_STATUS=ERROR
elif grep -qi "XDP attached" /tmp/pipeline_frankfurt.log; then
    echo PIPELINE_STATUS=OK
else
    echo PIPELINE_STATUS=STARTING
fi' | tr -d '\r')
echo "  ${STATUS_LINE}"
if echo "${STATUS_LINE}" | grep -q 'ERROR\|NOT_STARTED'; then
    echo -e "${RED}  Pipeline failed. Full log:${NC}"
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
# Step 8 — Leggi pkt_stats da frankfurt via bpftool
#
# Nota: il payload Python viene scritto su file via heredoc (non passato
# come stringa 'python3 -c "..."') perche' krun() gia' incapsula il comando
# in un livello di quoting bash; una stringa -c "..." con doppi apici Python
# annidati (liste, f-string) si scontra con quel livello e produce un file
# .sh malformato ("syntax error near unexpected token '('"). Un heredoc con
# delimitatore quotato ('PYEOF') e' scritto letteralmente, senza alcuna
# espansione/escaping, quindi qualunque quoting Python e' al sicuro.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 8] Reading BPF stats from frankfurt:${NC}"
cat > "${SCRIPT_DIR}/_stats_pkt.py" <<'PYEOF'
import subprocess, re, sys
try:
    out = subprocess.check_output(["bpftool", "map", "show"], text=True)
    map_id = None
    for line in out.splitlines():
        if "pkt_stats" in line:
            m = re.search(r"^(\d+):", line)
            if m:
                map_id = m.group(1)
    if map_id is None:
        print("STATS_ERROR: pkt_stats map not found")
        sys.exit(0)
    dump = subprocess.check_output(["bpftool", "map", "dump", "id", map_id], text=True)
    print("BPFTOOL_DUMP=" + dump.replace("\n", "|"))
except Exception as e:
    print(f"STATS_ERROR: {e}")
PYEOF
STATS_OUT=$(krun frankfurt "python3 /shared/_stats_pkt.py")
echo "  ${STATS_OUT}"
echo

# ---------------------------------------------------------------------------
# Step 9 — Leggi cls_stats e stampa porta di uscita per classe
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] Per-class egress port distribution on frankfurt:${NC}"
cat > "${SCRIPT_DIR}/_stats_cls.py" <<'PYEOF'
import subprocess, re, sys
try:
    out = subprocess.check_output(["bpftool", "map", "show"], text=True)
    map_id_pkt = None
    map_id_cls = None
    for line in out.splitlines():
        if "pkt_stats" in line:
            m = re.search(r"^(\d+):", line)
            if m:
                map_id_pkt = m.group(1)
        if "cls_stats" in line:
            m = re.search(r"^(\d+):", line)
            if m:
                map_id_cls = m.group(1)

    def read_array_map(mid):
        if mid is None:
            return []
        dump = subprocess.check_output(["bpftool", "map", "dump", "id", mid], text=True)
        vals = []
        for entry in dump.split("key:"):
            if not entry.strip():
                continue
            vm = re.search(r"value: ([\da-f ]+)", entry)
            if vm:
                hexbytes = vm.group(1).split()
                if len(hexbytes) >= 8:
                    val = int.from_bytes(bytes(int(h, 16) for h in hexbytes[:8]), "little")
                    vals.append(val)
        return vals

    pkt = read_array_map(map_id_pkt)
    cls = read_array_map(map_id_cls)

    hit = pkt[0] if len(pkt) > 0 else 0
    miss = pkt[1] if len(pkt) > 1 else 0
    drop = pkt[2] if len(pkt) > 2 else 0
    total = hit + miss + drop

    print(f"  TRUE HIT  (redirect) : {hit:>8}  ({100*hit/max(total,1):.1f}%)")
    print(f"  MISS      (no cache) : {miss:>8}  ({100*miss/max(total,1):.1f}%)")
    print(f"  DROP      (cls 6)    : {drop:>8}  ({100*drop/max(total,1):.1f}%)")
    print(f"  TOTAL                : {total:>8}")
    print()
    print("  Egress port chosen per class (inference output)::")
    cls_labels = ["eth0", "eth1", "eth2", "eth3", "eth4", "eth5", "DROP"]
    cls_total = sum(cls) if cls else 1
    for i, cnt in enumerate(cls[:7]):
        label = cls_labels[i] if i < len(cls_labels) else f"cls{i}"
        bar = "#" * int(30 * cnt / max(cls_total, 1))
        print(f"    cls {i} -> {label:6s} : {cnt:>6}  {bar}")
    print()
    chosen = cls_labels[cls.index(max(cls))] if cls else "NONE"
    print(f"CHOSEN_PORT={chosen}")
    print(f"HIT_COUNT={hit}")
except Exception as e:
    print(f"STATS_ERROR: {e}")
PYEOF
krun frankfurt "python3 /shared/_stats_cls.py"
echo

# ---------------------------------------------------------------------------
# Step 10 — Pipeline log su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 10] Pipeline log (last 20 lines) on frankfurt:${NC}"
krun frankfurt 'tail -20 /tmp/pipeline_frankfurt.log 2>/dev/null || echo no-log'
echo

# ---------------------------------------------------------------------------
# Step 11 — Verifica finale: TRUE HIT >= 80%
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 11] Final verdict:${NC}"
cat > "${SCRIPT_DIR}/_stats_hit.py" <<'PYEOF'
import subprocess, re
try:
    out = subprocess.check_output(["bpftool", "map", "show"], text=True)
    map_id = None
    for line in out.splitlines():
        if "pkt_stats" in line:
            m = re.search(r"^(\d+):", line)
            if m:
                map_id = m.group(1)
    if map_id is None:
        print("HIT=0")
    else:
        dump = subprocess.check_output(["bpftool", "map", "dump", "id", map_id], text=True)
        vals = []
        for entry in dump.split("key:"):
            if not entry.strip():
                continue
            vm = re.search(r"value: ([\da-f ]+)", entry)
            if vm:
                hexbytes = vm.group(1).split()
                if len(hexbytes) >= 8:
                    val = int.from_bytes(bytes(int(h, 16) for h in hexbytes[:8]), "little")
                    vals.append(val)
        print(f"HIT={vals[0] if vals else 0}")
except Exception as e:
    print("HIT=0")
PYEOF
HIT_LINE=$(krun frankfurt "python3 /shared/_stats_hit.py" | grep '^HIT=' | tr -d '\r')
rm -f "${SCRIPT_DIR}/_stats_pkt.py" "${SCRIPT_DIR}/_stats_cls.py" "${SCRIPT_DIR}/_stats_hit.py"

HIT_COUNT=$(echo "${HIT_LINE}" | grep -oE '[0-9]+$' || echo 0)
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
