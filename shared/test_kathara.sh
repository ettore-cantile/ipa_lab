#!/bin/bash
# =============================================================================
# test_kathara.sh  —  Test IPA su Kathara: darmstadt -> frankfurt
# =============================================================================
#
# Topologia (da lab.conf + darmstadt.startup):
#   darmstadt[0]="l59"   frankfurt[1]="l59"
#   darmstadt eth0  : 10.0.0.233/30
#   frankfurt eth1  : 10.0.0.234/30   <- ping diretto, senza OSPF
#   frankfurt lo    : 10.255.255.17   <- loopback OSPF, dopo convergenza
#
# Problema kathara exec + flag '-c':
#   kathara exec intercetta '-c' nella propria argv PRIMA di passarlo al
#   container, anche con '--'. Errore: "tried to call itself with '-c'".
#   Soluzione: NON usare mai '-c' in nessun punto della riga kathara exec.
#   kscript() scrive i file tramite uno script bootstrap minimale passato
#   via STDIN con process substitution: 'kathara exec node -- sh' < <(echo ...)
#   Il bootstrap contiene solo 'echo <b64> | base64 -d > path' — zero '-c'.
# =============================================================================

METHOD=${1:-hardcoded}
MODEL_ID=0
PACKET_COUNT=100
INTERVAL=0.002
WEIGHTS="/shared/weights.json"

FRANKFURT_DIRECT="10.0.0.234"   # link l59, raggiungibile subito
FRANKFURT_OSPF="10.255.255.17"  # loopback, dopo convergenza OSPF
FRANKFURT_IP="${FRANKFURT_OSPF}"
INGRESS_IFACE="eth0"            # darmstadt[0]=l59

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} IPA Kathara Test: darmstadt -> frankfurt  [${METHOD}]${NC}"
echo -e "${GREEN}============================================================${NC}"
echo

# ---------------------------------------------------------------------------
# kscript <node> <remote_path> <content>
#
# Scrive uno script nel container senza usare '-c' in nessun punto della
# riga 'kathara exec'.
#
# Strategia:
#   1. Encode content -> base64 (una riga, no newlines)
#   2. Crea un bootstrap a 2 righe che usa solo 'echo' e 'base64 -d'
#   3. Passa il bootstrap via STDIN con process substitution:
#        kathara exec <node> -- sh  < <(printf '%s\n' "$bootstrap")
#      'sh' senza argomenti legge da stdin — nessun '-c' nella argv.
# ---------------------------------------------------------------------------
kscript() {
    local node="$1"
    local path="$2"
    local content="$3"
    local b64
    b64=$(printf '%s' "${content}" | base64 -w0 2>/dev/null \
          || printf '%s' "${content}" | base64)
    # Bootstrap: due comandi separati da ; — nessuna flag '-c'
    local bootstrap
    bootstrap="echo '${b64}' | base64 -d > '${path}'; chmod +x '${path}'"
    kathara exec "${node}" -- sh < <(printf '%s\n' "${bootstrap}")
}

# ---------------------------------------------------------------------------
# kexec <node> <remote_script>
# Esegue uno script gia' presente nel container.
# '--' blocca il parsing kathara; bash legge il path come argomento normale.
# ---------------------------------------------------------------------------
kexec() {
    kathara exec "${1}" -- bash "${2}"
}

# ---------------------------------------------------------------------------
# kcat <node> <remote_file>
# ---------------------------------------------------------------------------
kcat() {
    kathara exec "${1}" -- cat "${2}"
}

# ---------------------------------------------------------------------------
# STEP 1: Containers attivi
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
# STEP 2a: Ping diretto link l59 — verifica container UP, nessun OSPF
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2a] Checking direct link darmstadt->frankfurt (${FRANKFURT_DIRECT})...${NC}"

kscript darmstadt /tmp/ping_direct.sh "#!/bin/sh
ping -c 1 -W 2 ${FRANKFURT_DIRECT} > /dev/null 2>&1 && echo OK || echo FAIL
"

DIRECT_OK=0
for i in $(seq 1 15); do
    RESULT=$(kexec darmstadt /tmp/ping_direct.sh 2>/dev/null | tr -d '\r\n')
    if [ "${RESULT}" = "OK" ]; then
        echo "  Direct link ${FRANKFURT_DIRECT} reachable — containers OK"
        DIRECT_OK=1
        break
    fi
    echo -n "."
    sleep 1
done

if [ ${DIRECT_OK} -eq 0 ]; then
    echo
    echo -e "${RED}  ERROR: Direct link ${FRANKFURT_DIRECT} unreachable after 15s.${NC}"
    echo -e "${RED}  Verify lab.conf: darmstadt[0]=l59, frankfurt[1]=l59${NC}"
    echo -e "${RED}  Check IP: kathara exec darmstadt -- ip addr show eth0${NC}"
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# STEP 2b: Convergenza OSPF — ping loopback frankfurt (10.255.255.17)
# 50 nodi FRR: convergenza tipicamente 60-90s. Timeout: 120s.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2b] Waiting for OSPF convergence (${FRANKFURT_OSPF}, up to 120s)...${NC}"

kscript darmstadt /tmp/ping_ospf.sh "#!/bin/sh
ping -c 1 -W 2 ${FRANKFURT_OSPF} > /dev/null 2>&1 && echo OK || echo FAIL
"

CONVERGED=0
for i in $(seq 1 120); do
    RESULT=$(kexec darmstadt /tmp/ping_ospf.sh 2>/dev/null | tr -d '\r\n')
    if [ "${RESULT}" = "OK" ]; then
        echo "  OSPF converged at ${i}s — ${FRANKFURT_OSPF} reachable"
        CONVERGED=1
        break
    fi
    if [ $((i % 10)) -eq 0 ]; then
        echo -n " ${i}s"
    else
        echo -n "."
    fi
    sleep 1
done

if [ ${CONVERGED} -eq 0 ]; then
    echo
    echo -e "${RED}  ERROR: OSPF loopback ${FRANKFURT_OSPF} unreachable after 120s.${NC}"
    echo -e "${RED}  Debug: kathara exec darmstadt -- vtysh -c 'show ip ospf neighbor'${NC}"
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# STEP 3: Receiver su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Starting IPA receiver on frankfurt...${NC}"

kscript frankfurt /tmp/run_recv.sh "#!/bin/sh
python3 /shared/recv_ipa.py --timeout 60 --count ${PACKET_COUNT} > /tmp/recv_ipa.log 2>&1 &
echo \$! > /tmp/recv_ipa.pid
echo \"recv_ipa.py started (pid=\$!)\"
"
kexec frankfurt /tmp/run_recv.sh
sleep 2
echo

# ---------------------------------------------------------------------------
# STEP 4: Carica pipeline XDP su darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Loading pipeline '${METHOD}' on darmstadt (iface=${INGRESS_IFACE})...${NC}"

kscript darmstadt /tmp/run_pipeline.sh "#!/bin/sh
python3 /shared/execute_pipeline.py \\
    --method ${METHOD} \\
    --iface ${INGRESS_IFACE} \\
    --model-id ${MODEL_ID} > /tmp/pipeline.log 2>&1 &
echo \$! > /tmp/pipeline.pid
echo \"Pipeline started (pid=\$!)\"
"
kexec darmstadt /tmp/run_pipeline.sh
echo "  Waiting 6s for XDP attach..."
sleep 6
echo

# ---------------------------------------------------------------------------
# STEP 5: Verifica pipeline startup
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Pipeline startup check:${NC}"
kscript darmstadt /tmp/check_pipeline.sh "#!/bin/sh
LOG=/tmp/pipeline.log
if [ ! -f \"\$LOG\" ]; then
    echo 'PIPELINE_STATUS=NOT_STARTED'
elif grep -qi 'error\|traceback\|exception' \"\$LOG\"; then
    echo 'PIPELINE_STATUS=ERROR'
else
    echo 'PIPELINE_STATUS=OK'
fi
"
STATUS_LINE=$(kexec darmstadt /tmp/check_pipeline.sh 2>/dev/null | tr -d '\r')
echo "  ${STATUS_LINE}"
if echo "${STATUS_LINE}" | grep -q 'ERROR\|NOT_STARTED'; then
    echo -e "${RED}  Pipeline failed. Full log:${NC}"
    kcat darmstadt /tmp/pipeline.log
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# STEP 6: Invia pacchetti IPA
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 6] Sending ${PACKET_COUNT} IPA packets: darmstadt -> frankfurt (${FRANKFURT_IP})...${NC}"

kscript darmstadt /tmp/send_ipa.sh "#!/bin/sh
python3 /shared/send_ipa.py \\
    --dst ${FRANKFURT_IP} \\
    --count ${PACKET_COUNT} \\
    --model-id ${MODEL_ID} \\
    --weights ${WEIGHTS} \\
    --interval ${INTERVAL} 2>&1
"
kexec darmstadt /tmp/send_ipa.sh
echo

# ---------------------------------------------------------------------------
# STEP 7: Log receiver frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7] Receiver log on frankfurt:${NC}"
sleep 2
kcat frankfurt /tmp/recv_ipa.log 2>/dev/null || echo "  (log not available)"
echo

# ---------------------------------------------------------------------------
# STEP 8: Log pipeline darmstadt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 8] Pipeline log on darmstadt:${NC}"
kcat darmstadt /tmp/pipeline.log 2>/dev/null || echo "  (no log)"
echo

# ---------------------------------------------------------------------------
# STEP 9: BPF map stats (informational)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 9] BPF map stats on darmstadt:${NC}"
kscript darmstadt /tmp/bpf_stats.sh "#!/bin/sh
bpftool map show 2>/dev/null | grep -E 'name|entries' || echo '  (no maps loaded)'
"
kexec darmstadt /tmp/bpf_stats.sh
echo

# ---------------------------------------------------------------------------
# STEP 10: Verifica conteggio pacchetti + TEST PASSED / TEST FAILED
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 10] Verifying packet counts...${NC}"

kscript frankfurt /tmp/check_recv.sh "#!/bin/sh
LOG=/tmp/recv_ipa.log
if [ ! -f \"\$LOG\" ]; then
    echo 'RECV_COUNT=0'
else
    CNT=\$(grep -ci 'received\|recv\|packet' \"\$LOG\" 2>/dev/null || echo 0)
    echo \"RECV_COUNT=\${CNT}\"
fi
"
RECV_LINE=$(kexec frankfurt /tmp/check_recv.sh 2>/dev/null | grep RECV_COUNT | tr -d '\r')
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
