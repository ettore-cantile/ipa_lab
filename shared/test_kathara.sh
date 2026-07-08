#!/bin/bash
# =============================================================================
# test_kathara.sh  —  Test IPA su Kathara: darmstadt -> frankfurt
# =============================================================================
#
# Topologia rilevante (da lab.conf + darmstadt.startup):
#   darmstadt[0]="l59"   frankfurt[1]="l59"
#   darmstadt eth0  : 10.0.0.233/30
#   frankfurt eth1  : 10.0.0.234/30   <- ping diretto, SEMPRE raggiungibile
#   frankfurt lo    : 10.255.255.17   <- loopback OSPF, raggiungibile DOPO convergenza
#
# Strategia convergenza (Step 2):
#   1) Ping diretto 10.0.0.234 -> verifica che il container sia UP (< 3s)
#   2) Ping loopback 10.255.255.17 -> verifica convergenza OSPF (fino a 120s)
#      OSPF su 50 nodi richiede tipicamente 60-90s al primo avvio.
#
# Problema kathara exec:
#   kathara exec <node> <cmd> intercetta i flag che iniziano con '-' nella
#   propria riga di comando, inclusi quelli destinati al comando remoto.
#   Soluzione: usare sempre 'kathara exec <node> -- <cmd>' con il separatore
#   '--' che blocca il parsing degli argomenti di kathara.
#
# Problema kscript con heredoc:
#   'kathara exec node sh << EOF' viene parsato dalla shell host che invia
#   stdin a kathara, non al container sh. Alcune versioni di kathara non
#   inoltrano stdin correttamente. Soluzione: scrivere il contenuto in base64,
#   inviarlo come singola riga e decodificarlo nel container.
# =============================================================================

METHOD=${1:-hardcoded}
MODEL_ID=0
PACKET_COUNT=100
INTERVAL=0.002
WEIGHTS="/shared/weights.json"

# IP diretto frankfurt su link l59 (eth1 frankfurt, /30 con darmstadt eth0)
FRANKFURT_DIRECT="10.0.0.234"
# Loopback OSPF frankfurt (raggiungibile solo dopo convergenza)
FRANKFURT_OSPF="10.255.255.17"
# Indirizzo usato per inviare i pacchetti IPA (loopback, stabile)
FRANKFURT_IP="${FRANKFURT_OSPF}"
# Interfaccia ingress su darmstadt verso frankfurt (darmstadt[0]=l59 -> eth0)
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
# kscript <node> <remote_path> <content>
#
# Scrive uno script bash nel container senza usare heredoc (broken su alcuni
# kathara) e senza flag '-c' (intercettati da kathara exec).
#
# Meccanismo:
#   1. Codifica il contenuto in base64 sul host
#   2. Passa la stringa base64 come ARGOMENTO POSIZIONALE a sh:
#        kathara exec <node> -- sh -c 'echo "$1"|base64 -d>$2;chmod +x $2' _ <b64> <path>
#      Il flag '-c' qui è argomento di 'sh' all'interno del container,
#      non di kathara exec, quindi non viene intercettato.
# ---------------------------------------------------------------------------
kscript() {
    local node="$1"
    local path="$2"
    local content="$3"
    local b64
    b64=$(printf '%s' "${content}" | base64 -w0 2>/dev/null \
          || printf '%s' "${content}" | base64)
    kathara exec "${node}" -- sh -c \
        'printf "%s" "$1" | base64 -d > "$2" && chmod +x "$2"' \
        _ "${b64}" "${path}"
}

# ---------------------------------------------------------------------------
# krun <node> <remote_script_path>
# Esegue uno script già presente nel container.
# Usa '--' per evitare che kathara parsi i flag di bash.
# ---------------------------------------------------------------------------
krun() {
    local node="$1"
    local path="$2"
    kathara exec "${node}" -- bash "${path}"
}

# ---------------------------------------------------------------------------
# kcat <node> <remote_file>
# ---------------------------------------------------------------------------
kcat() {
    kathara exec "${1}" -- cat "${2}"
}

# ---------------------------------------------------------------------------
# STEP 1: Verifica containers attivi
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
# STEP 2a: Ping diretto al link l59 — verifica container UP (no OSPF needed)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2a] Checking direct link darmstadt->frankfurt (${FRANKFURT_DIRECT})...${NC}"

kscript darmstadt /tmp/ping_direct.sh "#!/bin/sh
ping -c 1 -W 2 ${FRANKFURT_DIRECT} > /dev/null 2>&1 && echo OK || echo FAIL
"

DIRECT_OK=0
for i in $(seq 1 10); do
    RESULT=$(krun darmstadt /tmp/ping_direct.sh 2>/dev/null | tr -d '\r\n')
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
    echo -e "${RED}  ERROR: Direct link ${FRANKFURT_DIRECT} unreachable.${NC}"
    echo -e "${RED}  Check that kathara lstart completed and l59 is wired.${NC}"
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# STEP 2b: Attendi convergenza OSPF — ping loopback frankfurt (10.255.255.17)
# OSPF su 50 nodi richiede tipicamente 60-90s. Timeout: 120s.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2b] Waiting for OSPF convergence (${FRANKFURT_OSPF}, up to 120s)...${NC}"

kscript darmstadt /tmp/ping_ospf.sh "#!/bin/sh
ping -c 1 -W 2 ${FRANKFURT_OSPF} > /dev/null 2>&1 && echo OK || echo FAIL
"

CONVERGED=0
for i in $(seq 1 120); do
    RESULT=$(krun darmstadt /tmp/ping_ospf.sh 2>/dev/null | tr -d '\r\n')
    if [ "${RESULT}" = "OK" ]; then
        echo "  OSPF converged at ${i}s — ${FRANKFURT_OSPF} reachable"
        CONVERGED=1
        break
    fi
    # Mostra progresso ogni 5s
    if [ $((i % 5)) -eq 0 ]; then
        echo -n " ${i}s"
    else
        echo -n "."
    fi
    sleep 1
done

if [ ${CONVERGED} -eq 0 ]; then
    echo
    echo -e "${RED}  ERROR: OSPF loopback ${FRANKFURT_OSPF} unreachable after 120s.${NC}"
    echo -e "${RED}  FRR may not have started. Check: kathara exec darmstadt -- vtysh -c 'show ip ospf neighbor'${NC}"
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# STEP 3: Avvia receiver su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Starting IPA receiver on frankfurt...${NC}"

kscript frankfurt /tmp/run_recv.sh "#!/bin/sh
python3 /shared/recv_ipa.py --timeout 60 --count ${PACKET_COUNT} > /tmp/recv_ipa.log 2>&1 &
echo \$! > /tmp/recv_ipa.pid
echo \"recv_ipa.py started (pid=\$!)\"
"
krun frankfurt /tmp/run_recv.sh
sleep 2
echo

# ---------------------------------------------------------------------------
# STEP 4: Carica pipeline XDP su darmstadt
# --iface eth0: darmstadt[0]=l59 -> eth0 e' il link diretto verso frankfurt
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
krun darmstadt /tmp/run_pipeline.sh
echo "  Waiting 6s for XDP attach and BPF map population..."
sleep 6
echo

# ---------------------------------------------------------------------------
# STEP 5: Verifica che la pipeline sia partita (controlla pipeline.log)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Pipeline startup check:${NC}"
kscript darmstadt /tmp/check_pipeline.sh "#!/bin/sh
LOG=/tmp/pipeline.log
if [ ! -f \"\$LOG\" ]; then
    echo 'PIPELINE_STATUS=NOT_STARTED'
elif grep -q 'ERROR\|Traceback\|error' \"\$LOG\"; then
    echo 'PIPELINE_STATUS=ERROR'
    cat \"\$LOG\"
else
    echo 'PIPELINE_STATUS=OK'
fi
"
PIPELINE_STATUS=$(krun darmstadt /tmp/check_pipeline.sh 2>/dev/null | grep PIPELINE_STATUS | tr -d '\r')
echo "  ${PIPELINE_STATUS}"
if echo "${PIPELINE_STATUS}" | grep -q "ERROR\|NOT_STARTED"; then
    echo -e "${RED}  Pipeline failed to start. Full log:${NC}"
    kcat darmstadt /tmp/pipeline.log 2>/dev/null
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# STEP 6: Invia pacchetti IPA da darmstadt verso frankfurt
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
krun darmstadt /tmp/send_ipa.sh
echo

# ---------------------------------------------------------------------------
# STEP 7: Mostra log receiver su frankfurt
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7] Receiver log on frankfurt:${NC}"
sleep 2
kcat frankfurt /tmp/recv_ipa.log 2>/dev/null || echo "  (log not available)"
echo

# ---------------------------------------------------------------------------
# STEP 8: Log pipeline su darmstadt
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
krun darmstadt /tmp/bpf_stats.sh
echo

# ---------------------------------------------------------------------------
# STEP 10: Verifica conteggio pacchetti -> TEST PASSED / TEST FAILED
# run_pipeline_test.sh cerca la stringa esatta 'TEST PASSED' o 'TEST FAILED'.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 10] Verifying packet counts...${NC}"

kscript frankfurt /tmp/check_recv.sh "#!/bin/sh
LOG=/tmp/recv_ipa.log
if [ ! -f \"\$LOG\" ]; then
    echo 'RECV_COUNT=0'
else
    # recv_ipa.py stampa una riga per pacchetto ricevuto contenente 'Received'
    CNT=\$(grep -c 'Received\|received\|recv' \"\$LOG\" 2>/dev/null || echo 0)
    echo \"RECV_COUNT=\${CNT}\"
fi
"
RECV_LINE=$(krun frankfurt /tmp/check_recv.sh 2>/dev/null | grep RECV_COUNT | tr -d '\r')
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
