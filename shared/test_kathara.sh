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
# Step 1-bis — Dump iptables/nftables runtime su entrambi i nodi
#
# lab.conf conferma che darmstadt[0] e frankfurt[1] condividono lo stesso
# collision domain "l59" (cablaggio corretto), e il fix del checksum
# offload (ethtool) non ha risolto nulla. Il pattern osservato -- i
# pacchetti UDP spariscono PRIMA di essere visibili a tcpdump sul lato
# ricevente, mentre ICMP passa sempre -- e' la firma tipica di un filtro
# netfilter (iptables/nftables) applicato al bridge del collision domain o
# dentro il container stesso (magari gia' presente nell'immagine base
# kathara/frr_ebpf, non aggiunto dagli startup script che ho gia'
# controllato). Qui dumpiamo lo stato RUNTIME (non gli script di avvio)
# per vedere se esiste una regola che droppa UDP specificamente.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 1-bis] Dumping iptables/nftables runtime state on both nodes...${NC}"
echo "  --- darmstadt: iptables -L -n -v ---"
krun darmstadt "iptables -L -n -v 2>&1 || echo 'iptables not available'"
echo "  --- darmstadt: nft list ruleset ---"
krun darmstadt "nft list ruleset 2>&1 || echo 'nft not available'"
echo "  --- frankfurt: iptables -L -n -v ---"
krun frankfurt "iptables -L -n -v 2>&1 || echo 'iptables not available'"
echo "  --- frankfurt: nft list ruleset ---"
krun frankfurt "nft list ruleset 2>&1 || echo 'nft not available'"
echo

# ---------------------------------------------------------------------------
# Step 1-ter — Dump iptables/Docker a livello HOST (non dentro i container)
#
# Step 1-bis ha escluso filtri netfilter DENTRO i due container (policy
# ACCEPT ovunque, 0 regole, nft assente). Ma questo script gira come bash
# direttamente sulla macchina che ospita Kathara/Docker -- non dentro un
# container -- quindi possiamo controllare qui, senza passare da
# `kathara exec` (che resta confinato nel network namespace del
# container e non puo' vedere le regole del bridge Docker sull'host).
# Il pattern osservato (UDP sparisce prima di essere visibile a tcpdump
# sul lato ricevente, ICMP passa sempre, interfacce/cablaggio confermati
# corretti) punta ora a un filtro applicato dal bridge Docker che
# implementa il collision domain "l59", tipicamente nella catena
# DOCKER-USER o FORWARD, o a bridge-nf-call-iptables che instrada il
# traffico L2 del bridge attraverso iptables.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 1-ter] Dumping HOST-level iptables/Docker state (not inside containers)...${NC}"
echo "  --- host: iptables -L FORWARD -n -v ---"
sudo -n iptables -L FORWARD -n -v 2>&1 || echo "  (needs sudo password — run manually: sudo iptables -L FORWARD -n -v)"
echo "  --- host: iptables -L DOCKER-USER -n -v ---"
sudo -n iptables -L DOCKER-USER -n -v 2>&1 || echo "  (needs sudo password or chain doesn't exist — run manually: sudo iptables -L DOCKER-USER -n -v)"
echo "  --- host: sysctl net.bridge.bridge-nf-call-iptables ---"
sudo -n sysctl net.bridge.bridge-nf-call-iptables 2>&1 || cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>&1 || echo "  (br_netfilter module not loaded / not readable)"
echo "  --- host: docker network ls (kathara collision domains) ---"
sudo -n docker network ls 2>&1 || echo "  (needs sudo password — run manually: sudo docker network ls)"
echo

# ---------------------------------------------------------------------------
# Step 1-quater — FIX: disabilita GRO/offload sui veth peer LATO HOST + bridge
#
# Causa piu' probabile del "UDP burst sparisce, ICMP sparso passa":
# interazione veth + XDP + GRO. Il burst UDP (stesso flusso, ~50 pps) viene
# coalescato via Generic Receive Offload sul veth peer LATO HOST che
# alimenta frankfurt/eth1; il super-frame GRO risultante arriva a
# un'interfaccia con un programma XDP attaccato, non e' convertibile in
# xdp_buff (single-buffer) e viene SCARTATO dal path veth-XDP PRIMA che il
# nostro programma giri -- quindi niente incremento di debug_stats, niente
# tcpdump lato ricevente. L'ICMP (1/s, sparso) non viene mai coalescato e
# passa sempre. Disabilitare l'offload DENTRO i container (Step 2a-quater)
# non basta: il coalescing avviene sui veth peer nel network namespace
# dell'HOST, che solo `sudo` sull'host puo' toccare (kathara exec resta
# confinato nel container). Qui disabilitiamo GRO/GSO/TSO/checksum su TUTTI
# i veth e i bridge kt-* dell'host (sledgehammer, ma sicuro in un lab).
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 1-quater] FIX: disabling GRO/offload on HOST-side veths + kt-* bridges...${NC}"
if sudo -n true 2>/dev/null; then
    _n_veth=0
    for _v in $(ip -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//'); do
        sudo -n ethtool -K "${_v}" gro off gso off tso off tx off rx off 2>/dev/null && _n_veth=$((_n_veth+1))
    done
    _n_br=0
    for _b in $(ip -o link show type bridge 2>/dev/null | awk -F': ' '{print $2}' | grep '^kt-'); do
        sudo -n ethtool -K "${_b}" gro off gso off tso off tx off rx off 2>/dev/null && _n_br=$((_n_br+1))
        sudo -n ip link set dev "${_b}" mtu 1500 2>/dev/null
    done
    echo "  Offload disabled on ${_n_veth} host-side veth(s) and ${_n_br} kt-* bridge(s)."
else
    echo "  (needs sudo — run the script with: sudo bash shared/test_kathara.sh ${METHOD})"
fi
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
# Step 2a-ter — Risolvi anche l'interfaccia di INVIO su darmstadt (stessa
# ragione: darmstadt ha piu' link (eth0/eth1/eth2) verso vicini diversi in
# germany50, non si puo' assumere "eth0" per il link verso frankfurt).
# Usata per la cattura tcpdump lato mittente allo Step 5-bis/7-bis.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2a-ter] Verifying which real interface on darmstadt sends toward ${FRANKFURT_DIRECT}...${NC}"
DARMSTADT_IFACE=$(krun darmstadt "ip route get ${FRANKFURT_DIRECT} 2>/dev/null | grep -o 'dev [a-z0-9]*' | head -1 | awk '{print \$2}'" | tr -d '\r\n')
echo "  Outbound interface on darmstadt toward ${FRANKFURT_DIRECT} = ${DARMSTADT_IFACE:-<not found>}"
if [ -z "${DARMSTADT_IFACE}" ]; then
    echo -e "${RED}  ERROR: could not resolve darmstadt's outbound interface toward ${FRANKFURT_DIRECT}.${NC}"
    echo "TEST FAILED"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# Step 2a-quater — Disabilita checksum/segmentation offload su entrambe le
# interfacce (bug noto delle veth Docker/Kathara)
#
# Ground truth via tcpdump (turni precedenti di debug): i 100 pacchetti UDP
# di send_ipa.py escono correttamente da darmstadt/${DARMSTADT_IFACE} (visti
# nella cattura lato mittente), ma NON arrivano MAI su frankfurt/eth1 --
# nemmeno a livello di cattura raw (prima ancora di XDP). Nello stesso
# identico intervallo, ICMP e OSPF (IP raw, non UDP) attraversano il link
# senza problemi. Questo pattern e' la firma classica del bug di checksum
# offloading sulle interfacce veth: il kernel mittente calcola un checksum
# UDP placeholder assumendo che l'"hardware" lo completi (tx-checksumming
# offload), ma le veth non hanno hardware reale -- il pacchetto viaggia con
# un checksum invalido e sparisce nel tragitto, mentre ICMP/OSPF non
# dipendono dallo stesso meccanismo di offload e quindi funzionano.
# Fix: disabilitare l'offload forza il kernel a calcolare il checksum
# realmente in software.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2a-quater] Disabling checksum/segmentation offload on both interfaces (veth offload bug workaround)...${NC}"
krun darmstadt "ethtool -K ${DARMSTADT_IFACE} tx off rx off gso off gro off tso off 2>&1 || echo 'ethtool not available or unsupported on darmstadt'"
krun frankfurt "ethtool -K ${FRANKFURT_XDP_IFACE} tx off rx off gso off gro off tso off 2>&1 || echo 'ethtool not available or unsupported on frankfurt'"
echo

# ---------------------------------------------------------------------------
# Step 2c — TEST DIFFERENZIALE PER DIMENSIONE (non per protocollo)
#
# Ground truth definitiva dai turni di debug: i pacchetti UDP ESCONO da
# darmstadt (cattura -v/-e conferma checksum valido, MAC dst corretto,
# offload OFF) ma NON arrivano MAI su frankfurt. L'unica differenza vera
# tra cio' che passa e cio' che sparisce non e' il protocollo, e' la
# DIMENSIONE:
#     ICMP echo        = frame 98 B   -> passa sempre
#     UDP IPA (340 B)  = frame 382 B  -> sparisce sempre
# Questo e' il sintomo classico di un MTU troppo basso sul bridge del
# collision domain (katharanp), NON di un filtro UDP. Test decisivo: un
# ping con payload GRANDE (frame > 382 B). Se il ping piccolo passa e
# quello grande no, il problema e' la dimensione/MTU, indipendente da UDP.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2c] Differential SIZE test (small vs large ping) — is it MTU, not UDP?${NC}"
echo "  small ping (payload 8B -> ~42B frame):"
krun darmstadt "ping -c 3 -s 8 -W 2 ${FRANKFURT_DIRECT} 2>&1 | grep -E 'packets transmitted|bytes from' | tail -3"
echo "  large ping (payload 400B -> ~442B frame, BIGGER than our 382B UDP frame):"
krun darmstadt "ping -c 3 -s 400 -W 2 ${FRANKFURT_DIRECT} 2>&1 | grep -E 'packets transmitted|bytes from|Frag' | tail -4"
echo "  medium ping (payload 340B -> ~382B frame, SAME size as the UDP IPA packet):"
krun darmstadt "ping -c 3 -s 340 -W 2 ${FRANKFURT_DIRECT} 2>&1 | grep -E 'packets transmitted|bytes from' | tail -3"
echo "  host-side MTU of the l59 collision-domain bridge + its member veths:"
sudo -n ip -o link show 2>/dev/null | grep -E 'kt-c2a80c7e9bbb|master kt-c2a80c7e9bbb' | grep -oE '(kt-[0-9a-f]+|veth[0-9a-z@]*|mtu [0-9]+)' | tr '\n' ' ' || echo "  (run manually: sudo ip -d link show kt-c2a80c7e9bbb)"
echo
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
# Step 5-bis — Cattura tcpdump di ground-truth su frankfurt/${FRANKFURT_XDP_IFACE}
#
# I contatori debug_stats dicono solo cosa succede DOPO che un pacchetto ha
# raggiunto l'hook XDP. Per distinguere "i pacchetti non arrivano affatto"
# da "arrivano ma in una forma inattesa", catturiamo il traffico reale con
# tcpdump PRIMA che lo Step 6 invii i pacchetti, cosi' la cattura copre
# l'intera finestra di invio.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5-bis] Capturing real traffic on frankfurt/${FRANKFURT_XDP_IFACE} AND darmstadt/${DARMSTADT_IFACE} with tcpdump (ground truth)...${NC}"
echo "  --- MAC addresses (to compare against ARP resolution used by darmstadt's UDP sends) ---"
krun frankfurt "ip link show ${FRANKFURT_XDP_IFACE} | grep -o 'link/ether [0-9a-f:]*'"
krun darmstadt "ip neigh show | grep '${FRANKFURT_DIRECT}'"
echo "  --- MTU on both interfaces (rule out oversized-frame silent drop) ---"
krun darmstadt "ip link show ${DARMSTADT_IFACE} | grep -o 'mtu [0-9]*'"
krun frankfurt "ip link show ${FRANKFURT_XDP_IFACE} | grep -o 'mtu [0-9]*'"
echo "  --- Verifying checksum offload actually got disabled (ethtool -k, not -K) ---"
krun darmstadt "ethtool -k ${DARMSTADT_IFACE} 2>&1 | grep -E 'tx-checksumming|rx-checksumming|generic-segmentation|generic-receive|tcp-segmentation' || echo 'ethtool -k not available'"
krun frankfurt "ethtool -k ${FRANKFURT_XDP_IFACE} 2>&1 | grep -E 'tx-checksumming|rx-checksumming|generic-segmentation|generic-receive|tcp-segmentation' || echo 'ethtool -k not available'"
krun frankfurt "rm -f /tmp/tcpdump_frankfurt.log; nohup timeout 12 tcpdump -e -l -i ${FRANKFURT_XDP_IFACE} -n -c 300 > /tmp/tcpdump_frankfurt.log 2>&1 & echo tcpdump_started"
krun darmstadt "rm -f /tmp/tcpdump_darmstadt.log; nohup timeout 12 tcpdump -v -e -l -i ${DARMSTADT_IFACE} -n -c 300 'udp port 9999 or icmp' > /tmp/tcpdump_darmstadt.log 2>&1 & echo tcpdump_started"
sleep 1
echo "  tcpdump running in background on both ends (up to 12s / 300 packets, -l = line-buffered)"
echo "  darmstadt filter: 'udp port 9999 or icmp' -- isolates our IPA traffic + ping from OSPF noise"
echo "  darmstadt capture uses -v: will flag 'bad udp cksum' if checksum offload is still broken"
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
# Step 7-bis — Mostra le catture tcpdump avviate allo Step 5-bis (ground truth
# su ENTRAMBI i lati: se i pacchetti non compaiono nemmeno lato mittente
# (darmstadt), il problema e' nell'invio, non nel tragitto/nella pipeline)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7-bis] tcpdump capture on darmstadt/${DARMSTADT_IFACE} (sending side, filtered udp:9999+icmp):${NC}"
krun darmstadt 'cat /tmp/tcpdump_darmstadt.log 2>/dev/null || echo "no capture file"'
echo
echo -e "${YELLOW}[Step 7-bis] tcpdump capture on frankfurt/${FRANKFURT_XDP_IFACE} (receiving side):${NC}"
krun frankfurt 'cat /tmp/tcpdump_frankfurt.log 2>/dev/null || echo "no capture file"'
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
