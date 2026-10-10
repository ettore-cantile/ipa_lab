#!/usr/bin/env bash
# remeasure_campagna.sh -- la campagna di ottobre: tutte le misure delle slide
# "Inferenza di una rete neurale nel kernel Linux con eBPF XDP" rifatte sulla
# versione attuale, con il traffico vero di xdp_gen, sui P-core, sugli E-core
# e sui LP E-core, con istruzioni e cicli per pacchetto (hw_counters.py).
#
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_campagna.sh            # tutto (~2 h)
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_campagna.sh pcore      # solo i P-core
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_campagna.sh ecore lpe  # piu' sezioni
#
# Sezioni:
#   pcore   riferimento: nodo su un P-core (cpu6), capacita' a 1 e 2 core,
#           per classe, per taglia, tre marcature, curve del bit rate (~12 min)
#   ecore   lo stesso nodo su un E-core (cpu12, modulo 12-15 a riposo): 1 e
#           2 core, tre marcature, curve (~7 min)
#   lpe     nodo su un LP E-core (cpu20, fuori dalla L3, massimo 2,5 GHz):
#           capacita' e curve (~4 min)
#   assi    sotto traffico (traffic_models.py), sui core di $ASSI_CORES
#           (default "P E"): T2-T1 del checkpoint, poi per ogni punto di
#           larghezza, profondita', pari pesi, sparsita', nodi della rete,
#           ingressi densi e one-hot capacita' e ns di CPU e T2-T1 (la sola
#           inferenza, build strumentata) a $ASSI_RATES Mpps. ASSI_T2=0 salta
#           T2-T1, ASSI_AXES sceglie gli assi (~35 min per tipo di core)
#   kernel  BPF_PROG_TEST_RUN: suite, semantica per modello, modelli
#           sintetici, tail call, AOT, assi di bench_scaling (= remeasure_all.sh,
#           ~15 min)
#   sintesi le tabelle di confronto (campaign_report.py), anche da sola
#
# Il disegno: cambia solo il core del NODO. Generatore (cpu10) e uscita
# (cpu8) restano su P-core, a 3500 MHz, in tutte le configurazioni a un core:
# il generatore satura qualunque nodo e l'uscita non diventa il collo di
# bottiglia di un nodo veloce. L'E-core gira alla stessa frequenza del P-core
# (3500 MHz, il suo massimo e' 3800): il rapporto fra le capacita' e' il
# rapporto fra gli IPC. Il LP E-core si ferma al suo massimo, 2500 MHz
# (host_conditions taglia la frequenza chiesta al massimo del core).
#
# CSV in results/campagna_<data>/<sezione>/ ($CAMPAGNA per cambiarlo), log in
# results/campagna_<data>/log/ ($IPA_LOG_DIR per cambiarlo). I grafici del bit
# rate del P-core vanno anche in docs/figures/, dove li usa il quaderno.
set -u
cd "$(dirname "$0")/../.."
ROOT="$PWD"
OUT="${CAMPAGNA:-$ROOT/results/campagna_$(date +%Y-%m-%d)}"
LOG="${IPA_LOG_DIR:-$OUT/log}"
ASSI_CORES="${ASSI_CORES:-P E}"
# ASSI_SOLO="width_6 depth_4": solo questi punti degli assi
# T2-T1 e' piatto sul rate: due rate sotto la capacita' del punto piu' lento
# (P3 a 6 strati sull'E-core, con l'uscita sulla stessa CPU del nodo).
ASSI_RATES="${ASSI_RATES:-0.3,0.6}"
ASSI_T2="${ASSI_T2:-1}"
ASSI_AXES="${ASSI_AXES:-width depth isoparam sparsity nodes iv_dense iv_onehot}"
mkdir -p "$LOG" "$OUT"

sudo -v || exit 1
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
KEEP=$!
trap 'kill $KEEP 2>/dev/null; sudo chown -R "$(id -u):$(id -g)" "$ROOT/results" "$ROOT/ipa" "$ROOT/docs" "$LOG"' EXIT

bench() {
    local name=$1; shift
    local t0=$SECONDS
    sudo python3 "$@" > "$LOG/$name.log" 2>&1
    local rc=$?
    local dist
    dist=$(grep -c -E "NON ha girato nelle condizioni|NON e' rimasta nelle condizioni" "$LOG/$name.log")
    local hw
    hw=$(grep -c "istruzioni per ciclo non misurate" "$LOG/$name.log")
    printf '%-26s rc=%-3s %5ss%s%s\n' "$name" "$rc" "$((SECONDS - t0))" \
        "$([ "$dist" != 0 ] && echo '  [macchina disturbata: vedi il log]')" \
        "$([ "$hw" != 0 ] && echo '  [niente contatori hardware]')"
}

# I ruoli per tipo di core del nodo: DUT, uscita, generatore.
dut_of()  { case $1 in P) echo 6;; E) echo 12;; L) echo 20;; esac; }
EGRESS=8
GEN=10
PIPES=baseline,p1_static,hardcoded,template,modular
RATES=0.5,1,1.5,2,2.5,3,3.5,4,5,6,7,8,9,10,11,12

# capacita' a massima spinta, un core del nodo
compare1() {    # <tipo> <cartella> [argomenti in piu']
    local k=$1 dir=$2; shift 2
    bench "${dir//\//_}" ipa/test/bench_throughput.py --mode compare --generator xdp \
        --rounds 3 --gen-cpus $GEN --dut-cpus "$(dut_of "$k")" --egress-cpu $EGRESS \
        --out "$OUT/$dir" "$@"
}

# curve al crescere del rate (lotto da 256, cadenza precisa fino a ~11-12 Mpps)
bitrate1() {    # <tipo> <cartella> <rates> <giri>
    local k=$1 dir=$2 rates=$3 rounds=$4
    bench "${dir//\//_}" ipa/test/bench_bitrate.py --generator xdp --gen-cpus $GEN \
        --dut-cpus "$(dut_of "$k")" --egress-cpu $EGRESS --rates "$rates" \
        --rounds "$rounds" --out "$OUT/$dir"
}

# tre marcature: uscita sulla CPU del nodo (timbri in mappe per-CPU)
rates1() {      # <tipo> <cartella> [rates] [argomenti in piu']
    local k=$1 dir=$2 rates=${3:-0.05,0.5,1,1.5,2,2.5,3}
    shift; shift; [ $# -gt 0 ] && shift
    bench "${dir//\//_}" ipa/test/bench_throughput.py --mode rates --generator xdp \
        --frames 64 --rounds 3 --gen-cpus $GEN --dut-cpus "$(dut_of "$k")" \
        --rates "$rates" --out "$OUT/$dir" "$@"
}

sec_pcore() {
    echo "== P-core (nodo su cpu6)"
    compare1 P pcore/compare
    bench pcore_cores2 ipa/test/bench_throughput.py --mode compare --generator xdp \
        --rounds 3 --gen-cpus 10,1 --dut-cpus 6,8 --egress-cpu 3,5 \
        --out "$OUT/pcore/cores2"
    compare1 P pcore/per_class --per-class
    compare1 P pcore/frames --frames 64,512,1514
    rates1 P pcore/rates
    bitrate1 P pcore/bitrate "$RATES" 5
    for f in bitrate_latency bitrate_pps bitrate_loss; do
        [ -f "$OUT/pcore/bitrate/$f.pdf" ] && cp "$OUT/pcore/bitrate/$f.pdf" "$ROOT/docs/figures/"
    done
}

sec_ecore() {
    echo "== E-core (nodo su cpu12, modulo 12-15 a riposo)"
    compare1 E ecore/compare
    # due E-core, uno per modulo; uscite su due P-core
    bench ecore_cores2 ipa/test/bench_throughput.py --mode compare --generator xdp \
        --rounds 3 --gen-cpus 10,1 --dut-cpus 12,16 --egress-cpu 6,8 \
        --out "$OUT/ecore/cores2"
    rates1 E ecore/rates
    bitrate1 E ecore/bitrate "$RATES" 5
}

sec_lpe() {
    echo "== LP E-core (nodo su cpu20, 2500 MHz)"
    compare1 L lpe/compare
    bitrate1 L lpe/bitrate 0.25,0.5,1,1.5,2,2.5,3,3.5,4,5,6,7,8 3
}

sec_assi() {
    python3 ipa/test/traffic_models.py > "$LOG/traffic_models.log" 2>&1 || {
        echo "traffic_models.py fallito: vedi $LOG/traffic_models.log"; return; }
    for k in $ASSI_CORES; do
        echo "== assi sotto traffico, nodo su $k-core (cpu$(dut_of "$k"))"
        # il riferimento: la sola inferenza del checkpoint, agli stessi rate
        if [ "$ASSI_T2" = 1 ] && { [ -z "${ASSI_SOLO:-}" ] || \
                [[ " $ASSI_SOLO " == *" checkpoint "* ]]; }; then
            rates1 "$k" "assi_${k}core/checkpoint/rates" "$ASSI_RATES" \
                --method "$PIPES"
        fi
        for axis in $ASSI_AXES; do
            for d in $(python3 ipa/test/traffic_models.py --list "$axis"); do
                if [ -n "${ASSI_SOLO:-}" ] && \
                        ! [[ " $ASSI_SOLO " == *" $(basename "$d") "* ]]; then
                    continue
                fi
                # nodi e ingressi hanno una rete loro, accanto al modello
                local topo=()
                local t
                t=$(python3 ipa/test/traffic_models.py --topology "$d")
                [ -n "$t" ] && topo=(--topology "$t")
                compare1 "$k" "assi_${k}core/$(basename "$d")" --model "$d" \
                    "${topo[@]}" --method "$PIPES"
                [ "$ASSI_T2" = 1 ] && rates1 "$k" \
                    "assi_${k}core/$(basename "$d")/rates" "$ASSI_RATES" \
                    --model "$d" "${topo[@]}" --method "$PIPES"
            done
        done
    done
}

sec_kernel() {
    echo "== BPF_PROG_TEST_RUN (remeasure_all.sh)"
    IPA_LOG_DIR="$LOG/kernel" IPA_RESULTS="$OUT/kernel" bash ipa/test/remeasure_all.sh
}

sec_sintesi() {
    python3 ipa/test/campaign_report.py "$OUT" > "$OUT/sintesi.md" 2> "$LOG/sintesi.log" \
        && echo "sintesi: $OUT/sintesi.md" \
        || echo "sintesi fallita: vedi $LOG/sintesi.log"
}

SECTIONS="${*:-pcore ecore lpe assi kernel}"
echo "campagna in $OUT, log in $LOG"
# I contatori hardware si aprono davvero, su un core di ogni tipo, prima di
# spendere ore di misure senza IPC. IPA_NO_HW=1 per andare avanti lo stesso.
if [ "$SECTIONS" != sintesi ] && [ "$SECTIONS" != kernel ]; then
    if sudo python3 ipa/test/hw_counters.py --cpu 6,8,12,20 --seconds 0.2 \
            > "$LOG/hw_counters.log" 2>&1; then
        sed 's/^/  /' "$LOG/hw_counters.log"
    else
        echo "contatori hardware non disponibili: vedi $LOG/hw_counters.log"
        [ "${IPA_NO_HW:-0}" = 1 ] || exit 1
    fi
fi
for s in $SECTIONS; do
    case $s in
        pcore|ecore|lpe|assi|kernel|sintesi) "sec_$s" ;;
        tutto) for t in pcore ecore lpe assi kernel; do "sec_$t"; done ;;
        *) echo "sezione sconosciuta: $s (pcore ecore lpe assi kernel sintesi)"; exit 2 ;;
    esac
done
[ "$SECTIONS" = sintesi ] || sec_sintesi
