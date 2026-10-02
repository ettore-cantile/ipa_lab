#!/usr/bin/env bash
# remeasure_xdp.sh -- le misure con xdp_gen, tutte nella stessa sessione:
# capacita' a massima spinta su uno e due core, curve al crescere del rate,
# costo per classe e per taglia, tre marcature, modelli.
#
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_xdp.sh            # tutto
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_xdp.sh modelli    # solo i modelli
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_xdp.sh nuove      # per classe, taglie, tre marcature
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_xdp.sh curve      # solo le curve del bit rate e i grafici
#
# Da rifare dopo ogni modifica a xdp_gen: dal 2026-10-02 la finestra e' una
# sola chiamata test_run (vedi STEADY_CALL_FRAMES in xdp_gen.py), e le cifre
# prese prima contano ~12 ms di generatore fermo a ogni chiamata.
# Log in $IPA_LOG_DIR (default /tmp/ipa_logs), CSV in results/<nome>/.
# Circa 25 minuti (solo i modelli: ~5).
set -u
cd "$(dirname "$0")/../.."
ROOT="$PWD"
LOG="${IPA_LOG_DIR:-/tmp/ipa_logs}"
mkdir -p "$LOG" "$ROOT/results"

sudo -v || exit 1
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
KEEP=$!
trap 'kill $KEEP 2>/dev/null; sudo chown -R "$(id -u):$(id -g)" "$ROOT/results" "$ROOT/ipa" "$LOG"' EXIT

bench() {
    local name=$1; shift
    local t0=$SECONDS
    sudo python3 "$@" > "$LOG/$name.log" 2>&1
    local rc=$?
    local dist
    dist=$(grep -c -E "NON ha girato nelle condizioni|NON e' rimasta nelle condizioni" "$LOG/$name.log")
    printf '%-18s rc=%-3s %5ss%s\n' "$name" "$rc" "$((SECONDS - t0))" \
        "$([ "$dist" != 0 ] && echo '  [macchina disturbata: vedi il log]')"
}

MODE="${1:-tutto}"
if [ "$MODE" = tutto ]; then
# capacita' a massima spinta: un core (un thread, uscita su un core suo) e
# due core (un thread per coda, un core d'uscita per coda)
bench xdp_1core    ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu auto \
    --rounds 3 --gen-cpus 10 --dut-cpus 6 --out "$ROOT/results/cpu_time/xdp_1thread"
bench xdp_2core    ipa/test/bench_throughput.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10,1 --dut-cpus 6,8 --egress-cpu 3,5 --out "$ROOT/results/throughput_xdp_cores2"
fi
if [ "$MODE" = tutto ] || [ "$MODE" = curve ]; then
# curve al crescere del rate: lotto da 256 (cadenza precisa fino a ~11-12
# Mpps per thread, results/xdp_cadenza_test/)
bench bitrate_xdp  ipa/test/bench_bitrate.py --generator xdp --gen-cpus 10 --dut-cpus 6 \
    --egress-cpu auto --rates 0.5,1,1.5,2,2.5,3,3.5,4,5,6,7,8,9,10,11,12 --rounds 5 \
    --out "$ROOT/results/bitrate_xdp"
# ritardo a basso carico senza l'attesa di fine lotto nel generatore
bench bitrate_xdp32 ipa/test/bench_bitrate.py --generator xdp --gen-cpus 10 --dut-cpus 6 \
    --egress-cpu auto --rates 0.25,0.5,1,1.5,2 --rounds 5 --overhead-reps 0 \
    --xdp-batch 32 --out "$ROOT/results/bitrate_xdp_lotto32"
fi
if [ "$MODE" = tutto ] || [ "$MODE" = nuove ]; then
# costo per classe (inoltro contro DROP) e per taglia del frame, stesso banco
bench xdp_class    ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu auto \
    --per-class --rounds 3 --gen-cpus 10 --dut-cpus 6 --out "$ROOT/results/cpu_time/xdp_per_class"
bench xdp_frames   ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu auto \
    --frames 64,512,1514 --rounds 3 --gen-cpus 10 --dut-cpus 6 \
    --out "$ROOT/results/throughput_xdp_frames"
# tre marcature (T1 ingresso, T2 redirect, T3 nodo successivo), build
# strumentata; T3-T1 a 50 kpps e' la latenza minima arrivo -> ripartenza.
# L'uscita resta sulla CPU del DUT: i timbri sono in mappe per-CPU.
bench xdp_rates    ipa/test/bench_throughput.py --mode rates --generator xdp --frames 64 \
    --rounds 3 --gen-cpus 10 --dut-cpus 6 --rates 0.05,0.5,1,1.5,2,2.5,3 \
    --out "$ROOT/results/throughput_rates_xdp"
fi
if [ "$MODE" = tutto ] || [ "$MODE" = curve ]; then
# i grafici del bit rate del quaderno
for f in bitrate_latency bitrate_pps bitrate_loss; do
    cp "$ROOT/results/bitrate_xdp/$f.pdf" "$ROOT/docs/figures/"
done
fi
if [ "$MODE" = tutto ] || [ "$MODE" = modelli ]; then
# modelli diversi dal checkpoint (docs/testing.md §12): stesso banco a un core
for m in checkpoint deep small mixed large; do
    ref=$([ "$m" = checkpoint ] && echo checkpoint || echo "synth:$m")
    bench "xdp_model_$m" ipa/test/bench_throughput.py --mode compare --generator xdp \
        --egress-cpu auto --rounds 3 --gen-cpus 10 --dut-cpus 6 --model "$ref" \
        --out "$ROOT/results/models/xdp_$m"
done
bench xdp_bitrate_deep ipa/test/bench_bitrate.py --generator xdp --gen-cpus 10 --dut-cpus 6 \
    --egress-cpu auto --model synth:deep --rates 0.5,1,1.5,2,2.5,3,3.5,4,5,6,7,8 --rounds 3 \
    --overhead-reps 0 --out "$ROOT/results/models/bitrate_xdp_deep"
fi
