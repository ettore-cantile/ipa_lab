#!/usr/bin/env bash
# remeasure_traffic.sh -- la seconda meta' delle misure citate in docs/: il
# traffico vero (bench_throughput in tutte le modalita' che i documenti
# citano, bench_bitrate), lo sweep delle topologie, le equivalenze di P2/P3
# sui modelli sintetici.
#
#   cd ~/Desktop/ipa_lab && bash ipa/test/remeasure_traffic.sh
#
# Da lanciare DOPO remeasure_all.sh, non insieme: le condizioni della
# macchina le applica un processo alla volta. I banchi di traffico le
# applicano da se'; gli altri comandi girano con host_conditions.py --run.
# Log in $IPA_LOG_DIR (default /tmp/ipa_logs), CSV in results/<nome>/.
# Circa un'ora.
set -u
cd "$(dirname "$0")/../.."
ROOT="$PWD"
LOG="${IPA_LOG_DIR:-/tmp/ipa_logs}"
mkdir -p "$LOG" "$ROOT/results"

sudo -v || exit 1
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
KEEP=$!
# Anche ipa/ e docs/: i comandi girano come root e riscrivono file dentro il
# repository (l'oggetto AOT e il suo sorgente in ipa/poc_aot/, i __pycache__,
# i grafici in docs/figures/). Lasciati a root, il primo build da utente
# fallirebbe con PermissionError.
trap 'kill $KEEP 2>/dev/null; sudo chown -R "$(id -u):$(id -g)" "$ROOT/results" "$ROOT/ipa" "$ROOT/docs" "$LOG"' EXIT

report() {
    local name=$1 rc=$2 t0=$3
    local dist
    dist=$(grep -c -E "NON ha girato nelle condizioni|NON e' rimasta nelle condizioni" "$LOG/$name.log")
    printf '%-24s rc=%-3s %5ss%s\n' "$name" "$rc" "$((SECONDS - t0))" \
        "$([ "$dist" != 0 ] && echo '  [macchina disturbata: vedi il log]')"
}

# comando qualunque, sul core del DUT a condizioni applicate
run() {
    local name=$1; shift
    local t0=$SECONDS
    sudo python3 ipa/test/host_conditions.py --run -- "$@" > "$LOG/$name.log" 2>&1
    report "$name" $? $t0
}

# banco che applica le condizioni da se'
bench() {
    local name=$1; shift
    local t0=$SECONDS
    sudo python3 "$@" > "$LOG/$name.log" 2>&1
    report "$name" $? $t0
}

# correttezza
run fabric_sweep        python3 ipa/test/test_fabric.py --sweep
run synth_p2            python3 ipa/test/verify_synth_kernel.py --all --n 300 --pipeline p2
run synth_p3            python3 ipa/test/verify_synth_kernel.py --all --n 300 --pipeline p3
for m in checkpoint synth:ipa_like synth:deep synth:sparse synth:ipa_ttl16 synth:small synth:ones synth:mixed synth:large; do
    run "fabric_${m#synth:}" python3 ipa/test/test_fabric.py --model "$m" -q
done

# traffico vero
bench tp_compare    ipa/test/bench_throughput.py --mode compare --rounds 3 \
    --out "$ROOT/results/throughput_3500"
bench tp_cores1     ipa/test/bench_throughput.py --mode compare --rounds 3 \
    --gen-cpus 10,1,3 --dut-cpus 6 --out "$ROOT/results/throughput_cores1"
bench tp_cores2     ipa/test/bench_throughput.py --mode compare --rounds 3 \
    --gen-cpus 10,1,3 --dut-cpus 6,8 --out "$ROOT/results/throughput_cores2"
# modelli diversi dal checkpoint (docs/testing.md §12)
for m in checkpoint deep small mixed large; do
    ref=$([ "$m" = checkpoint ] && echo checkpoint || echo "synth:$m")
    bench "tp_model_$m" ipa/test/bench_throughput.py --mode compare --rounds 3 \
        --gen-cpus 10,1,3 --dut-cpus 6 --model "$ref" --out "$ROOT/results/models/throughput_$m"
done
bench bitrate_deep  ipa/test/bench_bitrate.py --model synth:deep --rounds 3 \
    --out "$ROOT/results/models/bitrate_deep"
# tempo di CPU per pacchetto e uno scrittore per coda (docs/testing.md §10.2, §10.5, §10.6)
bench cpu_pktgen3   ipa/test/bench_throughput.py --mode compare --rounds 3 \
    --gen-cpus 10,1,3 --dut-cpus 6 --out "$ROOT/results/cpu_time/pktgen_3thread"
bench cpu_pktgen1   ipa/test/bench_throughput.py --mode compare --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --out "$ROOT/results/cpu_time/pktgen_1thread"
bench cpu_xdp1      ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu auto \
    --rounds 3 --gen-cpus 10 --dut-cpus 6 --out "$ROOT/results/cpu_time/xdp_1thread"
bench cpu_xdp_class ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu auto \
    --per-class --rounds 3 --gen-cpus 10 --dut-cpus 6 --out "$ROOT/results/cpu_time/xdp_per_class"
bench bitrate       ipa/test/bench_bitrate.py --out "$ROOT/results/bitrate_3500"
bench tp_rates      ipa/test/bench_throughput.py --mode rates --frames 64 --rounds 3 \
    --rates 0.5,1,1.5,2,2.5,3 --out "$ROOT/results/throughput_rates"
bench tp_generator  ipa/test/bench_throughput.py --mode generator --frames 64 --rounds 5 \
    --rates 8,10,12,15,20,25 --out "$ROOT/results/throughput_generator"
bench tp_xdp        ipa/test/bench_throughput.py --mode compare --generator xdp \
    --egress-cpu auto --rounds 5 --out "$ROOT/results/throughput_xdp"
bench tp_xdp_frames ipa/test/bench_throughput.py --mode compare --generator xdp \
    --egress-cpu auto --frames 64,512,1514 --rounds 3 --out "$ROOT/results/throughput_xdp_frames"
bench tp_per_class  ipa/test/bench_throughput.py --mode compare --generator xdp \
    --egress-cpu auto --per-class --rounds 3 --out "$ROOT/results/throughput_per_class"
bench tp_latency    ipa/test/bench_throughput.py --latency --frames 512 --rounds 3 \
    --repeat 5 --out "$ROOT/results/throughput_latency"
# I grafici del bit rate che il quaderno usa (bench_bitrate li scrive accanto
# ai CSV; results/ ignora i PDF).
for f in bitrate_latency bitrate_pps bitrate_loss; do
    cp "$ROOT/results/bitrate_3500/$f.pdf" "$ROOT/docs/figures/"
done
echo "fatto: log in $LOG, grafici del bit rate in docs/figures/"
