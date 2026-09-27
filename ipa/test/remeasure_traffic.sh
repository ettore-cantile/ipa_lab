#!/usr/bin/env bash
# remeasure_traffic.sh -- la seconda meta' delle misure citate in docs/: il
# traffico vero (bench_throughput in tutte le modalita' che i documenti
# citano, bench_bitrate), il costo della semantica per modello, i soffitti di
# P3, lo sweep delle topologie, le equivalenze di P2/P3 sui modelli sintetici.
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

# L'albero di prima della semantica per modello (16f1a024), per il confronto
# di bench_semantics_models: un worktree git, senza toccare quello di lavoro.
BASE=/tmp/ipa_base_semantics
if [ ! -d "$BASE/ipa" ]; then
    git worktree add --detach "$BASE" 16f1a024^ > "$LOG/worktree.log" 2>&1 \
        || echo "worktree non creato: vedi $LOG/worktree.log"
fi

sudo -v || exit 1
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
KEEP=$!
trap 'kill $KEEP 2>/dev/null; sudo chown -R "$(id -u):$(id -g)" "$ROOT/results" "$LOG"' EXIT

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

# correttezza e soffitti
run fabric_sweep        python3 ipa/test/test_fabric.py --sweep
run synth_p2            python3 ipa/test/verify_synth_kernel.py --all --n 300 --pipeline p2
run synth_p3            python3 ipa/test/verify_synth_kernel.py --all --n 300 --pipeline p3
run p3_ceilings         python3 ipa/test/diag_p3_bisect.py --ceilings
# P1 larga/profonda a ~1 200 pesi: l'errore completo del caricamento
run dvw_cell_65_16_7    python3 ipa/test/bench_depth_vs_width.py --_worker default 16 200
run dvw_cell_65_14_14   python3 ipa/test/bench_depth_vs_width.py --_worker default 14,14 200
# semantica per modello: costo contro l'albero di prima
run semantics_models    python3 -u ipa/test/bench_semantics_models.py \
    --baseline-dir "$BASE/ipa" --trials 21 --csv "$ROOT/results/semantics_models.csv"

# traffico vero
bench tp_compare    ipa/test/bench_throughput.py --mode compare --rounds 3 \
    --out "$ROOT/results/throughput_3500"
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
echo "fatto: log in $LOG"
