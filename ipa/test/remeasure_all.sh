#!/usr/bin/env bash
# remeasure_all.sh -- tutte le misure e le verifiche citate in docs/ che non
# usano traffico vero (BPF_PROG_TEST_RUN, il fabric, i modelli sintetici),
# sulla macchina di laboratorio e nelle condizioni di host_conditions
# (core del banco fisso a 3500 MHz, isolato, senza C6/C10). Ogni comando gira
# sul core del DUT con `host_conditions.py --run`, che applica le condizioni,
# lo esegue e le ripristina.
#
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_all.sh
#
# I CSV vanno in $IPA_RESULTS (default results/kernel_<data>/; la campagna
# passa results/campagna_<data>/kernel). I log vanno in $IPA_LOG_DIR (default
# /tmp/ipa_logs); i grafici che il quaderno usa vengono rigenerati dai CSV e
# copiati in docs/figures/. Chiede la password di sudo una volta; circa 20
# minuti, quasi tutti bench_scaling (una compilazione clang per cella).
# Il traffico vero e' in remeasure_campagna.sh, che chiama anche questo
# script (sezione kernel).
set -u
cd "$(dirname "$0")/../.."
ROOT="$PWD"
LOG="${IPA_LOG_DIR:-/tmp/ipa_logs}"
RES="${IPA_RESULTS:-$ROOT/results/kernel_$(date +%Y-%m-%d)}"
mkdir -p "$LOG" "$RES"
sudo -v || exit 1
# tiene vivo sudo per tutta la durata
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
KEEP=$!
# Anche ipa/ e docs/: i comandi girano come root e riscrivono file dentro il
# repository (l'oggetto AOT e il suo sorgente in ipa/poc_aot/, i __pycache__,
# i grafici in docs/figures/). Lasciati a root, il primo build da utente
# fallirebbe con PermissionError.
trap 'kill $KEEP 2>/dev/null; sudo chown -R "$(id -u):$(id -g)" "$ROOT/results" "$ROOT/ipa" "$ROOT/docs" "$LOG"' EXIT

run() {
    local name=$1; shift
    local t0=$SECONDS
    printf '%-22s ' "$name"
    sudo python3 ipa/test/host_conditions.py --run -- "$@" > "$LOG/$name.log" 2>&1
    local rc=$?
    local dist
    dist=$(grep -c "NON ha girato nelle condizioni" "$LOG/$name.log")
    printf 'rc=%-3s %4ss%s\n' "$rc" "$((SECONDS - t0))" \
        "$([ "$dist" != 0 ] && echo '  [macchina disturbata: vedi il log]')"
}

run test_suite_kernel   python3 ipa/test/test_suite.py --only kernel
run test_fabric         python3 ipa/test/test_fabric.py
run test_fabric_aot     python3 ipa/test/test_fabric.py --method aot
run verify_prog_run     python3 ipa/test/verify_prog_run.py --method hardcoded
run verify_multi_model  python3 ipa/test/verify_multi_model.py
run per_model_semantics python3 ipa/test/verify_per_model_semantics.py
run synth_kernel        python3 ipa/test/verify_synth_kernel.py --all --n 300
run model_source_kernel python3 ipa/test/test_model_source.py --kernel
run fabric_sweep        python3 ipa/test/test_fabric.py --sweep
run synth_p2            python3 ipa/test/verify_synth_kernel.py --all --n 300 --pipeline p2
run synth_p3            python3 ipa/test/verify_synth_kernel.py --all --n 300 --pipeline p3
for m in checkpoint synth:ipa_like synth:deep synth:sparse synth:ipa_ttl16 synth:small synth:ones synth:mixed synth:large; do
    run "fabric_${m#synth:}" python3 ipa/test/test_fabric.py --model "$m" -q
done
# la suite kernel su ogni modello (docs/testing.md §12)
for m in checkpoint synth:ipa_like synth:deep synth:sparse synth:ipa_ttl16 synth:small synth:ones synth:mixed synth:large; do
    run "suite_${m#synth:}"  python3 ipa/test/test_suite.py --only kernel --model "$m"
done
run tailcall_overhead   python3 ipa/test/bench_tailcall_overhead.py
run diag_verifier       python3 ipa/test/diag_verifier.py
run aot_deploy_bench    python3 ipa/methods/method4_hardcoded_aot.py
run depth_vs_width      python3 ipa/test/bench_depth_vs_width.py
run scaling_verify      python3 ipa/test/bench_scaling.py --verify
run scaling_ports       python3 ipa/test/bench_scaling.py --verify-ports
run scaling_axes        python3 ipa/test/bench_scaling.py --axis all --out "$RES/"
run scaling_campaign    python3 ipa/test/bench_scaling.py --axis campaign --out "$RES/"

# I grafici del quaderno, dai CSV appena scritti (i PDF in $RES li ignora git).
FIGS="scaling_depth_insns scaling_depth_latency scaling_depth_update
      scaling_isoparam_insns scaling_isoparam_latency scaling_nodes_insns
      scaling_nodes_insns_log scaling_nodes_latency scaling_descriptor_insns
      scaling_width_latency scaling_sparsity_insns_log duel_p1_vs_p15"
python3 ipa/test/bench_scaling.py --plot "$RES/" > "$LOG/scaling_plot.log" 2>&1
for f in $FIGS; do cp "$RES/$f.pdf" "$ROOT/docs/figures/"; done
echo "fatto: log in $LOG, grafici del quaderno in docs/figures/"
