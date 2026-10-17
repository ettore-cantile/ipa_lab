#!/usr/bin/env bash
# run_kernel_checks.sh -- every check and measurement that needs no real traffic:
# the pipelines in the kernel (BPF_PROG_TEST_RUN), the veth fabric, the synthetic
# models, tail-call and verifier costs, bench_scaling. ~20 minutes, sudo once.
#
#   bash ipa/test/run_kernel_checks.sh
#
# One line per check (exit code, seconds); full logs in $IPA_LOG_DIR (default
# /tmp/ipa_logs), CSV in $IPA_RESULTS (default results/kernel_<date>/), the
# notebook charts copied to docs/figures/.
set -u
cd "$(dirname "$0")/../.."
ROOT="$PWD"
LOG="${IPA_LOG_DIR:-/tmp/ipa_logs}"
RES="${IPA_RESULTS:-$ROOT/results/kernel_$(date +%Y-%m-%d)}"
mkdir -p "$LOG" "$RES"
sudo -v || exit 1
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
KEEP=$!
trap 'kill $KEEP 2>/dev/null; sudo chown -R "$(id -u):$(id -g)" "$ROOT/results" "$ROOT/ipa" "$ROOT/docs" "$LOG"' EXIT

run() {
    local name=$1; shift
    local t0=$SECONDS
    printf '  %-30s ' "$name"
    sudo python3 ipa/test/host_conditions.py --run -- "$@" > "$LOG/$name.log" 2>&1
    local rc=$?
    local dist
    dist=$(grep -c "did NOT run in the declared conditions" "$LOG/$name.log")
    printf '%-14s %4ss%s\n' "$([ "$rc" = 0 ] && echo ok || echo "ERROR (rc=$rc)")" "$((SECONDS - t0))" \
        "$([ "$dist" != 0 ] && echo '  [machine disturbed: see the log]')"
}

echo "== correctness: the programs in the kernel against the integer reference"
run weights_and_metrics_kernel python3 ipa/test/test_weights_and_metrics.py --only kernel
run forwarding               python3 ipa/test/test_forwarding.py
run forwarding_p1_aot        python3 ipa/test/test_forwarding.py --method aot
run check_pipelines          python3 ipa/test/check_pipelines.py --method hardcoded
run check_multi_model        python3 ipa/test/check_multi_model.py
run semantics_per_model      python3 ipa/test/check_semantics_per_model.py
run kernel_vs_reference      python3 ipa/test/check_kernel_vs_reference.py --all --n 300
run model_source_kernel      python3 ipa/test/test_model_source.py --kernel
run forwarding_sweep         python3 ipa/test/test_forwarding.py --sweep
run kernel_vs_reference_p2   python3 ipa/test/check_kernel_vs_reference.py --all --n 300 --pipeline p2
run kernel_vs_reference_p3   python3 ipa/test/check_kernel_vs_reference.py --all --n 300 --pipeline p3
echo "== packet delivery on the veth fabric, one model at a time"
for m in checkpoint synth:ipa_like synth:deep synth:sparse synth:ipa_ttl16 synth:small synth:ones synth:mixed synth:large; do
    run "forwarding_${m#synth:}"  python3 ipa/test/test_forwarding.py --model "$m" -q
done
echo "== metrics in the kernel, one model at a time"
for m in checkpoint synth:ipa_like synth:deep synth:sparse synth:ipa_ttl16 synth:small synth:ones synth:mixed synth:large; do
    run "metrics_${m#synth:}"     python3 ipa/test/test_weights_and_metrics.py --only kernel --model "$m"
done
echo "== costs: tail call, verifier, P1 compiled off the node, scaling"
run tail_call                python3 ipa/test/bench_tail_call.py
run check_verifier_stats     python3 ipa/test/check_verifier_stats.py
run p1_aot_deploy            python3 ipa/methods/method4_hardcoded_aot.py
run depth_vs_width           python3 ipa/test/bench_depth_vs_width.py
run scaling_verify           python3 ipa/test/bench_scaling.py --verify
run scaling_ports            python3 ipa/test/bench_scaling.py --verify-ports
run scaling_axes             python3 ipa/test/bench_scaling.py --axis all --out "$RES/"
run scaling_campaign         python3 ipa/test/bench_scaling.py --axis campaign --out "$RES/"

FIGS="scaling_depth_insns scaling_depth_latency scaling_depth_update
      scaling_isoparam_insns scaling_isoparam_latency scaling_nodes_insns
      scaling_nodes_insns_log scaling_nodes_latency scaling_descriptor_insns
      scaling_width_latency scaling_sparsity_insns_log duel_p1_vs_p15"
echo "== notebook charts"
python3 ipa/test/bench_scaling.py --plot "$RES/" > "$LOG/scaling_plot.log" 2>&1
for f in $FIGS; do cp "$RES/$f.pdf" "$ROOT/docs/figures/"; done
echo "done: logs in $LOG, notebook charts in docs/figures/"
