#!/usr/bin/env python3
"""
bench_tailcall_overhead.py -- isolates the PURE cost of one bpf_tail_call hop,
decoupled from MLP inference and from the "double parse" the real pipelines
also pay (see EBPF_BASELINE_TAILCALL's docstring in verify_prog_run.py).

Why this exists: the literature on evaluating eBPF/XDP datapaths (e.g. the
in-kernel-ML papers cited in docs/testing.md, and general XDP performance
guidance) calls out THREE separable cost components in a tail-call-based
design: map lookups, the arithmetic itself, and tail-call overhead. testing.md
already isolates map-lookup cost (the "map lookup / pacchetto" column, via
CTR_INC instrumentation) and total latency (test_suite --only kernel), but
nothing isolated tail-call cost on its own until this script: hardcoded's
77 ns vs baseline's 29 ns bundles tail-call + a second packet parse + the
MLP together, so it cannot answer "how much of that 48 ns is just the jump".

Uses the same min-of-N methodology as bench_depth_vs_width.py: a single
BPF_PROG_TEST_RUN sample is not trustworthy (one-sided system noise only
ever slows a trial down), so MIN across TRIALS independent measurements is
reported, with median/max for context.

Run on Linux (Kathara or bare VM) with bcc installed:
    sudo python3 shared/test/bench_tailcall_overhead.py
    sudo python3 shared/test/bench_tailcall_overhead.py --repeat 5000 --trials 15
"""
import os
import sys
import argparse

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for p in (SHARED_DIR, _TEST_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from verify_prog_run import (
    setup_baseline, setup_baseline_tailcall, prog_test_run, build_frame,
)


def measure(setup, model_id, model_path, ttl, scale, repeat, trials):
    disp = setup["disp"]
    frame = build_frame(model_id, ttl, scale)
    prog_test_run(disp.fd, frame, repeat=repeat)   # warm-up
    samples = []
    for _ in range(trials):
        retval, ns = prog_test_run(disp.fd, frame, repeat=repeat)
        samples.append(ns)
    samples.sort()
    return {"min": samples[0], "median": samples[trials // 2], "max": samples[-1]}


def main():
    ap = argparse.ArgumentParser(description="Isolate pure bpf_tail_call overhead")
    ap.add_argument("--repeat", type=int, default=2000)
    ap.add_argument("--trials", type=int, default=7)
    ap.add_argument("--model", default=os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt"))
    ap.add_argument("--model-id", type=int, default=0)
    ap.add_argument("--ttl", type=int, default=42)
    ap.add_argument("--scale", type=int, default=128)
    args = ap.parse_args()

    print(f"{'variant':<28} {'n_tail':>7}  {'min':>8} {'median':>8} {'max':>8}  (ns/pkt)")
    print("-" * 70)

    s0 = setup_baseline(args.model_id, args.model)
    r0 = measure(s0, args.model_id, args.model, args.ttl, args.scale, args.repeat, args.trials)
    print(f"{'baseline (0 tail calls)':<28} {0:>7}  {r0['min']:>8.1f} {r0['median']:>8.1f} {r0['max']:>8.1f}")

    s1 = setup_baseline_tailcall(args.model_id, args.model)
    r1 = measure(s1, args.model_id, args.model, args.ttl, args.scale, args.repeat, args.trials)
    print(f"{'baseline + 1 tail call':<28} {1:>7}  {r1['min']:>8.1f} {r1['median']:>8.1f} {r1['max']:>8.1f}")

    delta = r1["min"] - r0["min"]
    print("-" * 70)
    print(f"Pure tail-call overhead (min-based): {delta:+.1f} ns/hop")
    print(f"(same parse, same redirect action on both sides -- the ONLY "
          f"difference is the PROG_ARRAY jump)")


if __name__ == "__main__":
    main()
