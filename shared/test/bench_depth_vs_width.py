#!/usr/bin/env python3
"""
bench_depth_vs_width.py -- Pipeline 1 (hardcoded) trade-off sweep: at a
roughly fixed neuron/weight budget, is it cheaper (ns/pkt, xlated insns) to
go WIDE (one or two big hidden layers) or DEEP (many small hidden layers)?

Reuses the same measurement path as verify_prog_run.py / test_suite.py
--only kernel: BCC-compiles ebpf_program.build_combined_hardcoded_source
for each (hidden_dims) shape and times the dispatcher with
BPF_PROG_TEST_RUN. Random int8 weights -- this measures SHAPE cost only,
not inference correctness (that is already covered by test_suite).

Run on Linux (Kathara or bare VM) with bcc installed:
    sudo python3 shared/test/bench_depth_vs_width.py
    sudo python3 shared/test/bench_depth_vs_width.py --repeat 5000
"""
import os
import sys
import random
import argparse
import ctypes as ct

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for p in (SHARED_DIR, _TEST_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from bcc import BPF
import model_meta as mm
from ebpf_program import build_combined_hardcoded_source
from verify_prog_run import (
    prog_test_run, prog_insn_count, build_frame_sparse,
    TEST_RUN_DEFAULT_INGRESS_IFINDEX,
)

# (label, hidden_dims) -- grouped in pairs of roughly equal total weight count
# at the default 65-in/7-out shape, wide vs deep.
SHAPES = [
    ("baseline (2x4)",  (4, 4)),
    ("wide  1x16",       (16,)),
    ("deep  4x4",        (4, 4, 4, 4)),
    ("wide  1x64",       (64,)),
    ("deep  8x8",        (8, 8, 8, 8, 8, 8, 8, 8)),
]


def weight_count(n_in, dims, n_out):
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))


def bench_shape(label, dims, shape, repeat):
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    rng = random.Random(42)
    weights = [rng.randint(-100, 100) for _ in range(nw)]
    scale = 128

    src = build_combined_hardcoded_source(
        models=[(0, weights, scale, list(range(2, 3)))],
        features=shape["features"], n_out=n_out, hidden_dims=dims)
    b = BPF(text=src)
    model_fn = b.load_func("model_0", BPF.XDP)
    disp_fn  = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ct.c_int(0)] = ct.c_int(model_fn.fd)

    xlated, jited = prog_insn_count(disp_fn.fd)
    xlated_model, jited_model = prog_insn_count(model_fn.fd)

    frame = build_frame_sparse(model_id=0, ttl=42, scale=scale,
                               n_in=n_in, n_out=n_out)
    # Warm-up run (JIT/branch predictor), then the timed run.
    prog_test_run(disp_fn.fd, frame, repeat=repeat)
    retval, dur_ns = prog_test_run(disp_fn.fd, frame, repeat=repeat)
    ns_per_pkt = dur_ns / max(1, repeat)

    shape_str = f"{n_in}-{'-'.join(map(str, dims))}-{n_out}"
    print(f"{label:<16} {shape_str:<22} weights={nw:<6} "
          f"xlated_insn(disp+model)={xlated}+{xlated_model:<5} "
          f"{ns_per_pkt:7.1f} ns/pkt  retval={retval}")
    return ns_per_pkt, nw, xlated + xlated_model


def main():
    ap = argparse.ArgumentParser(description="Hardcoded depth-vs-width trade-off sweep")
    ap.add_argument("--repeat", type=int, default=2000)
    args = ap.parse_args()

    base_shape = mm.derive_shape({"n_interfaces": 6, "n_nodes": 52})
    print(f"descriptor: {[f['type'] for f in base_shape['features']]}  "
          f"n_in={base_shape['n_in']}  n_out={base_shape['n_out']}")
    print("-" * 100)
    results = []
    for label, dims in SHAPES:
        results.append((label, dims, *bench_shape(label, dims, base_shape, args.repeat)))
    print("-" * 100)
    base_ns = results[0][2]
    for label, dims, ns, nw, insns in results:
        print(f"{label:<16} {ns:7.1f} ns/pkt  ({ns/base_ns:+.1%} vs baseline)  "
              f"{insns} insns  {nw} weights")


if __name__ == "__main__":
    main()
