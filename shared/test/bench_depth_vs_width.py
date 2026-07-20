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

Swept across SEVERAL feature descriptors (not just the historical default),
because the width-vs-depth verdict turned out to depend on the descriptor's
feature mix: onehot features (ingress_iface, node) generate a switch-case
that costs stack/instructions proportional to (that feature's size * n_h1),
paid only by the FIRST hidden layer. A descriptor with no onehot features,
or a small one instead of the 52-slot 'node' one, changes both the stack
ceiling AND which architecture is actually faster -- so a conclusion drawn
from one descriptor alone is not safe to generalize. See FEATURE_SETS.

Shapes predicted to overflow the 512-byte eBPF per-function stack are
SKIPPED BEFORE compiling (not try/except'd): BCC's LLVM backend reports that
failure via a fatal-error abort, which terminates the process -- a Python
try/except around BPF(text=...) cannot catch it. first_layer_stack_estimate()
is the (empirically confirmed) predictor used to decide what's safe to try.

Run on Linux (Kathara or bare VM) with bcc installed:
    sudo python3 shared/test/bench_depth_vs_width.py
    sudo python3 shared/test/bench_depth_vs_width.py --repeat 5000
    sudo python3 shared/test/bench_depth_vs_width.py --descriptor no_onehot
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
from verify_prog_run import prog_test_run, prog_insn_count, build_frame_sparse

# ---------------------------------------------------------------------------
# Feature descriptors to sweep. Isolates onehot COUNT (0 / 1 / 2) and onehot
# SIZE (ingress_iface=6 vs node=52, the topology's 'largest' onehot) as
# separate variables, instead of only ever testing the historical 4-feature
# default (which happens to carry the most expensive onehot: 'node', size 52).
# All variants keep n_out=7 so tier weight-budgets stay comparable.
# ---------------------------------------------------------------------------
FEATURE_SETS = {
    "default":     ["link_state", "ingress_iface", "ttl", "node"],   # 2 onehot (6 + 52)
    "no_onehot":   ["link_state", "ttl", "queue_occupancy"],         # 0 onehot
    "small_onehot": ["link_state", "ttl", "ingress_iface"],          # 1 onehot, size 6
    "big_onehot":  ["link_state", "ttl", "node"],                    # 1 onehot, size 52
}

# (tier, label, hidden_dims) -- SAME architecture grid tested against every
# descriptor above, so descriptor is the only thing that varies per sweep.
SHAPES = [
    ("A (~300 w)",  "baseline 2x4", (4, 4)),
    ("A (~300 w)",  "wide   1x4",   (4,)),
    ("A (~300 w)",  "deep   8x3",   (3, 3, 3, 3, 3, 3, 3, 3)),
    ("B (~1200 w)", "wide   1x16",  (16,)),
    ("B (~1200 w)", "deep   4x11",  (11, 11, 11, 11)),
    ("B (~1200 w)", "deep   8x9",   (9, 9, 9, 9, 9, 9, 9, 9)),
    ("C (~4700 w)", "wide   1x64",  (64,)),
    ("C (~4700 w)", "deep   4x29",  (29, 29, 29, 29)),
    ("C (~4700 w)", "deep   8x21",  (21, 21, 21, 21, 21, 21, 21, 21)),
]

# Empirical safety margin under the real 512-byte ceiling: leaves headroom
# for the packet-parse locals (eth/ip/udp/ipa pointers) that live on the same
# stack frame alongside the feature-building temporaries this estimates.
STACK_SAFETY_LIMIT = 480


def build_shape(descriptor_name: str, n_out: int = 7) -> dict:
    types = FEATURE_SETS[descriptor_name]
    meta = {"features": types, "n_out": n_out, "hidden_dims": [4, 4]}
    return mm.derive_shape(meta)


def weight_count(n_in, dims, n_out):
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))


def first_layer_stack_estimate(shape, n_h1):
    """Estimated live-stack bytes for the FIRST hidden layer's `long long`
    locals: ebpf_program._gen_feature_onehot_{iface,node} each declare their
    OWN n_h1-sized temp array (w_iface_j / w_node_j) IN ADDITION to the
    final h1_j output array, and _gen_feature_dense_vector declares one
    `long long` per value of that feature. clang/BCC does not appear to
    reuse these slots across the un-scoped C, so they all count toward the
    eBPF 512-byte per-function stack ceiling simultaneously. This is why
    WIDENING the first layer is far more expensive, byte for byte, than
    adding an extra (narrower) layer: every additional onehot feature in the
    descriptor multiplies the first layer's per-neuron stack cost, while
    layers 2+ (_gen_dense_layer) cost only 1 array each, no multiplier."""
    n_onehot = sum(1 for f in shape["features"]
                   if mm.FEATURE_CATALOG[f["type"]]["kind"] == "onehot")
    n_dense_vals = sum(f["size"] for f in shape["features"]
                       if mm.FEATURE_CATALOG[f["type"]]["kind"] == "dense_vector_map")
    return (1 + n_onehot) * n_h1 * 8 + n_dense_vals * 8


def bench_shape(label, dims, shape, repeat):
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    n_h1 = dims[0] if dims else n_out
    stack_est = first_layer_stack_estimate(shape, n_h1)
    shape_str = f"{n_in}-{'-'.join(map(str, dims))}-{n_out}"

    if stack_est > STACK_SAFETY_LIMIT:
        print(f"  {label:<14} {shape_str:<24} weights={nw:<6} "
              f"stack_est(L1)={stack_est:<5}  SKIPPED (predicted > {STACK_SAFETY_LIMIT}B "
              f"stack ceiling -- not attempted, BCC's compile failure is unrecoverable)")
        return None, nw, None, stack_est

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
    # dur_ns from BPF_PROG_TEST_RUN is already the per-repetition average
    # (kernel divides internally) -- test_suite.py uses it the same way, do
    # NOT divide by repeat again here.
    prog_test_run(disp_fn.fd, frame, repeat=repeat)   # warm-up (JIT icache)
    retval, ns_per_pkt = prog_test_run(disp_fn.fd, frame, repeat=repeat)

    print(f"  {label:<14} {shape_str:<24} weights={nw:<6} "
          f"stack_est(L1)={stack_est:<5} "
          f"xlated_insn(disp+model)={xlated}+{xlated_model:<5} "
          f"{ns_per_pkt:7.1f} ns/pkt  retval={retval}")
    return ns_per_pkt, nw, xlated + xlated_model, stack_est


def run_descriptor(name, repeat):
    shape = build_shape(name)
    feats_str = ", ".join(f"{f['type']}[{f['size']}]" for f in shape["features"])
    n_onehot = sum(1 for f in shape["features"]
                   if mm.FEATURE_CATALOG[f["type"]]["kind"] == "onehot")
    print("=" * 100)
    print(f"descriptor '{name}': [{feats_str}]  n_in={shape['n_in']}  "
          f"n_out={shape['n_out']}  onehot_features={n_onehot}")
    print("=" * 100)

    rows = []
    for tier, label, dims in SHAPES:
        ns, nw, insns, stack_est = bench_shape(label, dims, shape, repeat)
        rows.append((tier, label, dims, ns, nw, insns, stack_est))

    tiers = {}
    for row in rows:
        tiers.setdefault(row[0], []).append(row)
    for tier, group in tiers.items():
        nws = [r[4] for r in group]
        spread = (max(nws) - min(nws)) / min(nws)
        print(f"\n  Tier {tier} -- weight-count spread: {spread:.1%} "
              f"(min={min(nws)}, max={max(nws)})")
        ref_ns = next((r[3] for r in group if r[3] is not None), None)
        ref_label = group[0][1].strip()
        for _, label, dims, ns, nw, insns, stack_est in group:
            if ns is None:
                print(f"    {label:<14} weights={nw:<6} stack_est(L1)={stack_est:<5}  SKIPPED")
            else:
                rel = f"({ns/ref_ns:+.1%} vs {ref_label})" if ref_ns else ""
                print(f"    {label:<14} weights={nw:<6} stack_est(L1)={stack_est:<5} "
                      f"{ns:7.1f} ns/pkt  {rel}  {insns} insns")
    print()
    return rows


def main():
    ap = argparse.ArgumentParser(description="Hardcoded depth-vs-width trade-off sweep")
    ap.add_argument("--repeat", type=int, default=2000)
    ap.add_argument("--descriptor", choices=list(FEATURE_SETS) + ["all"], default="all",
                    help="Which feature descriptor(s) to sweep (default: all)")
    args = ap.parse_args()

    names = list(FEATURE_SETS) if args.descriptor == "all" else [args.descriptor]
    for name in names:
        run_descriptor(name, args.repeat)


if __name__ == "__main__":
    main()
