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
because the width-vs-depth verdict depends on the descriptor's feature mix:
onehot features (ingress_iface, node) generate a switch-case whose cost is
proportional to (that feature's size * n_h1), paid only by the FIRST hidden
layer. A conclusion drawn from one descriptor is not safe to generalize --
see FEATURE_SETS for the 0/1/2-onehot, small/big-onehot variants tested.

Stack-overflow safety: whether a given (descriptor, hidden_dims) shape
overflows the 512-byte eBPF per-function stack is NOT reliably predictable
from a simple formula -- two independent attempts at one (see git history)
were each contradicted by clang/BCC's actual -O2 stack-slot coalescing,
which seems to depend on total code size/layer count in ways not worth
reverse-engineering. And BCC's LLVM backend reports a real overflow via a
process-fatal abort (not a Python exception), so a bad guess crashes the
whole sweep. The robust fix used here: each (descriptor, shape) pair is
benchmarked in its OWN subprocess (this same script re-invoked with
--_worker); a subprocess crash only marks that one cell CRASHED and the
sweep continues. first_layer_stack_estimate() is kept as an informational
column only, not a gate.

Timing is reported as the MEDIAN of 7 independent trials, with the
[min-max] range printed alongside -- a single repeat=N sample turned out to
swing 5-10x on some shapes with no correlation to instruction count (pure
system noise: scheduler preemption, an unrelated process on the same host),
so a one-shot measurement is not trustworthy here.

`retval` (1=XDP_DROP or 2=XDP_PASS) is benign noise, not a defect: this
bench never populates mac_table, so a forward-class argmax always misses
(XDP_PASS) and only the random weights landing on the drop class gives
XDP_DROP -- the map lookup cost is the same either way, so it does not bias
the timing.

Run on Linux (Kathara or bare VM) with bcc installed:
    sudo python3 shared/test/bench_depth_vs_width.py
    sudo python3 shared/test/bench_depth_vs_width.py --repeat 5000
    sudo python3 shared/test/bench_depth_vs_width.py --descriptor no_onehot
"""
import os
import sys
import json
import random
import argparse
import subprocess
import ctypes as ct

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for p in (SHARED_DIR, _TEST_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

import model_meta as mm

# ---------------------------------------------------------------------------
# Feature descriptors to sweep. Isolates onehot COUNT (0 / 1 / 2) and onehot
# SIZE (ingress_iface=6 vs node=52, the topology's 'largest' onehot) as
# separate variables, instead of only ever testing the historical 4-feature
# default (which happens to carry the most expensive onehot: 'node', size 52).
# All variants keep n_out=7 so tier weight-budgets stay comparable.
# ---------------------------------------------------------------------------
FEATURE_SETS = {
    "default":      ["link_state", "ingress_iface", "ttl", "node"],   # 2 onehot (6 + 52)
    "no_onehot":    ["link_state", "ttl", "queue_occupancy"],         # 0 onehot
    "small_onehot": ["link_state", "ttl", "ingress_iface"],           # 1 onehot, size 6
    "big_onehot":   ["link_state", "ttl", "node"],                    # 1 onehot, size 52
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


def build_shape(descriptor_name: str, n_out: int = 7) -> dict:
    types = FEATURE_SETS[descriptor_name]
    meta = {"features": types, "n_out": n_out, "hidden_dims": [4, 4]}
    return mm.derive_shape(meta)


def weight_count(n_in, dims, n_out):
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))


def first_layer_stack_estimate(shape, n_h1):
    """INFORMATIONAL ONLY (not a safety gate, see module docstring): estimated
    live-stack bytes for just the FIRST hidden layer's `long long` locals --
    ebpf_program._gen_feature_onehot_{iface,node} each declare their OWN
    n_h1-sized temp array in addition to the h1_j output array, and
    _gen_feature_dense_vector declares one `long long` per feature value.
    Deeper layers (_gen_dense_layer) add their own n_cur-sized array each,
    not counted here -- empirically, whether those get stack-coalesced by
    -O2 is NOT reliably predictable, which is why this is a diagnostic
    number only, never used to decide whether to attempt a shape."""
    n_onehot = sum(1 for f in shape["features"]
                   if mm.FEATURE_CATALOG[f["type"]]["kind"] == "onehot")
    n_dense_vals = sum(f["size"] for f in shape["features"]
                       if mm.FEATURE_CATALOG[f["type"]]["kind"] == "dense_vector_map")
    return (1 + n_onehot) * n_h1 * 8 + n_dense_vals * 8


def _bench_one(descriptor_name, dims, repeat):
    """Runs in the WORKER subprocess. Prints exactly one JSON line to stdout
    (the parent's only contract) and exits 0/1. Any BCC/clang diagnostics go
    to stderr and are ignored by the parent unless this process crashes."""
    from bcc import BPF
    from ebpf_program import build_combined_hardcoded_source
    from verify_prog_run import prog_test_run, prog_insn_count, build_frame_sparse

    shape = build_shape(descriptor_name)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    n_h1 = dims[0] if dims else n_out
    stack_est = first_layer_stack_estimate(shape, n_h1)

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
    xlated_model, _ = prog_insn_count(model_fn.fd)

    frame = build_frame_sparse(model_id=0, ttl=42, scale=scale, n_in=n_in, n_out=n_out)
    # dur_ns from BPF_PROG_TEST_RUN is already the per-repetition average
    # (kernel divides internally) -- test_suite.py uses it the same way, do
    # NOT divide by repeat again here.
    #
    # A SINGLE repeat=N measurement is not enough: transient system noise
    # (scheduler preemption, interrupts, an unrelated cgroup on the same
    # host) can dominate one sample and produce swings of 5-10x that do not
    # correlate with instruction count at all -- exactly what a one-shot run
    # of this sweep showed. TRIALS independent repeat=`repeat` measurements
    # are taken and the MEDIAN is reported (standard practice for
    # microbenchmarks: min is sometimes preferred, but median is more
    # robust here since a shape that is genuinely slower should still show
    # up as slower across most trials, not just the fastest one).
    TRIALS = 7
    prog_test_run(disp_fn.fd, frame, repeat=repeat)   # warm-up (JIT icache)
    samples = []
    for _ in range(TRIALS):
        retval, ns = prog_test_run(disp_fn.fd, frame, repeat=repeat)
        samples.append(ns)
    samples.sort()
    median_ns = samples[TRIALS // 2]

    print(json.dumps({
        "ok": True, "nw": nw, "stack_est": stack_est,
        "insns": xlated + xlated_model, "ns": median_ns, "retval": retval,
        "ns_min": samples[0], "ns_max": samples[-1],
        "shape_str": f"{n_in}-{'-'.join(map(str, dims))}-{n_out}",
    }))


def bench_shape_isolated(descriptor_name, label, dims, repeat):
    """Runs _bench_one for (descriptor_name, dims) in a fresh subprocess so a
    fatal LLVM stack-overflow abort (uncatchable in-process) only kills that
    subprocess. Returns a result dict; on crash, {"ok": False, "detail":...}
    still carries nw/stack_est (computed here, cheaply, without compiling)."""
    shape = build_shape(descriptor_name)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    n_h1 = dims[0] if dims else n_out
    stack_est = first_layer_stack_estimate(shape, n_h1)
    shape_str = f"{n_in}-{'-'.join(map(str, dims))}-{n_out}"

    dims_arg = ",".join(map(str, dims))
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__),
         "--_worker", descriptor_name, dims_arg, str(repeat)],
        capture_output=True, text=True)

    result = {"nw": nw, "stack_est": stack_est, "shape_str": shape_str,
              "label": label, "dims": dims}
    last_line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None
    if proc.returncode == 0 and last_line:
        try:
            parsed = json.loads(last_line)
            result.update(parsed)
            return result
        except json.JSONDecodeError:
            pass
    detail = (proc.stderr.strip().splitlines()[-1] if proc.stderr.strip()
             else f"exit code {proc.returncode} (likely a fatal LLVM abort -- stack overflow)")
    result.update({"ok": False, "detail": detail[:90]})
    return result


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
        r = bench_shape_isolated(name, label, dims, repeat)
        r["tier"] = tier
        rows.append(r)
        if r["ok"]:
            print(f"  {label:<14} {r['shape_str']:<24} weights={r['nw']:<6} "
                  f"stack_est(L1)~{r['stack_est']:<5} insns={r['insns']:<6} "
                  f"{r['ns']:7.1f} ns/pkt  [{r['ns_min']:.0f}-{r['ns_max']:.0f}]  "
                  f"retval={r['retval']}")
        else:
            print(f"  {label:<14} {r['shape_str']:<24} weights={r['nw']:<6} "
                  f"stack_est(L1)~{r['stack_est']:<5} CRASHED ({r['detail']})")

    tiers = {}
    for row in rows:
        tiers.setdefault(row["tier"], []).append(row)
    for tier, group in tiers.items():
        nws = [r["nw"] for r in group]
        spread = (max(nws) - min(nws)) / min(nws)
        print(f"\n  Tier {tier} -- weight-count spread: {spread:.1%} "
              f"(min={min(nws)}, max={max(nws)})")
        ref = next((r for r in group if r["ok"]), None)
        for r in group:
            if not r["ok"]:
                print(f"    {r['label']:<14} weights={r['nw']:<6} "
                      f"stack_est(L1)~{r['stack_est']:<5}  CRASHED ({r['detail']})")
            else:
                rel = f"({r['ns']/ref['ns']:+.1%} vs {ref['label'].strip()})" if ref else ""
                print(f"    {r['label']:<14} weights={r['nw']:<6} "
                      f"stack_est(L1)~{r['stack_est']:<5} {r['ns']:7.1f} ns/pkt  "
                      f"{rel}  {r['insns']} insns")
    print()
    return rows


def main():
    ap = argparse.ArgumentParser(description="Hardcoded depth-vs-width trade-off sweep")
    ap.add_argument("--repeat", type=int, default=2000)
    ap.add_argument("--descriptor", choices=list(FEATURE_SETS) + ["all"], default="all",
                    help="Which feature descriptor(s) to sweep (default: all)")
    ap.add_argument("--_worker", nargs=3, default=None,
                    help=argparse.SUPPRESS)  # internal: descriptor, "d1,d2,...", repeat
    args = ap.parse_args()

    if args._worker:
        descriptor_name, dims_str, repeat_str = args._worker
        dims = tuple(int(x) for x in dims_str.split(",")) if dims_str else ()
        try:
            _bench_one(descriptor_name, dims, int(repeat_str))
        except Exception as e:
            print(json.dumps({"ok": False, "detail": str(e)[:200]}))
            sys.exit(1)
        return

    names = list(FEATURE_SETS) if args.descriptor == "all" else [args.descriptor]
    for name in names:
        run_descriptor(name, args.repeat)


if __name__ == "__main__":
    main()
