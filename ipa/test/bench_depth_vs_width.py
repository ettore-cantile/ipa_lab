#!/usr/bin/env python3
"""bench_depth_vs_width.py -- Pipeline 1: with the same number of weights, is a
wide or a deep network cheaper? (BPF_PROG_TEST_RUN, program size). Needs root.

    sudo python3 ipa/test/bench_depth_vs_width.py
"""
import os
import sys
import json
import random
import argparse
import subprocess

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for p in (SHARED_DIR, _TEST_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

import model_meta as mm

# --- Feature descriptors to sweep. Isolates onehot COUNT (0 / 1 / 2) and onehot ---
FEATURE_SETS = {
    "default":      ["link_state", "ingress_iface", "ttl", "node"],
    "no_onehot":    ["link_state", "ttl", "queue_occupancy"],
    "small_onehot": ["link_state", "ttl", "ingress_iface"],
    "big_onehot":   ["link_state", "ttl", "node"],
}

TIERS = [
    ("A (~300 w)", 300),
    ("B (~1200 w)", 1200),
    ("C (~4700 w)", 4700),
]

DEPTHS = [("wide  ", 1), ("base  ", 2), ("deep 4", 4), ("deep 8", 8)]
WIDTH_SEARCH = range(2, 513)


def solve_width(n_in, n_out, depth, target):
    """The uniform hidden width whose weight count lands closest to `target`."""
    best = None
    for h in WIDTH_SEARCH:
        dims = (h,) * depth
        nw = weight_count(n_in, dims, n_out)
        key = (abs(nw - target), h)
        if best is None or key < best[0]:
            best = (key, dims, nw)
    return best[1], best[2]


def shapes_for(shape):
    """The (tier, label, dims) grid for ONE descriptor, budgets solved."""
    n_in, n_out = shape["n_in"], shape["n_out"]
    out = []
    for tier, target in TIERS:
        for name, depth in DEPTHS:
            dims, nw = solve_width(n_in, n_out, depth, target)
            out.append((tier, f"{name} {depth}x{dims[0]}", dims))
    return out


BENCH_TOPOLOGY = {"n_interfaces": 6, "n_nodes": 52, "n_queues": 4}


def build_shape(descriptor_name: str, n_out: int = 7) -> dict:
    types = FEATURE_SETS[descriptor_name]
    meta = {"features": types, "n_out": n_out, "hidden_dims": [4, 4]}
    return mm.derive_shape(meta, topology_config=BENCH_TOPOLOGY)


def weight_count(n_in, dims, n_out):
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))


def first_layer_stack_estimate(shape, n_h1):
    """INFORMATIONAL ONLY (not a safety gate, see module docstring)."""
    n_onehot = sum(1 for f in shape["features"]
                   if mm.FEATURE_CATALOG[f["type"]]["kind"] == "onehot")
    n_dense_vals = sum(f["size"] for f in shape["features"]
                       if mm.FEATURE_CATALOG[f["type"]]["kind"] == "dense_vector_map")
    return (1 + n_onehot) * n_h1 * 8 + n_dense_vals * 8


def _bench_one(descriptor_name, dims, repeat):
    """Runs in the WORKER subprocess."""
    import p1_aot
    from check_pipelines import prog_test_run, prog_insn_count, build_frame_sparse

    shape = build_shape(descriptor_name)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    n_h1 = dims[0] if dims else n_out
    stack_est = first_layer_stack_estimate(shape, n_h1)

    rng = random.Random(42)
    weights = [rng.randint(-100, 100) for _ in range(nw)]
    scale = 128

    setup = p1_aot.load_p1([(0, weights, scale)], features=shape["features"],
                           n_out=n_out, hidden_dims=dims)
    model_fn, disp_fn = setup["fn"], setup["disp"]

    xlated, jited = prog_insn_count(disp_fn.fd)
    xlated_model, _ = prog_insn_count(model_fn.fd)

    frame = build_frame_sparse(model_id=0, ttl=42, scale=scale, n_in=n_in, n_out=n_out)
    TRIALS = 15
    prog_test_run(disp_fn.fd, frame, repeat=repeat)
    samples = []
    for _ in range(TRIALS):
        retval, ns = prog_test_run(disp_fn.fd, frame, repeat=repeat)
        samples.append(ns)
    samples.sort()

    def pct(p):
        idx = min(TRIALS - 1, int(round(p * (TRIALS - 1))))
        return samples[idx]

    print(json.dumps({
        "ok": True, "nw": nw, "stack_est": stack_est,
        "insns": xlated + xlated_model, "ns": samples[0], "retval": retval,
        "ns_p50": pct(0.50), "ns_p90": pct(0.90), "ns_max": samples[-1],
        "shape_str": f"{n_in}-{'-'.join(map(str, dims))}-{n_out}",
    }))


def bench_shape_isolated(descriptor_name, label, dims, repeat):
    """Runs _bench_one for (descriptor_name, dims) in a fresh subprocess so a
    fatal LLVM stack-overflow abort (uncatchable in-process) only kills that
    subprocess."""
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
    for tier, label, dims in shapes_for(shape):
        r = bench_shape_isolated(name, label, dims, repeat)
        r["tier"] = tier
        rows.append(r)
        if r["ok"]:
            print(f"  {label:<14} {r['shape_str']:<24} weights={r['nw']:<6} "
                  f"stack_est(L1)~{r['stack_est']:<5} insns={r['insns']:<6} "
                  f"{r['ns']:7.1f} ns/pkt (min)  [p50={r['ns_p50']:.0f} "
                  f"p90={r['ns_p90']:.0f} max={r['ns_max']:.0f}]  retval={r['retval']}")
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
                    help=argparse.SUPPRESS)
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
