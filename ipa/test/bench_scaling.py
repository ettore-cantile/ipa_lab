#!/usr/bin/env python3
"""
bench_scaling.py -- parametric scaling analysis across ALL THREE pipelines.

The question: how does the cost of the datapath change as the network, or the
model, gets bigger? And -- the part that matters for the design-space argument
-- do the three pipelines have DIFFERENT slopes?

They do, and the slopes are the whole point of having three of them:

                        P1 hardcoded     P2 template     P3 modular
  more NODES            grows            flat            flat
  more LAYERS           grows            impossible      flat
  more NEURONS/layer    grows            grows           grows
  changing the model    ~1.2 s of clang  a map write     a map write

Each cell of that table is a claim this script measures rather than asserts.

--------------------------------------------------------------------------
THREE AXES, one variable each
--------------------------------------------------------------------------
Exactly one thing moves per axis; everything else is pinned, so a curve can
be attributed to the variable named on the x axis and nothing else.

  nodes  n_nodes in {10, 25, 52, 75, 100}, hidden (4,4), n_out 7
         The node one-hot is `n_nodes` wide, so this is the input width:
         n_in = n_interfaces + n_interfaces + 1 + n_nodes = 13 + n_nodes.
         52 is Germany50, the checked-in topology. Capped at 100 because
         MAX_N_IN / ML_MAX_N_IN is 128 in P2 and P3.

  depth  1..6 hidden layers of 4 neurons, n_nodes 52 (n_in 65)
         P2 compiles EXACTLY two hidden layers (fc1, fc2), so it produces a
         single point. That is not a hole in the sweep, it is the result:
         depth is the axis P2 cannot travel at all.

  width  2, 4, 6, 8 neurons per hidden layer, two hidden layers, n_nodes 52
         8 is the compiled ceiling in P2 (T2_MAX_H1/H2) and P3 (ML1_MAX_H1,
         MLH_MAX_H). P1 has no ceiling but is swept over the same values so
         the three curves are comparable.

--------------------------------------------------------------------------
WHAT IS MEASURED
--------------------------------------------------------------------------
  insns      xlated instructions, summed over every program the pipeline
             loads -- the same convention test_suite.py --only kernel uses
             (dispatcher + leaves), so numbers are comparable with its table.
  jited      native bytes, same summation.
  lat_ns     per-packet latency, MIN of TRIALS independent BPF_PROG_TEST_RUN
             measurements. Min, not mean or median: the noise here is
             one-sided (an interrupt can only slow a trial down), so the
             smallest sample is the best estimate of the interference-free
             cost. Same reasoning as bench_depth_vs_width.py and hyperfine.
  build_ms   wall time to compile (BCC/clang) and load the program. This is
             the axis where P1 differs in KIND, not degree: P2 and P3 compile
             a source that does not depend on the model at all, so their
             build cost is flat by construction and a new model is a map
             write. Measured anyway rather than assumed.
  map_bytes  total map memory, per-CPU maps counted per CPU.
  tail       tail calls executed per packet (P3's grows with depth).
  nw         number of int8 weights the model has, for reference.

--------------------------------------------------------------------------
WHY EVERY CELL RUNS IN ITS OWN SUBPROCESS
--------------------------------------------------------------------------
P1 unrolls the whole network into one C function, and past a certain size
the 512-byte eBPF stack overflows. BCC's LLVM backend reports that with a
PROCESS-FATAL abort, not a Python exception, so one bad cell would kill the
whole sweep. Each cell therefore runs in a fresh subprocess (this file
re-invoked with --_worker) and a crash marks only that cell as CRASHED.
The same isolation covers a verifier refusal, which is a normal outcome
here rather than a bug -- see docs/testing.md on P3's complexity budget.

--------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------
    sudo python3 ipa/test/bench_scaling.py                  # all three axes
    sudo python3 ipa/test/bench_scaling.py --axis nodes
    sudo python3 ipa/test/bench_scaling.py --axis depth --trials 15
    sudo python3 ipa/test/bench_scaling.py --out results/   # CSV per axis

    python3 ipa/test/bench_scaling.py --plot results/       # no root needed

Measuring needs Linux + BCC + root. Plotting reads the CSV and needs only
matplotlib, so the graphs can be regenerated anywhere, including on the
machine the thesis is written on.
"""
import os
import sys
import csv
import json
import time
import random
import argparse
import subprocess
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")

# Pinned across every sweep: only the axis variable moves.
N_INTERFACES = 6
N_OUT = 7
FEATURES = ["link_state", "ingress_iface", "ttl", "node"]
SCALE = 128
PIPELINES = ("hardcoded", "template", "modular")

# The axes. (label, [values], builder(value) -> (n_nodes, hidden_dims))
AXES = {
    "nodes": {
        "xlabel": "nodi della rete (larghezza della one-hot `node`)",
        "values": [10, 25, 52, 75, 100],
        "shape": lambda v: (v, (4, 4)),
        "note": "n_in = 13 + n_nodes; il modello resta 4-4, cambia solo l'ingresso",
    },
    "depth": {
        "xlabel": "numero di hidden layer",
        "values": [1, 2, 3, 4, 5, 6],
        "shape": lambda v: (52, tuple([4] * v)),
        "note": "P2 compila esattamente 2 hidden layer: un punto solo, ed e' il risultato",
    },
    "width": {
        "xlabel": "neuroni per hidden layer",
        "values": [2, 4, 6, 8],
        "shape": lambda v: (52, (v, v)),
        "note": "8 e' il soffitto compilato di P2 (T2_MAX_H1/H2) e P3 (ML1_MAX_H1)",
    },
}


def topology(n_nodes):
    return {"n_interfaces": N_INTERFACES, "n_nodes": n_nodes}


def build_shape(n_nodes, hidden_dims):
    """Resolve the feature descriptor for this topology. n_out is DECLARED,
    never derived from the interface count -- see class_semantics.py."""
    import model_meta as mm
    meta = {"features": FEATURES, "n_out": N_OUT,
            "hidden_dims": list(hidden_dims)}
    return mm.derive_shape(meta, topology_config=topology(n_nodes))


def weight_count(n_in, dims, n_out):
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))


# ==========================================================================
# WORKERS -- one per pipeline, each running in its own subprocess
# ==========================================================================
def _timed(fn):
    t0 = time.perf_counter()
    out = fn()
    return out, (time.perf_counter() - t0) * 1000.0


def _sample(disp_fd, frame, repeat, trials):
    """MIN of `trials` independent measurements; see the module docstring on
    why min rather than mean. Returns (min, p50, max, retval)."""
    from verify_prog_run import prog_test_run
    prog_test_run(disp_fd, frame, repeat=repeat)      # warm the icache
    samples, retval = [], None
    for _ in range(trials):
        retval, ns = prog_test_run(disp_fd, frame, repeat=repeat)
        samples.append(ns)
    samples.sort()
    return samples[0], samples[len(samples) // 2], samples[-1], retval


def _totals(b, progs):
    """Sum xlated + jited over every loaded program, and map memory over every
    map, exactly as test_suite.py reports them.

    The map names come from test_suite._PIPELINE_MAP_NAMES rather than a copy
    kept here. That list carries a warning about staying in sync with the three
    eBPF sources, and it earned it: it was once incomplete, and because a
    missing map is silently skipped, the only symptom was a footprint smaller
    than the truth. A second copy would reintroduce exactly that failure.

    (A BCC `BPF` object has no .items(): it exposes maps through __getitem__
    and only caches the ones already asked for, so iterating it would have
    returned whatever happened to have been touched. That is what the first
    version of this function did, and every cell of the sweep crashed with
    `AttributeError: 'BPF' object has no attribute 'items'`.)"""
    from verify_prog_run import prog_insn_count, map_bytes, _nr_cpus
    from test_suite import _PIPELINE_MAP_NAMES
    insns = jited = 0
    per_prog = {}
    for name, fd in progs.items():
        x, j = prog_insn_count(fd)
        per_prog[name] = x
        insns += x
        jited += j
    nr = _nr_cpus()
    mb = 0
    counted = []
    for mname in _PIPELINE_MAP_NAMES:
        try:
            one = map_bytes(b[mname].map_fd, nr)
        except Exception:
            continue          # not a map this pipeline declares
        mb += one
        counted.append(mname)
    return insns, jited, mb, per_prog, counted


def _bench_p1(n_nodes, dims, repeat, trials):
    from bcc import BPF
    from ebpf_program import build_combined_hardcoded_source
    from verify_prog_run import build_frame_sparse, _seed_link_state

    shape = build_shape(n_nodes, dims)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    rng = random.Random(42)
    weights = [rng.randint(-100, 100) for _ in range(nw)]

    src = build_combined_hardcoded_source(
        models=[(0, weights, SCALE)],
        features=shape["features"], n_out=n_out, hidden_dims=tuple(dims))

    def _load():
        bb = BPF(text=src)
        m = bb.load_func("model_0", BPF.XDP)
        d = bb.load_func("ipa_switch_hardcoded", BPF.XDP)
        bb["model_progs"][ct.c_int(0)] = ct.c_int(m.fd)
        return bb, m, d

    (b, model_fn, disp_fn), build_ms = _timed(_load)
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(
        b, {"ipa_switch_hardcoded": disp_fn.fd, "model_0": model_fn.fd})
    frame = build_frame_sparse(model_id=0, ttl=42, scale=SCALE,
                               n_in=n_in, n_out=n_out)
    lo, med, hi, retval = _sample(disp_fn.fd, frame, repeat, trials)
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=1, nw=nw,
                n_in=n_in, build_ms=build_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, retval=retval, per_prog=per_prog, n_maps=len(maps))


def _bench_p2(n_nodes, dims, repeat, trials):
    # Checked BEFORE the imports on purpose: "P2 cannot do this depth" is a
    # property of P2, not of whether BCC happens to be installed. Behind the
    # imports, a machine without BCC would report this cell as a crash rather
    # than as the structural limit it is.
    if len(dims) != 2:
        raise NotImplementedError(
            f"P2 compila esattamente 2 hidden layer (fc1, fc2); "
            f"questa forma ne chiede {len(dims)}")

    from bcc import BPF
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                    EBPF_ARCH_GENERIC_2LAYER,
                                    load_arch_weights)
    from verify_prog_run import build_frame_sparse, _seed_link_state

    shape = build_shape(n_nodes, dims)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    rng = random.Random(42)
    weights = [rng.randint(-100, 100) for _ in range(nw)]

    # NOTE: the source does not mention the shape anywhere -- that is the
    # whole claim of P2. build_ms is therefore expected to be FLAT across the
    # sweep, and a rising curve here would be a finding.
    src = ("#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
           + "\n" + EBPF_ARCH_GENERIC_2LAYER)

    def _load():
        bb = BPF(text=src)
        d = bb.load_func("ipa_switch_template", BPF.XDP)
        leaf = bb.load_func("arch_generic_2layer", BPF.XDP)
        bb["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
        return bb, d, leaf

    (b, disp_fn, leaf_fn), build_ms = _timed(_load)
    load_arch_weights(b, weights, model_id=0, scale=SCALE,
                      n_h1=dims[0], n_h2=dims[1],
                      features=shape["features"], n_in=n_in,
                      semantics=shape.get("semantics"))
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(
        b, {"ipa_switch_template": disp_fn.fd,
            "arch_generic_2layer": leaf_fn.fd})
    frame = build_frame_sparse(model_id=0, ttl=42, scale=SCALE,
                               n_in=n_in, n_out=n_out)
    lo, med, hi, retval = _sample(disp_fn.fd, frame, repeat, trials)
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=1, nw=nw,
                n_in=n_in, build_ms=build_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, retval=retval, per_prog=per_prog, n_maps=len(maps))


def _bench_p3(n_nodes, dims, repeat, trials):
    from bcc import BPF
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    from verify_prog_run import build_frame_sparse, _seed_link_state

    shape = build_shape(n_nodes, dims)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    rng = random.Random(42)
    weights = [rng.randint(-100, 100) for _ in range(nw)]

    sizes = [n_in] + list(dims) + [n_out]
    layer_dims = [(sizes[i - 1], sizes[i]) for i in range(1, len(sizes))]

    def _load():
        bb = BPF(text=EBPF_MODULAR_FULL)
        d = bb.load_func("modular_dispatcher", BPF.XDP)
        first = bb.load_func("layer_first", BPF.XDP)
        hidden = bb.load_func("layer_hidden", BPF.XDP)
        bb["layer_chain"][ct.c_int(0)] = ct.c_int(first.fd)
        for i in range(1, 16):                       # LAYER_CHAIN_SIZE
            bb["layer_chain"][ct.c_int(i)] = ct.c_int(hidden.fd)
        return bb, d, first, hidden

    (b, disp_fn, first_fn, hidden_fn), build_ms = _timed(_load)
    load_modular_weights(b, weights, model_id=0, scale=SCALE,
                         layer_dims=layer_dims,
                         features=shape["features"],
                         semantics=shape.get("semantics"))
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(
        b, {"modular_dispatcher": disp_fn.fd,
            "layer_first": first_fn.fd,
            "layer_hidden": hidden_fn.fd})
    frame = build_frame_sparse(model_id=0, ttl=42, scale=SCALE,
                               n_in=n_in, n_out=n_out)
    lo, med, hi, retval = _sample(disp_fn.fd, frame, repeat, trials)
    # Tail calls actually executed: dispatcher -> layer_first -> layer_hidden
    # x (n_layers - 1). NOT the number of distinct programs, which is always 3.
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=len(layer_dims),
                nw=nw, n_in=n_in, build_ms=build_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, retval=retval, per_prog=per_prog, n_maps=len(maps))


_BENCH = {"hardcoded": _bench_p1, "template": _bench_p2, "modular": _bench_p3}


def _worker(pipeline, n_nodes, dims_csv, repeat, trials):
    """Runs in the subprocess. Prints exactly one JSON line; that is the
    parent's only contract with it."""
    os.chdir(SHARED_DIR)
    dims = tuple(int(x) for x in dims_csv.split(",") if x)
    try:
        out = _BENCH[pipeline](n_nodes, dims, repeat, trials)
        out["ok"] = True
    except NotImplementedError as e:
        out = {"ok": False, "skipped": True, "detail": str(e)}
    except Exception as e:
        detail = str(e).strip().splitlines()
        out = {"ok": False, "skipped": False,
               "detail": f"{type(e).__name__}: {detail[-1][:110] if detail else ''}"}
    print(json.dumps(out))
    return 0


def bench_cell(pipeline, n_nodes, dims, repeat, trials):
    """One cell, isolated. A fatal LLVM abort or a verifier refusal kills only
    the child."""
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--_worker", pipeline,
         str(n_nodes), ",".join(map(str, dims)), str(repeat), str(trials)],
        capture_output=True, text=True)
    last = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None
    if last:
        try:
            return json.loads(last)
        except json.JSONDecodeError:
            pass
    err = proc.stderr.strip().splitlines()
    return {"ok": False, "skipped": False,
            "detail": (err[-1][:110] if err else
                       f"exit {proc.returncode} (abort fatale: stack o verifier)")}


# ==========================================================================
# SWEEP
# ==========================================================================
def run_axis(axis, repeat, trials, out_dir):
    spec = AXES[axis]
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} asse x: {spec['xlabel']}{NC}")
    print(f"{GREY} {spec['note']}{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}\n")

    rows = []
    hdr = (f"  {'x':>5s} {'pipeline':10s} {'forma':>16s} {'pesi':>6s} "
           f"{'insns':>7s} {'ns':>7s} {'build ms':>9s} {'mappe B':>8s} {'tail':>4s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))

    for v in spec["values"]:
        n_nodes, dims = spec["shape"](v)
        for pipe in PIPELINES:
            r = bench_cell(pipe, n_nodes, dims, repeat, trials)
            shape_str = f"{13 + n_nodes}-{'-'.join(map(str, dims))}-{N_OUT}"
            if r.get("ok"):
                print(f"  {v:5d} {pipe:10s} {shape_str:>16s} {r['nw']:6d} "
                      f"{r['insns']:7d} {r['lat_ns']:7.1f} {r['build_ms']:9.1f} "
                      f"{r['map_bytes']:8d} {r['tail']:4d}")
                rows.append(dict(axis=axis, x=v, pipeline=pipe,
                                 shape=shape_str, **{
                                     k: r[k] for k in
                                     ("nw", "n_in", "insns", "jited",
                                      "map_bytes", "tail", "build_ms",
                                      "lat_ns", "lat_p50", "lat_max")}))
            else:
                mark = f"{GREY}n/d{NC}" if r.get("skipped") else f"{RED}CRASH{NC}"
                print(f"  {v:5d} {pipe:10s} {shape_str:>16s} {'':6s} "
                      f"{mark} {GREY}{r.get('detail', '')[:90]}{NC}")

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"scaling_{axis}.csv")
        if rows:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
            print(f"\n  {GREEN}scritto{NC} {path}  ({len(rows)} righe)")
        else:
            print(f"\n  {RED}nessuna riga da scrivere per {axis}{NC}")
    return rows


# ==========================================================================
# PLOTS -- read the CSV, never re-measure. No root, no BCC.
# ==========================================================================
PLOTS = [
    ("insns", "istruzioni eBPF (xlated)", "scaling_{axis}_insns"),
    ("lat_ns", "latenza (ns/pacchetto, minimo)", "scaling_{axis}_latenza"),
    ("build_ms", "compilazione + caricamento (ms)", "scaling_{axis}_build"),
    ("map_bytes", "memoria delle mappe (byte)", "scaling_{axis}_mappe"),
]
STYLE = {
    "hardcoded": dict(color="#c0392b", marker="o", label="P1 hardcoded"),
    "template": dict(color="#2980b9", marker="s", label="P2 template"),
    "modular": dict(color="#27ae60", marker="^", label="P3 modular"),
}


def plot_axis(axis, in_dir, fmt):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    path = os.path.join(in_dir, f"scaling_{axis}.csv")
    if not os.path.exists(path):
        print(f"  {GREY}salto {axis}: {path} non c'e'{NC}")
        return 0
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print(f"  {GREY}salto {axis}: CSV vuoto{NC}")
        return 0

    made = 0
    for metric, ylabel, stem in PLOTS:
        fig, ax = plt.subplots(figsize=(5.6, 3.6))
        drawn = False
        for pipe in PIPELINES:
            pts = sorted((float(r["x"]), float(r[metric]))
                         for r in rows if r["pipeline"] == pipe and r[metric])
            if not pts:
                continue
            xs, ys = zip(*pts)
            # A single point cannot show a slope, so it is drawn as a lone
            # marker: that is P2 on the depth axis, and the gap IS the result.
            ax.plot(xs, ys, linestyle="-" if len(xs) > 1 else "none",
                    linewidth=1.6, markersize=6, **STYLE[pipe])
            drawn = True
        if not drawn:
            plt.close(fig)
            continue
        ax.set_xlabel(AXES[axis]["xlabel"])
        ax.set_ylabel(ylabel)
        ax.grid(True, linewidth=0.4, alpha=0.4)
        ax.legend(frameon=False, fontsize=8)
        ax.set_ylim(bottom=0)
        fig.tight_layout()
        out = os.path.join(in_dir, stem.format(axis=axis) + "." + fmt)
        fig.savefig(out, dpi=160)
        plt.close(fig)
        print(f"  {GREEN}scritto{NC} {out}")
        made += 1
    return made


# ==========================================================================
def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("USAGE")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--axis", choices=list(AXES) + ["all"], default="all")
    p.add_argument("--repeat", type=int, default=100000,
                   help="ripetizioni dentro una singola BPF_PROG_TEST_RUN")
    p.add_argument("--trials", type=int, default=7,
                   help="misure indipendenti per cella; si tiene il minimo")
    p.add_argument("--out", default=os.path.join(SHARED_DIR, "..", "results"),
                   help="dove scrivere i CSV")
    p.add_argument("--plot", metavar="DIR", default=None,
                   help="non misurare: genera i grafici dai CSV in DIR")
    p.add_argument("--format", default="pdf", choices=["pdf", "png"])
    p.add_argument("--_worker", nargs=5, help=argparse.SUPPRESS)
    a = p.parse_args()

    if a._worker:
        pipe, n_nodes, dims_csv, repeat, trials = a._worker
        return _worker(pipe, int(n_nodes), dims_csv, int(repeat), int(trials))

    if a.plot:
        import importlib.util
        if importlib.util.find_spec("matplotlib") is None:
            sys.exit("serve matplotlib per i grafici: pip install matplotlib")
        n = sum(plot_axis(ax, a.plot, a.format) for ax in AXES)
        print(f"\n{GREEN}{n} grafici{NC} in {a.plot}")
        return 0

    if sys.platform != "linux":
        sys.exit(f"la misura richiede Linux, non {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("serve root: sudo python3 ipa/test/bench_scaling.py")

    os.chdir(SHARED_DIR)
    out_dir = os.path.abspath(a.out)
    axes = list(AXES) if a.axis == "all" else [a.axis]
    for ax in axes:
        run_axis(ax, a.repeat, a.trials, out_dir)

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(" Grafici (non serve root, basta matplotlib):")
    print(f"   python3 ipa/test/bench_scaling.py --plot {out_dir}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
