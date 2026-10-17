#!/usr/bin/env python3
"""bench_scaling.py -- how the cost of each pipeline grows with the model.

One variable at a time (nodes of the network, depth, width, weights at zero,
same weights in different shapes): program size and latency under
BPF_PROG_TEST_RUN. Needs root.

USAGE
    sudo python3 ipa/test/bench_scaling.py --axis depth
    python3 ipa/test/bench_scaling.py --plot <results dir>
"""
import os
import sys
import csv
import json
import time
import random
import argparse
import signal
import subprocess
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")

N_INTERFACES = 6
N_OUT = 7
SCALE = 128
PIPELINES = ("p1_static", "hardcoded", "template", "modular")
STATIC_NODE = 7

from bench_depth_vs_width import FEATURE_SETS  # noqa: E402
DEFAULT_DESCRIPTOR = "default"


_POOL_SIZE = 8192


def make_weights(nw, sparsity, seed=42):
    """The first `nw` weights of a fixed pool with a `sparsity` fraction of
    zeros."""
    rng = random.Random(seed)
    n_zero = int(round(_POOL_SIZE * sparsity))
    pool = [0] * n_zero + [rng.choice([v for v in range(-100, 101) if v != 0])
                           for _ in range(_POOL_SIZE - n_zero)]
    rng.shuffle(pool)
    if nw > _POOL_SIZE:
        raise ValueError(
            f"make_weights: {nw} weights asked of a {_POOL_SIZE}-wide pool. "
            f"Raise _POOL_SIZE -- but note that doing so changes every weight "
            f"vector, so re-measure the whole sweep rather than comparing new "
            f"numbers with old ones.")
    return pool[:nw]

AXES = {
    "nodes": {
        "xlabel": "network nodes (width of the column identifying the node)",
        "kind": "num",
        "values": [10, 25, 52, 75, 100],
        "cell": lambda v: dict(n_nodes=v, dims=(4, 4)),
        "note": "n_in = 13 + n_nodes; the model stays 4-4, only the input changes",
    },
    "depth": {
        "xlabel": "number of hidden layers",
        "kind": "num",
        "values": [1, 2, 3, 4, 5, 6],
        "cell": lambda v: dict(n_nodes=52, dims=tuple([4] * v)),
        "note": "P2 covers depth by RECOMPILING (build_arch_leaf), P3 does not: "
                "the recompilation IS the comparison",
    },
    "width": {
        "xlabel": "neurons per hidden layer",
        "kind": "num",
        "values": [2, 4, 6, 8],
        "cell": lambda v: dict(n_nodes=52, dims=(v, v)),
        "note": "8 is the compiled ceiling of P2 (T2_MAX_H1/H2) and P3 (ML1_MAX_H1)",
    },
    "descriptor": {
        "xlabel": "composition of the input vector",
        "kind": "cat",
        "values": list(FEATURE_SETS),
        "cell": lambda v: dict(n_nodes=52, dims=(4, 4), descriptor=v),
        "note": "same 4-4 model, different IVs: 0/1/2 one-hot, small (6) or large (52)",
    },
    "isoparam": {
        "xlabel": "hidden layers, with the same weights (~592)",
        "kind": "num",
        "values": [1, 2, 3, 4, 5],
        "cell": lambda v: dict(n_nodes=52, dims=ISOPARAM_DIMS[v]),
        "note": "same weight budget spent in different ways: one wide layer "
                "against many narrow ones",
    },
    "degree": {
        "xlabel": "ports actually present on the node (out of 6)",
        "kind": "num",
        "values": [2, 3, 4, 5, 6],
        "cell": lambda v: dict(n_nodes=52, dims=(4, 4),
                               static_ports=list(range(v))),
        "note": "same model, same weights, same weight columns: only how many "
                "of them the static P1 generates changes",
    },
    "sparsity": {
        "xlabel": "fraction of weights exactly zero",
        "kind": "num",
        "values": [0.0, 0.25, 0.5, 0.75, 0.9],
        "cell": lambda v: dict(n_nodes=52, dims=(4, 4), sparsity=v),
        "note": "same shape, different weights: P1 compiles them as literals, P2/P3 read them from a map",
    },

    # --- the campaign axes ---

    "iv_dense": {
        "xlabel": "input columns, all actually multiplied",
        "kind": "num",
        "values": [5, 9, 13, 17],
        "cell": lambda v: dict(n_nodes=52, dims=(8, 8), descriptor="iv_dense",
                               n_interfaces=(v - 1) // 2,
                               n_queues=(v - 1) // 2),
        "campaign": True,
        "note": "n_in = 2k+1 with link_state(k) + queue_occupancy(k) + ttl; "
                "every column costs h1 multiplications. Hard ceiling at 17",
    },

    "iv_onehot": {
        "xlabel": "input columns, width in a single column",
        "kind": "num",
        "values": [16, 32, 65],
        "cell": lambda v: dict(n_nodes=52, dims=(8, 8), descriptor="iv_onehot",
                               n_interfaces=v - 5, n_queues=4),
        "campaign": True,
        "note": "n_in = k+5 with ingress_iface(k) + ttl + queue_occupancy(4); "
                "the one-hot costs h1 additions however wide it is",
    },

    "width_camp": {
        "xlabel": "neurons per hidden layer (campaign)",
        "kind": "num",
        "values": [4, 8, 16, 32],
        "cell": lambda v: dict(n_nodes=52, dims=(v, v)),
        "campaign": True,
        "note": "65-v-v-7; above 8 only P1 and p1_static, which have no width "
                "ceilings",
    },

    "depth_camp": {
        "xlabel": "hidden layers, 8 neurons each (campaign)",
        "kind": "num",
        "values": [1, 2, 3, 4],
        "cell": lambda v: dict(n_nodes=52, dims=tuple([8] * v)),
        "campaign": True,
        "note": "65-8...8-7; P2 recompiles at every point, P3 does not -- and at "
                "width 8 P3's verifier may refuse",
    },
}

CAMPAIGN_AXES = [k for k, v in AXES.items() if v.get("campaign")]
LEGACY_AXES = [k for k, v in AXES.items() if not v.get("campaign")]
CAMPAIGN_CSV = "model_scaling_test_suite.csv"


def cell_of(axis, v):
    """Fill an axis cell out with the defaults the worker expects."""
    c = dict(n_nodes=52, dims=(4, 4), descriptor=DEFAULT_DESCRIPTOR,
             sparsity=0.0, static_ports=None,
             n_interfaces=N_INTERFACES, n_queues=N_QUEUES)
    c.update(AXES[axis]["cell"](v))
    return c


N_QUEUES = 4


ISOPARAM_DIMS = {
    1: (8,),
    2: (8, 4),
    3: (8, 3, 3),
    4: (7, 5, 5, 5),
    5: (7, 4, 4, 4, 4),
}


IV_FEATURE_SETS = {
    "iv_dense":  ["link_state", "queue_occupancy", "ttl"],
    "iv_onehot": ["ingress_iface", "ttl", "queue_occupancy"],
}
DESCRIPTORS = dict(FEATURE_SETS, **IV_FEATURE_SETS)


P2_MAX_H   = 8
P3_MAX_H1  = 8
P3_MAX_H   = 8
MAX_N_IN   = 128
MAX_FEAT   = 4
IV_DENSE_MAX = 17


def topology(n_nodes, n_interfaces=N_INTERFACES, n_queues=N_QUEUES):
    return {"n_interfaces": n_interfaces, "n_nodes": n_nodes,
            "n_queues": n_queues}


def build_shape(n_nodes, hidden_dims, descriptor=DEFAULT_DESCRIPTOR,
                n_interfaces=N_INTERFACES, n_queues=N_QUEUES):
    """Resolve the feature descriptor for this topology. n_out is DECLARED,
    never derived from the interface count -- see class_semantics.py."""
    import model_meta as mm
    meta = {"features": DESCRIPTORS[descriptor], "n_out": N_OUT,
            "hidden_dims": list(hidden_dims)}
    return mm.derive_shape(
        meta, topology_config=topology(n_nodes, n_interfaces, n_queues))


def shape_of(cell):
    """The shape of ONE cell."""
    return build_shape(cell["n_nodes"], cell["dims"],
                       cell.get("descriptor", DEFAULT_DESCRIPTOR),
                       cell.get("n_interfaces", N_INTERFACES),
                       cell.get("n_queues", N_QUEUES))


def weight_count(n_in, dims, n_out):
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))


def mac_count(n_in, dims, n_out):
    """NOMINAL MACs: the row-by-column product of every layer, as anyone
    would count it from the shape. Without the biases, which are
    additions."""
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] for i in range(1, len(sizes)))


def mac_count_eff(shape, dims, n_out):
    """MACs ACTUALLY EXECUTED, which on the first layer are not the nominal ones."""
    import model_meta as mm
    h1 = dims[0] if dims else n_out
    primo = 0
    for f in shape["features"]:
        kind = mm.FEATURE_CATALOG[f["type"]]["kind"]
        primo += h1 if kind == "onehot" else int(f["size"]) * h1
    resto = list(dims) + [n_out]
    return primo + sum(resto[i - 1] * resto[i] for i in range(1, len(resto)))


def ceiling_refusal(pipeline, shape, dims):
    """Why this cell cannot be measured on this pipeline, or None."""
    n_in, n_out = shape["n_in"], shape["n_out"]
    if pipeline not in ("template", "modular"):
        return None
    n_feat = len(shape["features"])
    if n_feat > MAX_FEAT:
        return f"{n_feat} feature > MAX_FEAT={MAX_FEAT}"
    if n_in > MAX_N_IN:
        return f"n_in={n_in} > MAX_N_IN={MAX_N_IN}"
    if pipeline == "template":
        oltre = [d for d in dims if d > P2_MAX_H]
        if oltre:
            return f"hidden {oltre} > T2_MAX_H1/H2={P2_MAX_H}"
        if n_out > P2_MAX_H:
            return f"n_out={n_out} > T2_MAX_H2={P2_MAX_H}"
    else:
        if dims and dims[0] > P3_MAX_H1:
            return f"h1={dims[0]} > ML1_MAX_H1={P3_MAX_H1}"
        oltre = [d for d in dims[1:] if d > P3_MAX_H]
        if oltre:
            return f"hidden {oltre} > MLH_MAX_H={P3_MAX_H}"
        if n_out > P3_MAX_H:
            return f"n_out={n_out} > MLH_MAX_H={P3_MAX_H}"
    return None


# --- WORKERS -- one per pipeline, each running in its own subprocess ---
def _timed(fn):
    t0 = time.perf_counter()
    out = fn()
    return out, (time.perf_counter() - t0) * 1000.0


def _sample(disp_fd, mk_frame, repeat, trials):
    """MIN of `trials` independent measurements;"""
    from check_pipelines import prog_test_run_bench
    prog_test_run_bench(disp_fd, mk_frame, 1000, max_chunks=2)
    samples, retval = [], None
    for _ in range(trials):
        retval, ns = prog_test_run_bench(disp_fd, mk_frame, repeat)
        samples.append(ns)
    samples.sort()
    return samples[0], samples[len(samples) // 2], samples[-1], retval


LOOKUP_REPEAT = 200
LOOKUP_TTL = 255


def _instrumented(raw):
    """The same source, with every `.lookup()` counted."""
    from common import instrument_map_lookups
    return "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(raw)


def _lookups_safe(build, n_in, n_out):
    """Map lookups per packet, or None if they cannot be measured."""
    from check_pipelines import build_frame_sparse, prog_test_run
    try:
        bb, disp_fd = build()
        frame = build_frame_sparse(model_id=0, ttl=LOOKUP_TTL, scale=SCALE,
                                   n_in=n_in, n_out=n_out)
        ctr = bb["lookup_ctr"]
        if getattr(ctr, "Leaf", None) is None:
            ctr[ct.c_int(0)] = ct.c_ulonglong(0)
            prog_test_run(disp_fd, frame, repeat=LOOKUP_REPEAT)
            return (int.from_bytes(ctr[ct.c_int(0)], "little")
                    / float(LOOKUP_REPEAT))
        ctr[ct.c_int(0)] = ctr.Leaf()
        prog_test_run(disp_fd, frame, repeat=LOOKUP_REPEAT)
        return sum(int(v) for v in ctr[ct.c_int(0)]) / float(LOOKUP_REPEAT)
    except Exception as e:
        print(f"[lookups] not measurable: {type(e).__name__}: {str(e)[:90]}",
              file=sys.stderr)
        return None


def _totals(b, progs):
    """Sum xlated + jited over every loaded program, and map memory over every
    map, exactly as test_weights_and_metrics.py reports them."""
    from check_pipelines import prog_insn_count, map_bytes, _nr_cpus
    from test_weights_and_metrics import _PIPELINE_MAP_NAMES
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
            continue
        mb += one
        counted.append(mname)
    return insns, jited, mb, per_prog, counted


def _bench_p1(cell, repeat, trials, static_node=None):
    ports = cell.get("static_ports") if static_node is not None else None
    import p1_aot
    from check_pipelines import build_frame_sparse, _seed_link_state

    dims = cell["dims"]
    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"], seed=cell.get("seed", 42))
    sparsity_real = weights.count(0) / len(weights) if weights else 0.0

    def _load(strumentata=False):
        return p1_aot.load_p1([(0, weights, SCALE)], instrument=strumentata,
                              cache=False, features=shape["features"],
                              n_out=n_out, hidden_dims=tuple(dims),
                              static_node=static_node, static_ports=ports)

    setup, build_ms = _timed(_load)
    update_ms = setup["t_redirect_s"] * 1000.0
    b, disp_fn = setup["b"], setup["disp"]
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(b, setup["progs"])
    lookups = None
    if cell.get("lookups"):
        def _ins():
            s2 = _load(True)
            _seed_link_state(s2["b"], 1)
            return s2["b"], s2["disp"].fd
        lookups = _lookups_safe(_ins, n_in, n_out)
    from check_pipelines import BENCH_TTL

    def mk_frame():
        return build_frame_sparse(model_id=0, ttl=BENCH_TTL, scale=SCALE,
                                  n_in=n_in, n_out=n_out)

    lo, med, hi, retval = _sample(disp_fn.fd, mk_frame, repeat, trials)
    mpps = (1000.0 / lo) if lo else 0.0
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=1, nw=nw,
                n_in=n_in, build_ms=build_ms, update_ms=update_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, mpps=mpps, retval=retval, per_prog=per_prog,
                n_maps=len(maps), sparsity_real=sparsity_real,
                lookups=lookups)


def _bench_p2(cell, repeat, trials):
    dims = cell["dims"]
    if len(dims) < 1:
        raise NotImplementedError("P2 has at least one hidden layer")
    if len(set(dims[1:])) > 1:
        raise NotImplementedError(
            f"in P2 the layers beyond the second are n_h2 wide; this shape "
            f"asks for different widths: {dims[1:]}")
    n_hidden = len(dims)
    n_h1 = dims[0]
    n_h2 = dims[1] if n_hidden >= 2 else dims[0]

    from bcc import BPF
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                    build_arch_leaf,
                                    load_arch_weights)
    from check_pipelines import build_frame_sparse, _seed_link_state

    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"], seed=cell.get("seed", 42))
    sparsity_real = weights.count(0) / len(weights) if weights else 0.0

    src = ("#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
           + "\n" + build_arch_leaf(n_hidden))

    def _load(strumentata=False):
        bb = BPF(text=_instrumented(src) if strumentata else src)
        d = bb.load_func("ipa_switch_template", BPF.XDP)
        leaf = bb.load_func("arch_generic_2layer", BPF.XDP)
        bb["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
        return bb, d, leaf

    (b, disp_fn, leaf_fn), build_ms = _timed(_load)
    _, update_ms = _timed(lambda: load_arch_weights(
        b, weights, model_id=0, scale=SCALE,
        n_h1=n_h1, n_h2=n_h2, n_hidden=n_hidden,
        features=shape["features"], n_in=n_in,
        semantics=shape.get("semantics")))
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(
        b, {"ipa_switch_template": disp_fn.fd,
            "arch_generic_2layer": leaf_fn.fd})
    lookups = None
    if cell.get("lookups"):
        def _ins():
            bb, dd, _leaf = _load(True)
            load_arch_weights(bb, weights, model_id=0, scale=SCALE,
                              n_h1=n_h1, n_h2=n_h2, n_hidden=n_hidden,
                              features=shape["features"], n_in=n_in,
                              semantics=shape.get("semantics"))
            _seed_link_state(bb, 1)
            return bb, dd.fd
        lookups = _lookups_safe(_ins, n_in, n_out)
    from check_pipelines import BENCH_TTL

    def mk_frame():
        return build_frame_sparse(model_id=0, ttl=BENCH_TTL, scale=SCALE,
                                  n_in=n_in, n_out=n_out)

    lo, med, hi, retval = _sample(disp_fn.fd, mk_frame, repeat, trials)
    mpps = (1000.0 / lo) if lo else 0.0
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=1, nw=nw,
                n_in=n_in, build_ms=build_ms, update_ms=update_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, mpps=mpps, retval=retval, per_prog=per_prog,
                n_maps=len(maps), sparsity_real=sparsity_real,
                lookups=lookups)


def _bench_p3(cell, repeat, trials):
    from bcc import BPF
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    from check_pipelines import build_frame_sparse, _seed_link_state

    dims = cell["dims"]
    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"], seed=cell.get("seed", 42))
    sparsity_real = weights.count(0) / len(weights) if weights else 0.0

    sizes = [n_in] + list(dims) + [n_out]
    layer_dims = [(sizes[i - 1], sizes[i]) for i in range(1, len(sizes))]

    def _load(strumentata=False):
        bb = BPF(text=_instrumented(EBPF_MODULAR_FULL) if strumentata
                 else EBPF_MODULAR_FULL)
        d = bb.load_func("modular_dispatcher", BPF.XDP)
        first = bb.load_func("layer_first", BPF.XDP)
        hidden = bb.load_func("layer_hidden", BPF.XDP)
        bb["layer_chain"][ct.c_int(0)] = ct.c_int(first.fd)
        for i in range(1, 16):
            bb["layer_chain"][ct.c_int(i)] = ct.c_int(hidden.fd)
        return bb, d, first, hidden

    (b, disp_fn, first_fn, hidden_fn), build_ms = _timed(_load)
    _, update_ms = _timed(lambda: load_modular_weights(
        b, weights, model_id=0, scale=SCALE,
        layer_dims=layer_dims,
        features=shape["features"],
        semantics=shape.get("semantics")))
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(
        b, {"modular_dispatcher": disp_fn.fd,
            "layer_first": first_fn.fd,
            "layer_hidden": hidden_fn.fd})
    lookups = None
    if cell.get("lookups"):
        def _ins():
            bb, dd, _f, _h = _load(True)
            load_modular_weights(bb, weights, model_id=0, scale=SCALE,
                                 layer_dims=layer_dims,
                                 features=shape["features"],
                                 semantics=shape.get("semantics"))
            _seed_link_state(bb, 1)
            return bb, dd.fd
        lookups = _lookups_safe(_ins, n_in, n_out)
    from check_pipelines import BENCH_TTL

    def mk_frame():
        return build_frame_sparse(model_id=0, ttl=BENCH_TTL, scale=SCALE,
                                  n_in=n_in, n_out=n_out)

    lo, med, hi, retval = _sample(disp_fn.fd, mk_frame, repeat, trials)
    mpps = (1000.0 / lo) if lo else 0.0
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=len(layer_dims),
                nw=nw, n_in=n_in, build_ms=build_ms, update_ms=update_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, mpps=mpps, retval=retval, per_prog=per_prog,
                n_maps=len(maps), sparsity_real=sparsity_real,
                lookups=lookups)


def _bench_p1_static(cell, repeat, trials):
    """P1 with this node's index frozen into the source."""
    return _bench_p1(cell, repeat, trials, static_node=STATIC_NODE)


def _bench_baseline(cell, repeat, trials):
    """The floor: parse, TTL decrement, redirect. No inference."""
    from bcc import BPF
    from check_pipelines import (EBPF_BASELINE, _install_mac_table,
                                 build_frame_sparse)
    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]

    def _load(strumentata=False):
        bb = BPF(text=_instrumented(EBPF_BASELINE) if strumentata
                 else EBPF_BASELINE)
        d = bb.load_func("xdp_baseline", BPF.XDP)
        _install_mac_table(bb, "mac_table")
        return bb, d

    (b, disp_fn), build_ms = _timed(_load)
    insns, jited, mb, per_prog, maps = _totals(b, {"xdp_baseline": disp_fn.fd})
    lookups = None
    if cell.get("lookups"):
        lookups = _lookups_safe(
            lambda: (lambda t: (t[0], t[1].fd))(_load(True)), n_in, n_out)
    from check_pipelines import BENCH_TTL

    def mk_frame():
        return build_frame_sparse(model_id=0, ttl=BENCH_TTL, scale=SCALE,
                                  n_in=n_in, n_out=n_out)

    lo, med, hi, retval = _sample(disp_fn.fd, mk_frame, repeat, trials)
    mpps = (1000.0 / lo) if lo else 0.0
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=0, nw=0,
                n_in=n_in, build_ms=build_ms, update_ms=0.0, lat_ns=lo,
                lat_p50=med, lat_max=hi, mpps=mpps, retval=retval,
                per_prog=per_prog, n_maps=len(maps), sparsity_real=0.0,
                lookups=lookups)


_BENCH = {"baseline": _bench_baseline,
          "p1_static": _bench_p1_static, "hardcoded": _bench_p1,
          "template": _bench_p2, "modular": _bench_p3}


def _worker(pipeline, spec_json):
    """Runs in the subprocess."""
    os.chdir(SHARED_DIR)
    spec = json.loads(spec_json)
    repeat, trials = spec.pop("repeat"), spec.pop("trials")
    spec["dims"] = tuple(spec["dims"])
    try:
        out = _BENCH[pipeline](spec, repeat, trials)
        out["ok"] = True
    except NotImplementedError as e:
        out = {"ok": False, "skipped": True, "detail": str(e)}
    except Exception as e:
        detail = str(e).strip().splitlines()
        msg = f"{type(e).__name__}: {detail[-1][:110] if detail else ''}"
        refused = ("Argument list too long" in msg
                   or "too large" in msg
                   or "Permission denied" in msg)
        out = {"ok": False, "skipped": False, "refused": refused,
               "detail": msg}
    print(json.dumps(out))
    return 0


CELL_TIMEOUT_S = int(os.environ.get("IPA_CELL_TIMEOUT_S", "900"))


def bench_cell(pipeline, cell, repeat, trials):
    """One cell, isolated. A fatal LLVM abort or a verifier refusal kills only
    the child; so does a hang, after CELL_TIMEOUT_S."""
    spec = dict(cell, dims=list(cell["dims"]), repeat=repeat, trials=trials)
    proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--_worker", pipeline,
         json.dumps(spec)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True)
    try:
        out, err_txt = proc.communicate(timeout=CELL_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        return {"ok": False, "skipped": False,
                "detail": f"TIMEOUT after {CELL_TIMEOUT_S}s: cell killed "
                          f"(worker and children)"}

    rc = proc.returncode

    class _R:
        pass
    proc = _R()
    proc.stdout, proc.stderr = out or "", err_txt or ""
    proc.returncode = rc
    last = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None
    if last:
        try:
            return json.loads(last)
        except json.JSONDecodeError:
            pass
    err = proc.stderr.strip().splitlines()
    return {"ok": False, "skipped": False,
            "detail": (err[-1][:110] if err else
                       f"exit {proc.returncode} (fatal abort: stack or verifier)")}


# --- HEAD TO HEAD: the two P1 variants, on their own scale ---
DUEL_PANELS = [
    ("nodes", "insns", "network nodes", "eBPF instructions",
     "the dependence on the network size disappears"),
    ("nodes", "jited", "network nodes", "native code (bytes)",
     "and in the generated code the gap is even wider"),
    ("width", "lat_ns", "neurons per hidden layer", "latency (ns/packet)",
     "speed, instead, barely moves"),
    ("sparsity", "insns", "fraction of zero weights", "eBPF instructions",
     "and with sparse weights the advantage vanishes"),
]


def plot_duel(in_dir, fmt):
    """One figure, four panels."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(2, 2, figsize=(9.6, 6.4))
    drawn = 0
    for ax, (axis, metric, xlab, ylab, note) in zip(axes.ravel(), DUEL_PANELS):
        path = os.path.join(in_dir, f"scaling_{axis}.csv")
        if not os.path.exists(path):
            ax.set_visible(False)
            continue
        with open(path, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        for pipe in ("p1_static", "hardcoded"):
            pts = sorted((float(r["x"]), float(r[metric]))
                         for r in rows
                         if r["pipeline"] == pipe and r.get(metric))
            if not pts:
                continue
            xs, ys = zip(*pts)
            ax.plot(xs, ys, linewidth=1.8, markersize=6, **STYLE[pipe])
            drawn += 1
        ax.set_xlabel(xlab, fontsize=9)
        ax.set_ylabel(ylab, fontsize=9)
        ax.set_title(note, fontsize=9, loc="left", color="#444444")
        ax.tick_params(labelsize=8)
        ax.grid(True, linewidth=0.4, alpha=0.4)
        ax.set_ylim(bottom=0)
    if not drawn:
        plt.close(fig)
        print(f"  {GREY}nothing to draw: the CSVs are missing{NC}")
        return 0
    axes.ravel()[0].legend(frameon=False, fontsize=9)
    fig.tight_layout()
    out = os.path.join(in_dir, "duel_p1_vs_p15." + fmt)
    fig.savefig(out, dpi=160)
    plt.close(fig)
    print(f"  {GREEN}written{NC} {out}")
    print(f"           {GREY}static P1 against P1.5, on their own scale{NC}")
    return 1


# --- SWEEP ---
def _warn_contaminated(rows, factor=2.0):
    """Say so when a latency cannot be a property of the x axis."""
    for pipe in PIPELINES:
        groups = {}
        for r in rows:
            if not r.get("lat_ns"):
                continue
            if r["pipeline"] == pipe:
                key = (r["insns"], r.get("tail"))
                groups.setdefault(key, []).append((r["x"], r["lat_ns"]))
        for (insns, tail), pts in groups.items():
            if len(pts) < 2:
                continue
            lats = [p[1] for p in pts]
            lo, hi = min(lats), max(lats)
            if lo > 0 and hi / lo > factor:
                worst = max(pts, key=lambda p: p[1])
                print(f"\n  {RED}SUSPECT{NC} {pipe}: identical program "
                      f"({insns} instructions, {tail} tail calls) at every x, "
                      f"but the latency goes from {lo:.0f} to {hi:.0f} ns "
                      f"({hi / lo:.1f}x).")
                print(f"  {GREY}The binary does not change along this axis, "
                      f"so the spread is the machine, not the variable. "
                      f"The worst point is x={worst[0]}. Measure again on an "
                      f"idle machine before putting it in a chart.{NC}")


def _give_back(path):
    """Hand a file or directory created under sudo back to the invoking user."""
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid or os.name != "posix":
        return
    try:
        os.chown(path, int(uid), int(gid or uid))
    except OSError:
        pass


# --- EQUIVALENCE: the specialised P1 must DECIDE the same thing as P1.5 ---
def _build_p1(cell, static_node):
    """Build and load one P1 variant (the AOT object);"""
    import p1_aot
    from check_pipelines import _install_mac_table

    dims = cell["dims"]
    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"], seed=cell.get("seed", 42))
    setup = p1_aot.load_p1(
        [(0, weights, SCALE)], features=shape["features"],
        n_out=n_out, hidden_dims=tuple(dims), static_node=static_node,
        static_ports=(cell.get("static_ports")
                      if static_node is not None else None))
    b = setup["b"]
    _install_mac_table(b, "mac_table")
    return b, setup["disp"].fd, shape


def _decide(b, disp_fd, n_in, n_out, ttl, links):
    """Run ONE packet and report which class fired."""
    from check_pipelines import (prog_test_run, build_frame_sparse,
                                 _read_u64)
    from common import write_vector_map
    from stats_maps import zero_counter
    for c in range(len(b["cls_stats"])):
        zero_counter(b["cls_stats"], c)
    for k in range(len(b["pkt_stats"])):
        zero_counter(b["pkt_stats"], k)
    write_vector_map(b, "link_state", list(links))
    frame = build_frame_sparse(model_id=0, ttl=ttl, scale=SCALE,
                               n_in=n_in, n_out=n_out)
    retval, _ = prog_test_run(disp_fd, frame, repeat=1)
    fired = -1
    for c in range(len(b["cls_stats"])):
        if _read_u64(b["cls_stats"], c) > 0:
            fired = c
            break
    return retval, fired


def verify_static(node=None):
    """P1 with the node index FROZEN must decide exactly what P1.5 decides with
    that same index installed in the node_id map."""
    node = STATIC_NODE if node is None else node
    cell = cell_of("nodes", 52)
    n_if = N_INTERFACES

    b_s, fd_s, shape = _build_p1(cell, static_node=node)
    b_d, fd_d, _ = _build_p1(cell, static_node=None)
    b_d["node_id"][ct.c_uint(0)] = ct.c_uint(node)

    n_in, n_out = shape["n_in"], shape["n_out"]
    print(f"{YELLOW}{'=' * 70}{NC}")
    print(f"{YELLOW} static P1 (node {node} frozen) against P1.5 "
          f"(node from the map){NC}")
    print(f"{YELLOW}{'=' * 70}{NC}\n")

    cases = []
    for ttl in range(2, 12):
        for pattern in (0, 1, 2, 3, 5, 7, 0b101010, 0b111111):
            links = [(pattern >> i) & 1 for i in range(n_if)]
            cases.append((ttl, tuple(links)))

    bad = 0
    for ttl, links in cases:
        rv_s, cl_s = _decide(b_s, fd_s, n_in, n_out, ttl, links)
        rv_d, cl_d = _decide(b_d, fd_d, n_in, n_out, ttl, links)
        if (rv_s, cl_s) != (rv_d, cl_d):
            bad += 1
            if bad <= 6:
                ls = "".join(map(str, links))
                print(f"  {RED}DIVERGES{NC} ttl={ttl:2d} link={ls}: "
                      f"frozen retval={rv_s} class={cl_s}, "
                      f"P1.5 retval={rv_d} class={cl_d}")

    n = len(cases)
    if bad:
        print(f"\n  {RED}{bad}/{n} cases diverge{NC} -- the frozen weight "
              f"column is NOT the one of node {node}.")
        print(f"  {GREY}Until this passes, every number in the p1_static "
              f"column measures a different model.{NC}")
        return 1
    print(f"  {GREEN}{n}/{n} identical cases{NC} (ttl 2-11 x 8 link patterns).")
    print(f"  {GREY}Freezing the node changes the code, not the decision.{NC}")
    return 0


def verify_ports(ports=None, node=None):
    """The P1 that does NOT generate the columns of the absent ports must
    decide exactly like the same P1 that generates them, as long as those
    slots are 0."""
    node = STATIC_NODE if node is None else node
    n_if = N_INTERFACES
    ports = {0, 1, 4} if ports is None else set(ports)
    assenti = sorted(set(range(n_if)) - ports)

    cell = dict(cell_of("nodes", 52), static_ports=sorted(ports))
    b_s, fd_s, shape = _build_p1(cell, static_node=node)
    b_f, fd_f, _ = _build_p1(dict(cell, static_ports=None), static_node=node)

    n_in, n_out = shape["n_in"], shape["n_out"]
    print(f"{YELLOW}{'=' * 70}{NC}")
    print(f"{YELLOW} P1 with only ports {sorted(ports)} generated, against "
          f"full-width P1{NC}")
    print(f"{GREY} slots without an interface on this node: {assenti} "
          f"-- structurally 0, not links down{NC}")
    print(f"{YELLOW}{'=' * 70}{NC}\n")

    def mask(v):
        """The reference sees 0 where the node has no interface."""
        return tuple(0 if i in assenti else x for i, x in enumerate(v))

    casi = sorted({(ttl, mask([(p >> i) & 1 for i in range(n_if)]))
                   for ttl in range(2, 12) for p in range(1 << n_if)})

    bad = 0
    for ttl, links in casi:
        r_s = _decide(b_s, fd_s, n_in, n_out, ttl, links)
        r_f = _decide(b_f, fd_f, n_in, n_out, ttl, links)
        if r_s != r_f:
            bad += 1
            if bad <= 6:
                ls = "".join(map(str, links))
                print(f"  {RED}DIVERGES{NC} ttl={ttl:2d} link={ls}: "
                      f"specialised retval={r_s[0]} class={r_s[1]}, "
                      f"full retval={r_f[0]} class={r_f[1]}")

    n = len(casi)
    if bad:
        print(f"\n  {RED}{bad}/{n} cases diverge{NC} -- the removed columns "
              f"were NOT zero.")
        print(f"  {GREY}Until this passes, every number in the p1_static "
              f"column on the degree axis measures a different model.{NC}")
        return 1
    print(f"  {GREEN}{n}/{n} identical cases{NC} (ttl 2-11 x "
          f"{1 << len(ports)} realisable patterns).")

    if not assenti:
        print(f"  {GREY}No absent slot: negative check not "
              f"applicable.{NC}")
        return 0

    def morde(seed):
        """On these weights, does turning on an absent slot change the decision?"""
        c = dict(cell, seed=seed)
        bs, fs, sh = _build_p1(c, static_node=node)
        bf, ff, _ = _build_p1(dict(c, static_ports=None), static_node=node)
        ni, no = sh["n_in"], sh["n_out"]
        n = 0
        for ttl in range(2, 12):
            for i in assenti:
                links = tuple(1 if k == i else 0 for k in range(n_if))
                if _decide(bs, fs, ni, no, ttl, links) != \
                   _decide(bf, ff, ni, no, ttl, links):
                    n += 1
        return n

    semi = [42, 1, 2, 3, 7, 123, 999]
    for seed in semi:
        visto = morde(seed)
        if visto:
            extra = "" if seed == 42 else f" (pool seed {seed})"
            print(f"  {GREEN}negative check{NC}: turning on an absent slot "
                  f"the two diverge in {visto} cases{extra} -- the "
                  f"condition \"absent slots at 0\" is load-bearing, not "
                  f"decorative.")
            print(f"  {GREY}Removing the columns changes the code, not the "
                  f"decision.{NC}")
            return 0

    print(f"\n  {RED}negative check SILENT on {len(semi)} weight sets{NC}: "
          f"not even turning on an absent slot do the two builds ever diverge.")
    print(f"  {GREY}The {n}/{n} above is therefore compatible with a wrong "
          f"specialisation too, and must not be cited as evidence until "
          f"this bites. Try a descriptor with fewer columns (where "
          f"link_state weighs more on the accumulator) or a narrower "
          f"model.{NC}")
    return 1


def _write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    _give_back(path)
    print(f"\n  {GREEN}written{NC} {path}  ({len(rows)} rows)")


def run_axis(axis, repeat, trials, out_dir, write=True, lookups=False,
             seeds=None):
    """One axis. Returns the rows; `write=False` leaves them to the caller,
    which is how the four campaign axes end up in one CSV."""
    spec = AXES[axis]
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} x axis: {spec['xlabel']}{NC}")
    print(f"{GREY} {spec['note']}{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}\n")

    rows = []
    hdr = (f"  {'x':>5s} {'pipeline':11s} {'shape':>16s} {'weights':>7s} "
           f"{'insns':>7s} {'ns':>7s} {'update ms':>10s} {'build ms':>9s} "
           f"{'maps B':>8s} {'tail':>4s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))

    pipelines = (("baseline",) + PIPELINES) if spec.get("campaign") else PIPELINES
    falliti = []

    for v, seed in [(v, s) for v in spec["values"] for s in (seeds or [None])]:
        cell = cell_of(axis, v)
        cell["lookups"] = lookups
        if seed is not None:
            cell["seed"] = seed
        tag = f" seed {seed}" if seed is not None else ""
        dims = cell["dims"]
        shape = shape_of(cell)
        n_in = shape["n_in"]
        shape_str = f"{n_in}-{'-'.join(map(str, dims))}-{N_OUT}"
        forma = dict(n_out=N_OUT, depth=len(dims),
                     width=(max(dims) if dims else 0),
                     macs=mac_count(n_in, dims, N_OUT),
                     macs_eff=mac_count_eff(shape, dims, N_OUT))
        for pipe in pipelines:
            oltre = ceiling_refusal(pipe, shape, dims)
            if oltre:
                r = {"ok": False, "refused": True,
                     "detail": f"compiled ceiling: {oltre}"}
            else:
                t_cella = time.time()
                print(f"  {GREY}[{time.strftime('%H:%M:%S')}] {axis} x={v} "
                      f"{pipe}{tag} ...{NC}", flush=True)
                r = bench_cell(pipe, cell, repeat, trials)
                r = dict(r, _secs=round(time.time() - t_cella, 1))
                if not r.get("ok"):
                    print(f"  {GREY}    ... {r.get('detail', 'fallita')} "
                          f"({r['_secs']} s){NC}", flush=True)
            if r.get("ok"):
                if pipe == "baseline":
                    r = dict(r)
                    forma_riga = dict(forma, macs=0, macs_eff=0)
                else:
                    forma_riga = forma
                print(f"  {str(v):>5s} {pipe:11s} {shape_str:>16s} {r['nw']:6d} "
                      f"{r['insns']:7d} {r['lat_ns']:7.1f} "
                      f"{r['update_ms']:10.2f} {r['build_ms']:9.1f} "
                      f"{r['map_bytes']:8d} {r['tail']:4d}{tag}")
                col_seme = {"seed": seed} if seed is not None else {}
                rows.append(dict(axis=axis, x=v, pipeline=pipe, **col_seme,
                                 shape=shape_str, **forma_riga, **{
                                     k: r[k] for k in
                                     ("nw", "n_in", "insns", "jited",
                                      "map_bytes", "n_maps", "tail",
                                      "build_ms", "update_ms",
                                      "lat_ns", "lat_p50", "lat_max",
                                      "mpps",
                                      "sparsity_real", "lookups")}))
            else:
                if r.get("skipped"):
                    mark = f"{GREY}n/a{NC}"
                elif r.get("refused"):
                    mark = f"{YELLOW}REFUSED{NC}"
                else:
                    mark = f"{RED}CRASH{NC}"
                print(f"  {str(v):>5s} {pipe:11s} {shape_str:>16s} {'':6s} "
                      f"{mark}{tag} {GREY}{r.get('detail', '')[:90]}{NC}")
                if str(r.get("detail", "")).startswith("compiled ceiling"):
                    genere = "ceiling"
                elif r.get("refused"):
                    genere = "verifier"
                elif r.get("skipped"):
                    genere = "n/a"
                else:
                    genere = "crash"
                falliti.append((v, pipe, seed, genere))

    _warn_contaminated(rows)
    if seeds:
        _summary_seeds(axis, rows, falliti, seeds)

    if out_dir and write:
        os.makedirs(out_dir, exist_ok=True)
        _give_back(out_dir)
        nome = f"scaling_{axis}_seeds.csv" if seeds else f"scaling_{axis}.csv"
        if rows:
            _write_csv(os.path.join(out_dir, nome), rows)
        else:
            print(f"\n  {RED}no row to write for {axis}{NC}")
    return rows


def _summary_seeds(axis, rows, falliti, seeds):
    """For every (x, pipeline)."""
    import statistics
    print(f"\n{YELLOW} {axis}: {len(seeds)} seeds of the weight pool "
          f"({', '.join(map(str, seeds))}){NC}")
    hdr = (f"  {'x':>5s} {'pipeline':11s} {'loaded':>8s} "
           f"{'insns median':>13s} {'[min - max]':>15s} "
           f"{'ns median':>10s} {'[min - max]':>13s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    xs = []
    for r in rows:
        if r["x"] not in xs:
            xs.append(r["x"])
    for f in falliti:
        if f[0] not in xs:
            xs.append(f[0])
    pipes = []
    for r in rows:
        if r["pipeline"] not in pipes:
            pipes.append(r["pipeline"])
    for x in xs:
        for pipe in pipes:
            sel = [r for r in rows if r["x"] == x and r["pipeline"] == pipe]
            ko = [(f[2], f[3]) for f in falliti if f[0] == x and f[1] == pipe]
            if not sel and not ko:
                continue
            ins = [r["insns"] for r in sel]
            lat = [r["lat_ns"] for r in sel]
            if sel:
                ins_s = (f"{statistics.median(ins):13.0f} "
                         f"{'[' + str(min(ins)) + ' - ' + str(max(ins)) + ']':>15s}")
                lat_s = (f"{statistics.median(lat):10.1f} "
                         f"{'[' + f'{min(lat):.0f}' + ' - ' + f'{max(lat):.0f}' + ']':>13s}")
            else:
                ins_s = f"{'-':>13s} {'':>15s}"
                lat_s = f"{'-':>10s} {'':>13s}"
            nota = ""
            for genere in ("verifier", "crash", "ceiling", "n/a"):
                semi = [str(k[0]) for k in ko if k[1] == genere]
                if semi:
                    nota += f"  {RED}{genere}: seed {', '.join(semi)}{NC}"
            print(f"  {str(x):>5s} {pipe:11s} {f'{len(sel)}/{len(sel) + len(ko)}':>8s} "
                  f"{ins_s} {lat_s}{nota}")


# --- PLOTS -- read the CSV, never re-measure. No root, no BCC. ---
PLOTS = [
    ("insns", "program instructions", "scaling_{axis}_insns", False),
    ("insns", "program instructions (log scale)", "scaling_{axis}_insns_log", True),
    ("lat_ns", "latency (ns/packet, minimum)", "scaling_{axis}_latency", False),
    ("lat_ns", "latency (ns/packet, log scale)", "scaling_{axis}_latency_log", True),
    ("mpps", "theoretical packets per second (1 / latency)", "scaling_{axis}_mpps", False),
    ("update_ms", "installing a new model (ms)", "scaling_{axis}_update", True),
    ("build_ms", "compiling the program, once (ms)", "scaling_{axis}_build", False),
    ("map_bytes", "table memory (bytes)", "scaling_{axis}_maps", False),
]

KEEP = {
    ("depth", "insns"):
        "P3 has the same size at every depth: it reuses layer_hidden; "
        "P2 grows by ~870 instructions per layer",
    ("depth", "lat_ns"):
        "and P3 pays it in time, ~53 ns per layer (P2 ~25): tail call and reads",
    ("depth", "update_ms"):
        "installing a model: P1 loads an AOT object, P2 and P3 "
        "write maps",
    ("nodes", "insns"):
        "the network size enters the program only in P1.5; freezing the "
        "node (static P1) the dependence DISAPPEARS",
    ("nodes", "insns_log"):
        "the same, readable: P1.5 rises 2.3x between 10 and 100 nodes, the "
        "static one stays flat",
    ("nodes", "lat_ns"):
        "but at runtime it costs nobody: the one-hot reads ONE column, and "
        "the switch runs ONE case",
    ("width", "lat_ns"):
        "widening the HIDDEN layers is paid instead, by all four",
    ("sparsity", "insns_log"):
        "with sparse weights P1 collapses and the two P1s CONVERGE: sparsity "
        "and frozen node are two roads to the same reduction, they do not add up",
    ("isoparam", "insns"):
        "with the SAME parameters (~592 weights): how much spreading them over "
        "more layers instead of one wide one costs in size",
    ("isoparam", "lat_ns"):
        "and how much it costs in time -- this answers 'wide or deep'",
    ("isoparam", "mpps"):
        "the same in theoretical throughput, the unit the question is asked in",
    ("descriptor", "insns"):
        "the control: without the 'node' feature the two P1s are IDENTICAL, "
        "with it they diverge -- the whole gap is there and nowhere else",
}

STYLE = {
    "baseline":  dict(color="#7f8c8d", marker="x", label="baseline (0 MAC)"),
    "p1_static": dict(color="#8e44ad", marker="D", label="P1 specializzata"),
    "hardcoded": dict(color="#c0392b", marker="o", label="P1.5 hardcoded"),
    "template": dict(color="#2980b9", marker="s", label="P2 template"),
    "modular": dict(color="#27ae60", marker="^", label="P3 modular"),
}


CAMPAIGN_MARKERS = {
    "iv_dense":   ("o", "dense IV"),
    "iv_onehot":  ("s", "one-hot IV"),
    "width_camp": ("D", "width"),
    "depth_camp": ("^", "depth"),
}


def _fit(xs, ys):
    """Least squares by hand."""
    n = len(xs)
    if n < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None
    m = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    q = my - m * mx
    sst = sum((y - my) ** 2 for y in ys)
    ssr = sum((y - (m * x + q)) ** 2 for x, y in zip(xs, ys))
    return m, q, (1.0 - ssr / sst) if sst else 1.0


def plot_campaign(in_dir, fmt):
    """MACs against latency, the four campaign axes overlaid."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    path = os.path.join(in_dir, CAMPAIGN_CSV)
    if not os.path.exists(path):
        print(f"  {GREY}skipping the campaign: {path} does not exist{NC}")
        return 0
    with open(path, encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r.get("lat_ns")]
    if not rows:
        print(f"  {GREY}skipping the campaign: empty CSV{NC}")
        return 0
    if "macs_eff" not in rows[0]:
        print(f"  {GREY}skipping the campaign: column macs_eff missing "
              f"(measure again to get it){NC}")
        return 0

    made = 0
    for col, nome, unita, stem in (
            ("macs_eff", "MACs executed per packet", "ns/MAC",
             "campaign_macs_eff_latency"),
            ("macs", "nominal MACs per packet (n_in x h1 + ...)", "ns/MAC",
             "campaign_macs_nominal_latency"),
            ("insns", "program instructions", "ns/instruction",
             "campaign_insns_latency")):
        fig, ax = plt.subplots(figsize=(6.4, 4.0))
        print(f"\n  {YELLOW}{nome}{NC}")
        for pipe in PIPELINES:
            px, py = [], []
            for r in rows:
                if r["pipeline"] != pipe:
                    continue
                mk = CAMPAIGN_MARKERS.get(r["axis"], ("o", r["axis"]))[0]
                x, y = float(r[col]), float(r["lat_ns"])
                px.append(x)
                py.append(y)
                ax.plot([x], [y], marker=mk, markersize=6, linestyle="none",
                        color=STYLE[pipe]["color"], alpha=0.9)
            f = _fit(px, py)
            if not f:
                if px:
                    ax.plot([], [], marker=STYLE[pipe]["marker"],
                            linestyle="none", color=STYLE[pipe]["color"],
                            label=f"{STYLE[pipe]['label']}: constant x "
                                  f"({px[0]:.0f}), no slope")
                    print(f"    {STYLE[pipe]['label']:22s} constant x at "
                          f"{px[0]:.0f}: {GREY}latency varies "
                          f"{min(py):.0f}-{max(py):.0f} ns at the same x{NC}")
                continue
            m, q, r2 = f
            xs = [min(px), max(px)]
            ax.plot(xs, [m * x + q for x in xs], linewidth=1.4,
                    color=STYLE[pipe]["color"],
                    label=f"{STYLE[pipe]['label']}: {m:.3f} {unita}  "
                          f"(r2 {r2:.2f})")
            fuori = []
            for axe in CAMPAIGN_MARKERS:
                res = [abs(float(r["lat_ns"]) - (m * float(r[col]) + q))
                       for r in rows
                       if r["pipeline"] == pipe and r["axis"] == axe
                       and r.get("lat_ns")]
                if res:
                    fuori.append((sum(res) / len(res), axe))
            fuori.sort(reverse=True)
            detta = "  ".join(f"{a} {v:.0f}ns" for v, a in fuori)
            print(f"    {STYLE[pipe]['label']:22s} {m:.3f} {unita}  "
                  f"r2 {r2:.2f}   {GREY}mean residual: {detta}{NC}")

        base = [float(r["lat_ns"]) for r in rows if r["pipeline"] == "baseline"]
        if base:
            lo, hi = min(base), max(base)
            ax.axhspan(lo, hi, color=STYLE["baseline"]["color"], alpha=0.18)
            ax.axhline(sum(base) / len(base), linewidth=1.0, linestyle=":",
                       color=STYLE["baseline"]["color"])
            print(f"    {'baseline (0 MAC)':22s} floor {lo:.0f}-{hi:.0f} ns "
                  f"{GREY}(XDP framework, no inference){NC}")

        ax.set_xlabel(nome)
        ax.set_ylabel("latency (ns/packet, minimum)")
        ax.grid(True, linewidth=0.4, alpha=0.4)
        ax.set_ylim(bottom=0)
        prima = ax.legend(frameon=False, fontsize=7.5, loc="upper left")
        ax.add_artist(prima)
        ax.legend(handles=[Line2D([], [], marker=mk, linestyle="none",
                                  color="#555555", markersize=6, label=lab)
                           for mk, lab in CAMPAIGN_MARKERS.values()],
                  fontsize=7.5, loc="lower right", title="axis",
                  title_fontsize=7.5,
                  frameon=True, framealpha=0.95, edgecolor="none",
                  facecolor="white")
        fig.tight_layout()
        out = os.path.join(in_dir, stem + "." + fmt)
        fig.savefig(out, dpi=160)
        plt.close(fig)
        print(f"  {GREEN}written{NC} {out}")
        made += 1
    return made


def plot_axis(axis, in_dir, fmt, draw_all=False):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    path = os.path.join(in_dir, f"scaling_{axis}.csv")
    if not os.path.exists(path):
        print(f"  {GREY}skipping {axis}: {path} does not exist{NC}")
        return 0
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print(f"  {GREY}skipping {axis}: empty CSV{NC}")
        return 0

    cat = AXES[axis]["kind"] == "cat"
    order = [str(v) for v in AXES[axis]["values"]]

    made = 0
    for metric, ylabel, stem, logy in PLOTS:
        fig_key = metric + ("_log" if logy and stem.endswith("_log") else "")
        if not draw_all and (axis, fig_key) not in KEEP:
            continue
        fig, ax = plt.subplots(figsize=(6.2 if cat else 5.6, 3.6))
        drawn = False
        if metric not in rows[0]:
            print(f"  {GREY}skipping {metric} for {axis}: column missing in the CSV "
                  f"(measure again to get it){NC}")
            plt.close(fig)
            continue
        for slot, pipe in enumerate(PIPELINES):
            vals = {r["x"]: r[metric] for r in rows
                    if r["pipeline"] == pipe and r.get(metric)}
            if not vals:
                continue
            if cat:
                idx = [i for i, k in enumerate(order) if k in vals]
                ys = [float(vals[order[i]]) for i in idx]
                w = 0.26
                ax.bar([i + (slot - 1) * w for i in idx], ys, width=w,
                       color=STYLE[pipe]["color"], label=STYLE[pipe]["label"])
            else:
                pts = sorted((float(k), float(v)) for k, v in vals.items())
                xs, ys = zip(*pts)
                ax.plot(xs, ys, linestyle="-" if len(xs) > 1 else "none",
                        linewidth=1.6, markersize=6, **STYLE[pipe])
            drawn = True
        if not drawn:
            plt.close(fig)
            continue
        if cat:
            ax.set_xticks(range(len(order)))
            ax.set_xticklabels(order, fontsize=8)
        else:
            vals = [float(v) for v in AXES[axis]["values"]]
            if all(v == int(v) for v in vals):
                ax.set_xticks([int(v) for v in vals])
        ax.set_xlabel(AXES[axis]["xlabel"])
        ax.set_ylabel(ylabel)
        ax.grid(True, linewidth=0.4, alpha=0.4)
        ax.legend(frameon=False, fontsize=8)
        if logy:
            ax.set_yscale("log")
        else:
            ax.set_ylim(bottom=0)
        fig.tight_layout()
        out = os.path.join(in_dir, stem.format(axis=axis) + "." + fmt)
        fig.savefig(out, dpi=160)
        plt.close(fig)
        why = KEEP.get((axis, fig_key))
        print(f"  {GREEN}written{NC} {out}")
        if why:
            print(f"           {GREY}{why}{NC}")
        made += 1
    return made


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(
        description=__doc__.split("USAGE")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--axis", choices=list(AXES) + ["all", "campaign"],
                   default="all",
                   help="`all` = the seven main axes; `campaign` = the "
                        "campaign architectures, all in "
                        + CAMPAIGN_CSV)
    p.add_argument("--repeat", type=int, default=100000,
                   help="target repetitions per measurement; split into "
                        "chunks of 200 with a new frame each, and "
                        "limited to TEST_RUN_MAX_CHUNKS chunks")
    p.add_argument("--trials", type=int, default=7,
                   help="independent measurements per cell; the minimum is kept")
    p.add_argument("--lookups", action="store_true",
                   help="also measure the map lookups per packet. "
                        "Off by default: it is a SECOND compilation per "
                        "cell (on P1 ~1.5 s more of clang each), and the "
                        "instrumented build is not the timed one")
    p.add_argument("--out", default=os.path.join(SHARED_DIR, "..", "results"),
                   help="where to write the CSVs")
    p.add_argument("--plot", metavar="DIR", default=None,
                   help="do not measure: draw the charts from the CSVs in DIR")
    p.add_argument("--format", default="pdf", choices=["pdf", "png"])
    p.add_argument("--verify", action="store_true",
                   help="do not measure: check that the static P1 decides "
                        "like P1.5 with the same node installed")
    p.add_argument("--verify-ports", action="store_true", dest="verify_ports",
                   help="do not measure: check that the P1 that does not "
                        "generate the absent ports decides like the full-width one")
    p.add_argument("--ports", default=None,
                   help="ports present for --verify-ports, e.g. '0,1,4' "
                        "(default 0,1,4)")
    p.add_argument("--seeds", default=None, metavar="S1,S2,...",
                   help="repeat the axis for every seed of the weight pool, "
                        "e.g. '42,1,2,3,7', and write scaling_<axis>_seeds.csv "
                        "with median and range per point. For the dependence "
                        "of P1/P1.5 on the weight values; P2/P3 act as "
                        "control. Only with --axis <one main axis>")
    p.add_argument("--all-plots", action="store_true",
                   help="draw every metric x axis combination, not only "
                        "the ones that carry a result")
    p.add_argument("--_worker", nargs=2, help=argparse.SUPPRESS)
    a = p.parse_args()

    if a._worker:
        return _worker(a._worker[0], a._worker[1])

    if a.plot:
        import importlib.util
        if importlib.util.find_spec("matplotlib") is None:
            sys.exit("matplotlib needed for the charts: pip install matplotlib")
        n = sum(plot_axis(ax, a.plot, a.format, a.all_plots)
                for ax in LEGACY_AXES)
        n += plot_duel(a.plot, a.format)
        n += plot_campaign(a.plot, a.format)
        print(f"\n{GREEN}{n} charts{NC} in {a.plot}")
        return 0

    if sys.platform != "linux":
        sys.exit(f"the measurement needs Linux, not {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("root needed: sudo python3 ipa/test/bench_scaling.py")

    if a.verify:
        os.chdir(SHARED_DIR)
        return verify_static()

    if a.verify_ports:
        os.chdir(SHARED_DIR)
        sel = ({int(x) for x in a.ports.split(",") if x.strip()}
               if a.ports else None)
        return verify_ports(sel)

    out_dir = os.path.abspath(a.out)
    os.chdir(SHARED_DIR)

    semi = None
    if a.seeds:
        semi = [int(x) for x in a.seeds.split(",") if x.strip()]
        if a.axis in ("all", "campaign") or AXES[a.axis].get("campaign"):
            sys.exit("--seeds applies to ONE main axis at a time, e.g. "
                     "--axis depth --seeds 42,1,2,3,7")
        righe = run_axis(a.axis, a.repeat, a.trials, out_dir,
                         lookups=a.lookups, seeds=semi)
        return 0 if righe else 1

    if a.axis == "all":
        axes = LEGACY_AXES
    elif a.axis == "campaign":
        axes = CAMPAIGN_AXES
    else:
        axes = [a.axis]

    campagna = []
    for ax in axes:
        e_campagna = bool(AXES[ax].get("campaign"))
        righe = run_axis(ax, a.repeat, a.trials, out_dir,
                         write=not e_campagna, lookups=a.lookups)
        if e_campagna:
            campagna += righe
    if campagna and out_dir:
        os.makedirs(out_dir, exist_ok=True)
        _give_back(out_dir)
        _write_csv(os.path.join(out_dir, CAMPAIGN_CSV), campagna)

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(" Charts (no root needed, just matplotlib):")
    print(f"   python3 ipa/test/bench_scaling.py --plot {out_dir}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
