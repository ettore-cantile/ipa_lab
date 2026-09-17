#!/usr/bin/env python3
"""
bench_scaling.py -- parametric scaling analysis across ALL THREE pipelines.

The question: how does the cost of the datapath change as the network, or the
model, gets bigger? And -- the part that matters for the design-space argument
-- do the three pipelines have DIFFERENT slopes?

They do, and the slopes are the whole point of having three of them:

                        P1 hardcoded     P2 template      P3 modular
  more NODES            grows            flat             flat
  more LAYERS           grows            needs a rebuild  flat
  more NEURONS/layer    grows            grows            grows
  sparser WEIGHTS       shrinks          flat             flat
  changing the model    ~1.2 s of clang  a map write      a map write

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
         Depth is the one dimension P2 does NOT cover at runtime: its widths
         come from a map, its depth is compiled in. build_arch_leaf(n) emits
         the extra blocks, so P2 reaches any depth -- by rebuilding. On this
         axis P2 therefore recompiles at every point and P3 does not, and
         that difference, not a missing point, is the result.

  width  2, 4, 6, 8 neurons per hidden layer, two hidden layers, n_nodes 52
         8 is the compiled ceiling in P2 (T2_MAX_H1/H2) and P3 (ML1_MAX_H1,
         MLH_MAX_H). P1 has no ceiling but is swept over the same values so
         the three curves are comparable.

  descriptor  the four input-vector compositions of bench_depth_vs_width:
         0, 1 or 2 one-hot features, and a small (6) vs large (52) one. Same
         model otherwise. Categorical, so it is drawn as bars.

  sparsity  0, 25, 50, 75, 90 percent of the weights exactly zero, same shape
         throughout. P1 compiles weights in as literals, so clang deletes a
         multiply by zero: its instruction count should FALL. P2 and P3 read
         the same bytes from a map and should not move at all. This is where
         'the weights are in the code' stops being a description and becomes
         a number.

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
  update_ms  cost of INSTALLING A NEW MODEL on a node already running. This
             is the metric where the three pipelines differ in KIND rather
             than degree, and the two must not be confused:
               P1  the weights are C literals, so a new model means
                   generating C and running clang -- order 1.5 s.
               P2  arch_registry + model_desc + a slice of arch_weights.
               P3  layer_registry + layer_shapes + model_desc + weights.
             For P2 and P3 no compiler runs, so this is map writes only.
  build_ms   cost of compiling and loading the eBPF program ONCE. For P2 and
             P3 this is paid when the node starts and never again, because
             the source never mentions the model's shape. For P1 it is the
             same event as update_ms, by construction -- the program IS the
             model. Plotting build_ms as if it were the cost of changing a
             model would make P2 and P3 look MORE expensive than P1, which
             is backwards: their ~2.5 s compile happens once, P1's ~1.5 s
             happens on every model.
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
SCALE = 128
PIPELINES = ("hardcoded", "template", "modular")

# Input-vector compositions. Imported rather than copied: bench_depth_vs_width
# already curates this set to separate onehot COUNT from onehot SIZE, and two
# copies would drift.
from bench_depth_vs_width import FEATURE_SETS      # noqa: E402
DEFAULT_DESCRIPTOR = "default"


_POOL_SIZE = 8192


def make_weights(nw, sparsity, seed=42):
    """The first `nw` weights of a fixed pool with a `sparsity` fraction of
    zeros.

    Why the weights matter at all: P1 writes them into the C source as
    literals, so clang deletes a multiply by zero outright and turns a multiply
    by a power of two into a shift. P1's instruction count therefore depends on
    the VALUES, not only on the shape. P2 and P3 read the same weights from a
    map, where a zero is a byte like any other. The sparsity axis turns that
    difference from an argument into a measurement.

    Why a POOL, rather than a fresh vector per shape: exactly because of the
    above. Drawing an independent vector for each `nw` meant that moving along
    an axis changed two things at once -- the model's shape AND every one of
    its weights -- so part of P1's curve was weight noise wearing the x axis's
    name. Taking a prefix of one pool makes a bigger model an EXTENSION of the
    smaller one: the weights they share are identical, and only the new ones
    are new.

    How much this matters is not hypothetical. On the depth axis, the shape
    (4,4,4,4) with seed 42 is REFUSED by the verifier while seeds 1, 2, 3, 7,
    123 and 999 all load, at 1 075 to 1 175 instructions -- the same program
    size, the same architecture, different values. That is a real property of
    compiling weights in, and it is why this function is written the way it is.

    A prefix holds roughly, not exactly, the requested zero fraction: the pool
    is shuffled, so any prefix is a random sample of it. The exact count per
    cell is not the point; holding the weights still while the axis moves
    is."""
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

# One axis = one variable. `cell(v)` returns everything a worker needs, so a
# new axis is a new entry here and nothing else. `kind` is "num" for an axis
# whose x is a number (plotted as a curve) or "cat" for one whose values are
# names (plotted as bars -- a line between two descriptors would imply a
# gradient that does not exist).
AXES = {
    "nodes": {
        "xlabel": "nodi della rete (larghezza della one-hot `node`)",
        "kind": "num",
        "values": [10, 25, 52, 75, 100],
        "cell": lambda v: dict(n_nodes=v, dims=(4, 4)),
        "note": "n_in = 13 + n_nodes; il modello resta 4-4, cambia solo l'ingresso",
    },
    "depth": {
        "xlabel": "numero di hidden layer",
        "kind": "num",
        "values": [1, 2, 3, 4, 5, 6],
        "cell": lambda v: dict(n_nodes=52, dims=tuple([4] * v)),
        "note": "P2 copre la profondita' RICOMPILANDO (build_arch_leaf), P3 no: "
                "la ricompilazione E' il confronto",
    },
    "width": {
        "xlabel": "neuroni per hidden layer",
        "kind": "num",
        "values": [2, 4, 6, 8],
        "cell": lambda v: dict(n_nodes=52, dims=(v, v)),
        "note": "8 e' il soffitto compilato di P2 (T2_MAX_H1/H2) e P3 (ML1_MAX_H1)",
    },
    "descriptor": {
        "xlabel": "composizione del vettore d'ingresso",
        "kind": "cat",
        "values": list(FEATURE_SETS),
        "cell": lambda v: dict(n_nodes=52, dims=(4, 4), descriptor=v),
        "note": "stesso modello 4-4, IV diverse: 0/1/2 one-hot, piccola (6) o grande (52)",
    },
    "sparsity": {
        "xlabel": "frazione di pesi esattamente zero",
        "kind": "num",
        "values": [0.0, 0.25, 0.5, 0.75, 0.9],
        "cell": lambda v: dict(n_nodes=52, dims=(4, 4), sparsity=v),
        "note": "stessa forma, pesi diversi: P1 li compila come letterali, P2/P3 li leggono da mappa",
    },
}


def cell_of(axis, v):
    """Fill an axis cell out with the defaults the worker expects."""
    c = dict(n_nodes=52, dims=(4, 4), descriptor=DEFAULT_DESCRIPTOR, sparsity=0.0)
    c.update(AXES[axis]["cell"](v))
    return c


# n_queues is declared even though the default descriptor does not use a
# queue feature: the `no_onehot` set does, and a descriptor cannot resolve a
# dimension the topology does not state. Leaving it out made all three
# pipelines fail that column with
#   ScenarioError: feature 'queue_occupancy' needs topology dimension 'n_queues'
# which reads like a pipeline problem and is really a missing line here.
# 4 is under both compiled ceilings (IPA_MAX_QUEUES is 8 in P2 and in P3).
N_QUEUES = 4


def topology(n_nodes):
    return {"n_interfaces": N_INTERFACES, "n_nodes": n_nodes,
            "n_queues": N_QUEUES}


def build_shape(n_nodes, hidden_dims, descriptor=DEFAULT_DESCRIPTOR):
    """Resolve the feature descriptor for this topology. n_out is DECLARED,
    never derived from the interface count -- see class_semantics.py."""
    import model_meta as mm
    meta = {"features": FEATURE_SETS[descriptor], "n_out": N_OUT,
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


def _bench_p1(cell, repeat, trials):
    from bcc import BPF
    from ebpf_program import build_combined_hardcoded_source
    from verify_prog_run import build_frame_sparse, _seed_link_state

    dims = cell["dims"]
    shape = build_shape(cell["n_nodes"], dims, cell["descriptor"])
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"])
    sparsity_real = weights.count(0) / len(weights) if weights else 0.0

    def _load():
        # Codegen is INSIDE the timed region on purpose. For P1 the weights
        # are C literals, so installing a model is generating C and running
        # clang over it -- there is no separate "load the weights" step to
        # measure. build_ms and update_ms below are therefore the same number
        # for this pipeline, by construction, and that identity is exactly
        # what distinguishes it from P2 and P3.
        src = build_combined_hardcoded_source(
            models=[(0, weights, SCALE)],
            features=shape["features"], n_out=n_out, hidden_dims=tuple(dims))
        bb = BPF(text=src)
        m = bb.load_func("model_0", BPF.XDP)
        d = bb.load_func("ipa_switch_hardcoded", BPF.XDP)
        bb["model_progs"][ct.c_int(0)] = ct.c_int(m.fd)
        return bb, m, d

    (b, model_fn, disp_fn), build_ms = _timed(_load)
    update_ms = build_ms          # see _load: for P1 they are the same event
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(
        b, {"ipa_switch_hardcoded": disp_fn.fd, "model_0": model_fn.fd})
    frame = build_frame_sparse(model_id=0, ttl=42, scale=SCALE,
                               n_in=n_in, n_out=n_out)
    lo, med, hi, retval = _sample(disp_fn.fd, frame, repeat, trials)
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=1, nw=nw,
                n_in=n_in, build_ms=build_ms, update_ms=update_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, retval=retval, per_prog=per_prog, n_maps=len(maps),
                sparsity_real=sparsity_real)


def _bench_p2(cell, repeat, trials):
    # Checked BEFORE the imports on purpose: "P2 cannot do this depth" is a
    # property of P2, not of whether BCC happens to be installed. Behind the
    # imports, a machine without BCC would report this cell as a crash rather
    # than as the structural limit it is.
    dims = cell["dims"]
    if len(dims) < 1:
        raise NotImplementedError("P2 ha almeno un hidden layer")
    if len(set(dims[1:])) > 1:
        raise NotImplementedError(
            f"in P2 i layer oltre il secondo sono larghi n_h2; questa forma "
            f"chiede larghezze diverse: {dims[1:]}")
    n_hidden = len(dims)
    # With one hidden layer there is no fc2, and the datapath carries h1 into
    # h2 unchanged -- so n_h2 must be registered equal to n_h1. See
    # build_arch_leaf; load_arch_weights refuses any other value.
    n_h1 = dims[0]
    n_h2 = dims[1] if n_hidden >= 2 else dims[0]

    from bcc import BPF
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                    build_arch_leaf,
                                    load_arch_weights)
    from verify_prog_run import build_frame_sparse, _seed_link_state

    shape = build_shape(cell["n_nodes"], dims, cell["descriptor"])
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"])
    sparsity_real = weights.count(0) / len(weights) if weights else 0.0

    # The source does not mention the model's WIDTHS anywhere -- that is P2's
    # claim, and why its instruction count is flat on the nodes and width
    # axes. DEPTH is different: it is baked in at compile time, so the leaf
    # is built for this shape's depth. On the depth axis P2 therefore
    # RECOMPILES at every point while P3 does not, and that is exactly the
    # comparison being made.
    src = ("#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
           + "\n" + build_arch_leaf(n_hidden))

    def _load():
        bb = BPF(text=src)
        d = bb.load_func("ipa_switch_template", BPF.XDP)
        leaf = bb.load_func("arch_generic_2layer", BPF.XDP)
        bb["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
        return bb, d, leaf

    (b, disp_fn, leaf_fn), build_ms = _timed(_load)
    # Installing a model in P2 is writing maps -- arch_registry, model_desc
    # and a slice of arch_weights. No compiler runs. This is the number that
    # belongs next to P1's build_ms, not P2's own build_ms, which is a
    # ONE-TIME cost paid when the node starts and never again.
    _, update_ms = _timed(lambda: load_arch_weights(
        b, weights, model_id=0, scale=SCALE,
        n_h1=n_h1, n_h2=n_h2, n_hidden=n_hidden,
        features=shape["features"], n_in=n_in,
        semantics=shape.get("semantics")))
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(
        b, {"ipa_switch_template": disp_fn.fd,
            "arch_generic_2layer": leaf_fn.fd})
    frame = build_frame_sparse(model_id=0, ttl=42, scale=SCALE,
                               n_in=n_in, n_out=n_out)
    lo, med, hi, retval = _sample(disp_fn.fd, frame, repeat, trials)
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=1, nw=nw,
                n_in=n_in, build_ms=build_ms, update_ms=update_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, retval=retval, per_prog=per_prog, n_maps=len(maps),
                sparsity_real=sparsity_real)


def _bench_p3(cell, repeat, trials):
    from bcc import BPF
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    from verify_prog_run import build_frame_sparse, _seed_link_state

    dims = cell["dims"]
    shape = build_shape(cell["n_nodes"], dims, cell["descriptor"])
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"])
    sparsity_real = weights.count(0) / len(weights) if weights else 0.0

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
    # Same as P2: a model install is a set of map writes -- layer_registry,
    # layer_shapes, model_desc and a slice of layer_weights. No compiler.
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
    frame = build_frame_sparse(model_id=0, ttl=42, scale=SCALE,
                               n_in=n_in, n_out=n_out)
    lo, med, hi, retval = _sample(disp_fn.fd, frame, repeat, trials)
    # Tail calls actually executed: dispatcher -> layer_first -> layer_hidden
    # x (n_layers - 1). NOT the number of distinct programs, which is always 3.
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=len(layer_dims),
                nw=nw, n_in=n_in, build_ms=build_ms, update_ms=update_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, retval=retval, per_prog=per_prog, n_maps=len(maps),
                sparsity_real=sparsity_real)


_BENCH = {"hardcoded": _bench_p1, "template": _bench_p2, "modular": _bench_p3}


def _worker(pipeline, spec_json):
    """Runs in the subprocess. Prints exactly one JSON line; that is the
    parent's only contract with it.

    The cell arrives as JSON rather than as positional arguments: adding an
    axis then means adding a key, not editing an argv layout in three
    places."""
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
        # A verifier refusal is a RESULT, not a failure of this script, and it
        # must not be filed next to a crash. The kernel answers E2BIG both when
        # a program is genuinely too long AND when the verifier gives up having
        # processed more than a million instructions -- and BCC turns that into
        # "Argument list too long" plus a "at most 4096 insns" string whose
        # 4096 is a stale constant in BCC itself. A program of 1 120
        # instructions refused with that text hit the COMPLEXITY ceiling, not
        # the size one; see docs/testing.md on P3's budget for the same trap.
        refused = ("Argument list too long" in msg
                   or "too large" in msg
                   or "Permission denied" in msg)
        out = {"ok": False, "skipped": False, "refused": refused,
               "detail": msg}
    print(json.dumps(out))
    return 0


def bench_cell(pipeline, cell, repeat, trials):
    """One cell, isolated. A fatal LLVM abort or a verifier refusal kills only
    the child."""
    spec = dict(cell, dims=list(cell["dims"]), repeat=repeat, trials=trials)
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--_worker", pipeline,
         json.dumps(spec)],
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
def _warn_contaminated(rows, factor=2.0):
    """Say so when a latency cannot be a property of the x axis.

    P2 and P3 compile a source that does not mention the model, so along the
    nodes, width, descriptor and sparsity axes their program is byte-identical
    at every point -- same instruction count, same jited size. If the latency
    of an IDENTICAL program swings by more than `factor` across the axis, the
    swing is the machine, not the variable on the x axis: another process, CPU
    frequency, a noisy neighbour on the hypervisor.

    Taking the min of N trials protects against a spike inside a cell. It does
    nothing when the whole cell was measured during a busy period, which is
    what this catches. Without it the reader is invited to explain a 3x jump
    that has no cause in the model."""
    for pipe in PIPELINES:
        groups = {}
        for r in rows:
            if not r.get("lat_ns"):
                continue
            if r["pipeline"] == pipe:
                # Grouped by (instructions, TAIL CALLS), not by instructions
                # alone. P3's program is byte-identical at every depth -- that
                # is its whole design -- but it executes one more tail call per
                # layer, so its latency legitimately doubles across the depth
                # axis. Keyed on instructions only, this check called that real
                # result contamination, which is the worst thing a check can
                # do: cry wolf on the finding. Identical code AND identical
                # hops is what makes a latency swing impossible to attribute to
                # the x axis.
                key = (r["insns"], r.get("tail"))
                groups.setdefault(key, []).append((r["x"], r["lat_ns"]))
        for (insns, tail), pts in groups.items():
            if len(pts) < 2:
                continue
            lats = [p[1] for p in pts]
            lo, hi = min(lats), max(lats)
            if lo > 0 and hi / lo > factor:
                worst = max(pts, key=lambda p: p[1])
                print(f"\n  {RED}SOSPETTO{NC} {pipe}: programma identico "
                      f"({insns} istruzioni, {tail} tail call) a ogni x, "
                      f"ma la latenza va da {lo:.0f} a {hi:.0f} ns "
                      f"({hi / lo:.1f}x).")
                print(f"  {GREY}Il binario non cambia lungo questo asse, "
                      f"quindi lo scarto e' la macchina, non la variabile. "
                      f"Il punto peggiore e' x={worst[0]}. Rimisura a macchina "
                      f"scarica prima di metterlo in un grafico.{NC}")


def _give_back(path):
    """Hand a file or directory created under sudo back to the invoking user.

    The measuring run needs root; plotting does not, and the documented next
    step is to run --plot WITHOUT sudo. Without this, that second command dies
    with `PermissionError: 'results/scaling_nodes_insns.pdf'`, because root
    owns the directory the plots go into. Silently ignored when not running
    under sudo, or if the chown is refused."""
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid or os.name != "posix":
        return
    try:
        os.chown(path, int(uid), int(gid or uid))
    except OSError:
        pass


def run_axis(axis, repeat, trials, out_dir):
    spec = AXES[axis]
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} asse x: {spec['xlabel']}{NC}")
    print(f"{GREY} {spec['note']}{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}\n")

    rows = []
    hdr = (f"  {'x':>5s} {'pipeline':10s} {'forma':>16s} {'pesi':>6s} "
           f"{'insns':>7s} {'ns':>7s} {'update ms':>10s} {'build ms':>9s} "
           f"{'mappe B':>8s} {'tail':>4s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))

    for v in spec["values"]:
        cell = cell_of(axis, v)
        dims = cell["dims"]
        # Computed here, not read back from the result: a cell that was
        # skipped or that crashed has no n_in to report, and printing "?-4-7"
        # made a structural note look like a broken measurement.
        n_in = build_shape(cell["n_nodes"], dims, cell["descriptor"])["n_in"]
        shape_str = f"{n_in}-{'-'.join(map(str, dims))}-{N_OUT}"
        for pipe in PIPELINES:
            r = bench_cell(pipe, cell, repeat, trials)
            if r.get("ok"):
                print(f"  {str(v):>5s} {pipe:10s} {shape_str:>16s} {r['nw']:6d} "
                      f"{r['insns']:7d} {r['lat_ns']:7.1f} "
                      f"{r['update_ms']:10.2f} {r['build_ms']:9.1f} "
                      f"{r['map_bytes']:8d} {r['tail']:4d}")
                rows.append(dict(axis=axis, x=v, pipeline=pipe,
                                 shape=shape_str, **{
                                     k: r[k] for k in
                                     ("nw", "n_in", "insns", "jited",
                                      "map_bytes", "n_maps", "tail",
                                      "build_ms", "update_ms",
                                      "lat_ns", "lat_p50", "lat_max",
                                      # requested vs achieved: the weights are
                                      # a prefix of a shuffled pool, so the
                                      # zero fraction of a short prefix is a
                                      # sample of the pool's, not equal to it.
                                      # Recorded so the x label can be checked
                                      # rather than trusted.
                                      "sparsity_real")}))
            else:
                if r.get("skipped"):
                    mark = f"{GREY}n/d{NC}"
                elif r.get("refused"):
                    mark = f"{YELLOW}RIFIUTATO{NC}"     # dato, non guasto
                else:
                    mark = f"{RED}CRASH{NC}"
                print(f"  {str(v):>5s} {pipe:10s} {shape_str:>16s} {'':6s} "
                      f"{mark} {GREY}{r.get('detail', '')[:90]}{NC}")

    _warn_contaminated(rows)

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        _give_back(out_dir)
        path = os.path.join(out_dir, f"scaling_{axis}.csv")
        if rows:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
            _give_back(path)
            print(f"\n  {GREEN}scritto{NC} {path}  ({len(rows)} righe)")
        else:
            print(f"\n  {RED}nessuna riga da scrivere per {axis}{NC}")
    return rows


# ==========================================================================
# PLOTS -- read the CSV, never re-measure. No root, no BCC.
# ==========================================================================
# (colonna, etichetta y, nome file, asse y logaritmico)
#
# update_ms is log: P1 sits around 1500 ms and P2/P3 around a millisecond, so
# on a linear axis the two cheap pipelines collapse onto the zero line and the
# graph shows one curve instead of three. The whole finding is the DISTANCE
# between them, which is what a log axis is for.
PLOTS = [
    ("insns", "istruzioni eBPF (xlated)", "scaling_{axis}_insns", False),
    ("lat_ns", "latenza (ns/pacchetto, minimo)", "scaling_{axis}_latenza", False),
    ("update_ms", "installare un modello nuovo (ms)", "scaling_{axis}_update", True),
    ("build_ms", "compilare il programma, una volta (ms)", "scaling_{axis}_build", False),
    ("map_bytes", "memoria delle mappe (byte)", "scaling_{axis}_mappe", False),
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

    cat = AXES[axis]["kind"] == "cat"
    # Categorical x (the descriptor axis) is drawn as grouped bars, not a
    # curve. A line from "no_onehot" to "big_onehot" would draw a slope
    # between two names, implying intermediate descriptors that do not exist.
    order = [str(v) for v in AXES[axis]["values"]]

    made = 0
    for metric, ylabel, stem, logy in PLOTS:
        fig, ax = plt.subplots(figsize=(6.2 if cat else 5.6, 3.6))
        drawn = False
        if metric not in rows[0]:
            # A CSV written by an older version of this script: it simply does
            # not have this column. Say so and move on -- crashing with a
            # KeyError would make an out-of-date file look like a broken
            # plotter, and re-measuring is the fix either way.
            print(f"  {GREY}salto {metric} per {axis}: colonna assente nel CSV "
                  f"(rimisura per averla){NC}")
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
                # A single point cannot show a slope, so it is drawn as a lone
                # marker: that is P2 on the depth axis when its compiled layer
                # ceiling is 2, and the gap IS the result.
                ax.plot(xs, ys, linestyle="-" if len(xs) > 1 else "none",
                        linewidth=1.6, markersize=6, **STYLE[pipe])
            drawn = True
        if not drawn:
            plt.close(fig)
            continue
        if cat:
            ax.set_xticks(range(len(order)))
            ax.set_xticklabels(order, fontsize=8)
        ax.set_xlabel(AXES[axis]["xlabel"])
        ax.set_ylabel(ylabel)
        ax.grid(True, linewidth=0.4, alpha=0.4)
        ax.legend(frameon=False, fontsize=8)
        if logy:
            ax.set_yscale("log")      # set_ylim(bottom=0) is invalid on a log axis
        else:
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
    p.add_argument("--_worker", nargs=2, help=argparse.SUPPRESS)
    a = p.parse_args()

    if a._worker:
        return _worker(a._worker[0], a._worker[1])

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

    # Resolved BEFORE the chdir: a relative --out is relative to where the
    # USER ran the command, not to ipa/. Resolving it after the chdir put
    # `--out results/` inside ipa/results/, which is not where anyone typing
    # that meant it to go.
    out_dir = os.path.abspath(a.out)
    os.chdir(SHARED_DIR)
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
