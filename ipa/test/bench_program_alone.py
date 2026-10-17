#!/usr/bin/env python3
"""bench_program_alone.py -- the program alone (BPF_PROG_TEST_RUN), for one model.

For each pipeline: latency of a single run and in a warm loop, table lookups
and tail calls per packet, time to build the pipeline and to install a model.

    sudo python3 ipa/test/bench_program_alone.py --model <dir> --topology <dir> --out <dir>
"""
import argparse
import csv
import ctypes as ct
import os
import sys
import time

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

PIPES = ("baseline", "p1_static", "hardcoded", "template", "modular")
LOOKUP_CALLS = 100
COLS = ["method", "esito", "lat_ns", "lat_min", "lat_max", "lat_hot",
        "hot_k", "retval", "fwd_pct",
        "build_ms", "update_ms", "lookups", "n_tail", "insns", "jited",
        "detail"]


def _timed(fn):
    t0 = time.perf_counter()
    out = fn()
    return out, (time.perf_counter() - t0) * 1000.0


XDP_REDIRECT = 4


def _where(PS, model):
    """The fabric's node and ingress port, for this model."""
    import test_forwarding as TF
    return (PS.node_index_for(model, TF.FABRIC_NODE_INDEX),
            PS.ingress_slot_for(model, TF.FABRIC_INGRESS_SLOT))


def _prepare(PS, setup, model):
    """The traffic inputs."""
    import bench_capacity as BT
    import check_pipelines as V
    node, slot = _where(PS, model)
    PS.set_node(setup, node)
    PS.set_ingress(setup, V.TEST_RUN_DEFAULT_INGRESS_IFINDEX, slot)
    if setup["pipeline"] == 0:
        PS.seed_inputs(setup)
        return None
    return BT._forwarding_inputs(setup, model, node, slot,
                                 ttl=BT.TRAFFIC_TTL)


def _hot_k(PS, model, inputs, kmax=31):
    """How many consecutive runs (TTL 32, 31, ...) decide the same class as
    the first."""
    import bench_capacity as BT
    if inputs is None:
        return kmax
    ls, q, c = inputs
    node, slot = _where(PS, model)
    k = 0
    for t in range(BT.TRAFFIC_TTL, BT.TRAFFIC_TTL - kmax, -1):
        ct_, _ = PS.reference(model, t, link_state=ls or None,
                              ingress_port=slot or 0, node_index=node,
                              queues=q or None)
        if ct_ != c:
            break
        k += 1
    return k


def _sample_hot(fd, model, k, chunks, trials):
    """Minimum, over trials and blocks, of the mean time of a block of k
    consecutive runs."""
    import bench_capacity as BT
    from check_pipelines import prog_test_run
    if k < 2:
        return None, None
    frame = _frame(model, BT.TRAFFIC_TTL)
    for _ in range(20):
        prog_test_run(fd, frame, repeat=k)
    best, fwd = None, True
    for _ in range(trials):
        for _ in range(chunks):
            r, ns = prog_test_run(fd, frame, repeat=k)
            fwd = fwd and r == XDP_REDIRECT
            if ns and (best is None or ns < best):
                best = ns
    return best, fwd


def _sample(fd, model, calls, trials):
    """(lat, minimum, maximum, most frequent retval, % forwarded)."""
    import collections
    import statistics as st
    import bench_capacity as BT
    from check_pipelines import prog_test_run
    frame = _frame(model, BT.TRAFFIC_TTL)
    for _ in range(200):
        prog_test_run(fd, frame, repeat=1)
    meds, lo, hi, rets = [], None, None, collections.Counter()
    for _ in range(trials):
        xs = []
        for _ in range(calls):
            r, ns = prog_test_run(fd, frame, repeat=1)
            rets[r] += 1
            if ns:
                xs.append(ns)
        if xs:
            meds.append(st.median(xs))
            lo = min(xs) if lo is None else min(lo, min(xs))
            hi = max(xs) if hi is None else max(hi, max(xs))
    n = sum(rets.values())
    return (min(meds) if meds else None, lo, hi, rets.most_common(1)[0][0],
            100.0 * rets.get(XDP_REDIRECT, 0) / n if n else None)


def _frame(model, ttl):
    from check_pipelines import build_frame_sparse
    return build_frame_sparse(model_id=0, ttl=ttl, scale=model.scale,
                              n_in=model.n_in, n_out=model.n_out)


def _lookups(PS, pipeline, model):
    """Map lookups per packet."""
    import bench_capacity as BT
    from check_pipelines import prog_test_run
    try:
        node, _ = _where(PS, model)
        s = PS.build(pipeline, model, node_index=node, instrument=True)
        _prepare(PS, s, model)
        ctr = s["b"]["lookup_ctr"]
        frame = _frame(model, BT.TRAFFIC_TTL)
        aot = getattr(ctr, "Leaf", None) is None
        if aot:
            ctr[ct.c_int(0)] = ct.c_ulonglong(0)
        else:
            ctr[ct.c_int(0)] = ctr.Leaf()
        for _ in range(LOOKUP_CALLS):
            prog_test_run(s["disp"].fd, frame, repeat=1)
        if aot:
            tot = int.from_bytes(ctr[ct.c_int(0)], "little")
        else:
            tot = sum(int(v) for v in ctr[ct.c_int(0)])
        return tot / float(LOOKUP_CALLS)
    except Exception as e:
        print(f"[lookups] {pipeline}: {type(e).__name__}: {str(e)[:90]}",
              file=sys.stderr)
        return None


def one(pipeline, model, calls, trials):
    import pipeline_setup as PS
    from bench_scaling import _totals
    row = dict(method=pipeline)
    node, _ = _where(PS, model)
    try:
        setup, build_ms = _timed(lambda: PS.build(pipeline, model,
                                                  node_index=node))
    except PS.NotApplicable as e:
        return dict(row, esito="N/A", detail=str(e)[:160])
    try:
        inputs = _prepare(PS, setup, model)
    except PS.NotApplicable as e:
        return dict(row, esito="N/A", detail=str(e)[:160])
    if pipeline in ("p1_static", "hardcoded"):
        update_ms = setup.get("t_redirect_s", 0.0) * 1000.0
    elif pipeline in ("template", "modular"):
        _, update_ms = _timed(lambda: PS.register_model_id(setup, 1, model))
    else:
        update_ms = 0.0
    insns, jited, _, _, _ = _totals(setup["b"], setup["progs"])
    lat, lo, hi, retval, fwd = _sample(setup["disp"].fd, model, calls,
                                       trials)
    k = _hot_k(PS, model, inputs)
    hot, hot_fwd = _sample_hot(setup["disp"].fd, model, k, 50, trials)
    if hot is not None and not hot_fwd:
        hot = None
    return dict(row, esito="OK", lat_ns=lat, lat_min=lo, lat_max=hi,
                lat_hot=hot, hot_k=k,
                retval=retval, fwd_pct=round(fwd, 1),
                build_ms=round(build_ms, 3), update_ms=round(update_ms, 3),
                lookups=_lookups(PS, pipeline, model),
                n_tail=setup.get("n_tail"), insns=insns, jited=jited)


def compile_times(model, rounds=3):
    """Generate P1's C and compile it with clang, without cache."""
    import p1_aot
    import pipeline_setup as PS
    node, _ = _where(PS, model)
    out = []
    for pl, static in (("p1_static", node), ("hardcoded", None)):
        gen, comp = [], []
        for _ in range(rounds):
            src, g = _timed(lambda: p1_aot.p1_source(
                [(0, model.weights, model.scale)],
                hidden_dims=tuple(model.hidden), features=model.features,
                n_out=model.n_out, semantics=model.semantics,
                static_node=static))
            o_path, c = p1_aot.compile_object(src, cache=False)
            for path in (o_path, o_path[:-2] + ".bpf.c"):
                try:
                    os.remove(path)
                except OSError:
                    pass
            gen.append(g)
            comp.append(c * 1000.0)
        out.append(dict(method=pl, generate_ms=round(min(gen), 3),
                        compile_ms=round(min(comp), 3),
                        source_bytes=len(src)))
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--model", required=True)
    p.add_argument("--topology", default=None)
    p.add_argument("--out", required=True)
    p.add_argument("--method", default=",".join(PIPES))
    p.add_argument("--compila", action="store_true",
                   help="only generate and compile P1 (no kernel, no "
                        "root): writes compila.csv")
    p.add_argument("--calls", type=int, default=1000,
                   help="single runs per trial (default 1000)")
    p.add_argument("--trials", type=int, default=7)
    a = p.parse_args(argv)
    import model_under_test as MUT
    model = MUT.select(a.model, a.topology)
    if model is None:
        import model_source as ms
        model = ms.load_model("checkpoint")
    os.makedirs(a.out, exist_ok=True)
    if a.compila:
        rows = compile_times(model)
        path = os.path.join(a.out, "compila.csv")
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"  {rows}\n  written {path}")
        return 0
    rows = []
    for pl in a.method.split(","):
        try:
            r = one(pl, model, a.calls, a.trials)
        except Exception as e:
            r = dict(method=pl, esito="errore",
                     detail=f"{type(e).__name__}: {str(e)[:150]}")
        rows.append(r)
        print(f"  {pl:10s} {r.get('esito'):6s} "
              f"{r.get('lat_ns', '-')!s:>8} ns  forwarded "
              f"{r.get('fwd_pct', '-')!s:>5} %  lookups "
              f"{r.get('lookups', '-')!s:>6}  update "
              f"{r.get('update_ms', '-')!s:>8} ms  {r.get('detail', '')}")
    path = os.path.join(a.out, "solo.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in COLS})
    print(f"  written {path}")
    return 1 if any(r.get("esito") == "errore" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
