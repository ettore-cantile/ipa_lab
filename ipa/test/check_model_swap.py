#!/usr/bin/env python3
"""check_model_swap.py -- what packets see while P2 or P3 change model.

One thread runs the program continuously, another replaces model A with B:
in place, or make-before-break (install under a new id, switch, retire).
Counts decisions of A, of B, and of neither. Needs root.

    sudo python3 ipa/test/check_model_swap.py
    sudo python3 ipa/test/check_model_swap.py --pipeline modular --seconds 5
"""
import argparse
import ctypes as ct
import json
import os
import subprocess
import sys
import threading
import time

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

XDP_PASS, XDP_DROP, XDP_REDIRECT = 2, 1, 4
POP = os.path.join(SHARED_DIR, "synth", "population")


def load(d):
    import contextlib
    import io
    import model_source as ms
    with contextlib.redirect_stdout(io.StringIO()):
        return ms.load_model(d, topology=ms.load_topology(d))


def inputs_of(PS, model):
    """The link state that makes `model` forward the traffic packet
    (TTL 32, fabric node and port), and the class it decides."""
    import itertools
    import test_forwarding as TF
    import bench_capacity as BT
    node = PS.node_index_for(model, TF.FABRIC_NODE_INDEX)
    slot = PS.ingress_slot_for(model, TF.FABRIC_INGRESS_SLOT)
    n_ls = {f["type"]: f["size"] for f in model.features}.get("link_state", 0)
    for ls in [[1] * n_ls] + [list(b) for b in
                              itertools.product([1, 0], repeat=n_ls)]:
        c, _ = PS.reference(model, BT.TRAFFIC_TTL, link_state=ls or None,
                            ingress_port=slot or 0, node_index=node)
        if model.semantics.action_of(c) == "FORWARD":
            return ls, node, slot, c
    return None


def pick_pair(pipeline):
    """Two population models with the same input layout and depth (P2 is
    compiled for one), different widths, and different classes for the same
    packet."""
    import csv
    import pipeline_setup as PS
    import pipeline_limits
    rows = list(csv.DictReader(open(os.path.join(POP, "population.csv"))))
    rows = [r for r in rows if r["family"] in ("base", "replica")
            and int(r["weights"]) <= 450]
    for a in rows:
        for b in rows:
            if (a["id"] >= b["id"] or a["layout"] != b["layout"]
                    or a["depth"] != b["depth"] or a["hidden"] == b["hidden"]):
                continue
            da = os.path.join(SHARED_DIR, "..", a["folder"])
            A = load(da)
            B = load(os.path.join(SHARED_DIR, "..", b["folder"]))
            if any(pipeline_limits.why_not(pipeline, M.hidden, M.n_in, M.n_out)
                   for M in (A, B)):
                continue
            ia = inputs_of(PS, A)
            if not ia:
                continue
            ls, node, slot, ca = ia
            import bench_capacity as BT
            cb, _ = PS.reference(B, BT.TRAFFIC_TTL, link_state=ls or None,
                                 ingress_port=slot or 0, node_index=node)
            if cb != ca:
                return A, B, (ls, node, slot, ca, cb), da
    raise SystemExit("no suitable pair of models in the population")


def counters(setup, n=16):
    from stats_maps import read_counter
    cs = setup["cls_stats"]
    return [read_counter(cs, k) for k in range(min(n, len(cs)))]


def run(pipeline, A, B, inputs, mode, seconds, cpu_r, cpu_w):
    import pipeline_setup as PS
    import check_pipelines as V
    from check_pipelines import prog_test_run, build_frame_sparse
    ls, node, slot, ca, cb = inputs
    setup = PS.build(pipeline, A)
    PS.set_node(setup, node)
    PS.set_ingress(setup, V.TEST_RUN_DEFAULT_INGRESS_IFINDEX, slot)
    PS.seed_inputs(setup, link_state=ls or None)
    fd = setup["disp"].fd

    frames = {}

    def frame(mid, M):
        k = (mid, M.name)
        if k not in frames:
            frames[k] = build_frame_sparse(model_id=mid, ttl=32,
                                           scale=M.scale, n_in=M.n_in,
                                           n_out=M.n_out)
        return frames[k]

    state = dict(cur=(0, A), stop=False)
    rets = {}
    retired_pass = [0]
    live = {0}

    def reader():
        os.sched_setaffinity(0, {cpu_r})
        while not state["stop"]:
            mid, M = state["cur"]
            r, _ = prog_test_run(fd, frame(mid, M), repeat=1)
            if r == XDP_PASS and mid not in live:
                retired_pass[0] += 1
            else:
                rets[r] = rets.get(r, 0) + 1

    changes = [0]

    def writer():
        os.sched_setaffinity(0, {cpu_w})
        t_end = time.time() + seconds
        cur_id, cur_M, other = 0, A, B
        while time.time() < t_end:
            if mode == "in place":
                PS.register_model_id(setup, 0, other, offset=0)
                cur_M, other = other, cur_M
            else:
                new_id = 1 - cur_id
                PS.install_model(setup, other, new_id)
                live.add(new_id)
                state["cur"] = (new_id, other)
                time.sleep(0.0005)
                live.discard(cur_id)
                PS.retire_model(setup, cur_id)
                cur_id, cur_M, other = new_id, other, cur_M
            changes[0] += 1
        state["stop"] = True

    import contextlib
    import io
    before = counters(setup)
    tr, tw = threading.Thread(target=reader), threading.Thread(target=writer)
    with contextlib.redirect_stdout(io.StringIO()):
        tr.start()
        tw.start()
        tw.join()
        tr.join()
    after = counters(setup)
    cls = {k: a - b for k, (a, b) in enumerate(zip(after, before)) if a - b}
    n = sum(rets.values())
    expected = cls.get(ca, 0) + cls.get(cb, 0)
    classified = sum(cls.values())
    other_cls = classified - expected
    passed = rets.get(XDP_PASS, 0)
    return dict(pipeline=pipeline, mode=mode, packets=n, changes=changes[0],
                class_a=ca, class_b=cb, classes=cls, mixed=other_cls + passed,
                other_class=other_cls, not_processed=passed,
                retired_id_pass=retired_pass[0])


def _timing_child(pipeline, d):
    """Runs in the child process."""
    import contextlib
    import io
    from bcc import BPF
    M = load(d)
    if pipeline == "template":
        from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                        build_arch_leaf, load_arch_weights)
        b = BPF(text="#define IPA_ARCH_COMBINED 1\n"
                + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n"
                + build_arch_leaf(len(M.hidden)))
        b.load_func("ipa_switch_template", BPF.XDP)
        b.load_func("arch_generic_2layer", BPF.XDP)
        h = M.hidden

        def reg(i):
            load_arch_weights(b, M.weights, model_id=i,
                              weight_offset=i * len(M.weights),
                              scale=M.scale, n_h1=h[0],
                              n_h2=h[1] if len(h) > 1 else h[0],
                              features=M.features, n_in=M.n_in,
                              semantics=M.semantics, n_hidden=len(h))
    else:
        from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
        b = BPF(text=EBPF_MODULAR_FULL)
        for f in ("modular_dispatcher", "layer_first", "layer_hidden"):
            b.load_func(f, BPF.XDP)

        def reg(i):
            load_modular_weights(b, M.weights, model_id=i,
                                 base_offset=i * len(M.weights),
                                 scale=M.scale, layer_dims=M.layer_dims,
                                 features=M.features, semantics=M.semantics)
    out = []
    for i in range(3):
        t0 = time.perf_counter()
        with contextlib.redirect_stdout(io.StringIO()):
            reg(i)
        out.append((time.perf_counter() - t0) * 1000.0)
    print(json.dumps(out))


def timing(pipeline, d):
    r = subprocess.run([sys.executable, os.path.abspath(__file__),
                        "--_timing", pipeline, d],
                       capture_output=True, text=True)
    last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    try:
        return json.loads(last)
    except json.JSONDecodeError:
        return None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--pipeline", default="all",
                   choices=("template", "modular", "all"))
    p.add_argument("--seconds", type=float, default=3.0)
    p.add_argument("--cpu-reader", type=int, default=6)
    p.add_argument("--cpu-writer", type=int, default=8)
    p.add_argument("--out", default=None, help="write swap.json here")
    p.add_argument("--_timing", nargs=2, help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    if a._timing:
        _timing_child(*a._timing)
        return 0
    if os.geteuid() != 0:
        sys.exit("root needed: sudo python3 ipa/test/check_model_swap.py")
    pipes = ("template", "modular") if a.pipeline == "all" else (a.pipeline,)
    results, ok = [], True
    for pl in pipes:
        A, B, inputs, folder_a = pick_pair(pl)
        print(f"\n== {pl}: A = {A.name} ({A.describe()}),\n"
              f"   B = {B.name} ({B.describe()}); class of A {inputs[3]}, "
              f"of B {inputs[4]} for the same packet")
        for mode in ("in place", "make-before-break"):
            r = run(pl, A, B, inputs, mode, a.seconds, a.cpu_reader,
                    a.cpu_writer)
            results.append(r)
            print(f"  {mode:18s} {r['packets']:>9} packets, "
                  f"{r['changes']:>5} swaps: classes {r['classes']}; "
                  f"mixed {r['mixed']} (foreign class {r['other_class']}, "
                  f"not processed {r['not_processed']}); just-retired id "
                  f"{r['retired_id_pass']}")
            if mode == "make-before-break" and r["mixed"]:
                ok = False
        t = timing(pl, folder_a)
        if t:
            print(f"  registering the same model in a new process: "
                  f"1st {t[0]:.2f} ms, 2nd {t[1]:.2f} ms, 3rd {t[2]:.2f} ms")
            results.append(dict(pipeline=pl, mode="registration",
                                ms=t))
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "swap.json"), "w") as f:
            json.dump(results, f, indent=1)
    print("\nmake-before-break: " + ("no mixed packet" if ok else
                                     "MIXED PACKETS, see above"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
