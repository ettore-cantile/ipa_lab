#!/usr/bin/env python3
"""
bench_semantics_models.py -- what per-model class semantics cost the datapath.

Two measurements, both on the real P2/P3 programs through the real dispatcher,
with the SAME harness `test_suite.py --only kernel` uses (BPF_PROG_TEST_RUN,
TTL-safe chunks of 200 runs, the minimum over `--trials` trials as the headline
latency, p50/max beside it, Mpps = 1000 / min):

  1. ISOLATED COST. The class-only lookup (`class_action[class]`, the tree
     given by --baseline-dir) against the per-model one
     (`class_action[(model_id, bank, class)]`, this tree). Same checked-in
     65-4-4-7 model, same packet, same kernel, same process -- and the trials
     are INTERLEAVED across all configurations, so a drift in the machine hits
     every configuration alike instead of whichever happened to run last.
     Nothing but the semantics lookup differs between the two sources.

  2. MODEL COUNT. 1, 2, 4, 8 registered models. The datapath resolves the
     model with a hash lookup on model_id and its semantics with an array
     lookup on (model_id, bank, class): neither walks the registered models,
     so the cost for the selected model must not move with N. Only memory
     would, and here it does not either: every map is preallocated to its
     ceiling. Extra models reuse model 0's weight slice (the P2 block holds
     three 65-4-4-7 models, not eight) but each has its OWN semantics in this
     tree -- a permutation of the ports -- so the multi-model rows really
     exercise distinct (model_id, class) rows. The baseline tree cannot hold
     different semantics, so its extra models share model 0's.

Also reported per configuration: xlated instructions, JIT bytes, map lookups
per packet (a separate IPA_COUNT_LOOKUPS build, as in the suite), tail calls,
declared map memory (same formula as the suite).

    sudo python3 ipa/test/bench_semantics_models.py --baseline-dir /path/to/old/ipa
    sudo python3 ipa/test/bench_semantics_models.py --baseline-dir ... --csv out.csv
"""
import argparse
import contextlib
import ctypes as ct
import importlib.util
import os
import sys
import time

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _dir in (SHARED_DIR, _TEST_DIR):
    if _dir not in sys.path:
        sys.path.insert(0, _dir)
os.chdir(SHARED_DIR)

from bcc import BPF                                            # noqa: E402
import verify_prog_run as V                                    # noqa: E402
from common import instrument_map_lookups                      # noqa: E402

MAP_NAMES = {
    "p2": ["link_state", "queue_state", "model_desc", "arch_weights",
           "arch_registry", "arch_progs", "class_action_t2", "mac_table_t2",
           "pkt_stats_t2", "cls_stats_t2", "ingress_port_t2", "node_id_t2"],
    "p3": ["link_state", "queue_state", "model_desc", "layer_weights",
           "layer_registry", "layer_shapes", "layer_chain", "scratch_acts",
           "scratch_meta", "class_action_t3", "mac_table_t3", "pkt_stats_t3",
           "cls_stats_t3", "ingress_port_t3", "node_id_t3"],
}
MODULES = ("ebpf_template_arch", "ebpf_modular")


@contextlib.contextmanager
def current(mods):
    """Make `mods` the modules that `import ebpf_template_arch` etc. resolve
    to, for the duration. The two control planes import each other by name."""
    saved = {k: sys.modules.get(k) for k in mods}
    sys.modules.update(mods)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def load_tree(ipa_dir, tag):
    mods = {}
    for name in MODULES:
        spec = importlib.util.spec_from_file_location(
            f"{name}__{tag}", os.path.join(ipa_dir, name + ".py"))
        mods[name] = importlib.util.module_from_spec(spec)
    with current(mods):
        for name in MODULES:
            mods[name].__spec__.loader.exec_module(mods[name])
    return mods


def semantics_for(model_id, sem0, distinct):
    """model 0: the descriptor's semantics. Others: the same ports rotated,
    so every model forwards each class somewhere else."""
    from class_semantics import ClassSemantics
    if model_id == 0 or not distinct:
        return sem0
    ports = sem0.logical_ports
    fwd = [c for c in range(sem0.n_out) if sem0.action_of(c) == "FORWARD"]
    rot = [ports[(i + model_id) % len(ports)] for i in range(len(fwd))]
    return ClassSemantics.forward_then_drop(len(fwd), drop_class=sem0.drop_class,
                                            n_out=sem0.n_out, ports=rot)


def build(mods, pl, n_models, distinct, instrument=False):
    weights, scale = V.load_weights(V.MODEL_PT)
    import model_meta as mm
    sem0 = mm.descriptor_semantics_or_reference(7, "bench")
    T, M = mods["ebpf_template_arch"], mods["ebpf_modular"]
    with current(mods):
        if pl == "p2":
            raw = ("#define IPA_ARCH_COMBINED 1\n" + T.EBPF_TEMPLATE_ARCH_DISPATCHER
                   + "\n" + T.EBPF_ARCH_GENERIC_2LAYER)
            src = ("#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(raw)
                   if instrument else raw)
            b = BPF(text=src)
            disp = b.load_func("ipa_switch_template", BPF.XDP)
            leaf = b.load_func("arch_generic_2layer", BPF.XDP)
            b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
            progs = [disp.fd, leaf.fd]
            for mid in range(n_models):
                T.load_arch_weights(b, weights, model_id=mid, scale=scale,
                                    weight_offset=0,
                                    semantics=semantics_for(mid, sem0, distinct))
            mac, n_tail = "mac_table_t2", 1
        else:
            src = ("#define IPA_COUNT_LOOKUPS 1\n"
                   + instrument_map_lookups(M.EBPF_MODULAR_FULL)
                   if instrument else M.EBPF_MODULAR_FULL)
            b = BPF(text=src)
            disp = b.load_func("modular_dispatcher", BPF.XDP)
            first = b.load_func("layer_first", BPF.XDP)
            hidden = b.load_func("layer_hidden", BPF.XDP)
            b["layer_chain"][ct.c_int(0)] = ct.c_int(first.fd)
            for i in range(1, M.LAYER_CHAIN_SIZE):
                b["layer_chain"][ct.c_int(i)] = ct.c_int(hidden.fd)
            progs = [disp.fd, first.fd, hidden.fd]
            for mid in range(n_models):
                M.load_modular_weights(b, weights, model_id=mid, scale=scale,
                                       layer_dims=[(65, 4), (4, 4), (4, 7)],
                                       base_offset=0,
                                       semantics=semantics_for(mid, sem0, distinct))
            mac, n_tail = "mac_table_t3", 3
        V._seed_link_state(b, 1)
        V._install_mac_table(b, mac, ports=list(range(8)))
    return {"b": b, "disp": disp, "progs": progs, "scale": scale,
            "n_tail": n_tail, "pl": pl, "n": n_models}


def static_metrics(s):
    insn = jit = 0
    for fd in s["progs"]:
        ic, jb = V.prog_insn_count(fd)
        insn += ic or 0
        jit += jb or 0
    mem = 0
    for name in MAP_NAMES[s["pl"]]:
        try:
            mem += V.map_bytes(s["b"][name].map_fd, V._NR_CPUS)
        except Exception:
            pass
    return insn, jit, mem


def lookups(s, model_id):
    ctr = s["b"]["lookup_ctr"]
    ctr[ct.c_int(0)] = ctr.Leaf()
    rep = V.TEST_RUN_MAX_CHUNK
    V.prog_test_run(s["disp"].fd, V.build_frame(model_id, V.BENCH_TTL, s["scale"]),
                    repeat=rep)
    return sum(int(v) for v in ctr[ct.c_int(0)]) / float(rep)


def sample(s, model_id, repeat):
    mk = lambda: V.build_frame(model_id, V.BENCH_TTL, s["scale"])
    rv, ns = V.prog_test_run_bench(s["disp"].fd, mk, repeat)
    return rv, ns


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline-dir", required=True,
                    help="ipa/ directory of the class-only (pre-change) tree")
    ap.add_argument("--trials", type=int, default=7)
    ap.add_argument("--repeat", type=int, default=50000)
    ap.add_argument("--models", default="1,2,4,8")
    ap.add_argument("--pipeline", choices=["p2", "p3", "all"], default="all")
    ap.add_argument("--csv", default=None)
    a = ap.parse_args()

    trees = {"base": load_tree(os.path.abspath(a.baseline_dir), "base"),
             "new": load_tree(SHARED_DIR, "new")}
    counts = [int(x) for x in a.models.split(",")]
    pls = ("p2", "p3") if a.pipeline == "all" else (a.pipeline,)

    # Progress on stderr, prefixed '#': loading the P2 leaf alone takes seconds
    # in the verifier, and there are 2 builds per (pipeline, tree, N), so a
    # silent run looks hung for minutes.
    t0 = time.monotonic()

    def progress(msg):
        print(f"# [{time.monotonic() - t0:6.0f}s] {msg}", file=sys.stderr,
              flush=True)

    # (pipeline, tree, N, measured model_id)
    configs = []
    n_builds, done = 2 * len(pls) * 2 * len(counts), 0
    for pl in pls:
        for tree in ("base", "new"):
            for n in counts:
                progress(f"build {done + 1}-{done + 2}/{n_builds}: "
                         f"{pl} {tree} N={n} (plain + IPA_COUNT_LOOKUPS)")
                s = build(trees[tree], pl, n, distinct=(tree == "new"))
                ins = build(trees[tree], pl, n, distinct=(tree == "new"),
                            instrument=True)
                done += 2
                for mid in sorted({0, n - 1}):
                    configs.append({"pl": pl, "tree": tree, "n": n, "mid": mid,
                                    "s": s, "ins": ins, "lat": [], "rv": set()})

    progress(f"static metrics + lookup counts, {len(configs)} configurations")
    for c in configs:
        c["insn"], c["jit"], c["mem"] = static_metrics(c["s"])
        c["lookups"] = lookups(c["ins"], c["mid"])
        sample(c["s"], c["mid"], 1000)                     # warm-up

    for t in range(a.trials):                              # interleaved
        progress(f"trial {t + 1}/{a.trials}")
        for c in configs:
            rv, ns = sample(c["s"], c["mid"], a.repeat)
            c["lat"].append(ns)
            c["rv"].add(rv)
    progress("done")

    hdr = (f"{'pl':<3} {'tree':<5} {'N':>2} {'mid':>3} {'insn':>6} {'jit':>6} "
           f"{'lookups':>7} {'tail':>4} {'mem(B)':>8} {'min':>6} {'p50':>6} "
           f"{'max':>6} {'Mpps':>7} retval")
    print("\n" + hdr + "\n" + "-" * len(hdr))
    rows = []
    for c in configs:
        lat = sorted(c["lat"])
        lo, p50, hi = lat[0], lat[len(lat) // 2], lat[-1]
        mpps = 1000.0 / lo if lo else 0.0
        row = [c["pl"], c["tree"], c["n"], c["mid"], c["insn"], c["jit"],
               c["lookups"], c["s"]["n_tail"], c["mem"], lo, p50, hi, mpps,
               "/".join(str(r) for r in sorted(c["rv"]))]
        rows.append(row)
        print(f"{row[0]:<3} {row[1]:<5} {row[2]:>2} {row[3]:>3} {row[4]:>6} "
              f"{row[5]:>6} {row[6]:>7.1f} {row[7]:>4} {row[8]:>8} {row[9]:>6} "
              f"{row[10]:>6} {row[11]:>6} {row[12]:>7.3f} {row[13]}")

    print("\nDelta new - base, N=1, measured model 0:")
    for pl in pls:
        b = next(r for r in rows if r[:4] == [pl, "base", counts[0], 0])
        n = next(r for r in rows if r[:4] == [pl, "new", counts[0], 0])
        def d(i, fmt="{:+.1f}"):
            pct = (n[i] - b[i]) / b[i] * 100.0 if b[i] else 0.0
            return f"{fmt.format(n[i] - b[i])} ({pct:+.2f}%)"
        print(f"  {pl}: insn {d(4, '{:+d}')}  jit {d(5, '{:+d}')}  lookups {d(6)}"
              f"  mem {d(8, '{:+d}')}  lat_min {d(9, '{:+d}')} ns"
              f"  lat_p50 {d(10, '{:+d}')} ns  Mpps {d(12, '{:+.3f}')}")

    if a.csv:
        with open(a.csv, "w") as f:
            f.write("pipeline,tree,n_models,model_id,insn,jit,lookups,tail,"
                    "map_bytes,lat_min,lat_p50,lat_max,mpps,retval\n")
            for r in rows:
                f.write(",".join(str(x) for x in r) + "\n")
        print(f"\ncsv: {a.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
