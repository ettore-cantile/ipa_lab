#!/usr/bin/env python3
"""
test_model_source.py -- models, network scenarios and their compatibility.

No root. Every model reference loads with the shape and class semantics its
files declare; a model runs on a network only if feature widths and TTL match.

    python3 ipa/test/test_model_source.py
    sudo python3 ipa/test/test_model_source.py --kernel
"""
import argparse
import contextlib
import io
import json
import os
import random
import shutil
import sys
import tempfile

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import model_source as ms  # noqa: E402
import pipeline_limits as pl  # noqa: E402

GREEN, RED, YELLOW, NC = "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0m"
_n_pass = _n_fail = 0

PRESETS = ("ipa_like", "small", "large", "deep", "mixed", "sparse", "ones",
           "ipa_ttl16")
FIXTURE = os.path.join(_TEST_DIR, "fixtures", "sparse_hetero_11")

EXPECTED = {
    "checkpoint":      ("65-4-4-7", 319, 5),
    "synth:ipa_like":  ("65-4-4-7", 319, 6),
    "synth:small":     ("15-4-4", 84, 3),
    "synth:large":     ("117-8-8-9", 1097, 8),
    "synth:deep":      ("65-4-4-4-7", 339, 6),
    "synth:mixed":     ("18-6-5", 149, 4),
    "synth:sparse":    ("65-4-4-7", 319, 6),
    "synth:ones":      ("11-2-3", 33, 2),
    "synth:ipa_ttl16": ("65-4-4-7", 319, 6),
}

MATRIX = {
    "germany50":       {"germany50", "ipa_like", "deep", "sparse",
                        "sparse_hetero_11"},
    "germany50_ttl16": {"ipa_ttl16"},
    "synth_small":     {"small"},
    "synth_ones":      {"ones"},
    "synth_large":     {"large"},
    "synth_mixed":     {"mixed"},
}


def ok(msg):
    global _n_pass
    _n_pass += 1
    print(f"  {GREEN}[PASS]{NC} {msg}")


def fail(msg):
    global _n_fail
    _n_fail += 1
    print(f"  {RED}[FAIL]{NC} {msg}")


def check(cond, msg):
    ok(msg) if cond else fail(msg)
    return cond


def raises(fn, needle, msg):
    try:
        fn()
    except ms.ModelError as e:
        return check(needle in str(e), f"{msg}: {e}")
    fail(f"{msg}: no error")
    return False


def _write_topology(root, name, cfg):
    d = os.path.join(root, name)
    os.makedirs(d)
    with open(os.path.join(d, ms.TOPOLOGY_FILE), "w") as f:
        json.dump(cfg, f)
    return d


def t_loading():
    print(f"\n{YELLOW}[1] Every reference loads with the declared shape{NC}")
    for ref, (shape, nw, drop) in EXPECTED.items():
        m = ms.load_model(ref)
        check(m.shape == shape and len(m.weights) == nw
              and m.semantics.drop_class == drop,
              f"{ref:16s} {m.shape}, {len(m.weights)} weights, DROP {m.semantics.drop_class}")


def t_checkpoint():
    print(f"\n{YELLOW}[2] The checkpoint is the one the benches measure{NC}")
    m = ms.load_model("checkpoint")
    with open(os.path.join(SHARED_DIR, "weights.json")) as f:
        wj = json.load(f)
    with open(os.path.join(SHARED_DIR, "weights_float.json")) as f:
        scale = json.load(f)["scale_factor"]
    check(m.weights == wj, "int8 weights identical to weights.json")
    check(m.scale == scale, f"scale {m.scale} == scale_factor of weights_float.json")
    check(m.reference and m.name == "germany50", "it is the reference, trained on germany50")
    sem = m.semantics
    check(sem.action_of(5) == "DROP" and sem.action_of(6) == "UNUSED"
          and sem.logical_ports == [0, 1, 2, 3, 4],
          "semantics from the descriptor: FORWARD 0-4, DROP 5, UNUSED 6")
    check(m.feature("ttl")["scale"] == 30, "ttl divided by 30 (normalize_by)")


def t_synth_semantics():
    print(f"\n{YELLOW}[3] A synthetic model uses ITS OWN semantics{NC}")
    m = ms.load_model("synth:ipa_like")
    sem = m.semantics
    check(sem.action_of(6) == "DROP" and sem.action_of(5) == "FORWARD",
          "ipa_like: DROP 6 as model.json declares, not the checkpoint's DROP 5")
    check(sem.logical_ports == list(range(6)), "six logical ports, 0-5")
    s = ms.semantics_with_drop(5, 2)
    check([s.action_of(c) for c in range(5)] ==
          ["FORWARD", "FORWARD", "DROP", "FORWARD", "FORWARD"]
          and [s.port_of(c) for c in (0, 1, 3, 4)] == [0, 1, 2, 3],
          "DROP in the middle: ports stay consecutive in class order")


def _all_models(topo):
    out = {}
    for ref in list(EXPECTED) + [FIXTURE]:
        try:
            m = ms.load_model(ref, topology=topo)
        except ms.ModelError:
            continue
        out[m.name] = m
    return out


def t_matrix():
    print(f"\n{YELLOW}[4] Scenarios x models{NC}")
    check(set(ms.list_topologies()) >= set(MATRIX),
          f"scenarios present: {', '.join(ms.list_topologies())}")
    for name, expected in MATRIX.items():
        topo = ms.load_topology(name)
        fits = {n for n, m in _all_models(topo).items()
                if not ms.mismatches(m, topo)}
        check(fits == expected, f"{name:16s} -> {sorted(fits)}")


def t_mismatch_reasons(root):
    print(f"\n{YELLOW}[5] The reason for an exclusion is readable{NC}")
    d = _write_topology(root, "net30", {"n_interfaces": 6, "n_nodes": 30,
                                        "n_queues": 4, "initial_ttl": 30})
    topo = ms.load_topology(d)
    why = ms.mismatches(ms.load_model("checkpoint"), topo)
    check(why == ["nodes: the model wants 52, the network has 30"],
          f"one-hot of 52 on a 30-node network: {why}")
    why = ms.mismatches(ms.load_model("synth:ipa_ttl16"),
                        ms.load_topology("germany50"))
    check(why == ["initial TTL: the model wants 16, the network has 30"],
          f"ipa_ttl16 on germany50: {why}")
    d = _write_topology(root, "senzattl", {"n_interfaces": 6, "n_nodes": 52})
    why = ms.mismatches(ms.load_model("checkpoint"), ms.load_topology(d))
    check(any("initial TTL" in w for w in why),
          "a network that does not declare the initial TTL is not taken as valid")


def t_scenarios(root):
    print(f"\n{YELLOW}[6] Scenarios outside the compiled ceilings{NC}")
    d = _write_topology(root, "nine", {"n_interfaces": 9, "n_nodes": 10})
    raises(lambda: ms.load_topology(d), "above the compiled ceiling",
           "9 interfaces")
    d = _write_topology(root, "code", {"n_interfaces": 4, "n_nodes": 10,
                                       "n_queues": 9})
    raises(lambda: ms.load_topology(d), "above the compiled ceiling", "9 code")
    d = _write_topology(root, "half", {"n_interfaces": 4})
    raises(lambda: ms.load_topology(d), "missing", "n_nodes missing")
    raises(lambda: ms.load_topology("non_esiste"), "available",
           "unknown name")
    g = ms.load_topology("germany50")
    check((g["n_interfaces"], g["n_nodes"], g["n_queues"], g["initial_ttl"])
          == (6, 52, 4, 30), "germany50: 6 / 52 / 4 / TTL 30")


def t_pipelines():
    print(f"\n{YELLOW}[7] Pipeline limits{NC}")
    cases = [
        ([4, 4], 65, 7, None, None),
        ([4, 4, 4], 65, 7, None, None),
        ([8, 8], 117, 9, "MAX_WEIGHT_ENTRIES", "ML1_MAX_H1"),
        ([9, 9], 65, 7, "T2_MAX_H1", "ML1_MAX_H1"),
        ([4, 4, 6], 65, 7, "beyond the second", None),
        ([4] * 16, 65, 7, None, "LAYER_CHAIN_SIZE"),
        ([4], 200, 7, "MAX_N_IN", "MAX_N_IN"),
    ]
    for hidden, n_in, n_out, p2, p3 in cases:
        w2 = pl.why_not("template", hidden, n_in, n_out)
        w3 = pl.why_not("modular", hidden, n_in, n_out)
        shape = "-".join(map(str, [n_in] + hidden + [n_out]))
        check((w2 is None if p2 is None else p2 in (w2 or ""))
              and (w3 is None if p3 is None else p3 in (w3 or "")),
              f"{shape:18s} P2: {w2 or 'ok'} | P3: {w3 or 'ok'}")
    check(pl.why_not("hardcoded", [16, 16], 65, 7) is None
          and pl.why_not("p1_static", [4] * 30, 65, 7) is None,
          "P1 and P1.5: no shape ceiling")
    check(pl.why_not("baseline", [99], 999, 99) is None,
          "baseline: no model, no limit")


def t_agrees_with_synth_kernel():
    print(f"\n{YELLOW}[8] check_kernel_vs_reference uses these limits{NC}")
    import check_kernel_vs_reference as VSK
    for name in PRESETS:
        m = ms.load_model(f"synth:{name}")
        model = {"arch": {"hidden": m.hidden, "n_in": m.n_in,
                          "n_out": m.n_out}}
        for pipe, key in (("p2", "template"), ("p3", "modular")):
            old = VSK.fuori_limiti(pipe, model)
            new = pl.why_not(key, m.hidden, m.n_in, m.n_out)
            check(old == new,
                  f"{name:10s} {pipe}: {new or 'allowed'}")


def t_errors(root):
    print(f"\n{YELLOW}[9] Readable errors{NC}")
    raises(lambda: ms.load_model("synth:nope"), "unknown", "missing preset")
    raises(lambda: ms.load_model("pippo"), "not recognised", "unknown reference")
    raises(lambda: ms.load_model("checkpoint:/tmp/non_esiste.pt"),
           "not found", "missing checkpoint")
    raises(lambda: ms.load_model(FIXTURE), "the scenario is needed",
           "fixture without a network")
    bad = os.path.join(root, "short")
    shutil.copytree(ms.load_model("synth:small").path, bad)
    with open(os.path.join(bad, "weights.json")) as f:
        w = json.load(f)
    with open(os.path.join(bad, "weights.json"), "w") as f:
        json.dump(w[:-1], f)
    raises(lambda: ms.load_model(bad), "needs 84", "one weight missing")


def t_kernel(n_cases):
    print(f"\n{YELLOW}[10] In the kernel: every scenario, every model, every pipeline{NC}")
    import pipeline_setup as PS
    import check_pipelines as V
    from common import write_vector_map
    kif = V.TEST_RUN_DEFAULT_INGRESS_IFINDEX
    n_na = 0
    for scen in sorted(MATRIX):
        topo = ms.load_topology(scen)
        for m in sorted(_all_models(topo).values(), key=lambda m: m.name):
            if ms.mismatches(m, topo):
                continue
            node = PS.node_index_for(m)
            slot = PS.ingress_slot_for(m)
            ttl_max = int(topo.get("initial_ttl", 30))
            for pipe in pl.PIPELINES:
                label = f"{scen}/{m.name}/{pipe}"
                chatter = io.StringIO()
                try:
                    with contextlib.redirect_stdout(chatter):
                        setup = PS.build(pipe, m, node_index=node)
                        PS.register_model_id(setup, 190)
                except PS.NotApplicable as e:
                    n_na += 1
                    print(f"  {YELLOW}[N/A ]{NC} {label}: {e}")
                    continue
                PS.set_node(setup, node)
                PS.set_ingress(setup, kif, slot)
                rng = random.Random(20260929)
                good = 0
                for i in range(n_cases):
                    ls = [rng.randint(0, 1) for _ in
                          range((m.feature("link_state") or {"size": 0})["size"])]
                    qs = [rng.randint(0, 15) for _ in
                          range((m.feature("queue_occupancy") or {"size": 0})["size"])]
                    ttl = rng.randint(2, max(2, ttl_max))
                    PS.seed_inputs(setup, link_state=ls or None,
                                   queues=qs or None)
                    want = (0 if pipe == "baseline" else
                            PS.reference(m, ttl, link_state=ls or None,
                                         ingress_port=slot or 0,
                                         node_index=node,
                                         queues=qs or None)[0])
                    mid = 190 if i % 2 else 0
                    frame = V.build_frame_sparse(mid, ttl, m.scale, m.n_in,
                                                 m.n_out)
                    V._reset_stats(setup, n_classes=m.n_out)
                    V.prog_test_run(setup["disp"].fd, frame, repeat=1)
                    got = next((c for c in range(m.n_out)
                                if V._read_u64(setup["cls_stats"], c) > 0), -1)
                    good += (got == want)
                if not check(good == n_cases,
                             f"{label:40s} {good}/{n_cases} decisions like "
                             f"the reference"):
                    print(chatter.getvalue())
                owner = setup.get("owner")
                if owner is not None:
                    owner.stop()
    if n_na:
        print(f"  {YELLOW}[INFO]{NC} {n_na} combinations not applicable "
              f"(pipeline limits), not counted as outcomes")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--kernel", action="store_true",
                    help="also the check in the kernel (root, BCC)")
    ap.add_argument("--n", type=int, default=40,
                    help="inputs per combination in the kernel check")
    args = ap.parse_args()
    if args.kernel and os.geteuid() != 0:
        print(f"{RED}--kernel loads eBPF programs: root needed{NC} "
              f"(sudo python3 ipa/test/test_model_source.py --kernel)")
        return 2
    print(f"{YELLOW}=== model_source / pipeline_limits / topologies ==={NC}")
    root = tempfile.mkdtemp(prefix="ipa_model_source_")
    try:
        t_loading()
        t_checkpoint()
        t_synth_semantics()
        t_matrix()
        t_mismatch_reasons(root)
        t_scenarios(root)
        t_pipelines()
        t_agrees_with_synth_kernel()
        t_errors(root)
        if args.kernel:
            t_kernel(args.n)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    total = _n_pass + _n_fail
    colour = GREEN if _n_fail == 0 else RED
    print(f"\n{YELLOW}{'=' * 60}{NC}")
    print(f"{colour} {_n_pass}/{total} checks passed{NC}")
    print(f"{YELLOW}{'=' * 60}{NC}")
    return 0 if _n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
