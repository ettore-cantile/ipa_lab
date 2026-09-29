#!/usr/bin/env python3
"""
test_model_source.py -- models, scenarios and their compatibility.

Userspace only: no root, no BCC, no kernel. Checks model_source.py (one loader
for the checkpoint, the synthetic presets and the descriptor fixtures),
pipeline_limits.py (which pipeline can run which shape) and the scenarios
under topologies/.

What is checked
---------------
  loading        every reference resolves, with the shape, weight count and
                 class semantics its own files declare -- the checkpoint's
                 DROP 5 / class 6 UNUSED, a synthetic model's drop_class.
  checkpoint     the int8 weights and scale are the ones every bench measures
                 (weights.json, weights_float.json's scale_factor).
  compatibility  the scenario x model matrix: a model runs on a network only
                 if every feature width equals the network's dimension and
                 the ttl scale equals its initial TTL. Includes the case that
                 motivated it: a node one-hot of 52 on a 30-node network.
  scenarios      a network over the compiled ceilings, or missing a required
                 dimension, is refused with the reason.
  pipelines      the P2/P3 ceilings; verify_synth_kernel.fuori_limiti
                 answers through them (it had its own copy until 2026-09-29).
  errors         unknown references, a missing checkpoint, a fixture without
                 a network, a weight file of the wrong length.
  kernel         (--kernel, root) every scenario x compatible model x
                 pipeline, loaded by pipeline_setup: random inputs through
                 the real dispatcher with BPF_PROG_TEST_RUN, under model_id 0
                 and under 190 (the id pktgen writes), class compared with
                 the reference. The baseline has no model: it must redirect.

    python3 ipa/test/test_model_source.py
    sudo python3 ipa/test/test_model_source.py --kernel [--n 40]
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

import model_source as ms          # noqa: E402
import pipeline_limits as pl       # noqa: E402

GREEN, RED, YELLOW, NC = "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0m"
_n_pass = _n_fail = 0

PRESETS = ("ipa_like", "small", "large", "deep", "mixed", "sparse", "ones",
           "ipa_ttl16")
FIXTURE = os.path.join(_TEST_DIR, "fixtures", "sparse_hetero_11")

# shape, weight count, DROP class -- from each model's own files
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

# scenario -> the models that run on it
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
    fail(f"{msg}: nessun errore")
    return False


def _write_topology(root, name, cfg):
    d = os.path.join(root, name)
    os.makedirs(d)
    with open(os.path.join(d, ms.TOPOLOGY_FILE), "w") as f:
        json.dump(cfg, f)
    return d


# ---------------------------------------------------------------------------
def t_loading():
    print(f"\n{YELLOW}[1] Ogni riferimento si carica con la forma dichiarata{NC}")
    for ref, (shape, nw, drop) in EXPECTED.items():
        m = ms.load_model(ref)
        check(m.shape == shape and len(m.weights) == nw
              and m.semantics.drop_class == drop,
              f"{ref:16s} {m.shape}, {len(m.weights)} pesi, DROP {m.semantics.drop_class}")


def t_checkpoint():
    print(f"\n{YELLOW}[2] Il checkpoint e' quello che i banchi misurano{NC}")
    m = ms.load_model("checkpoint")
    with open(os.path.join(SHARED_DIR, "weights.json")) as f:
        wj = json.load(f)
    with open(os.path.join(SHARED_DIR, "weights_float.json")) as f:
        scale = json.load(f)["scale_factor"]
    check(m.weights == wj, "pesi int8 identici a weights.json")
    check(m.scale == scale, f"scala {m.scale} == scale_factor di weights_float.json")
    check(m.reference and m.name == "germany50", "e' il riferimento, addestrato su germany50")
    sem = m.semantics
    check(sem.action_of(5) == "DROP" and sem.action_of(6) == "UNUSED"
          and sem.logical_ports == [0, 1, 2, 3, 4],
          "semantica dal descrittore: FORWARD 0-4, DROP 5, UNUSED 6")
    check(m.feature("ttl")["scale"] == 30, "ttl diviso per 30 (normalize_by)")


def t_synth_semantics():
    print(f"\n{YELLOW}[3] Un modello sintetico usa la SUA semantica{NC}")
    m = ms.load_model("synth:ipa_like")
    sem = m.semantics
    check(sem.action_of(6) == "DROP" and sem.action_of(5) == "FORWARD",
          "ipa_like: DROP 6 come dichiara model.json, non il DROP 5 del checkpoint")
    check(sem.logical_ports == list(range(6)), "sei porte logiche, 0-5")
    s = ms.semantics_with_drop(5, 2)
    check([s.action_of(c) for c in range(5)] ==
          ["FORWARD", "FORWARD", "DROP", "FORWARD", "FORWARD"]
          and [s.port_of(c) for c in (0, 1, 3, 4)] == [0, 1, 2, 3],
          "DROP in mezzo: le porte restano consecutive nell'ordine delle classi")


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
    print(f"\n{YELLOW}[4] Scenari x modelli{NC}")
    check(set(ms.list_topologies()) >= set(MATRIX),
          f"scenari presenti: {', '.join(ms.list_topologies())}")
    for name, expected in MATRIX.items():
        topo = ms.load_topology(name)
        fits = {n for n, m in _all_models(topo).items()
                if not ms.mismatches(m, topo)}
        check(fits == expected, f"{name:16s} -> {sorted(fits)}")


def t_mismatch_reasons(root):
    print(f"\n{YELLOW}[5] Il motivo dell'esclusione e' leggibile{NC}")
    d = _write_topology(root, "rete30", {"n_interfaces": 6, "n_nodes": 30,
                                         "n_queues": 4, "initial_ttl": 30})
    topo = ms.load_topology(d)
    why = ms.mismatches(ms.load_model("checkpoint"), topo)
    check(why == ["nodi: il modello ne vuole 52, la rete ne ha 30"],
          f"one-hot a 52 su una rete da 30 nodi: {why}")
    why = ms.mismatches(ms.load_model("synth:ipa_ttl16"),
                        ms.load_topology("germany50"))
    check(why == ["TTL iniziale: il modello ne vuole 16, la rete ne ha 30"],
          f"ipa_ttl16 su germany50: {why}")
    d = _write_topology(root, "senzattl", {"n_interfaces": 6, "n_nodes": 52})
    why = ms.mismatches(ms.load_model("checkpoint"), ms.load_topology(d))
    check(any("TTL iniziale" in w for w in why),
          "una rete che non dichiara il TTL iniziale non e' data per buona")


def t_scenarios(root):
    print(f"\n{YELLOW}[6] Scenari fuori dai limiti compilati{NC}")
    d = _write_topology(root, "nove", {"n_interfaces": 9, "n_nodes": 10})
    raises(lambda: ms.load_topology(d), "above the compiled ceiling",
           "9 interfacce")
    d = _write_topology(root, "code", {"n_interfaces": 4, "n_nodes": 10,
                                       "n_queues": 9})
    raises(lambda: ms.load_topology(d), "above the compiled ceiling", "9 code")
    d = _write_topology(root, "mezza", {"n_interfaces": 4})
    raises(lambda: ms.load_topology(d), "missing", "manca n_nodes")
    raises(lambda: ms.load_topology("non_esiste"), "disponibili",
           "nome sconosciuto")
    g = ms.load_topology("germany50")
    check((g["n_interfaces"], g["n_nodes"], g["n_queues"], g["initial_ttl"])
          == (6, 52, 4, 30), "germany50: 6 / 52 / 4 / TTL 30")


def t_pipelines():
    print(f"\n{YELLOW}[7] Limiti delle pipeline{NC}")
    cases = [
        ([4, 4], 65, 7, None, None),
        ([4, 4, 4], 65, 7, None, None),
        ([8, 8], 117, 9, "MAX_WEIGHT_ENTRIES", "ML1_MAX_H1"),
        ([9, 9], 65, 7, "T2_MAX_H1", "ML1_MAX_H1"),
        ([4, 4, 6], 65, 7, "oltre il secondo", None),
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
          "P1 e P1.5: nessun tetto di forma")
    check(pl.why_not("baseline", [99], 999, 99) is None,
          "baseline: nessun modello, nessun limite")


def t_agrees_with_synth_kernel():
    print(f"\n{YELLOW}[8] verify_synth_kernel usa questi limiti{NC}")
    import verify_synth_kernel as VSK
    for name in PRESETS:
        m = ms.load_model(f"synth:{name}")
        model = {"arch": {"hidden": m.hidden, "n_in": m.n_in,
                          "n_out": m.n_out}}
        for pipe, key in (("p2", "template"), ("p3", "modular")):
            old = VSK.fuori_limiti(pipe, model)
            new = pl.why_not(key, m.hidden, m.n_in, m.n_out)
            check(old == new,
                  f"{name:10s} {pipe}: {new or 'ammesso'}")


def t_errors(root):
    print(f"\n{YELLOW}[9] Errori comprensibili{NC}")
    raises(lambda: ms.load_model("synth:nope"), "sconosciuto", "preset inesistente")
    raises(lambda: ms.load_model("pippo"), "non riconosciuto", "riferimento ignoto")
    raises(lambda: ms.load_model("checkpoint:/tmp/non_esiste.pt"),
           "non trovato", "checkpoint mancante")
    raises(lambda: ms.load_model(FIXTURE), "serve lo scenario",
           "fixture senza rete")
    bad = os.path.join(root, "corto")
    shutil.copytree(ms.load_model("synth:small").path, bad)
    with open(os.path.join(bad, "weights.json")) as f:
        w = json.load(f)
    with open(os.path.join(bad, "weights.json"), "w") as f:
        json.dump(w[:-1], f)
    raises(lambda: ms.load_model(bad), "ne vuole 84", "un peso in meno")


def t_kernel(n_cases):
    print(f"\n{YELLOW}[10] Nel kernel: ogni scenario, ogni modello, ogni pipeline{NC}")
    import pipeline_setup as PS
    import verify_prog_run as V
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
                chatter = io.StringIO()   # the control planes' prints
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
                             f"{label:40s} {good}/{n_cases} decisioni come "
                             f"il riferimento"):
                    print(chatter.getvalue())
                owner = setup.get("owner")
                if owner is not None:
                    owner.stop()
    if n_na:
        print(f"  {YELLOW}[INFO]{NC} {n_na} combinazioni non applicabili "
              f"(limiti delle pipeline), non contate come esiti")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--kernel", action="store_true",
                    help="anche il controllo nel kernel (root, BCC)")
    ap.add_argument("--n", type=int, default=40,
                    help="ingressi per combinazione nel controllo kernel")
    args = ap.parse_args()
    if args.kernel and os.geteuid() != 0:
        print(f"{RED}--kernel carica programmi eBPF: serve root{NC} "
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
