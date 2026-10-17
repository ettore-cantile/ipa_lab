#!/usr/bin/env python3
"""check_kernel_vs_reference.py -- the eBPF pipelines against the reference.

On synthetic models, compares float (Python), int8 (Python) and int8 (eBPF in
the kernel, BPF_PROG_TEST_RUN): the kernel must decide exactly like the integer
reference. Needs root.

Usage:
    sudo python3 ipa/test/check_kernel_vs_reference.py --all --n 300
    sudo python3 ipa/test/check_kernel_vs_reference.py --scenario <dir> --pipeline p2
"""
import os
import sys
import json
import random
import argparse
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")

NOMI = {"queue_occ": "queue_occupancy"}


def ok(m):
    print(f"  {GREEN}[PASS]{NC} {m}")


def fail(m):
    print(f"  {RED}[FAIL]{NC} {m}")


def info(m):
    print(f"  {YELLOW}[INFO]{NC} {m}")


def note(m):
    print(f"  {GREY}{m}{NC}")


# --- the synthetic scenario, translated into what the eBPF generator expects ---
def carica_scenario(d):
    """model.json + the two weight files."""
    with open(os.path.join(d, "model.json")) as f:
        model = json.load(f)
    with open(os.path.join(d, "weights.json")) as f:
        wi = json.load(f)
    with open(os.path.join(d, "weights_float.json")) as f:
        wf = json.load(f)
    wi = wi["weights"] if isinstance(wi, dict) else wi
    wf = wf["weights"] if isinstance(wf, dict) else wf
    return model, wi, wf


def descrittore(model):
    """The scenario descriptor in the `derive_shape` format."""
    out = []
    for f in model["descriptor"]:
        t = NOMI.get(f["name"], f["name"])
        out.append({"type": t, "size": int(f["size"]),
                    "scale": int(f.get("scale", 1) or 1)})
    return out


def dims_strati(model):
    """[(n_prev, n_cur), ...] from the shape declared in the scenario."""
    a = model["arch"]
    sizes = [int(a["n_in"])] + [int(h) for h in a["hidden"]] + [int(a["n_out"])]
    return [(sizes[i], sizes[i + 1]) for i in range(len(sizes) - 1)]


# --- sampling: only what the datapath can express ---
def campioni(feats, n, seed, ttl_min=2, ttl_max=30):
    """`n` inputs, each as (dense map values, port, ttl)."""
    rng = random.Random(seed)
    per_tipo = {f["type"]: f["size"] for f in feats}
    n_if = per_tipo.get("ingress_iface", 0)
    fuori = []
    for _ in range(n):
        mappe = {}
        if "link_state" in per_tipo:
            mappe["link_state"] = [rng.randint(0, 1)
                                   for _ in range(per_tipo["link_state"])]
        if "queue_occupancy" in per_tipo:
            mappe["queue_state"] = [rng.randint(0, 15)
                                    for _ in range(per_tipo["queue_occupancy"])]
        fuori.append({
            "mappe": mappe,
            "porta": rng.randint(0, n_if) if n_if else 0,
            "ttl": rng.randint(ttl_min, ttl_max),
        })
    return fuori


def vettore_intero(feats, caso, node_index, scale_ttl):
    """The input vector as the datapath builds it."""
    import model_meta as mm
    x = [0] * sum(f["size"] for f in feats)
    o = 0
    for f in feats:
        t, size = f["type"], f["size"]
        kind = mm.FEATURE_CATALOG[t]["kind"]
        if kind == "scalar":
            x[o] = caso["ttl"] & 0xFF
        elif kind == "dense_vector_map":
            vals = caso["mappe"].get(mm.FEATURE_CATALOG[t]["map"], [0] * size)
            for i in range(size):
                x[o + i] = vals[i]
        elif kind == "onehot" and t == "ingress_iface":
            if 1 <= caso["porta"] <= size:
                x[o + caso["porta"] - 1] = 1
        elif kind == "onehot" and t == "node":
            if node_index is not None and 0 <= node_index < size:
                x[o + node_index] = 1
        o += size
    return x


def scale_colonne(model):
    """The per-column divisor, from the scenario descriptor."""
    out = []
    for f in model["descriptor"]:
        out.extend([int(f.get("scale", 1) or 1)] * int(f["size"]))
    return out


# --- the three paths ---
def via_float(wf, layer_dims, x_int, scales):
    from synth import reference as ref
    x_f = [v / s if s else float(v) for v, s in zip(x_int, scales)]
    return ref.argmax(ref.forward_float(wf, layer_dims, x_f))


def logit_int8_python(wi, layer_dims, x_int, scales, scale):
    from synth import reference as ref
    return ref.forward_int8(wi, layer_dims, x_int, scales, scale=scale)


def via_int8_python(wi, layer_dims, x_int, scales, scale):
    """The pure-Python integer reference, from the `synth` package."""
    from synth import reference as ref
    return ref.argmax(logit_int8_python(wi, layer_dims, x_int, scales, scale))


def via_int8_verify(wi, feats, model, caso, node_index, scale):
    """The integer reference of the other side of the project, as a cross-check."""
    from check_pipelines import ref_infer_sparse
    cls, _ = ref_infer_sparse(
        wi, feats, [int(h) for h in model["arch"]["hidden"]],
        int(model["arch"]["n_out"]), caso["ttl"], 0,
        caso["mappe"], ingress_port=caso["porta"], scale=scale,
        node_index=node_index)
    return cls


_KIF_SORGENTE = 1


def via_sorgente_c(prog, caso, feats):
    """The C that P1 compiles, evaluated from its TEXT with p1_c_eval."""
    maps = dict(caso["mappe"])
    if any(f["type"] == "ingress_iface" for f in feats):
        maps["ingress_port"] = {_KIF_SORGENTE: int(caso["porta"])}
    return prog.run(caso["ttl"], maps, ingress_ifindex=_KIF_SORGENTE)


def via_ebpf(setup, caso, model, scale):
    """One packet through the real XDP program, and the class it
    chose."""
    from check_pipelines import (build_frame_sparse, prog_test_run,
                                 _reset_stats, _read_u64)
    from common import write_vector_map

    for nome, vals in caso["mappe"].items():
        write_vector_map(setup["b"], nome, vals)

    if "ingress_port" in setup:
        from check_pipelines import TEST_RUN_DEFAULT_INGRESS_IFINDEX as _KIF
        setup["ingress_port"][ct.c_uint32(_KIF)] = \
            ct.c_uint32(int(caso["porta"]))

    n_out = int(model["arch"]["n_out"])
    frame = build_frame_sparse(0, caso["ttl"], scale,
                               int(model["arch"]["n_in"]), n_out)
    _reset_stats(setup, n_classes=n_out)
    prog_test_run(setup["disp"].fd, frame, repeat=1)

    for c in range(n_out):
        if _read_u64(setup["cls_stats"], c) > 0:
            return c
    return -1


class NonApplicabile(Exception):
    """The scenario does not fit the limits of the chosen pipeline."""


def fuori_limiti(pipeline, model):
    """Why `pipeline` cannot run this model, or None."""
    import pipeline_limits
    a = model["arch"]
    return pipeline_limits.why_not(
        {"p1": "p1_static", "p2": "template", "p3": "modular"}[pipeline],
        a["hidden"], a["n_in"], a["n_out"])


def _costruisci(pipeline, M, node_index):
    """A pipeline on the scenario's model, with the common builders
    (pipeline_setup.build)."""
    import pipeline_setup as PS
    try:
        return PS.build(pipeline, M, node_index=node_index)
    except PS.NotApplicable as e:
        raise NonApplicabile(str(e))


def costruisci_p2(M, node_index):
    """P2 on the synthetic weights."""
    import pipeline_setup as PS
    from ebpf_template_arch import load_model_desc
    setup = _costruisci("template", M, node_index)
    PS.set_node(setup, node_index)
    b = setup["b"]
    setup["ingress_port"] = b["ingress_port_t2"]
    setup["ricarica_desc"] = lambda f: load_model_desc(b, f, M.n_in, model_id=0)
    return setup


def costruisci_p3(M, node_index):
    """P3 on the synthetic weights."""
    import pipeline_setup as PS
    from ebpf_modular import load_model_desc
    setup = _costruisci("modular", M, node_index)
    PS.set_node(setup, node_index)
    b = setup["b"]
    setup["ingress_port"] = b["ingress_port_t3"]
    setup["ricarica_desc"] = lambda f: load_model_desc(b, f, M.n_in, model_id=0)
    return setup


def scale_colonne_default(model):
    """The per-column divisors the datapath would use if it ignored the
    declared scale."""
    import model_meta as mm
    out = []
    for f in model["descriptor"]:
        t = NOMI.get(f["name"], f["name"])
        out.extend([int(mm.feature_scale(t))] * int(f["size"]))
    return out


def sorgente_p1(M, node_index):
    """P1's source on the synthetic weights, with the scenario descriptor."""
    import p1_aot
    return p1_aot.p1_source(
        [(0, M.weights, M.scale)], hidden_dims=tuple(M.hidden),
        features=M.features, n_out=M.n_out, semantics=M.semantics,
        static_node=node_index)


def costruisci_p1(M, node_index):
    """P1 (the AOT object) on the synthetic weights, with the scenario
    descriptor and the frozen node, loaded and pinned by loader_aot."""
    setup = _costruisci("p1_static", M, node_index)
    try:
        setup["ingress_port"] = setup["b"]["ingress_port"]
    except Exception:
        pass
    return setup


def confronta(d, n, seed, node_index, dry=False, pipeline="p1"):
    """One scenario, one pipeline."""
    nome = os.path.basename(os.path.abspath(d))
    model, wi, wf = carica_scenario(d)
    import model_source as ms
    M = ms.load_model(d)
    feats = descrittore(model)
    larghezza_nodo = next((f["size"] for f in feats if f["type"] == "node"), 0)
    if larghezza_nodo and node_index >= larghezza_nodo:
        node_index = larghezza_nodo - 1
    scale = int(model["quant"]["scale_factor"])
    layer_dims = dims_strati(model)
    scales = scale_colonne(model)

    print(f"\n{YELLOW}=== {nome}: {model['arch']['shape']}, "
          f"{len(wi)} weights, scale {scale} ==={NC}")
    note(f"descriptor: {[(f['type'], f['size']) for f in feats]}")

    att = os.path.join(d, "inputs.json")
    if os.path.exists(att):
        with open(att) as f:
            depositati = json.load(f).get("col_scales")
        if depositati is not None and list(depositati) != list(scales):
            fail(f"recomputed col_scales differ from the stored ones "
                 f"({scales[:8]}... against {list(depositati)[:8]}...)")
            return False
        ok("col_scales recomputed from the descriptor == the stored ones")

    import model_meta as _mm
    fuori_default = []
    for f in model["descriptor"]:
        t = NOMI.get(f["name"], f["name"])
        dichiarata = int(f.get("scale", 1) or 1)
        catalogo = int(_mm.feature_scale(t))
        if dichiarata != catalogo:
            fuori_default.append((t, dichiarata, catalogo))
    if fuori_default:
        for t, dich, cat in fuori_default:
            info(f"feature `{t}` uses scale {dich}, different from the "
                 f"catalogue default ({cat}): the datapath must follow the model")

    casi = campioni(feats, n, seed)
    scales_def = scale_colonne_default(model)
    k_scala = 0
    if fuori_default:
        k_scala = sum(
            via_int8_python(wi, layer_dims, x, scales, scale)
            != via_int8_python(wi, layer_dims, x, scales_def, scale)
            for x in (vettore_intero(feats, c, node_index, scale) for c in casi))
        if k_scala:
            ok(f"the declared scale moves {k_scala}/{len(casi)} decisions "
               f"against the default: this scenario puts it to the test")
        else:
            info(f"the declared scale moves 0/{len(casi)} decisions: with "
                 f"these weights a 100% does NOT prove the datapath applies it")

    if pipeline != "p1":
        motivo = fuori_limiti(pipeline, model)
        if motivo:
            info(f"{pipeline.upper()} NOT APPLICABLE: {motivo}")
            return {"esito": None, "scala_provata": False}

    setup = prog = None
    if not dry:
        costruisci = {"p1": costruisci_p1, "p2": costruisci_p2,
                      "p3": costruisci_p3}[pipeline]
        try:
            setup = costruisci(M, node_index)
        except NonApplicabile as e:
            info(f"{pipeline.upper()} NOT APPLICABLE: {e}")
            return {"esito": None, "scala_provata": False}
        dove = "frozen" if pipeline == "p1" else "from the node_id map"
        ok(f"{pipeline.upper()} compiled and loaded on the synthetic weights "
           f"(node {node_index}, {dove})")
    else:
        from p1_c_eval import P1Program
        prog = P1Program(sorgente_p1(M, node_index),
                         func="xdp_model")
        ok(f"P1 generated on the synthetic weights and read by p1_c_eval "
           f"(frozen node: {node_index})")
        if pipeline != "p1":
            note(f"{pipeline.upper()} cannot be evaluated without a kernel: "
                 f"--dry-run keeps the Python paths and P1's C")
    acc_qf = acc_impl = acc_tot = acc_ref = acc_cat = acc_src = 0
    esempi = []
    for c in casi:
        x = vettore_intero(feats, c, node_index, scale)
        c_float = via_float(wf, layer_dims, x, scales)
        c_int8 = via_int8_python(wi, layer_dims, x, scales, scale)
        if dry:
            acc_qf += (c_float == c_int8)
            atteso = logit_int8_python(wi, layer_dims, x, scales, scale)
            dal_c = via_sorgente_c(prog, c, feats)
            acc_src += (dal_c["logits"] == atteso and dal_c["cls"] == c_int8)
            if dal_c["logits"] != atteso and len(esempi) < 5:
                esempi.append((c, atteso, dal_c["logits"]))
            continue
        c_ref = via_int8_verify(wi, feats, model, c, node_index, scale)
        c_bpf = via_ebpf(setup, c, model, scale)
        acc_qf += (c_float == c_int8)
        acc_ref += (c_int8 == c_ref)
        acc_cat += (c_ref == c_bpf)
        acc_impl += (c_int8 == c_bpf)
        acc_tot += (c_float == c_bpf)
        if c_int8 != c_bpf and len(esempi) < 5:
            esempi.append((c, c_int8, c_bpf))

    if dry:
        n = len(casi)
        print()
        print(f"  float vs int8 (Python): agreement {100.0*acc_qf/n:.2f}%, "
              f"disagreement {100.0*(n-acc_qf)/n:.2f}%  over {n} inputs")
        if acc_src == n:
            ok(f"int8 (Python) vs P1's C (evaluated source): {n}/{n} "
               f"inputs with identical logits")
        else:
            fail(f"int8 (Python) vs P1's C (evaluated source): logits "
                 f"differ on {n - acc_src}/{n}. The reference and the "
                 f"generator do not compute the same formula.")
            for c, a, b in esempi:
                note(f"  ttl={c['ttl']} port={c['porta']} maps={c['mappe']} "
                     f"-> python={a} C={b}")
        note("--dry-run mode: the kernel was not queried; the C "
             "is evaluated from its text, without clang, verifier and JIT")
        return {"esito": acc_src == n, "scala_provata": k_scala > 0}

    n = len(casi)
    print()
    print(f"  {'comparison':34s} {'agreement':>9s} {'disagreement':>12s}")
    print("  " + "-" * 56)
    for etichetta, acc in (
            ("float  vs  int8 (Python)", acc_qf),
            ("int8 (Python)  vs  int8 (riferim.)", acc_ref),
            ("int8 (riferim.)  vs  int8 (eBPF)", acc_cat),
            ("int8 (Python)  vs  int8 (eBPF)", acc_impl),
            ("float  vs  int8 (eBPF)", acc_tot)):
        print(f"  {etichetta:34s} {100.0*acc/n:8.2f}% "
              f"{100.0*(n-acc)/n:10.2f}%")
    print()

    if acc_impl == n:
        ok(f"implementation: {n}/{n} identical decisions between integer "
           f"reference and eBPF")
    else:
        fail(f"implementation: {n - acc_impl}/{n} DIFFERENT decisions between "
             f"integer reference and eBPF. It is NOT quantization. Causes, "
             f"in order: (1) the bench does not pass the kernel an input the "
             f"reference uses; (2) a scale declared by the model that the "
             f"datapath does not apply, see above; (3) a datapath defect.")
        for c, a, b in esempi:
            note(f"  ttl={c['ttl']} port={c['porta']} maps={c['mappe']} "
                 f"-> python={a} ebpf={b}")
    if acc_ref != n and acc_cat == n:
        ok(f"the datapath is EXACT with respect to the scale it was "
           f"compiled with: {n}/{n} decisions identical to `ref_infer_sparse`. "
           f"The disagreement with `synth.reference` ({n - acc_ref}/{n}) is "
           f"entirely the scale declared by the model and never applied.")
    elif acc_ref != n:
        fail(f"the two Python integer implementations disagree on "
             f"{n - acc_ref}/{n}, AND the eBPF agrees with neither: "
             f"the scale does not explain it, to be investigated")
    if acc_qf < n:
        note(f"the {100.0*(n-acc_qf)/n:.1f}% float/int8 disagreement is "
             f"quantization: a property of the model and the scale, not a "
             f"defect")

    controllo = True
    scala_provata = False
    if pipeline != "p1" and fuori_default:
        if not k_scala:
            info("negative check not run: K = 0, it would distinguish "
                 "nothing")
        else:
            import model_meta as _mm2
            feats_def = [dict(f, scale=int(_mm2.feature_scale(f["type"])))
                         for f in feats]
            setup["ricarica_desc"](feats_def)
            segue_def = stacca = 0
            for c in casi:
                x = vettore_intero(feats, c, node_index, scale)
                c_bpf = via_ebpf(setup, c, model, scale)
                segue_def += (c_bpf == via_int8_python(wi, layer_dims, x,
                                                       scales_def, scale))
                stacca += (c_bpf != via_int8_python(wi, layer_dims, x,
                                                    scales, scale))
            setup["ricarica_desc"](feats)
            if segue_def == n and stacca == k_scala:
                scala_provata = True
                ok(f"negative check: with feat_ent.scale rewritten to the "
                   f"default the eBPF follows the default reference on "
                   f"{n}/{n} and departs from the declared one exactly on the "
                   f"{k_scala} expected cases -- the kernel reads that byte")
            else:
                controllo = False
                fail(f"negative check: with feat_ent.scale at the default "
                     f"the eBPF follows that reference on {segue_def}/{n} and "
                     f"departs from the declared one on {stacca} cases "
                     f"(expected {n}/{n} and {k_scala}). The datapath does not "
                     f"divide by the byte the control plane writes.")
    elif pipeline == "p1" and fuori_default and k_scala and acc_impl == n:
        scala_provata = True
    esito = acc_impl == n and acc_ref == n and controllo
    return {"esito": esito, "scala_provata": scala_provata and esito}


# --- the scenarios: present or regenerated, never assumed ---
def scenari(base_richiesta=None, n_inputs=64):
    """The scenario folders, generating them if they are missing."""
    import tempfile
    from synth.generate import preset, generate_scenario, PRESETS

    if base_richiesta and os.path.isdir(base_richiesta):
        dirs = sorted(os.path.join(base_richiesta, d)
                      for d in os.listdir(base_richiesta)
                      if os.path.isdir(os.path.join(base_richiesta, d)))
        if dirs:
            note(f"scenarios already present in {base_richiesta}")
            presenti = {os.path.basename(x) for x in dirs}
            mancanti = [p for p in PRESETS if p not in presenti]
            if mancanti:
                base = tempfile.mkdtemp(prefix="ipa_synth_scen_")
                info(f"presets missing from that folder: {mancanti}; "
                     f"generating them in {base}")
                for nome in mancanti:
                    d = os.path.join(base, nome)
                    generate_scenario(preset(nome), d, n_inputs=n_inputs)
                    dirs.append(d)
            return dirs

    base = tempfile.mkdtemp(prefix="ipa_synth_scen_")
    info(f"scenarios not present: regenerating them in {base} "
         f"({len(PRESETS)} presets, fixed seed)")
    dirs = []
    for nome in PRESETS:
        d = os.path.join(base, nome)
        generate_scenario(preset(nome), d, n_inputs=n_inputs)
        dirs.append(d)
    return dirs


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("USO")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario", help="folder of a synthetic scenario")
    p.add_argument("--all", action="store_true",
                   help="every scenario in ipa/synth/scenarios/")
    p.add_argument("--n", type=int, default=200,
                   help="inputs per scenario (default 200)")
    p.add_argument("--seed", type=int, default=20260918)
    p.add_argument("--node", type=int, default=7,
                   help="node index (P1: frozen in the program; "
                        "P2/P3: written in the node_id map)")
    p.add_argument("--pipeline", choices=("p1", "p2", "p3"), default="p1",
                   help="which pipeline to compare (default p1)")
    p.add_argument("--dry-run", action="store_true",
                   help="the two Python paths (float against int8) and P1's C "
                        "evaluated from the source (p1_c_eval): needs neither "
                        "Linux nor root, and checks inputs and formula before "
                        "taking the test to a real machine")
    a = p.parse_args()

    if not a.dry_run:
        if sys.platform != "linux":
            sys.exit(f"Linux needed, not {sys.platform} "
                     f"(or --dry-run for the Python paths only)")
        if os.geteuid() != 0:
            sys.exit("root needed: sudo python3 ipa/test/check_kernel_vs_reference.py ...")

    if a.all:
        dirs = scenari(os.path.join(SHARED_DIR, "synth", "scenarios"))
    elif a.scenario:
        if not os.path.isdir(a.scenario):
            sys.exit(f"{a.scenario} does not exist. The scenarios are "
                     f"regenerable artefacts not kept in git: use --all, which "
                     f"generates them, or "
                     f"`python3 ipa/synth/make_scenario.py --preset all`.")
        dirs = [a.scenario]
    else:
        p.error("--scenario DIR or --all is needed")

    print(f"{YELLOW}{'=' * 74}{NC}")
    print(f" Three-way comparison on SYNTHETIC models: float / int8 Python / "
          f"eBPF -- pipeline {a.pipeline.upper()}")
    print(f"{YELLOW}{'=' * 74}{NC}")

    esiti, provata = {}, []
    for d in dirs:
        try:
            r = confronta(d, a.n, a.seed, a.node, dry=a.dry_run,
                          pipeline=a.pipeline)
            esiti[os.path.basename(d)] = r["esito"]
            if r["scala_provata"]:
                provata.append(os.path.basename(d))
        except Exception as e:
            fail(f"{os.path.basename(d)}: {type(e).__name__}: {e}")
            esiti[os.path.basename(d)] = False

    print(f"\n{YELLOW}{'=' * 74}{NC}")
    buoni = sum(1 for v in esiti.values() if v)
    na = sum(1 for v in esiti.values() if v is None)
    if na:
        print(f" {na} scenarios NOT APPLICABLE to {a.pipeline.upper()} (the "
              f"reason is in the detail above): not counted as outcomes")
    if a.dry_run:
        print(f" {buoni}/{len(esiti) - na} scenarios in --dry-run with identical "
              f"logits between the Python reference and P1's evaluated C.")
        print(f" {RED}The kernel was NOT queried{NC}: "
              f"the equivalence with eBPF remains to be shown, run again "
              f"without --dry-run on Linux.")
        note(" The float/int8 agreement printed above is NOT expected.json's "
             "`quant_agreement` and must not be compared with it: there the "
             "inputs are sampled freely, here only among those the datapath "
             "can express.")
    else:
        print(f" {buoni}/{len(esiti) - na} scenarios with exact numerical "
              f"equivalence between integer reference and eBPF")
    if provata:
        print(f" scale different from the default put to the test"
              f"{' and seen by the kernel' if not a.dry_run and a.pipeline != 'p1' else ''}"
              f": {', '.join(provata)}")
    else:
        print(f" {RED}no scenario put a scale different from the default "
              f"to the test{NC}: this run says nothing about it")
    for nome, v in esiti.items():
        stato = "N/A" if v is None else ("OK " if v else "NO ")
        print(f"   {stato} {nome}")
    print(f"{YELLOW}{'=' * 74}{NC}")
    return 0 if all(v is not False for v in esiti.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
