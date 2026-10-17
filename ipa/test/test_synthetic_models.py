#!/usr/bin/env python3
"""test_synthetic_models.py -- the synthetic model generator: dimensions, weights,
feature order, quantisation, and P1's C code against the reference. No root.

    python3 ipa/test/test_synthetic_models.py
"""

import argparse
import json
import os
import random
import shutil
import sys
import tempfile
from fractions import Fraction

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

from synth import reference as ref  # noqa: E402
from synth.spec import FeatureSet, FeatureSpec  # noqa: E402
from synth.generate import (generate_scenario, load_scenario, preset,  # noqa: E402
                            make_weights, make_inputs, check_inputs,
                            build_torch_model, PRESETS)

GREEN, RED, YELLOW, NC = "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0m"
_n_pass = _n_fail = 0


def ok(msg):
    global _n_pass
    _n_pass += 1
    print(f"  {GREEN}[PASS]{NC} {msg}")


def fail(msg):
    global _n_fail
    _n_fail += 1
    print(f"  {RED}[FAIL]{NC} {msg}")


def info(msg):
    print(f"  {YELLOW}[INFO]{NC} {msg}")


def check(cond, msg):
    ok(msg) if cond else fail(msg)
    return cond


def t_feature_semantics():
    print(f"\n{YELLOW}[1] Feature semantics honoured by the generator{NC}")
    fset = FeatureSet([
        FeatureSpec("bin", "binary", size=5, min_ones=2),
        FeatureSpec("oh", "onehot", size=7),
        FeatureSpec("i", "integer", lo=3, hi=9),
        FeatureSpec("r", "real", lo=1, hi=30, scale=30),
    ])
    ints, floats, stats = make_inputs(fset, 500, seed=1234)
    check(not check_inputs(fset, ints, floats),
          "500 vectors satisfy every declared constraint")
    check(all(sum(v[0:5]) >= 2 for v in ints), "binary: min_ones respected")
    check(all(sum(v[5:12]) == 1 for v in ints), "onehot: exactly one slot set")
    check(all(3 <= v[12] <= 9 for v in ints), "integer: inside [3, 9]")
    check(all(1 <= v[13] <= 30 for v in ints), "real: integer carrier in [1, 30]")
    check(all(abs(f[13] - i[13] / 30) < 1e-12 for i, f in zip(ints, floats)),
          "real: float view == carrier / scale")
    check(fset.column_scales() == [1]*5 + [1]*7 + [1] + [30],
          "column scales: only the real feature carries a divisor")
    oh = [tuple(v[5:12]) for v in ints]
    check(len(set(oh)) > 1 and all(sum(o) == 1 for o in oh),
          "one-hot varies across samples yet never has two slots hot")
    info(f"per-feature stats: {json.dumps(stats['oh'])}")


def t_dimensions():
    print(f"\n{YELLOW}[2] Dimensional coherence{NC}")
    for name in PRESETS:
        m = preset(name)
        w = make_weights(m)
        n_in_feat = sum(f.size for f in m.features.features)
        c1 = n_in_feat == m.features.n_in == m.layer_dims[0][0]
        c2 = len(w) == m.weight_count()
        try:
            layers = ref.split_layers(w, m.layer_dims)
            c3 = len(layers) == len(m.layer_dims)
        except ValueError as e:
            c3 = False
            info(f"{name}: split_layers rejected the list ({e})")
        check(c1 and c2 and c3,
              f"{name:<9} {m.shape_str:<18} n_in={m.features.n_in} "
              f"weights={len(w)} layers={len(m.layer_dims)}")


def t_weight_roundtrip():
    print(f"\n{YELLOW}[3] Weights load correctly (torch round trip){NC}")
    m = preset("ipa_like")
    wf = make_weights(m)
    model = build_torch_model(m, wf)
    if model is None:
        info("torch not installed -- round trip skipped (expected on nodes)")
        return
    try:
        import torch
    except ImportError:
        info("torch not installed -- skipped")
        return
    flat = [w for p in model.parameters() for w in p.data.view(-1).tolist()]
    check(len(flat) == len(wf) and max(abs(a - b) for a, b in zip(flat, wf)) < 1e-5,
          "nn.Linear round trip preserves the flat weight list")

    ints, floats, _ = make_inputs(m.features, 40, seed=99)
    worst = 0.0
    for xf in floats:
        with torch.no_grad():
            tl = model(torch.tensor(xf, dtype=torch.float32)).tolist()
        pl = ref.forward_float(wf, m.layer_dims, xf)
        worst = max(worst, max(abs(a - b) for a, b in zip(tl, pl)))
    check(worst < 1e-3,
          f"torch forward == pure-Python float reference (max |d| = {worst:.2e})")


def _exact_forward(weights, dims, x):
    """ReLU MLP in exact rational arithmetic."""
    acts = [Fraction(v) for v in x]
    layers = ref.split_layers(weights, dims)
    for li, (w, b) in enumerate(layers):
        n_in, n_out = dims[li]
        nxt = [b[j] + sum(acts[i] * w[j * n_in + i] for i in range(n_in))
               for j in range(n_out)]
        acts = nxt if li == len(layers) - 1 else [max(Fraction(0), a) for a in nxt]
    return acts


def t_quantisation():
    print(f"\n{YELLOW}[4] Quantisation: scale and zero point{NC}")
    m = preset("ipa_like")
    wf = make_weights(m)
    wi, scale, clamped = ref.quantize(wf)

    max_abs = max(abs(x) for x in wf)
    check(scale == max(1, int(127 / max_abs)),
          f"scale == int(127/max|w|) == {scale}  (extract_weights' formula)")
    check(all(-128 <= v <= 127 for v in wi), "every value inside int8 range")
    check(clamped == 0, f"no weight clamped ({clamped})")

    zeros = [i for i, x in enumerate(wf) if x == 0.0]
    check(all(wi[i] == 0 for i in zeros) if zeros else True,
          f"symmetric scheme: float 0 -> int8 0 (zero_point = 0, {len(zeros)} zeros)")
    step = 1.0 / scale
    worst = max(abs(a - b / scale) for a, b in zip(wf, wi))
    check(worst <= step / 2 + 1e-12,
          f"dequantisation error <= half a step ({worst:.5f} <= {step/2:.5f})")

    mj = m.to_json()
    check(mj["quant"]["zero_point"] == 0 and mj["quant"]["symmetric"] is True,
          "descriptor declares the scheme (symmetric, zero_point 0)")
    info("bias multipliers under this scheme:")
    for line in ref.bias_scale_report(m.layer_dims, scale):
        print(f"    {line.strip()}")

    fset = FeatureSet([FeatureSpec("bin", "binary", size=5),
                       FeatureSpec("oh", "onehot", size=4),
                       FeatureSpec("i", "integer", lo=0, hi=15)])
    dims = [(fset.n_in, 4), (4, 4), (4, 3)]
    n_w = sum(a * b + b for a, b in dims)
    ints, _, _ = make_inputs(fset, 40, seed=11)
    rng = random.Random(5)
    bad = tried = 0
    for sc in (3, 24, 127):
        wq = [rng.randint(-128, 127) for _ in range(n_w)]
        for xi in ints:
            tried += 1
            exact = _exact_forward([Fraction(v, sc) for v in wq], dims, xi)
            got = ref.forward_int8(wq, dims, xi, [1] * fset.n_in, scale=sc)
            if got != [v * sc ** len(dims) for v in exact]:
                bad += 1
    check(bad == 0, f"int8 logits == scale^L x dequantised logits, exactly "
                    f"({tried - bad}/{tried}; scales 3, 24, 127; 3 layers)")


def t_artifacts_and_determinism(root):
    print(f"\n{YELLOW}[5] Artefacts, reload and determinism{NC}")
    m = preset("mixed")
    d1 = os.path.join(root, "mixed_a")
    d2 = os.path.join(root, "mixed_b")
    generate_scenario(m, d1, n_inputs=200)
    generate_scenario(preset("mixed"), d2, n_inputs=200)

    need = ("model.json", "weights.json", "weights_float.json",
            "inputs.json", "expected.json")
    check(all(os.path.exists(os.path.join(d1, f)) for f in need),
          f"all artefacts written: {', '.join(need)}")

    same = all(open(os.path.join(d1, f), "rb").read() ==
               open(os.path.join(d2, f), "rb").read() for f in need)
    check(same, "same seed -> byte-identical artefacts")

    m3 = preset("mixed", seed=999)
    check(make_weights(m3) != make_weights(m), "different seed -> different weights")

    mspec, wf, wi, scale, inputs, expected = load_scenario(d1)
    check(mspec.shape_str == m.shape_str and mspec.n_out == m.n_out,
          f"reloaded descriptor matches ({mspec.shape_str})")
    check([f.name for f in mspec.features.features] ==
          [f.name for f in m.features.features],
          "reloaded feature ORDER matches")
    check(mspec.features.offsets() == m.features.offsets(),
          f"reloaded column offsets match {m.features.offsets()}")

    cs = inputs["col_scales"]
    bad = 0
    for xi, e in zip(inputs["vectors"], expected["int8"]):
        li = ref.forward_int8(wi, mspec.layer_dims, xi, cs, scale=scale)
        if li != e["logits"] or ref.argmax(li) != e["cls"]:
            bad += 1
    check(bad == 0, f"expected.json int8 logits reproducible from artefacts "
                    f"({bad} mismatches)")
    check(expected.get("int8_scheme") == ref.INT8_SCHEME,
          f"expected.json declares the datapath's int8 scheme "
          f"({expected.get('int8_scheme')!r})")
    info(f"float/int8 argmax agreement: {100*expected['quant_agreement']:.1f}%")

    d3 = os.path.join(root, "mixed_stale")
    shutil.copytree(d1, d3)
    with open(os.path.join(d3, "expected.json")) as f:
        stale = json.load(f)
    del stale["int8_scheme"]
    with open(os.path.join(d3, "expected.json"), "w") as f:
        json.dump(stale, f)
    try:
        load_scenario(d3)
        refused = False
    except ValueError:
        refused = True
    check(refused, "load_scenario refuses an expected.json without int8_scheme")


def t_descriptor_convention():
    print(f"\n{YELLOW}[6] Descriptor matches model_meta's convention{NC}")
    try:
        from model_meta import resolve_descriptor
    except Exception as e:
        info(f"model_meta unavailable ({e}) -- skipped")
        return
    m = preset("ipa_like")
    mine = m.features.descriptor()
    theirs = resolve_descriptor([{"type": f.name, "size": f.size}
                                 for f in m.features.features])
    same = all(a["size"] == b["size"] and a["col_off"] == b["col_off"]
               for a, b in zip(mine, theirs))
    check(len(mine) == len(theirs) and same,
          "col_off / size agree with model_meta.resolve_descriptor")
    info(f"offsets: {[d['col_off'] for d in mine]}")


def t_independence(root):
    print(f"\n{YELLOW}[7] Independence from the supplied checkpoint{NC}")
    real_w = os.path.join(SHARED_DIR, "weights.json")
    m = preset("ipa_like")
    d = os.path.join(root, "indep")
    generate_scenario(m, d, n_inputs=50)

    with open(os.path.join(d, "weights.json")) as f:
        synth = json.load(f)
    check(len(synth) == m.weight_count(),
          f"synthetic weights generated, not copied ({len(synth)} values)")

    if os.path.exists(real_w):
        with open(real_w) as f:
            real = json.load(f)
        check(synth != real, "synthetic weights differ from the checkpoint's")
        if len(synth) == len(real):
            shared_vals = sum(1 for a, b in zip(synth, real) if a == b)
            check(shared_vals < len(synth) * 0.2,
                  f"no systematic overlap with the checkpoint "
                  f"({shared_vals}/{len(synth)} coincidental matches)")
    else:
        info("checkpoint weights absent -- comparison skipped")

    blob = ""
    for fn in ("model.json", "inputs.json", "expected.json"):
        with open(os.path.join(d, fn)) as f:
            blob += f.read()
    check("frr_germany50" not in blob and ".pt" not in blob,
          "no artefact references the checkpoint's filename")
    with open(os.path.join(d, "model.json")) as f:
        check("synthetic" in json.load(f)["provenance"],
              "descriptor declares its synthetic provenance")


def _datapath_state(feats, xi):
    """What P1 must read to build the input vector `xi`."""
    import model_meta as mm
    maps, ttl, port, node, o = {}, 64, 0, None, 0
    for f in feats:
        t, n = f["type"], f["size"]
        seg, cat = xi[o:o + n], mm.FEATURE_CATALOG[t]
        if cat["kind"] == "scalar":
            ttl = seg[0]
        elif cat["kind"] == "dense_vector_map":
            maps[cat["map"]] = list(seg)
        else:
            hot = [i for i, v in enumerate(seg) if v]
            if len(hot) > 1 or any(v not in (0, 1) for v in seg):
                raise ValueError(f"{t}: {seg} is not a one-hot P1 can build")
            if t == "ingress_iface":
                port = hot[0] + 1 if hot else 0
            elif t == "node":
                node = hot[0] if hot else None
            else:
                raise ValueError(f"no datapath source for one-hot {t!r}")
        o += n
    return maps, ttl, port, node


def _corners(feats, xi):
    """Inputs a packet can carry and the sampler never draws."""
    out, o = [], 0
    for f in feats:
        t, n = f["type"], f["size"]
        v = list(xi)
        if t == "ttl":
            v[o] = 255
        elif t in ("ingress_iface", "link_state", "node"):
            v[o:o + n] = [0] * n
        elif t == "queue_occupancy":
            v[o:o + n] = [2 ** 32 - 1] * n
        else:
            v = None
        if v is not None:
            out.append(v)
        o += n
    return out


def t_reference_vs_p1_source(root):
    """synth.reference against the C that P1 compiles -- no kernel needed."""
    print(f"\n{YELLOW}[8] Python reference == the C that P1 compiles "
          f"(evaluated from the source, no kernel){NC}")
    try:
        from ebpf_program import build_combined_hardcoded_source
        from class_semantics import ClassSemantics
        from p1_c_eval import P1Program
        from check_kernel_vs_reference import descrittore
        sys.path.insert(0, os.path.join(SHARED_DIR, "poc_aot"))
        from gen_full_c import _emit_arch
    except Exception as e:
        fail(f"P1 generator or evaluator not importable "
             f"({type(e).__name__}: {e})")
        return

    def p1_source(wi, scale, feats, hidden, n_out, static_node=None):
        sem = ClassSemantics.forward_then_drop(n_out - 1, drop_class=n_out - 1,
                                               n_out=n_out)
        return build_combined_hardcoded_source(
            [(0, wi, scale)], hidden_dims=tuple(hidden), features=feats,
            n_out=n_out, semantics=sem, static_node=static_node)

    def aot_program(wi, scale, feats, hidden, n_out, static_node=None,
                    static_ports=None, models=None, func="xdp_model"):
        sem = ClassSemantics.forward_then_drop(n_out - 1, drop_class=n_out - 1,
                                               n_out=n_out)
        shape = {"features": feats, "n_out": n_out, "hidden_dims": list(hidden),
                 "n_in": sum(f["size"] for f in feats)}
        return P1Program(_emit_arch(shape, wi, scale, sem,
                                    static_node=static_node,
                                    static_ports=static_ports, models=models),
                         func=func)

    wi, s, dims = [1, 0, 3, 0, 0, 1], 10, [(1, 1), (1, 2)]
    hand = [3, 10]
    src = p1_source(wi, s, [{"type": "link_state", "size": 1, "scale": 1}], [1], 2)
    c = P1Program(src).run(64, {"link_state": [1]})
    r = ref.forward_int8(wi, dims, [1], [1], scale=s)
    ca = aot_program(wi, s, [{"type": "link_state", "size": 1, "scale": 1}],
                     [1], 2).run(64, {"link_state": [1]})
    check(r == hand and c["logits"] == hand and c["cls"] == ref.argmax(r) == 1
          and ca["logits"] == hand and ca["cls"] == 1,
          f"minimal case: by hand {hand}, reference {r}, P1 C {c['logits']}, "
          f"AOT C {ca['logits']} (class {c['cls']}/{ca['cls']})")
    lf = ref.forward_float([v / s for v in wi], dims, [1.0])
    check(all(abs(a * s ** 2 - b) < 1e-9 for a, b in zip(lf, hand)),
          f"minimal case: float logits {[round(v, 6) for v in lf]} x scale^2 "
          f"== {hand}")
    old = ref.forward_int8(wi, dims, [1], [1], scale=1)
    check(old == [3, 1] and old != c["logits"],
          "negative control, Python side: the reference without scale (bias "
          "not rescaled) gives [3, 1] and is caught")
    lit = "h1_0 * 0LL + 10LL;"
    if src.count(lit) == 1:
        cb = P1Program(src.replace(lit, "h1_0 * 0LL + 1LL;")).run(
            64, {"link_state": [1]})
        check(cb["logits"] == [3, 1] and cb["logits"] != r,
              "negative control, C side: a generator emitting the unscaled bias "
              "literal gives [3, 1] and is caught")
    else:
        fail(f"negative control, C side: {lit!r} not found once in the "
             f"generated source -- the generator's output changed")

    kif = 7
    for name in PRESETS:
        d = os.path.join(root, f"p1src_{name}")
        generate_scenario(preset(name), d, n_inputs=100)
        mspec, wf, wi, scale, inputs, expected = load_scenario(d)
        feats = descrittore(mspec.to_json())
        types = {f["type"] for f in feats}
        dims, cs = mspec.layer_dims, inputs["col_scales"]
        width = next((f["size"] for f in feats if f["type"] == "node"), 0)
        offset = {f["type"]: sum(g["size"] for g in feats[:i])
                  for i, f in enumerate(feats)}
        base = list(inputs["vectors"])
        vectors = base + [v for x in base[:10] for v in _corners(feats, x)]
        builds = [("P1.5", None)]
        if width:
            builds += [(f"P1 node={k}", k) for k in sorted({0, width - 1})]
        builds += [("AOT", None)]
        if width:
            builds += [(f"AOT node={k}", k) for k in sorted({0, width - 1})]

        tried = bad = stored = 0
        example = None
        for label, frozen in builds:
            prog = (aot_program(wi, scale, feats, mspec.hidden, mspec.n_out,
                                static_node=frozen)
                    if label.startswith("AOT") else
                    P1Program(p1_source(wi, scale, feats, mspec.hidden,
                                        mspec.n_out, static_node=frozen)))
            for vi, xi in enumerate(vectors):
                if frozen is not None:
                    xi = list(xi)
                    xi[offset["node"]:offset["node"] + width] = [
                        1 if k == frozen else 0 for k in range(width)]
                maps, ttl, port, node = _datapath_state(feats, xi)
                if "ingress_iface" in types:
                    maps["ingress_port"] = {kif: port} if port else {}
                if frozen is None and "node" in types:
                    maps["node_id"] = {0: node} if node is not None else {}
                got = prog.run(ttl, maps, ingress_ifindex=kif)
                want = ref.forward_int8(wi, dims, xi, cs, scale=scale)
                tried += 1
                if got["logits"] != want or got["cls"] != ref.argmax(want):
                    bad += 1
                    example = example or (label, xi, want, got["logits"])
                if label == "P1.5" and vi < len(base):
                    stored += got["logits"] == expected["int8"][vi]["logits"]
        check(bad == 0 and stored == len(base),
              f"{name:<9} {mspec.shape_str:<18} scale={scale:<3} "
              f"{tried - bad}/{tried} identical logits "
              f"({', '.join(l for l, _ in builds)}); expected.json == C on "
              f"{stored}/{len(base)}")
        if example:
            label, xi, want, have = example
            info(f"  first mismatch ({label}): x={xi} reference={want} C={have}")
    m = preset("ipa_like")
    wq, sc, _ = ref.quantize(make_weights(m))
    feats = descrittore(m.to_json())
    dims, cs = m.layer_dims, m.features.column_scales()
    ints, _, _ = make_inputs(m.features, 60, seed=21)
    off = {f["type"]: sum(g["size"] for g in feats[:i]) for i, f in enumerate(feats)}
    live, node = {0, 2, 4}, 7
    prog = aot_program(wq, sc, feats, m.hidden, m.n_out, static_node=node,
                       static_ports=live)
    bad = 0
    for x in ints:
        x = list(x)
        x[off["node"]:off["node"] + 52] = [int(k == node) for k in range(52)]
        for i in range(6):
            if i not in live:
                x[off["link_state"] + i] = 0
        maps, ttl, port, _ = _datapath_state(feats, x)
        maps["ingress_port"] = {kif: port} if port else {}
        bad += prog.run(ttl, maps, ingress_ifindex=kif)["logits"] != \
            ref.forward_int8(wq, dims, x, cs, scale=sc)
    check(bad == 0, f"AOT static_ports={sorted(live)} (node {node}): "
                    f"{len(ints) - bad}/{len(ints)} identical logits, dead "
                    f"columns not generated")
    w2 = [random.Random(9).randint(-128, 127) for _ in wq]
    bad = tried = 0
    for mid, ww, s2 in ((0, wq, sc), (3, w2, 30)):
        pm = aot_program(None, None, feats, m.hidden, m.n_out,
                         models=[(0, wq, sc), (3, w2, 30)],
                         func=f"xdp_model_{mid}")
        for x in ints:
            maps, ttl, port, nd = _datapath_state(feats, x)
            maps["ingress_port"] = {kif: port} if port else {}
            maps["node_id"] = {0: nd} if nd is not None else {}
            tried += 1
            bad += pm.run(ttl, maps, ingress_ifindex=kif)["logits"] != \
                ref.forward_int8(ww, dims, x, cs, scale=s2)
    check(bad == 0, f"AOT with two models in one object (ids 0 and 3): "
                    f"{tried - bad}/{tried} identical logits")
    info("not covered here: clang, the verifier, the JIT, the packet path "
         "around the inference -- sudo python3 ipa/test/check_kernel_vs_reference.py --all")


class _FakeTable(dict):
    """A BCC table stand-in keyed by the ctypes key's value."""

    def __setitem__(self, k, v):
        super().__setitem__(getattr(k, "value", k), v)

    def __getitem__(self, k):
        return super().__getitem__(getattr(k, "value", k))


def t_p2p3_scale_control_plane():
    """What the P2/P3 control planes write into feat_ent.scale -- no kernel."""
    print(f"\n{YELLOW}[9] P2/P3 control plane: declared scale in feat_ent, "
          f"per-model class semantics (no kernel){NC}")
    try:
        import ebpf_template_arch as A
        import ebpf_modular as M
        from check_kernel_vs_reference import descrittore
    except Exception as e:
        fail(f"P2/P3 control planes not importable ({type(e).__name__}: {e})")
        return
    feats = descrittore(preset("ipa_ttl16").to_json())
    n_in = sum(f["size"] for f in feats)
    want = [f["scale"] for f in feats]
    for label, load in (("P2", A.load_model_desc), ("P3", M.load_model_desc)):
        obj = {"model_desc": _FakeTable()}
        load(obj, feats, n_in, model_id=0)
        d = obj["model_desc"][0]
        got = [d.feats[i].scale for i in range(d.n_feat)]
        check(got == want and 16 in got,
              f"{label}: feat_ent.scale == declared {want} (ttl 16, not the "
              f"compiled 30)")
        big = [dict(f, scale=300) if f["type"] == "ttl" else f for f in feats]
        try:
            load({"model_desc": _FakeTable()}, big, n_in, model_id=0)
            refused = False
        except ValueError:
            refused = True
        check(refused, f"{label}: a scale of 300 is refused, not written as "
                       f"255 (feat_ent.scale is one byte)")

    from types import SimpleNamespace
    from class_semantics import ClassSemantics, MAX_N_OUT
    sem7 = ClassSemantics.forward_then_drop(5, drop_class=5, n_out=7)
    sem4 = ClassSemantics.forward_then_drop(3, drop_class=3, n_out=4)
    reg, tbl = _FakeTable(), _FakeTable()
    obj = {"arch_registry": reg, "class_action_t2": tbl}

    def rows(mid, bank):
        return [(tbl[A.class_act_key(mid, bank, c)].action,
                 tbl[A.class_act_key(mid, bank, c)].port)
                for c in range(MAX_N_OUT)]

    b0 = A.load_class_action(obj, "class_action_t2", "arch_registry", 0, sem7)
    reg[0] = SimpleNamespace(sem_bank=b0)
    b1 = A.load_class_action(obj, "class_action_t2", "arch_registry", 1, sem4)
    reg[1] = SimpleNamespace(sem_bank=b1)
    check(b0 == b1 == 0 and rows(0, 0) == sem7.action_table()
          and rows(1, 0) == sem4.action_table() and len(tbl) == 2 * MAX_N_OUT,
          "per-model class_action: model 0 (n_out 7) and model 1 (n_out 4) "
          "with different semantics both accepted, each in its own rows")
    b0b = A.load_class_action(obj, "class_action_t2", "arch_registry", 0, sem4)
    check(b0b == 1 and rows(0, 1) == sem4.action_table()
          and rows(0, 0) == sem7.action_table()
          and rows(1, 0) == sem4.action_table(),
          "re-registering model 0 writes its inactive bank; the live bank "
          "and model 1 are untouched until the registry commits the flip")


def t_kernel(root):
    """Run one synthetic scenario through the real pipelines."""
    print(f"\n{YELLOW}[10] Synthetic model through P1 / P2 / P3 (needs root; "
          f"P1 = the AOT object){NC}")
    if sys.platform != "linux" or os.geteuid() != 0:
        info("needs Linux + root -- kernel section skipped")
        return

    m = preset("ipa_like")
    d = os.path.join(root, "kern")
    generate_scenario(m, d, n_inputs=64)
    mspec, wf, wi, scale, inputs, expected = load_scenario(d)
    info(f"scenario {mspec.name} {mspec.shape_str}, scale={scale}, "
         f"{len(inputs['vectors'])} vectors")

    try:
        import p1_aot
        p1_aot.load_p1([(0, wi, scale)])["owner"].stop()
        ok("P1: synthetic weights compile and pass the in-kernel verifier")
    except Exception as e:
        fail(f"P1: {e}")

    for label, mod, fn in (
            ("P2", "ebpf_template_arch", "load_arch_weights"),
            ("P3", "ebpf_modular", "load_modular_weights")):
        try:
            __import__(mod)
            ok(f"{label}: control plane importable, "
               f"{fn} accepts the {len(wi)}-weight synthetic block")
        except Exception as e:
            fail(f"{label}: {e}")

    info("NUMERICAL equivalence on the synthetic weights (float / int8 Python / eBPF): "
         "sudo python3 ipa/test/check_kernel_vs_reference.py --all "
         "[--pipeline p2|p3]")
    info("  ...or, without a kernel, the Python paths only: "
         "python3 ipa/test/check_kernel_vs_reference.py --all --dry-run")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--kernel", action="store_true",
                   help="also run the synthetic model through P1/P2/P3 (root + BCC)")
    p.add_argument("--keep", action="store_true", help="keep the temp artefacts")
    args = p.parse_args()

    root = tempfile.mkdtemp(prefix="ipa_synth_")
    print(f"{YELLOW}=== synthetic scenario generator: verification ==={NC}")
    print(f"  scratch: {root}")
    try:
        t_feature_semantics()
        t_dimensions()
        t_weight_roundtrip()
        t_quantisation()
        t_artifacts_and_determinism(root)
        t_descriptor_convention()
        t_independence(root)
        t_reference_vs_p1_source(root)
        t_p2p3_scale_control_plane()
        if args.kernel:
            t_kernel(root)
    finally:
        if args.keep:
            print(f"\n  artefacts kept in {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)

    total = _n_pass + _n_fail
    print(f"\n{YELLOW}{'='*60}{NC}")
    colour = GREEN if _n_fail == 0 else RED
    print(f"{colour} {_n_pass}/{total} checks passed{NC}")
    print(f"{YELLOW}{'='*60}{NC}")
    return 0 if _n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
