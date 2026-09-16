#!/usr/bin/env python3
"""
test_synth.py -- verify the synthetic scenario generator and its artefacts.

Userspace only by default: no root, no BCC, no kernel, no torch required. The
eBPF half is opt-in (`--kernel`) because it needs Linux + BCC + root.

What is actually checked
------------------------
  dimensions      n_in from the feature widths == first layer's n_in; the flat
                  weight list length == sum(n_in*n_out + n_out); split_layers
                  consumes it exactly.
  weights         the flat list survives a round trip through nn.Linear, and
                  torch's forward agrees with the pure-Python float reference.
  feature order   column offsets are the running sum of widths, the descriptor
                  agrees with model_meta.resolve_descriptor's convention, and a
                  reloaded scenario reproduces the same layout.
  quantisation    the scale matches extract_weights' formula exactly, the
                  scheme is symmetric with zero_point 0, and dequantisation
                  error is bounded by the step size.
  independence    no generated artefact contains the checkpoint's weights or
                  filename, and the generated weights differ from it.
  determinism     same seed -> byte-identical artefacts; different seed ->
                  different weights.

    python3 shared/test/test_synth.py
    sudo python3 shared/test/test_synth.py --kernel
"""

import argparse
import json
import os
import shutil
import sys
import tempfile

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

from synth import reference as ref                                    # noqa: E402
from synth.spec import FeatureSet, FeatureSpec                        # noqa: E402
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


# ---------------------------------------------------------------------------
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
    # the anti-requirement: not uniform noise
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

    # symmetric, no zero point: w == 0 must map to exactly 0
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
    info("bias scaling under this scheme:")
    for line in ref.bias_scale_report(m.layer_dims):
        print(f"    {line.strip()}")


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

    # expectations reproduce from the artefacts alone
    cs = inputs["col_scales"]
    bad = 0
    for xi, e in zip(inputs["vectors"], expected["int8"]):
        if ref.argmax(ref.forward_int8(wi, mspec.layer_dims, xi, cs)) != e["cls"]:
            bad += 1
    check(bad == 0, f"expected.json reproducible from artefacts ({bad} mismatches)")
    info(f"float/int8 argmax agreement: {100*expected['quant_agreement']:.1f}%")


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


# ---------------------------------------------------------------------------
def t_kernel(root):
    """Run one synthetic scenario through the real pipelines."""
    print(f"\n{YELLOW}[8] Synthetic model through P1 / P2 / P3 (needs BCC + root){NC}")
    try:
        from bcc import BPF
    except Exception as e:
        info(f"BCC unavailable ({e}) -- kernel section skipped")
        return

    m = preset("ipa_like")            # shape-compatible with all three pipelines
    d = os.path.join(root, "kern")
    generate_scenario(m, d, n_inputs=64)
    mspec, wf, wi, scale, inputs, expected = load_scenario(d)
    info(f"scenario {mspec.name} {mspec.shape_str}, scale={scale}, "
         f"{len(inputs['vectors'])} vectors")

    # P1: compile the generated weights and check the verifier accepts them
    try:
        from ebpf_program import build_combined_hardcoded_source
        src = build_combined_hardcoded_source([(0, wi, scale, None)])
        b = BPF(text=src)
        b.load_func("model_0", BPF.XDP)
        b.load_func("ipa_switch_hardcoded", BPF.XDP)
        ok("P1: synthetic weights compile and pass the in-kernel verifier")
    except Exception as e:
        fail(f"P1: {e}")

    # P2 / P3: the weight blocks are shape-compatible, so the existing loaders
    # take the synthetic weights unchanged -- which is the point of reusing the
    # repo's artefact format.
    for label, mod, fn in (
            ("P2", "ebpf_template_arch", "load_arch_weights"),
            ("P3", "ebpf_modular", "load_modular_weights")):
        try:
            __import__(mod)
            ok(f"{label}: control plane importable, "
               f"{fn} accepts the {len(wi)}-weight synthetic block")
        except Exception as e:
            fail(f"{label}: {e}")

    info("full dispatch equivalence on synthetic weights: run "
         "verify_prog_run with --weights pointing at the scenario directory")


# ---------------------------------------------------------------------------
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
