"""
generate.py -- build a synthetic scenario: model, weights, inputs, expectations.

Everything is derived from a declared seed, so a scenario is reproducible from
its descriptor. Nothing here reads the professor's checkpoint.

Artefacts written into <outdir>/, reusing the repo's existing file names and
formats so that every loader already in the tree consumes them unchanged --
ebpf_program.generate_ebpf_hardcoded, load_arch_weights, load_modular_weights
and poc_aot/gen_full_c all take `weights.json` / `weights_float.json` as-is:

  model.json          descriptor (spec.ModelSpec.to_json)
  weights_float.json  {scale_factor, weights:[float]}
  weights.json        [int8]
  model.pt            PyTorch state_dict, when torch is available
  inputs.json         {seed, n, vectors:[[int]], float_vectors:[[float]], ...}
  expected.json       per-vector float logits/class and int8 logits/class.
                      The int8 side is the datapath's scheme (bias of layer l
                      times scale**l), named in `int8_scheme`; load_scenario
                      refuses a file that does not declare it, because until
                      2026-09-23 this file was written with the bias unscaled.
"""

import json
import os
import random
from typing import List, Optional

from .spec import FeatureSet, FeatureSpec, ModelSpec, ipa_feature_set
from . import reference as ref


# ---------------------------------------------------------------------------
# weights
# ---------------------------------------------------------------------------
def make_weights(mspec: ModelSpec) -> List[float]:
    """Float weights for `mspec`, from its seed.

    Scaled per layer by 1/sqrt(fan_in) (He/Xavier-style). Without it a wide
    first layer produces accumulators orders of magnitude larger than a narrow
    later one, the global int8 scale is then set by the widest layer, and every
    other layer quantises to near-zero -- which would make the synthetic model
    degenerate for reasons that have nothing to do with the pipelines.

    weight_init:
      uniform  U(-b, b) with b = 1/sqrt(fan_in)
      normal   N(0, b)
      sparse   uniform, then ~70% of entries zeroed -- exercises Pipeline 1's
               strength reduction, which folds away multiplications by zero
      ones     every weight 1.0, biases 0. A degenerate but fully predictable
               model: useful as a smoke test where the expected output can be
               computed by hand.
    """
    rng = random.Random(mspec.seed)
    w: List[float] = []
    for n_in, n_out in mspec.layer_dims:
        b = 1.0 / (n_in ** 0.5)
        for _ in range(n_in * n_out):
            if mspec.weight_init == "uniform":
                w.append(rng.uniform(-b, b))
            elif mspec.weight_init == "normal":
                w.append(rng.gauss(0.0, b))
            elif mspec.weight_init == "sparse":
                w.append(0.0 if rng.random() < 0.7 else rng.uniform(-b, b))
            else:                                    # ones
                w.append(1.0)
        for _ in range(n_out):
            w.append(0.0 if mspec.weight_init == "ones" else rng.uniform(-b, b))
    assert len(w) == mspec.weight_count(), (len(w), mspec.weight_count())

    # Global rescale to the declared dynamic range. The per-layer 1/sqrt(fan_in)
    # above sets the RELATIVE balance between layers; this sets the ABSOLUTE
    # magnitude, which determines the int8 scale. See ModelSpec.max_abs.
    peak = max((abs(x) for x in w), default=0.0)
    if peak > 0 and mspec.weight_init != "ones":
        k = mspec.max_abs / peak
        w = [x * k for x in w]
    return w


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------
def _sample_feature(f: FeatureSpec, rng: random.Random):
    """One sample of `f`, as (datapath integers, training floats).

    The two differ only for `real` features: the datapath carries the raw
    integer and divides the product by `scale`, while the model was trained on
    value/scale. Returning both keeps the float and int8 paths comparable
    without either side guessing what the other meant.
    """
    if f.kind == "real":
        v = rng.randint(int(f.lo), int(f.hi))
        return [v], [v / f.scale]
    if f.kind == "integer":
        v = rng.randint(int(f.lo), int(f.hi))
        return [v], [float(v)]
    if f.kind == "binary":
        while True:
            bits = [1 if rng.random() < 0.5 else 0 for _ in range(f.size)]
            if sum(bits) >= f.min_ones:
                return bits, [float(b) for b in bits]
    # onehot
    k = rng.randrange(f.size)
    bits = [1 if i == k else 0 for i in range(f.size)]
    return bits, [float(b) for b in bits]


def make_inputs(fset: FeatureSet, n: int, seed: int):
    """`n` input vectors honouring every feature's semantics.

    Returns (int_vectors, float_vectors, per_feature_stats). The stats exist so
    a reader can confirm the constraints actually held -- a one-hot with exactly
    one bit per sample, a binary vector never below its minimum -- instead of
    trusting the generator.
    """
    rng = random.Random(seed)
    ints, floats = [], []
    stats = {f.name: {"kind": f.kind, "size": f.size} for f in fset.features}
    hot_counts = {f.name: [] for f in fset.features}
    val_range = {f.name: [None, None] for f in fset.features}

    for _ in range(n):
        xi, xf = [], []
        for f in fset.features:
            a, b = _sample_feature(f, rng)
            xi += a
            xf += b
            if f.kind in ("binary", "onehot"):
                hot_counts[f.name].append(sum(a))
            else:
                lo, hi = val_range[f.name]
                val_range[f.name] = [a[0] if lo is None else min(lo, a[0]),
                                     a[0] if hi is None else max(hi, a[0])]
        ints.append(xi)
        floats.append(xf)

    for f in fset.features:
        if f.kind in ("binary", "onehot"):
            hc = hot_counts[f.name]
            stats[f.name].update(min_set=min(hc), max_set=max(hc),
                                 mean_set=sum(hc) / len(hc))
        else:
            stats[f.name].update(observed_min=val_range[f.name][0],
                                 observed_max=val_range[f.name][1],
                                 scale=f.scale)
    return ints, floats, stats


def check_inputs(fset: FeatureSet, ints, floats) -> List[str]:
    """Validate generated vectors against the declared semantics.

    Returns a list of violations; empty means the generator honoured every
    constraint. Run by the test suite -- a generator nobody checks is just
    another source of wrong data.
    """
    errs = []
    offs = fset.offsets()
    scales = fset.column_scales()
    for vi, (xi, xf) in enumerate(zip(ints, floats)):
        if len(xi) != fset.n_in or len(xf) != fset.n_in:
            errs.append(f"vector {vi}: width {len(xi)}/{len(xf)} != n_in {fset.n_in}")
            continue
        for f, off in zip(fset.features, offs):
            seg = xi[off:off + f.size]
            if f.kind == "onehot":
                if sum(seg) != 1 or any(v not in (0, 1) for v in seg):
                    errs.append(f"vector {vi}, {f.name}: not one-hot ({seg})")
            elif f.kind == "binary":
                if any(v not in (0, 1) for v in seg):
                    errs.append(f"vector {vi}, {f.name}: non-binary value ({seg})")
                elif sum(seg) < f.min_ones:
                    errs.append(f"vector {vi}, {f.name}: {sum(seg)} set < min {f.min_ones}")
            else:
                v = seg[0]
                if not (int(f.lo) <= v <= int(f.hi)):
                    errs.append(f"vector {vi}, {f.name}: {v} outside [{f.lo}, {f.hi}]")
                expect = v / f.scale if f.kind == "real" else float(v)
                if abs(xf[off] - expect) > 1e-9:
                    errs.append(f"vector {vi}, {f.name}: float {xf[off]} != "
                                f"int {v} / scale {f.scale}")
        if len(scales) != fset.n_in:
            errs.append("column_scales width mismatch")
    return errs


# ---------------------------------------------------------------------------
# torch bridge (optional)
# ---------------------------------------------------------------------------
def build_torch_model(mspec: ModelSpec, weights_float: List[float]):
    """An nn.Sequential carrying exactly `weights_float`.

    Verifies the flat-list convention from the other direction: loading the
    list into Linear layers and reading `parameters()` back must reproduce it.
    Returns None when torch is unavailable.
    """
    try:
        import torch
        import torch.nn as nn
    except ImportError:
        return None

    dims = mspec.layer_dims
    mods = []
    for li, (n_in, n_out) in enumerate(dims):
        mods.append(nn.Linear(n_in, n_out))
        if li < len(dims) - 1:
            mods.append(nn.ReLU())
    model = nn.Sequential(*mods)

    off = 0
    with torch.no_grad():
        for m in model:
            if not isinstance(m, nn.Linear):
                continue
            n_out, n_in = m.weight.shape
            wv = weights_float[off: off + n_in * n_out]
            bv = weights_float[off + n_in * n_out: off + n_in * n_out + n_out]
            m.weight.copy_(torch.tensor(wv, dtype=torch.float32).view(n_out, n_in))
            m.bias.copy_(torch.tensor(bv, dtype=torch.float32))
            off += n_in * n_out + n_out
    assert off == len(weights_float)

    flat = [w for p in model.parameters() for w in p.data.view(-1).tolist()]
    if len(flat) != len(weights_float):
        raise AssertionError("torch round-trip changed the weight count")
    worst = max(abs(a - b) for a, b in zip(flat, weights_float))
    if worst > 1e-5:
        raise AssertionError(f"torch round-trip altered weights (max |d| = {worst})")
    return model


# ---------------------------------------------------------------------------
# the whole scenario
# ---------------------------------------------------------------------------
def generate_scenario(mspec: ModelSpec, outdir: str, n_inputs: int = 1000,
                      input_seed: Optional[int] = None) -> dict:
    """Write every artefact for `mspec` into `outdir` and return a manifest."""
    os.makedirs(outdir, exist_ok=True)
    if input_seed is None:
        input_seed = mspec.seed + 1        # distinct from the weight seed
    fset = mspec.features
    dims = mspec.layer_dims

    wf = make_weights(mspec)
    wi, scale, clamped = ref.quantize(wf)

    ints, floats, stats = make_inputs(fset, n_inputs, input_seed)
    viol = check_inputs(fset, ints, floats)
    if viol:
        raise AssertionError("generated inputs violate their own spec:\n  " +
                             "\n  ".join(viol[:10]))

    col_scales = fset.column_scales()
    exp_float, exp_int8 = [], []
    for xi, xf in zip(ints, floats):
        lf = ref.forward_float(wf, dims, xf, mspec.activation)
        li = ref.forward_int8(wi, dims, xi, col_scales, mspec.activation,
                              scale=scale)
        exp_float.append({"logits": lf, "cls": ref.argmax(lf)})
        exp_int8.append({"logits": li, "cls": ref.argmax(li)})

    agree = sum(1 for a, b in zip(exp_float, exp_int8) if a["cls"] == b["cls"])

    model_json = mspec.to_json()
    model_json["quant"]["scale_factor"] = scale
    model_json["quant"]["clamped"] = clamped
    model_json["inputs"] = {"seed": input_seed, "n": n_inputs}

    def _w(name, obj):
        p = os.path.join(outdir, name)
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    _w("model.json", model_json)
    _w("weights_float.json", {"scale_factor": scale, "weights": wf})
    _w("weights.json", wi)
    _w("inputs.json", {"seed": input_seed, "n": n_inputs,
                       "n_in": fset.n_in, "col_scales": col_scales,
                       "vectors": ints, "float_vectors": floats,
                       "per_feature": stats})
    _w("expected.json", {"int8_scheme": ref.INT8_SCHEME, "scale_factor": scale,
                         "float": exp_float, "int8": exp_int8,
                         "quant_agreement": agree / n_inputs})

    torch_ok = None
    model = build_torch_model(mspec, wf)
    if model is not None:
        try:
            import torch
            torch.save(model.state_dict(), os.path.join(outdir, "model.pt"))
            torch_ok = True
        except Exception:
            torch_ok = False

    return {
        "outdir": outdir, "shape": mspec.shape_str, "n_in": fset.n_in,
        "n_out": mspec.n_out, "weights": len(wi), "scale_factor": scale,
        "clamped": clamped, "n_inputs": n_inputs, "input_seed": input_seed,
        "quant_agreement": agree / n_inputs, "torch": torch_ok,
        "layer_dims": dims, "col_scales": col_scales,
        "classes_float": sorted({e["cls"] for e in exp_float}),
        "classes_int8": sorted({e["cls"] for e in exp_int8}),
    }


def load_scenario(outdir: str):
    """Read back a generated scenario: (ModelSpec, weights_float, weights_int8,
    scale, inputs, expected).

    Refuses an expected.json that does not declare the int8 scheme the
    datapath runs. Files written before 2026-09-23 have no `int8_scheme`: their
    int8 logits leave the bias unscaled, and comparing a pipeline against them
    would report a datapath defect that is really a stale reference."""
    def _r(name):
        with open(os.path.join(outdir, name)) as f:
            return json.load(f)
    mj = _r("model.json")
    mspec = ModelSpec.from_json(mj)
    wfj = _r("weights_float.json")
    expected = _r("expected.json")
    scheme = expected.get("int8_scheme")
    if scheme != ref.INT8_SCHEME:
        raise ValueError(
            f"{outdir}: expected.json declares int8_scheme={scheme!r}, the "
            f"reference and the datapath use {ref.INT8_SCHEME!r}. It was "
            f"generated with an older reference; regenerate it: python3 "
            f"ipa/synth/make_scenario.py --preset all")
    if expected.get("scale_factor") != wfj["scale_factor"]:
        raise ValueError(f"{outdir}: expected.json was computed with scale "
                         f"{expected.get('scale_factor')}, weights_float.json "
                         f"declares {wfj['scale_factor']}")
    return (mspec, wfj["weights"], _r("weights.json"), wfj["scale_factor"],
            _r("inputs.json"), expected)


# ---------------------------------------------------------------------------
# ready-made scenarios
# ---------------------------------------------------------------------------
def preset(name: str, seed: int = 20260916) -> ModelSpec:
    """Named scenarios covering the axes the pipelines need exercised.

    `ipa_like` matches the checked-in model's SHAPE without using its weights,
    so a failure there is about the pipelines, not about the checkpoint. The
    others move one axis at a time: smaller and larger topologies, a different
    class count, more/fewer features, depth, and the mixed-feature-kind case
    that the real descriptor never exercises.
    """
    P = {
        # shape-compatible with the repo's model, weights synthetic
        "ipa_like": lambda: ModelSpec(
            "ipa_like", ipa_feature_set(6, 52, 30), n_out=7, hidden=[4, 4],
            seed=seed),
        # smaller topology
        "small": lambda: ModelSpec(
            "small", ipa_feature_set(3, 8, 16), n_out=4, hidden=[4], seed=seed),
        # larger topology, still within MAX_N_IN=128
        "large": lambda: ModelSpec(
            "large", ipa_feature_set(8, 100, 64), n_out=9, hidden=[8, 8],
            seed=seed),
        # deeper than the reference model
        "deep": lambda: ModelSpec(
            "deep", ipa_feature_set(6, 52, 30), n_out=7, hidden=[4, 4, 4],
            seed=seed),
        # every feature kind, including ones the real descriptor never uses
        "mixed": lambda: ModelSpec(
            "mixed", FeatureSet([
                FeatureSpec("link_state", "binary", size=4, min_ones=1, code=0x01),
                FeatureSpec("queue_occ", "integer", lo=0, hi=15, code=0x05),
                FeatureSpec("ttl", "real", lo=1, hi=30, scale=30, code=0x03),
                FeatureSpec("node", "onehot", size=12, code=0x04),
            ]), n_out=5, hidden=[6], seed=seed),
        # sparse weights: exercises Pipeline 1's strength reduction
        "sparse": lambda: ModelSpec(
            "sparse", ipa_feature_set(6, 52, 30), n_out=7, hidden=[4, 4],
            weight_init="sparse", seed=seed),
        # the reference SHAPE with a TTL trained on ttl/16: the only preset
        # P2 accepts (its control plane requires the configured model's n_out,
        # 7) whose scale is not the compiled default 30 -- without it no
        # scenario proves that P2 divides by the scale in feat_ent
        "ipa_ttl16": lambda: ModelSpec(
            "ipa_ttl16", ipa_feature_set(6, 52, 16), n_out=7, hidden=[4, 4],
            seed=seed),
        # fully predictable, for hand-checkable smoke tests
        "ones": lambda: ModelSpec(
            "ones", ipa_feature_set(3, 4, 8), n_out=3, hidden=[2],
            weight_init="ones", seed=seed),
    }
    if name not in P:
        raise ValueError(f"unknown preset {name!r}; known: {sorted(P)}")
    return P[name]()


PRESETS = ("ipa_like", "small", "large", "deep", "mixed", "sparse", "ones",
           "ipa_ttl16")
