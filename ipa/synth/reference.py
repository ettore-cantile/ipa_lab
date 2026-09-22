"""
reference.py -- float and int8 forward passes over a flat input vector.

Two independent references, both driven by the same flat weight list the eBPF
pipelines consume:

  forward_float  the model as PyTorch would compute it (pure Python, so it runs
                 without torch; test_synth cross-checks it against torch when
                 torch is available).
  forward_int8   bit-for-bit what the datapath computes.

The int8 scheme, and why every bias is rescaled
-----------------------------------------------
Quantisation is symmetric with no zero point and ONE global scale for every
parameter: w_int8 = clamp(round(w_float * s), -128, 127). The inference never
divides by s, because argmax is invariant under a positive scaling of all
logits -- provided every term of an accumulator carries the same power of s.

At layer l (0-based) the products carry s**(l+1): the input carries s**0 and
every layer multiplies by one more quantised weight. A stored bias carries
s**1. The pipelines therefore multiply the bias of layer l by s**l (P1:
ebpf_program._gen_dense_layer, bias_mul=scale**li), and so does forward_int8.
With no column divided (col_scales all 1) the integer logits are then EXACTLY
s**L times the logits of the dequantised model, whose weights are w_int8/s.

`scale` is therefore a required argument. It used to default to 1 -- the right
multiplier for a model of scale 1 and the wrong one for every other -- and
generate.py called forward_int8 without it: until 2026-09-23 expected.json held
the logits of an unscaled-bias scheme that no pipeline runs (float/int8
agreement 0.789 on ipa_like, 0.986 with the datapath's scheme). Two
implementations can each be consistent and still disagree with each other, so
test_synth now checks forward_int8 against the C that P1 compiles, logit for
logit (test/p1_c_eval.py), and against the dequantised model.
"""

from typing import List, Sequence, Tuple

# Written into expected.json by generate.py and required by load_scenario: a
# scenario whose int8 expectations were computed under any other scheme is
# refused instead of being compared against the datapath.
INT8_SCHEME = "bias_l*scale^l"


def trunc_div(a: int, b: int) -> int:
    """Integer division truncating toward ZERO, like C.

    Python's // floors, so -7 // 30 == -1 while C gives 0. The datapath divides
    scaled feature terms with C semantics; a reference that floors disagrees on
    negative weights, which is exactly the class of bug that survives testing.
    """
    if b == 1:
        return a
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _s8(v: int) -> int:
    """Reinterpret the low byte as a signed int8, like (__s8) in the datapath."""
    v &= 0xFF
    return v - 256 if v >= 128 else v


def split_layers(weights: Sequence, layer_dims: Sequence[Tuple[int, int]]):
    """Slice the flat weight list into [(W, B)] per layer.

    Layout, shared with every consumer in the repo: for each layer,
    n_in*n_out weights (row-major by output neuron: index j*n_in + i) followed
    by n_out biases, layers back to back input -> output. This is also exactly
    what `[w for p in model.parameters() for w in p.data.view(-1)]` produces for
    a stack of nn.Linear, which is why the two interoperate.
    """
    out, off = [], 0
    for n_in, n_out in layer_dims:
        w = weights[off: off + n_in * n_out]
        b = weights[off + n_in * n_out: off + n_in * n_out + n_out]
        if len(w) != n_in * n_out or len(b) != n_out:
            raise ValueError(
                f"weight list too short for layer ({n_in},{n_out}): "
                f"need {n_in * n_out + n_out} more, got {len(w) + len(b)}")
        out.append((w, b))
        off += n_in * n_out + n_out
    if off != len(weights):
        raise ValueError(f"weight list has {len(weights)} entries, "
                         f"layer_dims accounts for {off}")
    return out


# ---------------------------------------------------------------------------
# float
# ---------------------------------------------------------------------------
def forward_float(weights_float: Sequence[float], layer_dims, x: Sequence[float],
                  activation: str = "relu") -> List[float]:
    """Plain float forward. `x` is already in the units the model was TRAINED
    on -- i.e. a `real` feature is passed as value/scale, not as the raw
    integer the datapath carries."""
    if activation != "relu":
        raise ValueError(f"unsupported activation {activation!r}")
    acts = list(x)
    layers = split_layers(weights_float, layer_dims)
    for li, (w, b) in enumerate(layers):
        n_in, n_out = layer_dims[li]
        is_last = (li == len(layers) - 1)
        nxt = []
        for j in range(n_out):
            acc = b[j] + sum(acts[i] * w[j * n_in + i] for i in range(n_in))
            nxt.append(acc if is_last else max(0.0, acc))
        acts = nxt
    return acts


# ---------------------------------------------------------------------------
# int8, bit-for-bit with the datapath
# ---------------------------------------------------------------------------
def forward_int8(weights_int8: Sequence[int], layer_dims, x_int: Sequence[int],
                 col_scales: Sequence[int] = None,
                 activation: str = "relu", *, scale: int) -> List[int]:
    """Integer forward identical to the eBPF programs.

    `scale` is the model's global quantisation scale, keyword-only and without
    a default: the bias of layer l is multiplied by scale**l, and no value of
    it is right for every model (see the module docstring).

    `x_int` holds what the datapath reads: raw integers, NOT pre-divided.
    `col_scales` gives the per-column divisor applied to the PRODUCT (see
    spec.FeatureSet.column_scales). Dividing the feature instead of the product
    would collapse a small integer range onto 0/1 and throw the resolution away
    -- the bug this project already hit with the TTL.

    Only the FIRST layer consumes raw features, so scaling applies only there;
    later layers consume activations, already in the model's own units.
    """
    if activation != "relu":
        raise ValueError(f"unsupported activation {activation!r}")
    if scale is None or int(scale) != scale or int(scale) < 1:
        raise ValueError(f"scale must be a positive integer, got {scale!r}")
    scale = int(scale)
    n_in0 = layer_dims[0][0]
    if col_scales is None:
        col_scales = [1] * n_in0
    if len(col_scales) != n_in0:
        raise ValueError(f"col_scales has {len(col_scales)} entries, "
                         f"first layer takes {n_in0}")

    acts = [int(v) for v in x_int]
    layers = split_layers(weights_int8, layer_dims)
    for li, (w, b) in enumerate(layers):
        n_in, n_out = layer_dims[li]
        is_last = (li == len(layers) - 1)
        scales = col_scales if li == 0 else None
        nxt = []
        for j in range(n_out):
            # Bias in the accumulator's units: layer li's products carry
            # scale**(li+1), a stored bias carries scale**1, so the bias is
            # multiplied by scale**li -- the literal P1 compiles. See the
            # module docstring.
            acc = _s8(b[j]) * (scale ** li)
            base = j * n_in
            for i in range(n_in):
                p = acts[i] * _s8(w[base + i])
                acc += trunc_div(p, scales[i]) if scales else p
            nxt.append(acc if is_last else max(0, acc))
        acts = nxt
    return acts


def argmax(logits: Sequence) -> int:
    """First index of the maximum -- the same tie-break the datapath uses
    (`if (acc > best_val)` keeps the earliest winner)."""
    best_i, best_v = 0, None
    for i, v in enumerate(logits):
        if best_v is None or v > best_v:
            best_i, best_v = i, v
    return best_i


# ---------------------------------------------------------------------------
# quantisation, matching extract_weights.py exactly
# ---------------------------------------------------------------------------
def quant_scale(weights_float: Sequence[float]) -> int:
    """scale = int(127 / max|w|), the scheme extract_weights.py uses.

    Truncating, global over every parameter, symmetric, no zero point. Returns
    at least 1: a model whose largest weight exceeds 127 would otherwise get
    scale 0 and quantise to all zeros, silently.
    """
    max_abs = max((abs(float(w)) for w in weights_float), default=0.0)
    if max_abs == 0.0:
        return 1
    return max(1, int(127 / max_abs))


def quantize(weights_float: Sequence[float], scale: int = None):
    """Return (weights_int8, scale, n_clamped)."""
    if scale is None:
        scale = quant_scale(weights_float)
    out, clamped = [], 0
    for wf in weights_float:
        wi = int(round(float(wf) * scale))
        c = max(-128, min(127, wi))
        if c != wi:
            clamped += 1
        out.append(c)
    return out, scale, clamped


def bias_scale_report(layer_dims, scale: int) -> List[str]:
    """The multiplier each layer's bias gets, as a number.

    Layer l (0-based) accumulates products carrying scale**(l+1); a stored bias
    carries scale**1 and is multiplied by scale**l to match. Printed so the
    multipliers compiled into the datapath (`bias_mul` in ebpf_program) can be
    checked against a value rather than taken on trust.
    """
    lines = []
    for li in range(len(layer_dims)):
        mul = scale ** li
        lines.append(f"  layer {li + 1}: products carry scale^{li + 1}, "
                     f"bias x scale^{li} = x{mul}")
    return lines
