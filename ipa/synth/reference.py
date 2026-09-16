"""
reference.py -- float and int8 forward passes over a flat input vector.

Two independent references, both driven by the same flat weight list the eBPF
pipelines consume:

  forward_float  the model as PyTorch would compute it (pure Python, so it runs
                 without torch; `torch_forward` cross-checks it when torch is
                 available).
  forward_int8   bit-for-bit what the datapath computes.

Why forward_int8 replicates a scheme that is not textbook-correct
-----------------------------------------------------------------
The project's quantisation is symmetric with no zero point, and uses ONE global
scale for every parameter: w_int8 = clamp(round(w_float * s), -128, 127). The
inference never divides by s, because argmax is invariant under a positive
scaling of all logits.

That invariance is only exact if every term in an accumulator carries the same
power of s. It does not: at layer L the products carry s**L while the bias
carries s**1, so biases are progressively under-weighted with depth. This is a
real property of the existing scheme, not of this module. forward_int8
reproduces it deliberately -- the point of a reference is to agree with the
datapath, and a "corrected" reference would disagree with all three pipelines.
`bias_scale_report` quantifies the distortion so it can be stated rather than
discovered.
"""

from typing import List, Sequence, Tuple


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
                 activation: str = "relu", scale: int = 1) -> List[int]:
    """Integer forward identical to the eBPF programs.

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
            # multiplied by scale**li. See the module docstring.
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


def bias_scale_report(layer_dims) -> List[str]:
    """How badly the shared-scale scheme under-weights each layer's bias.

    At layer L (1-based) the products carry scale**L and the bias scale**1, so
    the bias is effectively divided by scale**(L-1) relative to the products.
    Reported so the distortion is a stated property rather than a surprise.
    """
    lines = []
    for li in range(len(layer_dims)):
        power = li  # bias under-weighted by scale**li
        if power == 0:
            lines.append("  layer 1: bias and products both carry scale^1 -- consistent")
        else:
            lines.append(f"  layer {li + 1}: bias under-weighted by scale^{power} "
                         f"relative to the products")
    return lines
