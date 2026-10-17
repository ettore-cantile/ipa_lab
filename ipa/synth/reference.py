"""reference.py -- float and int8 forward passes over a flat input vector.

forward_int8 is bit for bit what the eBPF pipelines compute (bias of layer l
multiplied by scale**l), and is the reference every correctness test uses.
"""

from typing import List, Sequence, Tuple

INT8_SCHEME = "bias_l*scale^l"


def trunc_div(a: int, b: int) -> int:
    """Integer division truncating toward ZERO, like C."""
    if b == 1:
        return a
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _s8(v: int) -> int:
    """Reinterpret the low byte as a signed int8, like (__s8) in the datapath."""
    v &= 0xFF
    return v - 256 if v >= 128 else v


def split_layers(weights: Sequence, layer_dims: Sequence[Tuple[int, int]]):
    """Slice the flat weight list into [(W, B)] per layer."""
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


# --- float ---
def forward_float(weights_float: Sequence[float], layer_dims, x: Sequence[float],
                  activation: str = "relu") -> List[float]:
    """Plain float forward."""
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


# --- int8, bit-for-bit with the datapath ---
def forward_int8(weights_int8: Sequence[int], layer_dims, x_int: Sequence[int],
                 col_scales: Sequence[int] = None,
                 activation: str = "relu", *, scale: int) -> List[int]:
    """Integer forward identical to the eBPF programs."""
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
            acc = _s8(b[j]) * (scale ** li)
            base = j * n_in
            for i in range(n_in):
                p = acts[i] * _s8(w[base + i])
                acc += trunc_div(p, scales[i]) if scales else p
            nxt.append(acc if is_last else max(0, acc))
        acts = nxt
    return acts


def argmax(logits: Sequence) -> int:
    """First index of the maximum -- the same tie-break the datapath uses (`if
    (acc > best_val)` keeps the earliest winner)."""
    best_i, best_v = 0, None
    for i, v in enumerate(logits):
        if best_v is None or v > best_v:
            best_i, best_v = i, v
    return best_i


# --- quantisation, matching extract_weights.py exactly ---
def quant_scale(weights_float: Sequence[float]) -> int:
    """scale = int(127 / max|w|), the scheme extract_weights.py uses."""
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
    """The multiplier each layer's bias gets, as a number."""
    lines = []
    for li in range(len(layer_dims)):
        mul = scale ** li
        lines.append(f"  layer {li + 1}: products carry scale^{li + 1}, "
                     f"bias x scale^{li} = x{mul}")
    return lines
