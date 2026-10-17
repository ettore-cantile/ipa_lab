#!/usr/bin/env python3
"""check_multi_model.py -- several different models registered at the same time,
each answered with its own shape and weights. Needs root.

    sudo python3 ipa/test/check_multi_model.py
"""
import os
import sys
import random
import ctypes as ct

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _dir in (SHARED_DIR, _TEST_DIR):
    if _dir not in sys.path:
        sys.path.insert(0, _dir)
os.chdir(SHARED_DIR)

from bcc import BPF
from check_pipelines import (
    load_weights, build_frame, prog_test_run, _install_mac_table,
    _seed_link_state, MODEL_PT,
)

PASS_RETVALS = frozenset({0, 4})


def ref_infer_shape(weights: list, layer_dims: list, ttl: int, model_id: int,
                    ingress_port: int = 0, scale: int = 1, node_index=None):
    """Generalized reference forward for an MLP of arbitrary depth/width,
    layer_dims = [(n_in0,n_out0), (n_in1,n_out1), ...] with n_in0 == 65
    (protocol-fixed IPA feature vector)."""
    def s8(v):
        return ct.c_int8(int(v) & 0xFF).value

    assert layer_dims[0][0] == 65, "first layer n_in must be the protocol-fixed 65"
    x = [0] * 65
    for i in range(6):
        x[i] = 1
    x[12] = ttl
    if 1 <= ingress_port <= 6:
        x[5 + ingress_port] = 1
    if node_index is not None and 0 <= node_index <= 51:
        x[13 + node_index] = 1

    layer_offsets, offset = [], 0
    for (n_in, n_out) in layer_dims:
        layer_offsets.append(offset)
        offset += n_in * n_out + n_out

    from model_meta import feature_scale
    from check_pipelines import _trunc_div
    col_scale = [1] * 65
    col_scale[12] = feature_scale("ttl")

    acts = x
    best_cls, best_val = 0, None
    for li, (n_in, n_out) in enumerate(layer_dims):
        woff = layer_offsets[li]
        bias_off = n_in * n_out
        is_last = (li == len(layer_dims) - 1)
        scales = col_scale if li == 0 else [1] * n_in
        out = []
        for j in range(n_out):
            acc = s8(weights[woff + bias_off + j]) * (scale ** li)
            for i in range(n_in):
                acc += _trunc_div(acts[i] * s8(weights[woff + j * n_in + i]),
                                  scales[i])
            if is_last and (best_val is None or acc > best_val):
                best_val, best_cls = acc, j
            out.append(acc if is_last else max(0, acc))
        acts = out
    return best_cls, best_val


def synth_weights(layer_dims: list, seed: int) -> list:
    """Deterministic pseudo-random int8 weights for a synthetic (untrained)
    model of the given shape -- only used to prove the mechanism handles a
    genuinely different architecture, not to produce a meaningful model."""
    n = sum(n_in * n_out + n_out for (n_in, n_out) in layer_dims)
    rng = random.Random(seed)
    return [rng.randint(-30, 30) for _ in range(n)]


def _read_u64(table, key_val):
    """A counter, summed over every CPU (pkt_stats/cls_stats are per-CPU)."""
    from stats_maps import read_counter
    return read_counter(table, key_val)


def _reset(ps, cs, n_cls=7):
    from stats_maps import zero_all
    zero_all(ps, 3)
    zero_all(cs, min(n_cls, len(cs)))


def _check(name, model_id, disp_fd, ps, cs, ref_layer_dims, weights, ttl=3,
           ingress_port=0, scale=24, node_index=None):
    """ingress_port / node_index."""
    ref_cls, ref_val = ref_infer_shape(weights, ref_layer_dims, ttl, model_id,
                                       ingress_port=ingress_port, scale=scale,
                                       node_index=node_index)
    frame = build_frame(model_id, ttl, scale)
    _reset(ps, cs)
    retval, _ = prog_test_run(disp_fd, frame, repeat=1)
    sem = _semantics_for(ref_layer_dims[-1][1])
    act = sem.action_of(ref_cls)
    if act == "FORWARD":
        got = _read_u64(cs, ref_cls)
        ok = (retval in PASS_RETVALS) and got > 0
    elif act == "DROP":
        got = _read_u64(ps, 2)
        ok = (retval == 1) and got > 0
    else:
        got = _read_u64(cs, ref_cls)
        ok = (retval == 2) and got > 0
    tag = "PASS" if ok else "FAIL"
    shape = "-".join(str(d[0]) for d in ref_layer_dims) + f"-{ref_layer_dims[-1][1]}"
    print(f"  [{tag}] {name:10s} model_id={model_id} shape={shape:14s} "
          f"ref_cls={ref_cls} ref_val={ref_val:>8} retval={retval} hit={got>0}")
    return ok


_SEM_CACHE = {}


def _semantics_for(n_out: int):
    """Class semantics for an n_out-wide model, resolved once per width."""
    if n_out not in _SEM_CACHE:
        import model_meta as mm
        _SEM_CACHE[n_out] = mm.descriptor_semantics_or_reference(
            n_out, "check_multi_model")
    return _SEM_CACHE[n_out]


def test_hardcoded():
    print("\n--- Pipeline 1 (hardcoded): 2 model_id, SAME shape (routing only) ---")
    import p1_aot
    weights0, scale0 = load_weights(MODEL_PT)
    dims = [(65, 4), (4, 4), (4, 7)]

    setup = p1_aot.load_p1([(0, weights0, scale0), (1, weights0, scale0)])
    b, disp_fn = setup["b"], setup["disp"]
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table")

    ps, cs = b["pkt_stats"], b["cls_stats"]
    ok = True
    ok &= _check("hardcoded", 0, disp_fn.fd, ps, cs, dims, weights0)
    ok &= _check("hardcoded", 1, disp_fn.fd, ps, cs, dims, weights0)
    return ok


def test_template():
    print("\n--- Pipeline 2 (template): model_id=0 real 65-4-4-7, model_id=1 synthetic 65-6-5-7 ---")
    from ebpf_template_arch import (
        EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_GENERIC_2LAYER,
        load_arch_weights, arch_weight_count,
    )
    weights0, scale0 = load_weights(MODEL_PT)
    dims0 = [(65, 4), (4, 4), (4, 7)]
    dims1 = [(65, 6), (6, 5), (5, 7)]
    weights1 = synth_weights(dims1, seed=1234)

    src = "#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_GENERIC_2LAYER
    b = BPF(text=src)
    disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
    leaf_fn = b.load_func("arch_generic_2layer", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)

    load_arch_weights(b, weights0, model_id=0, scale=scale0, weight_offset=0, n_h1=4, n_h2=4)
    off1 = arch_weight_count(4, 4)
    load_arch_weights(b, weights1, model_id=1, scale=30, weight_offset=off1, n_h1=6, n_h2=5)

    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table_t2")

    ps, cs = b["pkt_stats_t2"], b["cls_stats_t2"]
    ok = True
    ok &= _check("template", 0, disp_fn.fd, ps, cs, dims0, weights0)
    ok &= _check("template", 1, disp_fn.fd, ps, cs, dims1, weights1)
    return ok


def test_modular():
    print("\n--- Pipeline 3 (modular): model_id=0 real 65-4-4-7 (3 layers), model_id=1 synthetic 65-5-6-4-7 (4 layers) ---")
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights0, scale0 = load_weights(MODEL_PT)
    dims0 = [(65, 4), (4, 4), (4, 7)]
    dims1 = [(65, 5), (5, 6), (6, 4), (4, 7)]
    weights1 = synth_weights(dims1, seed=5678)

    b = BPF(text=EBPF_MODULAR_FULL)
    disp_fn   = b.load_func("modular_dispatcher", BPF.XDP)
    fn_first  = b.load_func("layer_first",  BPF.XDP)
    fn_hidden = b.load_func("layer_hidden", BPF.XDP)
    b["layer_chain"][ct.c_int(0)] = ct.c_int(fn_first.fd)
    for i in range(1, 16):
        b["layer_chain"][ct.c_int(i)] = ct.c_int(fn_hidden.fd)

    consumed0 = load_modular_weights(b, weights0, model_id=0, scale=scale0, layer_dims=dims0, base_offset=0)
    load_modular_weights(b, weights1, model_id=1, scale=30, layer_dims=dims1, base_offset=consumed0)

    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table_t3")

    ps, cs = b["pkt_stats_t3"], b["cls_stats_t3"]
    ok = True
    ok &= _check("modular", 0, disp_fn.fd, ps, cs, dims0, weights0)
    ok &= _check("modular", 1, disp_fn.fd, ps, cs, dims1, weights1)
    return ok


def main():
    print("=" * 70)
    print(" IPA/eBPF multi-model concurrent registration -- design-space proof")
    print("=" * 70)
    if not sys.platform.startswith("linux"):
        print("Needs Linux + BCC + root.")
        sys.exit(1)

    results = {
        "hardcoded": test_hardcoded(),
        "template":  test_template(),
        "modular":   test_modular(),
    }
    print()
    print("=" * 70)
    for name, ok in results.items():
        print(f"  {name:10s}: {'PASS' if ok else 'FAIL'}")
    print("=" * 70)
    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
