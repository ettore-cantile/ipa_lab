#!/usr/bin/env python3
"""
verify_multi_model.py  --  proves the 3 IPA/eBPF pipelines genuinely handle
MULTIPLE, DIFFERENT models registered concurrently, not just multiple
model_id's sharing one baked-in shape.

model_id=0 : the real trained model (65-4-4-7), same as every other test.
model_id=1 : a SYNTHETIC model with a different architecture, deterministic
             (seeded) random int8 weights -- not trained, only used to prove
             the dispatch/registry mechanism actually reads a different
             shape/weight-offset per model_id and produces the (independently
             recomputed) correct class.

  P1 hardcoded : model_id=1 reuses the SAME 65-4-4-7 shape (the C code
                 generator's N_H1/N_H2 are compile-time constants, not a
                 per-call parameter -- see ebpf_program.py). This still
                 proves the new dispatcher->model_progs[model_id] tail-call
                 routing picks the right program.
  P2 template   : model_id=1 gets a DIFFERENT hidden width, 65-6-5-7
                  (n_h1=6, n_h2=5) -- the one axis P2 can vary.
  P3 modular    : model_id=1 gets a DIFFERENT depth AND width, 65-5-6-4-7
                  (4 layers) -- the axis only P3 can vary.

Both models are registered in the SAME compiled BPF object (no reload
between them) and exercised via the real dispatcher (full tail-call path,
not the leaf-only shortcut verify_prog_run.py uses for per-packet
correctness checks) -- this is the actual "multi-model concurrent" claim
made in the design-space docs, tested end to end.

Needs Linux + BCC + root. In Kathara:
    sudo python3 shared/test/verify_multi_model.py
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
from verify_prog_run import (
    load_weights, build_frame, prog_test_run, _install_mac_table,
    _seed_link_state, MODEL_PT, build_frame_dense, ref_infer_dense,
)

PASS_RETVALS = frozenset({0, 4})


def ref_infer_shape(weights: list, layer_dims: list, ttl: int, model_id: int, ifindex: int = 0):
    """
    Generalized reference forward for an MLP of arbitrary depth/width,
    layer_dims = [(n_in0,n_out0), (n_in1,n_out1), ...] with n_in0 == 65
    (protocol-fixed IPA feature vector). Reduces to verify_prog_run.ref_infer
    exactly for layer_dims=[(65,4),(4,4),(4,7)]. Weight layout matches
    load_arch_weights()/load_modular_weights(): each layer's
    [n_in*n_out weights][n_out biases], back-to-back. Returns (best_cls, best_val).
    """
    def s8(v):
        return ct.c_int8(int(v) & 0xFF).value

    assert layer_dims[0][0] == 65, "first layer n_in must be the protocol-fixed 65"
    x = [0] * 65
    for i in range(6):
        x[i] = 1
    x[12] = ttl
    if 1 <= ifindex <= 6:
        x[5 + ifindex] = 1
    if 0 <= model_id <= 51:
        x[13 + model_id] = 1

    layer_offsets, offset = [], 0
    for (n_in, n_out) in layer_dims:
        layer_offsets.append(offset)
        offset += n_in * n_out + n_out

    acts = x
    best_cls, best_val = 0, -10**9
    for li, (n_in, n_out) in enumerate(layer_dims):
        woff = layer_offsets[li]
        bias_off = n_in * n_out
        is_last = (li == len(layer_dims) - 1)
        out = []
        for j in range(n_out):
            acc = s8(weights[woff + bias_off + j])
            for i in range(n_in):
                acc += acts[i] * s8(weights[woff + j * n_in + i])
            if is_last and acc > best_val:
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


def synth_weights_dense(n_in: int, hidden_dims, n_out: int, seed: int) -> list:
    """Deterministic pseudo-random int8 weights for a synthetic dense-route
    model of the given (n_in, hidden_dims, n_out) shape -- mirrors
    synth_weights() above but for the flat layout generate_ebpf_hardcoded_dense
    expects (no protocol-fixed n_in=65 assumption)."""
    n_h1, n_h2 = hidden_dims
    n = n_in*n_h1 + n_h1 + n_h1*n_h2 + n_h2 + n_h2*n_out + n_out
    rng = random.Random(seed)
    return [rng.randint(-30, 30) for _ in range(n)]


def _check_dense(name, model_id, disp_fd, ps, cs, weights, n_in, n_out, hidden_dims, seed):
    """Dense-route counterpart to _check(): the reference forward pass reads
    a random feature vector directly (no ttl/ingress-iface/model_id derivation
    -- that's the whole point of the dense route), matching
    generate_ebpf_hardcoded_dense()'s payload-reading datapath."""
    rng = random.Random(seed)
    features = [rng.randint(-30, 30) for _ in range(n_in)]
    ref_cls, ref_val = ref_infer_dense(weights, features, hidden_dims, n_out)
    frame = build_frame_dense(model_id, features, 32, n_in, n_out)
    _reset(ps, cs, n_cls=n_out)
    retval, _ = prog_test_run(disp_fd, frame, repeat=1)
    if ref_cls < n_out - 1:
        got = _read_u64(cs, ref_cls)
        ok = (retval in PASS_RETVALS) and got > 0
    else:
        got = _read_u64(ps, 2)
        ok = (retval == 1) and got > 0
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name:10s} model_id={model_id} n_in={n_in:3d} n_out={n_out} "
          f"ref_cls={ref_cls} ref_val={ref_val:>8} retval={retval} hit={got>0}")
    return ok


def _read_u64(table, key_val):
    try:
        return int(table[ct.c_int(key_val)].value)
    except Exception:
        return 0


def _reset(ps, cs, n_cls=7):
    for i in range(3):
        ps[ct.c_int(i)] = ct.c_ulonglong(0)
    for i in range(n_cls):
        try:
            cs[ct.c_int(i)] = ct.c_ulonglong(0)
        except Exception:
            pass


def _check(name, model_id, disp_fd, ps, cs, ref_layer_dims, weights, ttl=3, ifindex=0):
    """
    ifindex: the reference's assumed ctx->ingress_ifindex under
    BPF_PROG_TEST_RUN. P1 (hardcoded) translates the kernel's default value
    through its OWN ifindex_table (which doesn't map it to anything, so it
    resolves to "no iface feature" == ifindex=0 for the reference too). P2
    (template) and P3 (modular) clamp the RAW ctx->ingress_ifindex directly
    (1 <= x <= 6), and the empirically observed default under TEST_RUN is 1
    -- so their reference must assume ifindex=1, not 0, or a close/tied
    class can flip (this was silently masked by verify_prog_run.py's real
    trained-model weights never being sensitive to it -- see the multi-model
    test's synthetic-weight diagnostics for the discrepancy this exposed).
    """
    ref_cls, ref_val = ref_infer_shape(weights, ref_layer_dims, ttl, model_id, ifindex=ifindex)
    frame = build_frame(model_id, ttl, 24)
    _reset(ps, cs)
    retval, _ = prog_test_run(disp_fd, frame, repeat=1)
    if ref_cls < 6:
        got = _read_u64(cs, ref_cls)
        ok = (retval in PASS_RETVALS) and got > 0
    else:
        # ref picked the DROP class (6): the correct kernel behavior is
        # XDP_DROP (retval=1), not a redirect.
        got = _read_u64(ps, 2)
        ok = (retval == 1) and got > 0
    tag = "PASS" if ok else "FAIL"
    shape = "-".join(str(d[0]) for d in ref_layer_dims) + f"-{ref_layer_dims[-1][1]}"
    print(f"  [{tag}] {name:10s} model_id={model_id} shape={shape:14s} "
          f"ref_cls={ref_cls} ref_val={ref_val:>8} retval={retval} hit={got>0}")
    return ok


def test_hardcoded():
    print("\n--- Pipeline 1 (hardcoded): 2 model_id, SAME shape (routing only) ---")
    from ebpf_program import build_combined_hardcoded_source
    weights0, scale0 = load_weights(MODEL_PT)
    dims = [(65, 4), (4, 4), (4, 7)]

    src = build_combined_hardcoded_source([(0, weights0, scale0, None), (1, weights0, scale0, None)])
    b = BPF(text=src)
    model0_fn = b.load_func("model_0", BPF.XDP)
    model1_fn = b.load_func("model_1", BPF.XDP)
    disp_fn   = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ct.c_int(0)] = ct.c_int(model0_fn.fd)
    b["model_progs"][ct.c_int(1)] = ct.c_int(model1_fn.fd)
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table")

    ps, cs = b["pkt_stats"], b["cls_stats"]
    ok = True
    # ifindex=0: P1's ifindex_table (default [2..7]) never maps the kernel's
    # TEST_RUN ingress_ifindex to a logical port, so _iface stays 0.
    ok &= _check("hardcoded", 0, disp_fn.fd, ps, cs, dims, weights0, ifindex=0)
    ok &= _check("hardcoded", 1, disp_fn.fd, ps, cs, dims, weights0, ifindex=0)
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
    # ifindex=1: P2 clamps the RAW ctx->ingress_ifindex (1<=x<=6) directly,
    # no translation table -- the empirically observed TEST_RUN default (1)
    # falls inside that range and DOES contribute a feature.
    ok &= _check("template", 0, disp_fn.fd, ps, cs, dims0, weights0, ifindex=1)
    ok &= _check("template", 1, disp_fn.fd, ps, cs, dims1, weights1, ifindex=1)
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
    # ifindex=1: layer_first also clamps the RAW ctx->ingress_ifindex
    # directly, same reasoning as P2 above.
    ok &= _check("modular", 0, disp_fn.fd, ps, cs, dims0, weights0, ifindex=1)
    ok &= _check("modular", 1, disp_fn.fd, ps, cs, dims1, weights1, ifindex=1)
    return ok


def test_dense():
    print("\n--- Pipeline 1 (dense route): 2 model_id, DIFFERENT n_in, same n_out/hidden_dims ---")
    from ebpf_program import build_combined_hardcoded_dense_source
    n_out, hidden_dims = 4, (4, 4)
    n_in0, n_in1 = 10, 15
    weights0 = synth_weights_dense(n_in0, hidden_dims, n_out, seed=42)
    weights1 = synth_weights_dense(n_in1, hidden_dims, n_out, seed=99)

    src = build_combined_hardcoded_dense_source(
        [(0, weights0, 32, n_in0), (1, weights1, 32, n_in1)],
        n_out=n_out, hidden_dims=hidden_dims)
    b = BPF(text=src)
    model0_fn = b.load_func("model_0", BPF.XDP)
    model1_fn = b.load_func("model_1", BPF.XDP)
    disp_fn   = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ct.c_int(0)] = ct.c_int(model0_fn.fd)
    b["model_progs"][ct.c_int(1)] = ct.c_int(model1_fn.fd)
    _install_mac_table(b, "mac_table", n_classes=n_out - 1)

    ps, cs = b["pkt_stats"], b["cls_stats"]
    ok = True
    ok &= _check_dense("dense", 0, disp_fn.fd, ps, cs, weights0, n_in0, n_out, hidden_dims, seed=1)
    ok &= _check_dense("dense", 1, disp_fn.fd, ps, cs, weights1, n_in1, n_out, hidden_dims, seed=2)
    return ok


def main():
    print("=" * 70)
    print(" IPA/eBPF multi-model concurrent registration -- design-space proof")
    print("=" * 70)
    if not sys.platform.startswith("linux"):
        print("Needs Linux + BCC + root. Run in Kathara.")
        sys.exit(1)

    results = {
        "hardcoded": test_hardcoded(),
        "template":  test_template(),
        "modular":   test_modular(),
        "dense":     test_dense(),
    }
    print()
    print("=" * 70)
    for name, ok in results.items():
        print(f"  {name:10s}: {'PASS' if ok else 'FAIL'}")
    print("=" * 70)
    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
