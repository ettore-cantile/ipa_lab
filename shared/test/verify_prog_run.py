#!/usr/bin/env python3
"""
verify_prog_run.py  --  BPF_PROG_TEST_RUN verifier for the 3 IPA pipelines.

Lives in shared/test/; the pipeline modules it imports (ebpf_program,
ebpf_template_arch, ebpf_modular, extract_weights) live one level up in
shared/, so SHARED_DIR is added to sys.path below.
"""

import os
import sys
import json
import random
import struct
import time
import argparse
import ctypes as ct

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

from bcc import BPF

_libc = ct.CDLL("libc.so.6", use_errno=True)
BPF_PROG_TEST_RUN = 10

class _BpfAttrTest(ct.Structure):
    _fields_ = [
        ("prog_fd",       ct.c_uint32),
        ("retval",        ct.c_uint32),
        ("data_size_in",  ct.c_uint32),
        ("data_size_out", ct.c_uint32),
        ("data_in",       ct.c_uint64),
        ("data_out",      ct.c_uint64),
        ("repeat",        ct.c_uint32),
        ("duration",      ct.c_uint32),
        ("ctx_size_in",   ct.c_uint32),
        ("ctx_size_out",  ct.c_uint32),
        ("ctx_in",        ct.c_uint64),
        ("ctx_out",       ct.c_uint64),
        ("flags",         ct.c_uint32),
        ("cpu",           ct.c_uint32),
        ("batch_size",    ct.c_uint32),
    ]

class _XdpMd(ct.Structure):
    """struct xdp_md — kept for reference; NOT passed as ctx_in (see below)."""
    _fields_ = [
        ("data",            ct.c_uint32),
        ("data_end",        ct.c_uint32),
        ("data_meta",       ct.c_uint32),
        ("ingress_ifindex", ct.c_uint32),
        ("rx_queue_index",  ct.c_uint32),
        ("egress_ifindex",  ct.c_uint32),
    ]

# TEST_RUN_DEFAULT_INGRESS_IFINDEX: empirically observed value of
# ctx->ingress_ifindex under BPF_PROG_TEST_RUN when no ctx_in is supplied
# (this kernel's dummy test device). A prior attempt to force it to 0 via a
# zeroed xdp_md ctx_in caused every packet to be dropped before inference
# (100% XDP_PASS on all 3 pipelines) -- the exact data/data_end/data_meta
# semantics BPF_PROG_TEST_RUN expects for ctx_in are kernel-version-specific
# and were not verified against this kernel. Simpler and verified-safe:
# don't fight the default, just match it on the Python reference side.
TEST_RUN_DEFAULT_INGRESS_IFINDEX = 1

def prog_test_run(prog_fd: int, frame: bytes, repeat: int = 1, ingress_ifindex: int = None):
    """Run an XDP program on `frame` via BPF_PROG_TEST_RUN (no ctx_in --
    ctx_in field semantics for xdp_md are not reliably portable across
    kernels, see TEST_RUN_DEFAULT_INGRESS_IFINDEX). `ingress_ifindex` is
    accepted for API compatibility but unused; the kernel's default test
    device ifindex is used (see TEST_RUN_DEFAULT_INGRESS_IFINDEX)."""
    out = (ct.c_uint8 * 2048)()
    buf = ct.create_string_buffer(frame, len(frame))
    a = _BpfAttrTest(
        prog_fd       = prog_fd,
        data_size_in  = len(frame),
        data_size_out = ct.sizeof(out),
        data_in       = ct.cast(buf, ct.c_void_p).value,
        data_out      = ct.cast(out, ct.c_void_p).value,
        repeat        = repeat,
    )
    r = _libc.syscall(321, BPF_PROG_TEST_RUN, ct.byref(a), ct.sizeof(a))
    if r != 0:
        e = ct.get_errno()
        raise OSError(e, os.strerror(e))
    return a.retval, a.duration

_BPF_OBJ_GET_INFO_BY_FD = 15

class _BpfProgInfo(ct.Structure):
    _fields_ = [
        ("type",            ct.c_uint32),
        ("id",              ct.c_uint32),
        ("tag",             ct.c_uint8 * 8),
        ("jited_prog_len",  ct.c_uint32),
        ("xlated_prog_len", ct.c_uint32),
    ]

class _BpfAttrObjInfo(ct.Structure):
    _fields_ = [
        ("bpf_fd",   ct.c_uint32),
        ("info_len", ct.c_uint32),
        ("info",     ct.c_uint64),
    ]

def prog_insn_count(prog_fd: int):
    buf  = (ct.c_uint8 * 256)()
    info = ct.cast(buf, ct.POINTER(_BpfProgInfo)).contents
    attr = _BpfAttrObjInfo(
        bpf_fd   = prog_fd,
        info_len = ct.sizeof(buf),
        info     = ct.cast(buf, ct.c_void_p).value,
    )
    r = _libc.syscall(321, _BPF_OBJ_GET_INFO_BY_FD, ct.byref(attr), ct.sizeof(attr))
    if r != 0:
        return None, None
    return int(info.xlated_prog_len) // 8, int(info.jited_prog_len)

class _BpfMapInfo(ct.Structure):
    _fields_ = [
        ("map_type",    ct.c_uint32),
        ("id",          ct.c_uint32),
        ("key_size",    ct.c_uint32),
        ("value_size",  ct.c_uint32),
        ("max_entries", ct.c_uint32),
    ]

_PERCPU_MAP_TYPES = frozenset({5, 6, 10, 21})

def map_info(map_fd: int):
    info = _BpfMapInfo()
    attr = _BpfAttrObjInfo(
        bpf_fd   = map_fd,
        info_len = ct.sizeof(info),
        info     = ct.cast(ct.byref(info), ct.c_void_p).value,
    )
    r = _libc.syscall(321, _BPF_OBJ_GET_INFO_BY_FD, ct.byref(attr), ct.sizeof(attr))
    if r != 0:
        return None
    return (int(info.map_type), int(info.key_size), int(info.value_size), int(info.max_entries))

def map_bytes(map_fd: int, nr_cpus: int = 1) -> int:
    mi = map_info(map_fd)
    if mi is None:
        return 0
    map_type, ksz, vsz, ment = mi
    per_cpu = nr_cpus if map_type in _PERCPU_MAP_TYPES else 1
    return (ksz + vsz * per_cpu) * ment

MODEL_PT     = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
WEIGHTS_JSON = os.path.join(SHARED_DIR, "weights_float.json")

def _nr_cpus() -> int:
    try:
        with open("/sys/devices/system/cpu/online") as f:
            s = f.read().strip()
        count = 0
        for part in s.split(","):
            if "-" in part:
                a, b2 = part.split("-")
                count += int(b2) - int(a) + 1
            else:
                count += 1
        return max(1, count)
    except Exception:
        return max(1, os.cpu_count() or 1)

_NR_CPUS = _nr_cpus()
_PercpuLeaf = ct.c_longlong * _NR_CPUS

def _percpu_arr(val: int) -> "_PercpuLeaf":
    return _PercpuLeaf(*([int(val)] * _NR_CPUS))

def load_weights(model_path=MODEL_PT):
    from extract_weights import extract_weights_int8
    weights = extract_weights_int8(model_path)
    scale = 128
    if os.path.exists(WEIGHTS_JSON):
        with open(WEIGHTS_JSON) as f:
            scale = int(json.load(f).get("scale_factor", 128))
    return weights, scale

def build_frame(model_id: int, ttl: int, scale: int) -> bytes:
    eth = b'\x00'*6 + b'\x00'*6 + struct.pack('!H', 0x0800)
    ip  = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 48, 0, 0, ttl, 17, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    udp = struct.pack('!HHHH', 12345, 9999, 28, 0)
    # NOTE: exactly 20 format letters (3 B + 1 H + 16 B) = 21 bytes, matching
    # sizeof(struct ipa_hdr) in the eBPF C source. An earlier version of this
    # format string carried a spurious 21st field (an extra trailing 'b'),
    # producing a 22-byte header -- harmless for the sparse/template/modular
    # routes (which never read past the header), but it silently shifted
    # every payload byte by one position for the dense route, corrupting
    # the feature vector it reads at ipa_hdr+1 (see build_frame_dense()).
    ipa = struct.pack('!BBBHBBBBBBBBBBBBBBBB', model_id, 0, 0, scale, 65, 7, 2, 4, 3, 0, 65, 0, 0, 0, 0, 0, 0, 1, 0, 7)
    return eth + ip + udp + ipa

def ref_infer(weights, scale: int, ttl: int, model_id: int, ifindex: int = 0):
    def s8(v):
        return ct.c_int8(int(v) & 0xFF).value
    N_IN, N_H1, N_H2, N_OUT = 65, 4, 4, 7
    off_fc1_b = N_IN * N_H1
    off_fc2_w = off_fc1_b + N_H1
    off_fc2_b = off_fc2_w + N_H1 * N_H2
    off_out_w = off_fc2_b + N_H2
    off_out_b = off_out_w + N_H2 * N_OUT
    x = [0] * N_IN
    # link_state features [0..5] = 1 (all egress links up) -- matches the
    # verify baseline where the link_state map is seeded to all-up.
    for i in range(6):
        x[i] = 1
    x[12] = ttl
    if 1 <= ifindex <= 6:
        x[5 + ifindex] = 1
    if 0 <= model_id <= 51:
        x[13 + model_id] = 1
    h1 = []
    for j in range(N_H1):
        acc = s8(weights[off_fc1_b + j])
        for i in range(N_IN):
            acc += x[i] * s8(weights[j * N_IN + i])
        h1.append(max(0, acc))
    h2 = []
    for j in range(N_H2):
        acc = s8(weights[off_fc2_b + j])
        for i in range(N_H1):
            acc += h1[i] * s8(weights[off_fc2_w + j * N_H1 + i])
        h2.append(max(0, acc))
    best_val, best_cls = -10**9, 0
    for k in range(N_OUT):
        acc = s8(weights[off_out_b + k])
        for i in range(N_H2):
            acc += h2[i] * s8(weights[off_out_w + k * N_H2 + i])
        if acc > best_val:
            best_val, best_cls = acc, k
    return best_cls, best_val, h1, h2

def build_frame_dense(model_id: int, features: list, scale: int, n_in: int, n_out: int) -> bytes:
    """Same eth/ip/udp/ipa_hdr skeleton as build_frame(), but input_size/
    output_size in the header reflect the dense scenario's real shape, and
    the feature vector (quantized int8) is appended as payload -- the dense
    datapath (generate_ebpf_hardcoded_dense) reads it directly, unlike the
    sparse route where the payload is never touched. IP/UDP length fields
    are dummy placeholders (as in build_frame): BPF_PROG_TEST_RUN derives
    data_end from the actual buffer length, not from these fields."""
    eth = b'\x00'*6 + b'\x00'*6 + struct.pack('!H', 0x0800)
    ip  = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 48, 0, 0, 64, 17, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    udp = struct.pack('!HHHH', 12345, 9999, 28, 0)
    # Exactly 20 format letters (3 B + 1 H + 16 B) = 21 bytes == sizeof(struct
    # ipa_hdr) -- must match precisely here (unlike build_frame()'s sparse
    # frame, which never reads past the header): the dense datapath computes
    # _feat = (__u8*)(ipa+1), so any extra/missing byte in this header
    # shifts every feature read by one position.
    ipa = struct.pack('!BBBHBBBBBBBBBBBBBBBB', model_id, 0, 0, scale, n_in, n_out, 2, 4,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, n_out)
    payload = bytes(int(f) & 0xFF for f in features)
    return eth + ip + udp + ipa + payload


def ref_infer_dense(weights, features: list, hidden_dims, n_out: int):
    """Python reference for generate_ebpf_hardcoded_dense()'s forward pass:
    plain MLP dot product over the raw feature vector (no ttl/iface/node
    derivation -- that's the whole point of the dense route). Returns
    (best_cls, best_val); by convention best_cls == n_out-1 means DROP,
    matching _gen_action_epilogue(f"best_cls >= {n_out-1}")."""
    def s8(v):
        return ct.c_int8(int(v) & 0xFF).value
    n_in = len(features)
    n_h1, n_h2 = hidden_dims
    off_fc1_b = n_in * n_h1
    off_fc2_w = off_fc1_b + n_h1
    off_fc2_b = off_fc2_w + n_h1 * n_h2
    off_out_w = off_fc2_b + n_h2
    off_out_b = off_out_w + n_h2 * n_out
    x = [s8(f) for f in features]
    h1 = []
    for j in range(n_h1):
        acc = s8(weights[off_fc1_b + j])
        for i in range(n_in):
            acc += x[i] * s8(weights[j * n_in + i])
        h1.append(max(0, acc))
    h2 = []
    for j in range(n_h2):
        acc = s8(weights[off_fc2_b + j])
        for i in range(n_h1):
            acc += h1[i] * s8(weights[off_fc2_w + j * n_h1 + i])
        h2.append(max(0, acc))
    best_val, best_cls = -10**9, 0
    for k in range(n_out):
        acc = s8(weights[off_out_b + k])
        for i in range(n_h2):
            acc += h2[i] * s8(weights[off_out_w + k * n_h2 + i])
        if acc > best_val:
            best_val, best_cls = acc, k
    return best_cls, best_val


class _FwdAction(ct.Structure):
    _pack_ = 1
    _fields_ = [("ifindex",  ct.c_uint32), ("src_mac",  ct.c_uint8 * 6), ("dst_mac",  ct.c_uint8 * 6)]

def _install_mac_table(b, name, ifindex=2, n_classes=6):
    """Pre-install the class->action map for classes 0..n_classes-1 (the
    argmax output). The NN picks the class; this dictionary resolves it to
    {ifindex, MACs}. n_classes defaults to 6 (sparse route's historical
    egress count); pass n_out-1 for the dense route's egress count."""
    action = _FwdAction(
        ifindex=ifindex,
        src_mac=(ct.c_uint8 * 6)(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        dst_mac=(ct.c_uint8 * 6)(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
    )
    for cls in range(n_classes):
        b[name][ct.c_uint32(cls)] = action

def _prime_scratch_p3(b, h2: list, scale: int, model_id: int, layer_idx: int, ingress_ifindex: int = 0, ttl: int = 0):
    """Seed scratch_acts/scratch_meta so that calling layer_hidden directly
    (bypassing dispatcher + earlier hops) exercises just the model's LAST
    layer: layer_idx must be n_layers-1 so layer_hidden's own
    (layer_idx+1==n_layers) check resolves to argmax+forward. The weight
    offset for that layer comes from layer_shapes[{model_id, layer_idx}]
    (already populated by load_modular_weights), not from scratch_meta --
    unlike the old fixed 3-block design there is no w_off_out slot anymore."""
    for i, v in enumerate(h2[:4]):
        b["scratch_acts"][ct.c_int(i)] = _percpu_arr(v)
    meta = {0: model_id, 1: scale, 2: layer_idx, 3: ingress_ifindex, 4: ttl}
    for slot, val in meta.items():
        b["scratch_meta"][ct.c_int(slot)] = _percpu_arr(val)


def _seed_link_state(b, val: int = 1):
    """Seed the link_state map [0..5] with `val` (1=up) if the program has it.
    All three pipelines read these 6 slots as the model's first input features
    (egress up/down). Verify runs the 'all links up' baseline, so it must match
    ref_infer's x[0..5]=1."""
    try:
        for i in range(6):
            b["link_state"][ct.c_int(i)] = ct.c_uint32(int(val))
    except Exception:
        pass


def setup_hardcoded(model_id: int, model_path: str):
    """
    Load the pure hardcoded eBPF program (Pipeline 1).

    There is NO model_cache / weight map anymore: the weights are C literals
    compiled into the program, so updating the model = recompiling+reloading the
    whole program. We therefore measure only the redirect/reload cost:
      - t_redirect_s : BPF compile + load_func into the kernel (the real update cost)
      - t_insert_s   : 0 (no runtime weight insertion in the pure hardcoded design)
    """
    from ebpf_program import build_combined_hardcoded_source
    weights, scale = load_weights(model_path)
    src = build_combined_hardcoded_source([(model_id, weights, scale, None)])

    # --- redirect/reload: eBPF compile + load into the kernel ---
    t0 = time.perf_counter()
    b  = BPF(text=src)
    model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
    fn = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ct.c_int(model_id)] = ct.c_int(model_fn.fd)
    t_redirect_s = time.perf_counter() - t0

    # Dispatcher tail-calls model_progs[model_id] -- 1 tail call, matching
    # the design-space spec's hardcoded pipeline (packet -> dispatcher ->
    # tail call -> model_<id> -> action). Still zero weight-map lookups.
    disp = fn

    # link_state[0..5] = 1 (all egress links up) -- input feature, not a weight.
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table")

    progs = {"ipa_switch_hardcoded": fn.fd, f"model_{model_id}": model_fn.fd}

    return {
        "b": b, "fn": model_fn, "disp": disp,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats"],
        "pkt_stats": b["pkt_stats"],
        "pipeline": 1,
        "progs": progs,
        # real model-update timing: pure hardcoded = full recompile, no weight insert
        "t_redirect_s": t_redirect_s,
        "t_insert_s": 0.0,
    }


def setup_template(model_id: int, model_path: str):
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_GENERIC_2LAYER, load_arch_weights)
    weights, scale = load_weights(model_path)
    src = "#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_GENERIC_2LAYER
    b = BPF(text=src)
    disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
    leaf_fn = b.load_func("arch_generic_2layer", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
    load_arch_weights(b, weights, model_id=model_id, scale=scale)  # default n_h1=n_h2=4 matches weights.json
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table_t2")
    return {
        "b": b, "fn": leaf_fn, "disp": disp_fn,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats_t2"],
        "pkt_stats": b["pkt_stats_t2"],
        "pipeline": 2,
        "progs": {"ipa_switch_template": disp_fn.fd, "arch_generic_2layer": leaf_fn.fd},
    }


def setup_modular(model_id: int, model_path: str):
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights, scale = load_weights(model_path)
    b = BPF(text=EBPF_MODULAR_FULL)
    disp_fn   = b.load_func("modular_dispatcher", BPF.XDP)
    fn_first  = b.load_func("layer_first",  BPF.XDP)
    fn_hidden = b.load_func("layer_hidden", BPF.XDP)
    # slot 0 = layer_first (always hop 0), slots 1..15 = layer_hidden
    # (always a later hop) -- see ebpf_modular.py module docstring for why.
    b["layer_chain"][ct.c_int(0)] = ct.c_int(fn_first.fd)
    for i in range(1, 16):  # LAYER_CHAIN_SIZE
        b["layer_chain"][ct.c_int(i)] = ct.c_int(fn_hidden.fd)
    layer_dims = [(65, 4), (4, 4), (4, 7)]
    n_layers = len(layer_dims)
    load_modular_weights(b, weights, model_id=model_id, scale=scale, layer_dims=layer_dims)
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table_t3")
    print(f"[P3 setup] nr_cpus={_NR_CPUS}  PERCPU ctypes Array enabled")
    return {
        # "fn" is the direct BPF_PROG_TEST_RUN target used by run() below to
        # exercise the model's LAST layer in isolation (see _prime_scratch_p3):
        # for a 3-layer model that's always layer_hidden (layer_idx>=1).
        "b": b, "fn": fn_hidden, "disp": disp_fn,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats_t3"],
        "pkt_stats": b["pkt_stats_t3"],
        "pipeline": 3,
        "last_layer_idx": n_layers - 1,
        # n_tail = actual runtime tail-call hops for this model (dispatcher ->
        # layer_first -> layer_hidden x (n_layers-1)): NOT len(progs)-1 --
        # there are only 2 distinct layer programs regardless of depth.
        "n_tail": n_layers,
        "progs": {
            "modular_dispatcher": disp_fn.fd,
            "layer_first": fn_first.fd,
            "layer_hidden": fn_hidden.fd,
        },
    }


def setup_dense(model_id: int, model_dir: str):
    """
    Load the dense-generic route of Pipeline 1 (generate_ebpf_hardcoded_dense),
    from a directory holding model_meta.json (+ weights.json/weights_float.json,
    see shared/model_meta.py). No .pt/torch involved -- same "no incremental
    path, every add is a full recompile" cost profile as setup_hardcoded(),
    just with n_in/n_out declared by model_meta.json instead of the protocol-
    fixed 65/7.
    """
    from ebpf_program import load_and_generate
    import model_meta as mm

    model_path = os.path.join(model_dir, "model.pt")  # need not exist -- see model_meta.py
    meta = mm.load_model_meta(model_path)
    if meta.get("scenario") != "dense":
        raise ValueError(f"{model_dir}/model_meta.json is not scenario=\"dense\"")
    shape = mm.derive_shape(meta)

    t0 = time.perf_counter()
    src, weights, scale = load_and_generate(model_path, model_id=model_id, meta=meta)
    b = BPF(text=src)
    model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
    fn = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ct.c_int(model_id)] = ct.c_int(model_fn.fd)
    t_redirect_s = time.perf_counter() - t0

    n_egress = shape["n_out"] - 1  # last class = DROP, by convention (see ebpf_program.py)
    _install_mac_table(b, "mac_table", n_classes=n_egress)

    return {
        "b": b, "fn": model_fn, "disp": fn,
        "weights": weights, "scale": scale, "shape": shape,
        "cls_stats": b["cls_stats"],
        "pkt_stats": b["pkt_stats"],
        "pipeline": 1,
        "t_redirect_s": t_redirect_s,
        "t_insert_s": 0.0,
        "progs": {"ipa_switch_hardcoded": fn.fd, f"model_{model_id}": model_fn.fd},
    }


def count_lookups(method: str, model_id: int, model_path: str, ttl: int = 5, repeat: int = 2000) -> float:
    """
    Real per-packet map-lookup count for `method`, measured via a dedicated
    instrumented build (every `.lookup()` call wrapped with CTR_INC(), see
    common.py instrument_map_lookups()). This compiles a SEPARATE BPF object
    from the one used for latency/instruction measurement -- the counting
    overhead never contaminates the hardware-measured performance numbers,
    only this metric. Runs `repeat` packets through the dispatcher (the real
    per-packet path, tail calls included) and returns lookup_ctr[0]/repeat.

    For method == "dense", `model_path` is actually a model_dir (directory
    holding model_meta.json) -- see setup_dense(). Expect 0 lookups: the
    dense route reads its feature vector straight from the packet payload,
    no map read at all (not even link_state).
    """
    from common import instrument_map_lookups
    frame_override = None

    if method != "dense":
        weights, scale = load_weights(model_path)

    if method == "hardcoded":
        from ebpf_program import build_combined_hardcoded_source
        raw = build_combined_hardcoded_source([(model_id, weights, scale, None)])
        src = "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(raw)
        b = BPF(text=src)
        model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
        disp_fn  = b.load_func("ipa_switch_hardcoded", BPF.XDP)
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(model_fn.fd)
        _seed_link_state(b, 1)
        _install_mac_table(b, "mac_table")
    elif method == "template":
        from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_GENERIC_2LAYER, load_arch_weights)
        raw = "#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_GENERIC_2LAYER
        src = "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(raw)
        b = BPF(text=src)
        disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
        leaf_fn = b.load_func("arch_generic_2layer", BPF.XDP)
        b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
        load_arch_weights(b, weights, model_id=model_id, scale=scale)
        _seed_link_state(b, 1)
        _install_mac_table(b, "mac_table_t2")
    elif method == "modular":
        from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
        src = "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(EBPF_MODULAR_FULL)
        b = BPF(text=src)
        disp_fn   = b.load_func("modular_dispatcher", BPF.XDP)
        fn_first  = b.load_func("layer_first",  BPF.XDP)
        fn_hidden = b.load_func("layer_hidden", BPF.XDP)
        b["layer_chain"][ct.c_int(0)] = ct.c_int(fn_first.fd)
        for i in range(1, 16):
            b["layer_chain"][ct.c_int(i)] = ct.c_int(fn_hidden.fd)
        load_modular_weights(b, weights, model_id=model_id, scale=scale,
                             layer_dims=[(65, 4), (4, 4), (4, 7)])
        _seed_link_state(b, 1)
        _install_mac_table(b, "mac_table_t3")
    elif method == "dense":
        from ebpf_program import load_and_generate
        import model_meta as mm

        model_dir = model_path
        dummy_model_path = os.path.join(model_dir, "model.pt")
        meta = mm.load_model_meta(dummy_model_path)
        shape = mm.derive_shape(meta)
        raw, weights, scale = load_and_generate(dummy_model_path, model_id=model_id, meta=meta)
        src = "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(raw)
        b = BPF(text=src)
        model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
        disp_fn  = b.load_func("ipa_switch_hardcoded", BPF.XDP)
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(model_fn.fd)
        _install_mac_table(b, "mac_table", n_classes=shape["n_out"] - 1)
        features = [0] * shape["n_in"]
        frame_override = build_frame_dense(model_id, features, scale, shape["n_in"], shape["n_out"])
    else:
        raise ValueError(f"count_lookups: unknown method {method!r}")

    frame = frame_override if frame_override is not None else build_frame(model_id, ttl, scale)
    b["lookup_ctr"][ct.c_int(0)] = ct.c_ulonglong(0)
    prog_test_run(disp_fn.fd, frame, repeat=repeat)
    total = int(b["lookup_ctr"][ct.c_int(0)].value)
    return total / float(repeat)


def _read_u64(table, key_val):
    try:
        return int(table[ct.c_int(key_val)].value)
    except Exception:
        try:
            return int(table[ct.c_uint32(key_val)].value)
        except Exception:
            return 0

def _reset_stats(setup, n_classes=7):
    ps = setup["pkt_stats"]
    for i in range(3):
        ps[ct.c_int(i)] = ct.c_ulonglong(0)
    cs = setup.get("cls_stats")
    if cs is not None:
        for i in range(n_classes):
            try:
                cs[ct.c_uint32(i)] = ct.c_ulonglong(0)
            except Exception:
                pass

XDP_PASS = 2
XDP_REDIRECT_PASS = frozenset({0, 4})


def _fired_cls_p1(setup) -> int:
    """After a single-packet run of Pipeline 1, return the egress class that
    fired: 0..5 = redirect on that class, 6 = DROP, -1 = nothing."""
    cs = setup["cls_stats"]
    for c in range(6):
        if _read_u64(cs, c) > 0:
            return c
    if _read_u64(setup["pkt_stats"], 2) > 0:
        return 6
    return -1


def probe_link_down(model_path, model_id: int = 0, ttl_min: int = 1, ttl_max: int = 5):
    """Prove that link_state is a live routing input: for each TTL and each
    egress k, run Pipeline 1 with all links up, then with link k down
    (link_state[k]=0), and record the cases where the argmax egress class
    changes. Returns (changes, tested) where changes is a list of
    (ttl, k, cls_up, cls_down). A non-empty result means a link failure
    actually reroutes the packet."""
    setup = setup_hardcoded(model_id, model_path)
    b, fn, scale = setup["b"], setup["fn"], setup["scale"]
    changes, tested = [], 0
    for ttl in range(ttl_min, ttl_max + 1):
        frame = build_frame(model_id, ttl, scale)
        _seed_link_state(b, 1)
        _reset_stats(setup)
        prog_test_run(fn.fd, frame, repeat=1)
        cls_up = _fired_cls_p1(setup)
        for k in range(6):
            _seed_link_state(b, 1)
            b["link_state"][ct.c_int(k)] = ct.c_uint32(0)
            _reset_stats(setup)
            prog_test_run(fn.fd, frame, repeat=1)
            cls_down = _fired_cls_p1(setup)
            tested += 1
            if cls_down != cls_up:
                changes.append((ttl, k, cls_up, cls_down))
    _seed_link_state(b, 1)
    return changes, tested

def run(method: str, model_id: int, model_path: str, ttl_min: int, ttl_max: int, repeat: int):
    print("=" * 70)
    print(f" IPA/eBPF BPF_PROG_TEST_RUN  --  method={method}  model_id={model_id}")
    print("=" * 70)
    print()
    print("NOTE: bpf_redirect() runs in the TEST_RUN sandbox.")
    print("      PASS = retval in {0,4} (redirect fire) + cls_stats/pkt_stats hit.")
    print()
    setup_fn = {"hardcoded": setup_hardcoded, "template": setup_template, "modular": setup_modular}[method]
    setup = setup_fn(model_id, model_path)
    b, fn, disp = setup["b"], setup["fn"], setup["disp"]
    weights = setup["weights"]
    scale = setup["scale"]
    ps = setup["pkt_stats"]
    cs = setup.get("cls_stats")
    pipeline = setup["pipeline"]

    # Model-update timing for Method 1
    if pipeline == 1:
        t_redir = setup.get("t_redirect_s", 0.0)
        t_ins   = setup.get("t_insert_s", 0.0)
        print(f"[M1 update timing] redirect/reload (BPF compile+load): {t_redir*1000:.3f} ms")
        print(f"[M1 update timing] weight insert   (n/a, pure hardcoded): {t_ins*1000:.3f} ms")
        print(f"[M1 update timing] total:                               {(t_redir+t_ins)*1000:.3f} ms")
        print()

    print(f"[setup] scale={scale}  weights={len(weights)}  disp_fd={disp.fd}")
    print("      All pipelines tested via the REAL dispatcher (full tail-call chain,")
    print("      dispatcher -> ... -> action) -- no leaf-priming shortcut.")
    print("      argmax -> mac_table[class] -> bpf_redirect.")
    print("      PASS = retval in {0,4} (redirect) AND cls_stats[ref_cls] > 0.")
    # Reference ingress_ifindex: under BPF_PROG_TEST_RUN, the sandbox's real
    # default ctx->ingress_ifindex is 1 (empirically confirmed -- see
    # TEST_RUN_DEFAULT_INGRESS_IFINDEX above and the multi-model diagnostics
    # in verify_multi_model.py). P1 translates it through its OWN
    # ifindex_table (default [2..7]), which does NOT map 1 -> _iface stays 0.
    # P2/P3 clamp the raw value directly (1<=x<=6), so 1 DOES contribute an
    # iface feature there. This only ever flips a close/tied argmax; the
    # real trained 65-4-4-7 model isn't sensitive to it (class 0 dominates),
    # which is why ifindex=0 "worked" here for years without anyone noticing.
    ref_ifindex = 0 if pipeline == 1 else 1
    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        ref_cls, ref_val, h1, h2 = ref_infer(weights, scale, ttl, model_id, ifindex=ref_ifindex)
        frame = build_frame(model_id, ttl, scale)
        _reset_stats(setup)
        retval, dur_ns = prog_test_run(disp.fd, frame, repeat=repeat, ingress_ifindex=0)
        cls_count = _read_u64(cs, ref_cls) if cs is not None else 0
        ok = (retval in XDP_REDIRECT_PASS) and (cls_count > 0)
        detail = f"retval={retval} cls_stats[{ref_cls}]={cls_count}"
        if retval == XDP_PASS:
            ok = False
            detail += "  <-- XDP_PASS: inference did not complete / no mac_table entry"
        lat_us = dur_ns / 1000 / max(1, repeat)
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"  TTL={ttl:3d}  ref_cls={ref_cls}  ref_val={ref_val:8d}  {detail}  lat={lat_us:.2f}us  [{status}]")
    print("-" * 70)
    print(f"Results: {passed} PASS / {failed} FAIL  (TTL range [{ttl_min},{ttl_max}])")
    print(f"pkt_stats: HIT={_read_u64(ps,0)}  MISS={_read_u64(ps,1)}  DROP={_read_u64(ps,2)}")
    return failed

def run_dense(model_dir: str, model_id: int, n_vectors: int, repeat: int, seed: int = 0) -> int:
    """
    Dense-route counterpart to run(): instead of sweeping TTL against a
    fixed 65-4-4-7 model (ttl is irrelevant here, features aren't derived
    from packet metadata), exercise `n_vectors` random quantized feature
    vectors and check the kernel's argmax/redirect against ref_infer_dense().
    """
    print("=" * 70)
    print(f" IPA/eBPF BPF_PROG_TEST_RUN  --  method=dense  model_id={model_id}  dir={model_dir}")
    print("=" * 70)
    print()
    setup = setup_dense(model_id, model_dir)
    b, disp = setup["b"], setup["disp"]
    weights, scale, shape = setup["weights"], setup["scale"], setup["shape"]
    n_in, n_out, hidden_dims = shape["n_in"], shape["n_out"], tuple(shape["hidden_dims"])
    ps, cs = setup["pkt_stats"], setup["cls_stats"]

    t_redir = setup.get("t_redirect_s", 0.0)
    print(f"[dense update timing] redirect/reload (BPF compile+load): {t_redir*1000:.3f} ms")
    print(f"[setup] scale={scale}  weights={len(weights)}  n_in={n_in}  n_out={n_out}  disp_fd={disp.fd}")
    print(f"      Feature vector travels in the PAYLOAD (read directly by the datapath),")
    print(f"      not derived from ttl/ingress-iface/model_id like the sparse route.")
    print(f"      PASS = retval in {{0,4}} (redirect) AND cls_stats[ref_cls] > 0 "
          f"(or XDP_DROP for ref_cls == {n_out - 1}).")

    rng = random.Random(seed)
    passed = failed = 0
    for v in range(n_vectors):
        features = [rng.randint(-30, 30) for _ in range(n_in)]
        ref_cls, ref_val = ref_infer_dense(weights, features, hidden_dims, n_out)
        frame = build_frame_dense(model_id, features, scale, n_in, n_out)
        _reset_stats(setup, n_classes=n_out)
        retval, dur_ns = prog_test_run(disp.fd, frame, repeat=repeat)
        if ref_cls < n_out - 1:
            cls_count = _read_u64(cs, ref_cls)
            ok = (retval in XDP_REDIRECT_PASS) and (cls_count > 0)
            detail = f"retval={retval} cls_stats[{ref_cls}]={cls_count}"
        else:
            cls_count = _read_u64(ps, 2)
            ok = (retval == 1) and (cls_count > 0)
            detail = f"retval={retval} pkt_stats[DROP]={cls_count}"
        lat_us = dur_ns / 1000 / max(1, repeat)
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"  vec={v:3d}  ref_cls={ref_cls}  ref_val={ref_val:8d}  {detail}  lat={lat_us:.2f}us  [{status}]")
    print("-" * 70)
    print(f"Results: {passed} PASS / {failed} FAIL  ({n_vectors} random feature vectors, n_in={n_in})")
    print(f"pkt_stats: HIT={_read_u64(ps,0)}  MISS={_read_u64(ps,1)}  DROP={_read_u64(ps,2)}")
    return failed


def main():
    p = argparse.ArgumentParser(description="IPA/eBPF pipeline verifier")
    p.add_argument("--method", choices=["hardcoded", "template", "modular", "dense"], default="hardcoded")
    p.add_argument("--model-id", type=int, default=0)
    p.add_argument("--model", default=MODEL_PT)
    p.add_argument("--model-dir", default=os.path.join(SHARED_DIR, "test", "fixtures", "dense_10_4_4_4"),
                   help="dense only: directory with model_meta.json (+ weights.json)")
    p.add_argument("--n-vectors", type=int, default=20,
                   help="dense only: random feature vectors to test (default 20)")
    p.add_argument("--ttl-min", type=int, default=1)
    p.add_argument("--ttl-max", type=int, default=10)
    p.add_argument("--repeat", type=int, default=1000, help="BPF_PROG_TEST_RUN repeat count for latency measurement")
    args = p.parse_args()
    if args.method == "dense":
        sys.exit(run_dense(args.model_dir, args.model_id, args.n_vectors, args.repeat))
    sys.exit(run(args.method, args.model_id, args.model, args.ttl_min, args.ttl_max, args.repeat))

if __name__ == "__main__":
    main()
