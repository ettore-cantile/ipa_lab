#!/usr/bin/env python3
"""
verify_prog_run.py  --  BPF_PROG_TEST_RUN verifier for the 3 IPA pipelines.
"""

import os
import sys
import json
import struct
import time
import argparse
import ctypes as ct

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
    """struct xdp_md — passed as ctx so ingress_ifindex is deterministic.
    Under BPF_PROG_TEST_RUN the data* fields must be 0 (the kernel fills them
    from data_in); we only care about pinning ingress_ifindex."""
    _fields_ = [
        ("data",            ct.c_uint32),
        ("data_end",        ct.c_uint32),
        ("data_meta",       ct.c_uint32),
        ("ingress_ifindex", ct.c_uint32),
        ("rx_queue_index",  ct.c_uint32),
        ("egress_ifindex",  ct.c_uint32),
    ]

def prog_test_run(prog_fd: int, frame: bytes, repeat: int = 1, ingress_ifindex: int = 0):
    """Run an XDP program on `frame`. A zeroed xdp_md ctx pins ingress_ifindex
    (default 0) so every pipeline sees the same value and matches the Python
    reference. Falls back to a no-ctx call on kernels without XDP ctx support."""
    out = (ct.c_uint8 * 2048)()
    ctx_in  = _XdpMd(ingress_ifindex=ingress_ifindex)
    ctx_out = _XdpMd()
    a = _BpfAttrTest(
        prog_fd       = prog_fd,
        data_size_in  = len(frame),
        data_size_out = ct.sizeof(out),
        data_in       = ct.cast(ct.c_char_p(frame), ct.c_void_p).value,
        data_out      = ct.cast(out, ct.c_void_p).value,
        repeat        = repeat,
        ctx_size_in   = ct.sizeof(ctx_in),
        ctx_size_out  = ct.sizeof(ctx_out),
        ctx_in        = ct.cast(ct.byref(ctx_in), ct.c_void_p).value,
        ctx_out       = ct.cast(ct.byref(ctx_out), ct.c_void_p).value,
    )
    r = _libc.syscall(321, BPF_PROG_TEST_RUN, ct.byref(a), ct.sizeof(a))
    if r != 0:
        # retry without ctx (older kernels reject xdp_md ctx)
        a.ctx_size_in = 0; a.ctx_size_out = 0; a.ctx_in = 0; a.ctx_out = 0
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

SHARED_DIR   = os.path.dirname(os.path.abspath(__file__))
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
    ipa = struct.pack('!BBBHBBBBBBBBBBBBBBBBb', model_id, 0, 0, scale, 65, 7, 2, 4, 3, 0, 65, 0, 0, 0, 0, 0, 0, 1, 0, 7, 0)
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

class _FwdAction(ct.Structure):
    _pack_ = 1
    _fields_ = [("ifindex",  ct.c_uint32), ("src_mac",  ct.c_uint8 * 6), ("dst_mac",  ct.c_uint8 * 6)]

def _install_mac_table(b, name, ifindex=2):
    """Pre-install the class->action map for classes 0..5 (the argmax output).
    The NN picks the class; this dictionary resolves it to {ifindex, MACs}."""
    action = _FwdAction(
        ifindex=ifindex,
        src_mac=(ct.c_uint8 * 6)(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        dst_mac=(ct.c_uint8 * 6)(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
    )
    for cls in range(6):
        b[name][ct.c_uint32(cls)] = action

def _prime_scratch_p3(b, h2: list, scale: int, model_id: int, w_off_out: int, ingress_ifindex: int = 0, ttl: int = 0):
    for i, v in enumerate(h2[:4]):
        b["scratch_acts"][ct.c_int(i)] = _percpu_arr(v)
    meta = {0: model_id, 1: scale, 2: 2, 3: ingress_ifindex, 4: ttl, 7: w_off_out}
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
    from ebpf_program import generate_ebpf_hardcoded
    weights, scale = load_weights(model_path)
    src = generate_ebpf_hardcoded(weights, scale, model_id)

    # --- redirect/reload: eBPF compile + load into the kernel ---
    t0 = time.perf_counter()
    b  = BPF(text=src)
    fn = b.load_func("ipa_switch", BPF.XDP)
    t_redirect_s = time.perf_counter() - t0

    # Pure hardcoded: single leaf program, no dispatcher / model_progs tail-call map.
    disp = fn

    # link_state[0..5] = 1 (all egress links up) -- input feature, not a weight.
    _seed_link_state(b, 1)

    progs = {"ipa_switch": fn.fd}

    return {
        "b": b, "fn": fn, "disp": disp,
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
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_65_4_4_7, load_arch_weights)
    weights, scale = load_weights(model_path)
    src = "#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_65_4_4_7
    b = BPF(text=src)
    disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
    leaf_fn = b.load_func("arch_65_4_4_7", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
    load_arch_weights(b, weights, model_id=model_id, scale=scale)
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table_t2")
    return {
        "b": b, "fn": leaf_fn, "disp": disp_fn,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats_t2"],
        "pkt_stats": b["pkt_stats_t2"],
        "pipeline": 2,
        "progs": {"ipa_switch_template": disp_fn.fd, "arch_65_4_4_7": leaf_fn.fd},
    }


def setup_modular(model_id: int, model_path: str):
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights, scale = load_weights(model_path)
    b = BPF(text=EBPF_MODULAR_FULL)
    disp_fn = b.load_func("modular_dispatcher", BPF.XDP)
    lf0 = b.load_func("layer_65_4", BPF.XDP)
    lf1 = b.load_func("layer_4_4", BPF.XDP)
    lf2 = b.load_func("layer_4_7_argmax", BPF.XDP)
    b["layer_chain"][ct.c_int(0)] = ct.c_int(lf0.fd)
    b["layer_chain"][ct.c_int(1)] = ct.c_int(lf1.fd)
    b["layer_chain"][ct.c_int(2)] = ct.c_int(lf2.fd)
    load_modular_weights(b, weights, model_id=model_id, scale=scale)
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table_t3")
    w_off_out = (65 * 4 + 4) + (4 * 4 + 4)
    print(f"[P3 setup] nr_cpus={_NR_CPUS}  PERCPU ctypes Array enabled")
    return {
        "b": b, "fn": lf2, "disp": disp_fn,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats_t3"],
        "pkt_stats": b["pkt_stats_t3"],
        "pipeline": 3,
        "w_off_out": w_off_out,
        "progs": {
            "modular_dispatcher": disp_fn.fd,
            "layer_65_4": lf0.fd,
            "layer_4_4": lf1.fd,
            "layer_4_7_argmax": lf2.fd,
        },
    }


def _read_u64(table, key_val):
    try:
        return int(table[ct.c_int(key_val)].value)
    except Exception:
        try:
            return int(table[ct.c_uint32(key_val)].value)
        except Exception:
            return 0

def _reset_stats(setup):
    ps = setup["pkt_stats"]
    for i in range(3):
        ps[ct.c_int(i)] = ct.c_ulonglong(0)
    cs = setup.get("cls_stats")
    if cs is not None:
        for i in range(7):
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
    b, fn = setup["b"], setup["fn"]
    weights = setup["weights"]
    scale = setup["scale"]
    ps = setup["pkt_stats"]
    cs = setup.get("cls_stats")
    pipeline = setup["pipeline"]
    w_off_out = setup.get("w_off_out", 0)

    # Model-update timing for Method 1
    if pipeline == 1:
        t_redir = setup.get("t_redirect_s", 0.0)
        t_ins   = setup.get("t_insert_s", 0.0)
        print(f"[M1 update timing] redirect/reload (BPF compile+load): {t_redir*1000:.3f} ms")
        print(f"[M1 update timing] weight insert   (n/a, pure hardcoded): {t_ins*1000:.3f} ms")
        print(f"[M1 update timing] total:                               {(t_redir+t_ins)*1000:.3f} ms")
        print()

    print(f"[setup] scale={scale}  weights={len(weights)}  prog_fd={fn.fd}")
    print("      All pipelines: argmax -> mac_table[class] -> bpf_redirect.")
    print("      PASS = retval in {0,4} (redirect) AND cls_stats[ref_cls] > 0.")
    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        # Reference (ingress=0, matched by the zeroed xdp_md ctx we pass below).
        ref_cls, ref_val, h1, h2 = ref_infer(weights, scale, ttl, model_id, ifindex=0)
        frame = build_frame(model_id, ttl, scale)
        _reset_stats(setup)
        # P3 runs the leaf directly, so prime the intermediate activations it reads.
        if pipeline == 3:
            _prime_scratch_p3(b, h2, scale, model_id, w_off_out=w_off_out, ingress_ifindex=0, ttl=ttl)
        retval, dur_ns = prog_test_run(fn.fd, frame, repeat=repeat, ingress_ifindex=0)
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

def main():
    p = argparse.ArgumentParser(description="IPA/eBPF pipeline verifier")
    p.add_argument("--method", choices=["hardcoded", "template", "modular"], default="hardcoded")
    p.add_argument("--model-id", type=int, default=0)
    p.add_argument("--model", default=MODEL_PT)
    p.add_argument("--ttl-min", type=int, default=1)
    p.add_argument("--ttl-max", type=int, default=10)
    p.add_argument("--repeat", type=int, default=1000, help="BPF_PROG_TEST_RUN repeat count for latency measurement")
    args = p.parse_args()
    sys.exit(run(args.method, args.model_id, args.model, args.ttl_min, args.ttl_max, args.repeat))

if __name__ == "__main__":
    main()
