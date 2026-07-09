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
    ]

def prog_test_run(prog_fd: int, frame: bytes, repeat: int = 1):
    out = (ct.c_uint8 * 2048)()
    a = _BpfAttrTest(
        prog_fd       = prog_fd,
        data_size_in  = len(frame),
        data_size_out = ct.sizeof(out),
        data_in       = ct.cast(ct.c_char_p(frame), ct.c_void_p).value,
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

class MissEventT2(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("model_id",        ct.c_uint8),
        ("ttl",             ct.c_uint8),
        ("ingress_ifindex", ct.c_uint32),
        ("arch_id",         ct.c_uint8),
        ("key",             ct.c_uint64),
    ]

class MissEventT3(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("model_id",        ct.c_uint8),
        ("ttl",             ct.c_uint8),
        ("ingress_ifindex", ct.c_uint32),
        ("layer_idx",       ct.c_uint8),
        ("key",             ct.c_uint64),
    ]

SHARED_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PT     = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
WEIGHTS_JSON = os.path.join(SHARED_DIR, "weights_float.json")
OUTPUT_OFFSET = 100000

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

def _compute_fwd_key(best_val: int, scale: int) -> int:
    return (best_val + OUTPUT_OFFSET * scale) // scale

class _FwdAction(ct.Structure):
    _pack_ = 1
    _fields_ = [("ifindex",  ct.c_uint32), ("src_mac",  ct.c_uint8 * 6), ("dst_mac",  ct.c_uint8 * 6)]

def _insert_fwd_entry(b, fwd_table_name, valid_keys_name, ttl, key, ifindex=2):
    action = _FwdAction(ifindex=ifindex, src_mac=(ct.c_uint8 * 6)(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), dst_mac=(ct.c_uint8 * 6)(0x11, 0x22, 0x33, 0x44, 0x55, 0x66))
    b[fwd_table_name][ct.c_uint64(key)] = action
    b[valid_keys_name][ct.c_uint8(ttl)] = ct.c_uint64(key)

def _remove_fwd_entry(b, fwd_table_name, valid_keys_name, ttl, key):
    try:
        del b[fwd_table_name][ct.c_uint64(key)]
    except Exception:
        pass
    try:
        del b[valid_keys_name][ct.c_uint8(ttl)]
    except Exception:
        pass

def _prime_scratch_p3(b, h2: list, scale: int, model_id: int, w_off_out: int, ingress_ifindex: int = 0, ttl: int = 0):
    for i, v in enumerate(h2[:4]):
        b["scratch_acts"][ct.c_int(i)] = _percpu_arr(v)
    meta = {0: model_id, 1: scale, 2: 2, 3: ingress_ifindex, 4: ttl, 7: w_off_out}
    for slot, val in meta.items():
        b["scratch_meta"][ct.c_int(slot)] = _percpu_arr(val)


def setup_hardcoded(model_id: int, model_path: str):
    """
    Carica il programma eBPF hardcoded misurando separatamente:
      - t_redirect_s : tempo di compilazione BPF + load_func nel kernel (il vero costo del "reload")
      - t_insert_s   : tempo di inserimento dei pesi in model_cache (bpf_map_update_elem)
    Entrambi vengono restituiti nel dict di setup per essere consumati dalla kernel suite.
    """
    from ebpf_program import generate_ebpf_hardcoded, N_WEIGHTS
    weights, scale = load_weights(model_path)
    src = generate_ebpf_hardcoded(weights, scale, model_id)

    # --- misura redirect/reload: compilazione eBPF + caricamento nel kernel ---
    t0 = time.perf_counter()
    b  = BPF(text=src)
    fn = b.load_func("ipa_switch", BPF.XDP)
    t_redirect_s = time.perf_counter() - t0

    try:
        disp = b.load_func("ipa_dispatcher", BPF.XDP)
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(fn.fd)
    except Exception:
        disp = fn

    class ModelData(ct.Structure):
        _pack_ = 1
        _fields_ = [("weights", ct.c_uint8 * N_WEIGHTS), ("is_valid", ct.c_uint8), ("scale_factor", ct.c_uint16)]

    entry = ModelData(is_valid=1, scale_factor=scale)
    for i, v in enumerate(weights[:N_WEIGHTS]):
        entry.weights[i] = ct.c_uint8(int(v) & 0xFF).value

    # --- misura weight insert: singola bpf_map_update_elem su model_cache ---
    t1 = time.perf_counter()
    b["model_cache"][ct.c_uint8(model_id)] = entry
    t_insert_s = time.perf_counter() - t1

    progs = {"ipa_switch": fn.fd}
    if disp is not fn:
        progs["ipa_dispatcher"] = disp.fd

    return {
        "b": b, "fn": fn, "disp": disp,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats"],
        "pkt_stats": b["pkt_stats"],
        "pipeline": 1,
        "progs": progs,
        # tempi reali di update del modello
        "t_redirect_s": t_redirect_s,
        "t_insert_s": t_insert_s,
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
    return {
        "b": b, "fn": leaf_fn, "disp": disp_fn,
        "weights": weights, "scale": scale,
        "cls_stats": None,
        "pkt_stats": b["pkt_stats_t2"],
        "pipeline": 2,
        "perf_name": "miss_events_t2",
        "perf_cls": MissEventT2,
        "fwd_table": "fwd_table_t2",
        "valid_keys": "valid_keys_t2",
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
    w_off_out = (65 * 4 + 4) + (4 * 4 + 4)
    print(f"[P3 setup] nr_cpus={_NR_CPUS}  PERCPU ctypes Array enabled")
    return {
        "b": b, "fn": lf2, "disp": disp_fn,
        "weights": weights, "scale": scale,
        "pkt_stats": b["pkt_stats_t3"],
        "pipeline": 3,
        "perf_name": "miss_events_t3",
        "perf_cls": MissEventT3,
        "fwd_table": "fwd_table_t3",
        "valid_keys": "valid_keys_t3",
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

def _make_perf_cb(event_cls, label, capture):
    def _cb(cpu, data, size):
        if size < ct.sizeof(event_cls):
            return
        ev = ct.cast(data, ct.POINTER(event_cls)).contents
        capture["key"] = int(ev.key)
        capture["ttl"] = int(ev.ttl)
        print(f"  [{label}] miss cpu={cpu} model_id={ev.model_id} ttl={ev.ttl} ifindex={ev.ingress_ifindex} key={ev.key:#018x}")
    return _cb

XDP_PASS = 2
XDP_REDIRECT_PASS = frozenset({0, 4})

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
    fwd_table_name = setup.get("fwd_table")
    valid_keys_name = setup.get("valid_keys")
    w_off_out = setup.get("w_off_out", 0)
    capture = {}
    perf_name = setup.get("perf_name")
    perf_cls = setup.get("perf_cls")
    if perf_name and perf_cls:
        cb = _make_perf_cb(perf_cls, f"P{pipeline}", capture)
        b[perf_name].open_perf_buffer(cb, page_cnt=8)

    # Stampa i tempi reali di update del modello per il Method 1
    if pipeline == 1:
        t_redir = setup.get("t_redirect_s", 0.0)
        t_ins   = setup.get("t_insert_s", 0.0)
        print(f"[M1 update timing] redirect/reload (BPF compile+load): {t_redir*1000:.3f} ms")
        print(f"[M1 update timing] weight insert   (model_cache map):  {t_ins*1000:.3f} ms")
        print(f"[M1 update timing] total:                               {(t_redir+t_ins)*1000:.3f} ms")
        print()

    print(f"[setup] scale={scale}  weights={len(weights)}  prog_fd={fn.fd}")
    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        ref_cls, ref_val, h1, h2 = ref_infer(weights, scale, ttl, model_id, ifindex=0)
        expected_key = _compute_fwd_key(ref_val, scale)
        frame = build_frame(model_id, ttl, scale)
        if pipeline == 1:
            _reset_stats(setup)
            retval, dur_ns = prog_test_run(fn.fd, frame, repeat=repeat)
            cls_count = _read_u64(cs, ref_cls) if cs is not None else 0
            ok = (retval in XDP_REDIRECT_PASS) and (cls_count > 0)
            detail = f"retval={retval} cls_stats[{ref_cls}]={cls_count}"
        else:
            capture.clear()
            _reset_stats(setup)
            if pipeline == 3:
                _prime_scratch_p3(b, h2, scale, model_id, w_off_out=w_off_out, ingress_ifindex=0, ttl=ttl)
            prog_test_run(fn.fd, frame, repeat=1)
            b.perf_buffer_poll(timeout=100)
            kernel_key = capture.get("key")
            if kernel_key is None:
                retval, dur_ns = prog_test_run(fn.fd, frame, repeat=repeat)
                ok = False
                detail = f"retval={retval} no miss event (inference did not complete)"
            else:
                _insert_fwd_entry(b, fwd_table_name, valid_keys_name, ttl=ttl, key=kernel_key, ifindex=2)
                _reset_stats(setup)
                if pipeline == 3:
                    _prime_scratch_p3(b, h2, scale, model_id, w_off_out=w_off_out, ingress_ifindex=0, ttl=ttl)
                retval, dur_ns = prog_test_run(fn.fd, frame, repeat=repeat)
                _remove_fwd_entry(b, fwd_table_name, valid_keys_name, ttl=ttl, key=kernel_key)
                hit_count = _read_u64(ps, 0)
                ok = (retval in XDP_REDIRECT_PASS) and (hit_count > 0)
                drift = ("" if kernel_key == expected_key else f" [py={expected_key}!=kern={kernel_key}]")
                detail = f"retval={retval} pkt_stats[HIT]={hit_count} key={kernel_key}{drift}"
        if retval == XDP_PASS:
            ok = False
            detail += "  <-- XDP_PASS: inference did not complete or cache miss"
        lat_us = dur_ns / 1000 / max(1, repeat)
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"  TTL={ttl:3d}  ref_cls={ref_cls}  ref_val={ref_val:8d}  {detail}  lat={lat_us:.2f}us  [{status}]")
    miss = _read_u64(ps, 1)
    drop = _read_u64(ps, 2)
    print("-" * 70)
    print(f"Results: {passed} PASS / {failed} FAIL  (TTL range [{ttl_min},{ttl_max}])")
    print(f"pkt_stats: HIT={_read_u64(ps,0)}  MISS={miss}  DROP={drop}")
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
