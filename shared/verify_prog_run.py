#!/usr/bin/env python3
"""
verify_prog_run.py  --  BPF_PROG_TEST_RUN verifier for the 3 IPA pipelines.

Usage (root, inside Kathara frankfurt container or any BCC host):

    python3 verify_prog_run.py --method hardcoded
    python3 verify_prog_run.py --method template
    python3 verify_prog_run.py --method modular
    python3 verify_prog_run.py --method modular --model-id 3

Exit 0 = all TTLs PASS.  Exit 1 = at least one mismatch.

--- Architecture per professor spec ---

Pipeline 1 - Hardcoded Model (baseline assoluta)
  Un programma eBPF per modello, pesi hardcoded come letterali C, inferenza
  completamente unrolled.  Nessuna BPF map per i pesi, nessuna fwd_table.
  Azione: switch(best_cls) { case 0: bpf_redirect(ifindex0); ... case 6: DROP }
  dispatcher -> tail call -> ipa_switch (tutto in un blocco, max velocita)

Pipeline 2 - Pre-built Architecture Template (compromesso pratico)
  Un programma per forma architetturale (es. arch_65_4_4_7), pesi in
  BPF_ARRAY.  Dispatcher consulta arch_registry[model_id] -> arch_id,
  poi tail call -> arch_65_4_4_7 che legge i pesi da arch_weights[offset+i].
  Azione: bpf_redirect(ifindex[best_cls]) diretto dopo argmax (no fwd_table).
  Aggiornamento modello = sovrascrivere arch_weights, zero recompile.

Pipeline 3 - Modular Neural Pipeline (massima flessibilita)
  La rete e spezzata in layer indipendenti.  Ogni layer e un programma XDP:
    layer_65_4  -> layer_4_4 -> layer_4_7_argmax
  Le attivazioni intermedie sono salvate in BPF_PERCPU_ARRAY scratch.
  Ogni layer fa una tail call al successivo.  Il costo misurato e quello
  di multiple tail calls + letture/scritture scratch per lo stato intermedio.
  Azione finale: bpf_redirect(ifindex[best_cls]) in layer_4_7_argmax.

Perche retval != 3 con BPF_PROG_TEST_RUN:
  bpf_redirect() in sandbox: su kernel recenti (>= 5.18) il redirect viene
  eseguito davvero e restituisce XDP_REDIRECT(4); su kernel piu vecchi
  ritorna XDP_ABORTED(0).  Criterio di PASS: retval in {0, 4} (redirect
  fire) E cls_stats/pkt_stats[HIT] incrementato (confirm correct path).

Fixed bug (2026-07-09 v7): build_frame format string mismatch.
  '!BBBHBBBBBBBBBBBBBBBb' had 20 format specs but pack() received 21
  arguments -> struct.error: pack expected 20 items for packing (got 21).
  The tail group (n_output_types=1, out0_code=0, out0_count=7, pad=0) is
  4 values; the old format only had 'BBb' = 3 specs for that group.
  Fix: use '!BBBHBBBBBBBBBBBBBBBBb' (21 specs matching 21 args exactly).

Fixed bug (2026-07-09 v6): build_frame IPA header layout (param_size missing).
  struct ipa_hdr C layout:
    model_id(u8), model_type(u8), param_size(u8), scale_factor(be16), ...
  build_frame was packing '!BBH...' -> param_size was absent, scale_factor
  received the wrong bytes -> kernel read scale=0 -> guard 'if (scale==0)
  return XDP_PASS' fired -> key was never computed -> all packets produced
  key=0x0000000000000000 and MISS.
  Fix: use '!BBBHBBBBBBBBBBBBBBBBb' with explicit param_size=0.

Fixed bug (2026-07-09 v4): PERCPU write type must be ctypes Array.
  BCC ~0.18 PerCpuArray.__setitem__ calls ct.byref(leaf) internally.
  ct.byref() requires a ctypes instance; a Python list raises:
    TypeError: byref() argument must be a ctypes instance, not 'list'
  Fix: _percpu_arr(val) now returns (ct.c_longlong * _NR_CPUS)(*([val]*_NR_CPUS))
  which is a properly-typed ctypes Array of nr_cpus elements.

Fixed bug (2026-07-09 v3): BPF_PERCPU_ARRAY write semantics.
  Writing a scalar only populates CPU-0 slot.  BPF_PROG_TEST_RUN runs on
  an arbitrary CPU -> stale zeros -> argmax wrong -> all TTL FAIL.

Fixed bug (2026-07-09 v2): retval acceptance, fwd_table pre-population,
  tail-call bypass (run TEST_RUN on lf2 directly).

Fixed bug (2026-07-09): __u8 perf event crash via BCC auto-deserializer.
  Fix: explicit ctypes.Structure + cast.
"""

import os
import sys
import json
import struct
import argparse
import ctypes as ct

from bcc import BPF

# ---------------------------------------------------------------------------
# BPF_PROG_TEST_RUN via raw syscall (libbcc legacy: no bpf_prog_test_run)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# ctypes mirror structs for perf event deserialization.
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SHARED_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PT     = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
WEIGHTS_JSON = os.path.join(SHARED_DIR, "weights_float.json")
OUTPUT_OFFSET = 100000

# ---------------------------------------------------------------------------
# Numero di CPU online
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# PERCPU Array helper
# ---------------------------------------------------------------------------

_PercpuLeaf = ct.c_longlong * _NR_CPUS

def _percpu_arr(val: int) -> "_PercpuLeaf":
    """
    Return a ctypes Array of _NR_CPUS c_longlong elements all set to val.
    This is the correct leaf type expected by BCC PerCpuArray.__setitem__.
    """
    return _PercpuLeaf(*([int(val)] * _NR_CPUS))

# ---------------------------------------------------------------------------
# Weights loader
# ---------------------------------------------------------------------------

def load_weights(model_path=MODEL_PT):
    from extract_weights import extract_weights_int8
    weights = extract_weights_int8(model_path)
    scale = 128
    if os.path.exists(WEIGHTS_JSON):
        with open(WEIGHTS_JSON) as f:
            scale = int(json.load(f).get("scale_factor", 128))
    return weights, scale

# ---------------------------------------------------------------------------
# Frame builder
# ---------------------------------------------------------------------------

def build_frame(model_id: int, ttl: int, scale: int) -> bytes:
    eth = b'\x00'*6 + b'\x00'*6 + struct.pack('!H', 0x0800)
    ip  = struct.pack('!BBHHHBBH4s4s',
                      0x45, 0, 48, 0, 0,
                      ttl, 17, 0,
                      b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    udp = struct.pack('!HHHH', 12345, 9999, 28, 0)
    # struct ipa_hdr C layout (packed), 21 fields:
    #  [0]  model_id         u8
    #  [1]  model_type       u8
    #  [2]  param_size       u8   <-- must be explicit before scale_factor
    #  [3]  scale_factor     be16
    #  [4]  input_size       u8
    #  [5]  output_size      u8
    #  [6]  hidden_layers    u8
    #  [7]  neurons_per_layer u8
    #  [8]  n_feature_types  u8
    #  [9]  feat0_code       u8
    # [10]  feat0_count      u8
    # [11]  feat1_code       u8
    # [12]  feat1_count      u8
    # [13]  feat2_code       u8
    # [14]  feat2_count      u8
    # [15]  feat3_code       u8
    # [16]  feat3_count      u8
    # [17]  n_output_types   u8
    # [18]  out0_code        u8
    # [19]  out0_count       u8
    # [20]  pad              s8
    # Format '!BBBHBBBBBBBBBBBBBBBBb' = 3B + H + 16B + b = 21 specs / 21 args
    ipa = struct.pack('!BBBHBBBBBBBBBBBBBBBBb',
                      model_id,   # [0]  model_id
                      0,          # [1]  model_type
                      0,          # [2]  param_size
                      scale,      # [3]  scale_factor (be16)
                      65,         # [4]  input_size
                      7,          # [5]  output_size
                      2,          # [6]  hidden_layers
                      4,          # [7]  neurons_per_layer
                      3,          # [8]  n_feature_types
                      0,          # [9]  feat0_code
                      65,         # [10] feat0_count
                      0,          # [11] feat1_code
                      0,          # [12] feat1_count
                      0,          # [13] feat2_code
                      0,          # [14] feat2_count
                      0,          # [15] feat3_code
                      0,          # [16] feat3_count
                      1,          # [17] n_output_types
                      0,          # [18] out0_code
                      7,          # [19] out0_count
                      0)          # [20] pad (signed)
    return eth + ip + udp + ipa

# ---------------------------------------------------------------------------
# Python reference inference
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# fwd_table helpers
# ---------------------------------------------------------------------------

class _FwdAction(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("ifindex",  ct.c_uint32),
        ("src_mac",  ct.c_uint8 * 6),
        ("dst_mac",  ct.c_uint8 * 6),
    ]

def _insert_fwd_entry(b, fwd_table_name, valid_keys_name, ttl, key, ifindex=2):
    action = _FwdAction(
        ifindex = ifindex,
        src_mac = (ct.c_uint8 * 6)(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        dst_mac = (ct.c_uint8 * 6)(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
    )
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

# ---------------------------------------------------------------------------
# Pipeline 3: pre-populate scratch PERCPU maps
# ---------------------------------------------------------------------------

def _prime_scratch_p3(b, h2: list, scale: int, model_id: int,
                      w_off_out: int, ingress_ifindex: int = 0, ttl: int = 0):
    for i, v in enumerate(h2[:4]):
        b["scratch_acts"][ct.c_int(i)] = _percpu_arr(v)

    meta = {
        0: model_id,
        1: scale,
        2: 2,
        3: ingress_ifindex,
        4: ttl,
        7: w_off_out,
    }
    for slot, val in meta.items():
        b["scratch_meta"][ct.c_int(slot)] = _percpu_arr(val)

# ---------------------------------------------------------------------------
# Pipeline 1: Hardcoded
# ---------------------------------------------------------------------------

def setup_hardcoded(model_id: int, model_path: str):
    from ebpf_program import generate_ebpf_hardcoded, N_WEIGHTS
    weights, scale = load_weights(model_path)
    src = generate_ebpf_hardcoded(weights, scale, model_id)
    b   = BPF(text=src)
    fn  = b.load_func("ipa_switch", BPF.XDP)
    try:
        disp = b.load_func("ipa_dispatcher", BPF.XDP)
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(fn.fd)
    except Exception:
        disp = fn

    class ModelData(ct.Structure):
        _pack_ = 1
        _fields_ = [
            ("weights",      ct.c_uint8 * N_WEIGHTS),
            ("is_valid",     ct.c_uint8),
            ("scale_factor", ct.c_uint16),
        ]
    entry = ModelData(is_valid=1, scale_factor=scale)
    for i, v in enumerate(weights[:N_WEIGHTS]):
        entry.weights[i] = ct.c_uint8(int(v) & 0xFF).value
    b["model_cache"][ct.c_uint8(model_id)] = entry

    return {
        "b":         b,
        "fn":        fn,
        "disp":      disp,
        "weights":   weights,
        "scale":     scale,
        "cls_stats": b["cls_stats"],
        "pkt_stats": b["pkt_stats"],
        "pipeline":  1,
    }

# ---------------------------------------------------------------------------
# Pipeline 2: Template
# ---------------------------------------------------------------------------

def setup_template(model_id: int, model_path: str):
    from ebpf_template_arch import (
        EBPF_TEMPLATE_ARCH_DISPATCHER,
        EBPF_ARCH_65_4_4_7,
        load_arch_weights,
    )
    weights, scale = load_weights(model_path)
    src = "#define IPA_ARCH_COMBINED 1\n" + \
          EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + \
          EBPF_ARCH_65_4_4_7
    b       = BPF(text=src)
    disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
    leaf_fn = b.load_func("arch_65_4_4_7",       BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
    load_arch_weights(b, weights, model_id=model_id, scale=scale)
    return {
        "b":         b,
        "fn":        leaf_fn,
        "disp":      disp_fn,
        "weights":   weights,
        "scale":     scale,
        "cls_stats": None,
        "pkt_stats": b["pkt_stats_t2"],
        "pipeline":  2,
        "perf_name": "miss_events_t2",
        "perf_cls":  MissEventT2,
        "fwd_table":  "fwd_table_t2",
        "valid_keys": "valid_keys_t2",
    }

# ---------------------------------------------------------------------------
# Pipeline 3: Modular
# ---------------------------------------------------------------------------

def setup_modular(model_id: int, model_path: str):
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights, scale = load_weights(model_path)
    b       = BPF(text=EBPF_MODULAR_FULL)
    disp_fn = b.load_func("modular_dispatcher", BPF.XDP)
    lf0     = b.load_func("layer_65_4",         BPF.XDP)
    lf1     = b.load_func("layer_4_4",          BPF.XDP)
    lf2     = b.load_func("layer_4_7_argmax",   BPF.XDP)
    b["layer_chain"][ct.c_int(0)] = ct.c_int(lf0.fd)
    b["layer_chain"][ct.c_int(1)] = ct.c_int(lf1.fd)
    b["layer_chain"][ct.c_int(2)] = ct.c_int(lf2.fd)
    load_modular_weights(b, weights, model_id=model_id, scale=scale)
    w_off_out = (65 * 4 + 4) + (4 * 4 + 4)  # 284
    print(f"[P3 setup] nr_cpus={_NR_CPUS}  PERCPU ctypes Array enabled")
    return {
        "b":         b,
        "fn":        lf2,
        "disp":      disp_fn,
        "weights":   weights,
        "scale":     scale,
        "pkt_stats": b["pkt_stats_t3"],
        "pipeline":  3,
        "perf_name": "miss_events_t3",
        "perf_cls":  MissEventT3,
        "fwd_table":  "fwd_table_t3",
        "valid_keys": "valid_keys_t3",
        "w_off_out":  w_off_out,
    }

# ---------------------------------------------------------------------------
# Lettura contatori
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Perf buffer handler
# ---------------------------------------------------------------------------

def _make_perf_cb(event_cls, label):
    def _cb(cpu, data, size):
        if size < ct.sizeof(event_cls):
            return
        ev = ct.cast(data, ct.POINTER(event_cls)).contents
        print(f"  [{label}] miss cpu={cpu} model_id={ev.model_id} "
              f"ttl={ev.ttl} ifindex={ev.ingress_ifindex} key={ev.key:#018x}")
    return _cb

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

XDP_PASS          = 2
XDP_REDIRECT_PASS = frozenset({0, 4})

def run(method: str, model_id: int, model_path: str,
        ttl_min: int, ttl_max: int, repeat: int):
    print("=" * 70)
    print(f" IPA/eBPF BPF_PROG_TEST_RUN  --  method={method}  model_id={model_id}")
    print("=" * 70)
    print()
    print("NOTA: bpf_redirect() in TEST_RUN sandbox.")
    print("      PASS = retval in {0,4} (redirect fire) + cls_stats/pkt_stats hit.")
    print()

    setup_fn = {"hardcoded": setup_hardcoded,
                "template":  setup_template,
                "modular":   setup_modular}[method]
    setup = setup_fn(model_id, model_path)

    b, fn           = setup["b"], setup["fn"]
    weights         = setup["weights"]
    scale           = setup["scale"]
    ps              = setup["pkt_stats"]
    cs              = setup.get("cls_stats")
    pipeline        = setup["pipeline"]
    fwd_table_name  = setup.get("fwd_table")
    valid_keys_name = setup.get("valid_keys")
    w_off_out       = setup.get("w_off_out", 0)

    perf_name = setup.get("perf_name")
    perf_cls  = setup.get("perf_cls")
    if perf_name and perf_cls:
        cb = _make_perf_cb(perf_cls, f"P{pipeline}")
        b[perf_name].open_perf_buffer(cb, page_cnt=8)

    print(f"[setup] scale={scale}  weights={len(weights)}  prog_fd={fn.fd}")

    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        _reset_stats(setup)

        ref_cls, ref_val, h1, h2 = ref_infer(weights, scale, ttl, model_id, ifindex=0)
        expected_key = _compute_fwd_key(ref_val, scale)

        if pipeline == 3:
            _prime_scratch_p3(b, h2, scale, model_id,
                              w_off_out=w_off_out,
                              ingress_ifindex=0, ttl=ttl)

        if fwd_table_name and valid_keys_name:
            _insert_fwd_entry(b, fwd_table_name, valid_keys_name,
                              ttl=ttl, key=expected_key, ifindex=2)

        frame = build_frame(model_id, ttl, scale)
        retval, dur_ns = prog_test_run(fn.fd, frame, repeat=repeat)

        if fwd_table_name and valid_keys_name:
            _remove_fwd_entry(b, fwd_table_name, valid_keys_name,
                              ttl=ttl, key=expected_key)

        if perf_name and perf_cls:
            b.perf_buffer_poll(timeout=0)

        hit_count = _read_u64(ps, 0)

        if pipeline == 1 and cs is not None:
            cls_count = _read_u64(cs, ref_cls)
            ok = (retval in XDP_REDIRECT_PASS) and (cls_count > 0)
            detail = f"retval={retval} cls_stats[{ref_cls}]={cls_count}"
        else:
            ok = (retval in XDP_REDIRECT_PASS) and (hit_count > 0)
            detail = f"retval={retval} pkt_stats[HIT]={hit_count}"

        if retval == XDP_PASS:
            ok = False
            detail += "  <-- XDP_PASS: inferenza non completata o cache miss"

        lat_us = dur_ns / 1000 / repeat
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1

        print(f"  TTL={ttl:3d}  ref_cls={ref_cls}  ref_val={ref_val:8d}  "
              f"{detail}  lat={lat_us:.2f}us  [{status}]")

    miss = _read_u64(ps, 1)
    drop = _read_u64(ps, 2)
    print("-" * 70)
    print(f"Risultati: {passed} PASS / {failed} FAIL  "
          f"(TTL range [{ttl_min},{ttl_max}])")
    print(f"pkt_stats: HIT={_read_u64(ps,0)}  MISS={miss}  DROP={drop}")
    return failed


def main():
    p = argparse.ArgumentParser(description="IPA/eBPF pipeline verifier")
    p.add_argument("--method",   choices=["hardcoded", "template", "modular"],
                   default="hardcoded")
    p.add_argument("--model-id", type=int, default=0)
    p.add_argument("--model",    default=MODEL_PT)
    p.add_argument("--ttl-min",  type=int, default=1)
    p.add_argument("--ttl-max",  type=int, default=10)
    p.add_argument("--repeat",   type=int, default=1000,
                   help="BPF_PROG_TEST_RUN repeat per misura latenza")
    args = p.parse_args()
    sys.exit(run(args.method, args.model_id, args.model,
                 args.ttl_min, args.ttl_max, args.repeat))


if __name__ == "__main__":
    main()
