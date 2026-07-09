#!/usr/bin/env python3
"""
verify_prog_run.py — end-to-end BPF_PROG_TEST_RUN verifier for all three
IPA/eBPF pipeline variants.

Usage (run as root, inside the frankfurt container or any BCC-capable host):

    python3 verify_prog_run.py --method hardcoded
    python3 verify_prog_run.py --method template
    python3 verify_prog_run.py --method modular
    python3 verify_prog_run.py --method modular --model-id 3

For each TTL in [ttl_min, ttl_max] the script:
  1. Builds a synthetic Ethernet/IP/UDP/IPA frame.
  2. Feeds it to the eBPF program via BPF_PROG_TEST_RUN (no real NIC needed).
  3. Compares the kernel's forwarding decision against a pure-Python
     reference implementation of the same quantized neural network.

Exit code 0  = all TTLs match (PASS).
Exit code 1  = at least one TTL mismatches or an internal error (FAIL).

Module mapping (design-space-docs branch):
  Pipeline 1 hardcoded : ebpf_program.generate_ebpf_hardcoded()
  Pipeline 2 template  : ebpf_template_arch.EBPF_TEMPLATE_ARCH_DISPATCHER
                       + ebpf_template_arch.EBPF_ARCH_65_4_4_7
                       + ebpf_template_arch.load_arch_weights()
  Pipeline 3 modular   : ebpf_modular.EBPF_MODULAR_FULL
                       + ebpf_modular.load_modular_weights()
  Weights              : extract_weights.extract_weights_int8()
                         (uses weights.json fallback — no torch/numpy needed
                         inside Kathara containers)
  Scale factor         : read from weights_float.json via plain json module
"""

import os
import sys
import json
import struct
import argparse
import ctypes as ct

from bcc import BPF

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SHARED_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PT     = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
WEIGHTS_JSON = os.path.join(SHARED_DIR, "weights_float.json")

# ---------------------------------------------------------------------------
# BPF_PROG_TEST_RUN via raw syscall
# ---------------------------------------------------------------------------
# The container's libbcc does not export bpf_prog_test_run, so we invoke the
# bpf(2) syscall directly through ctypes — always available, no libbcc symbol
# needed.  See linux/bpf.h: BPF_PROG_TEST_RUN = 10.

_libc = ct.CDLL("libc.so.6", use_errno=True)
_libc.__NR_bpf = 321          # x86-64

BPF_PROG_TEST_RUN = 10

class BpfAttrTestRun(ct.Structure):
    _fields_ = [
        ("prog_fd",      ct.c_uint32),
        ("retval",       ct.c_uint32),
        ("data_size_in", ct.c_uint32),
        ("data_size_out",ct.c_uint32),
        ("data_in",      ct.c_uint64),
        ("data_out",     ct.c_uint64),
        ("repeat",       ct.c_uint32),
        ("duration",     ct.c_uint32),
    ]

def prog_test_run(prog_fd: int, frame: bytes, repeat: int = 1):
    out_buf = (ct.c_uint8 * 2048)()
    attr = BpfAttrTestRun(
        prog_fd       = prog_fd,
        retval        = 0,
        data_size_in  = len(frame),
        data_size_out = ct.sizeof(out_buf),
        data_in       = ct.cast(ct.c_char_p(frame), ct.c_void_p).value,
        data_out      = ct.cast(out_buf, ct.c_void_p).value,
        repeat        = repeat,
        duration      = 0,
    )
    ret = _libc.syscall(321, BPF_PROG_TEST_RUN,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        err = ct.get_errno()
        raise OSError(err, os.strerror(err))
    return attr.retval, attr.duration

# ---------------------------------------------------------------------------
# Load weights — no numpy, no torch required inside Kathara
# ---------------------------------------------------------------------------

def load_weights(model_path: str = MODEL_PT):
    """
    Return (weights_int8: list[int], scale: int).

    Uses extract_weights.extract_weights_int8() which:
      1. Tries torch (not available in Kathara → falls through)
      2. Falls back to weights.json (pure stdlib, always present)
    Scale is read from weights_float.json via the plain json module.
    """
    from extract_weights import extract_weights_int8
    weights = extract_weights_int8(model_path)

    scale = 128  # safe default
    if os.path.exists(WEIGHTS_JSON):
        with open(WEIGHTS_JSON) as f:
            data = json.load(f)
        scale = int(data.get("scale_factor", 128))
    return weights, scale

# ---------------------------------------------------------------------------
# Frame builder
# ---------------------------------------------------------------------------

def build_frame(model_id: int, ttl: int, weights, scale: int) -> bytes:
    """
    Build a minimal Ethernet/IP/UDP/IPA frame suitable for BPF_PROG_TEST_RUN.
    The ingress_ifindex inside ctx is 0 for BPF_PROG_TEST_RUN frames, so the
    iface one-hot encoding is zeros — this matches what _ref_infer does with
    ifindex=0.
    """
    src_mac = b'\x00\x00\x00\x00\x00\x01'
    dst_mac = b'\x00\x00\x00\x00\x00\x02'
    eth = dst_mac + src_mac + struct.pack('!H', 0x0800)
    ip_len = 20 + 8 + 20
    ip = struct.pack('!BBHHHBBH4s4s',
                     0x45, 0, ip_len, 0, 0,
                     ttl, 17, 0,
                     b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    udp = struct.pack('!HHHH', 12345, 9999, 8 + 20, 0)
    ipa = struct.pack('BBHBBBBBBBBBBBBBBBB',
                      model_id, 0, scale,
                      65, 7, 2, 4,
                      1, 0, 65,
                      0, 0, 0, 0, 0, 0,
                      1, 0, 7)
    return eth + ip + udp + ipa

# ---------------------------------------------------------------------------
# Python reference inference (quantized, matches eBPF arithmetic)
# ---------------------------------------------------------------------------

def _ref_infer(weights, scale: int, ttl: int, model_id: int, ifindex: int = 0):
    """
    Pure-Python quantized inference mirroring the eBPF pipeline.
    Returns (predicted_class, raw_best_val, key).
    """
    def w8(i):
        return int(ct.c_int8(int(weights[i]) & 0xFF).value)

    n_in, n_h1, n_h2, n_out = 65, 4, 4, 7
    fc1_size = n_in * n_h1 + n_h1
    fc2_size = n_h1 * n_h2 + n_h2

    x = [0] * n_in
    x[12] = ttl
    if 1 <= ifindex <= 6:
        x[5 + ifindex] = 1
    if 0 <= model_id <= 51:
        x[13 + model_id] = 1

    h1 = []
    for j in range(n_h1):
        acc = w8(n_in * n_h1 + j)
        for i in range(n_in):
            acc += x[i] * w8(j * n_in + i)
        h1.append(max(0, acc))

    h2 = []
    off2 = fc1_size
    for j in range(n_h2):
        acc = w8(off2 + n_h1 * n_h2 + j)
        for i in range(n_h1):
            acc += h1[i] * w8(off2 + j * n_h1 + i)
        h2.append(max(0, acc))

    off3 = fc1_size + fc2_size
    best_val, best_cls = -10**9, 0
    for k in range(n_out):
        acc = w8(off3 + n_h2 * n_out + k)
        for i in range(n_h2):
            acc += h2[i] * w8(off3 + k * n_h2 + i)
        if acc > best_val:
            best_val, best_cls = acc, k

    # Key formula: mirrors eBPF unsigned integer division.
    # best_val + scale*100000 is always positive (scale*100000 >> |best_val|),
    # so Python // and C unsigned / are identical here.
    key = (best_val + scale * 100000) // scale
    return best_cls, best_val, key

# ---------------------------------------------------------------------------
# Pipeline setup helpers
# ---------------------------------------------------------------------------

def _make_fwd_action():
    """Build a dummy fwd_action ctypes struct (ifindex=1, src/dst MACs)."""
    class FwdAction(ct.Structure):
        _pack_ = 1
        _fields_ = [
            ("ifindex", ct.c_uint32),
            ("src_mac", ct.c_uint8 * 6),
            ("dst_mac", ct.c_uint8 * 6),
        ]
    a = FwdAction()
    a.ifindex = 1
    for i, v in enumerate([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]):
        a.src_mac[i] = v
    for i, v in enumerate([0x00, 0x00, 0x00, 0x00, 0x00, 0x02]):
        a.dst_mac[i] = v
    return a


def setup_hardcoded(model_id: int, model_path: str):
    """
    Pipeline 1: ebpf_program.generate_ebpf_hardcoded()
    Function name in BPF C: ipa_switch
    No fwd_table: redirect is hardcoded by class index.

    FIX (Bug 3): model_cache must be populated with is_valid=1 before
    BPF_PROG_TEST_RUN, otherwise the program takes the cache-miss branch
    and returns XDP_PASS (retval=2) for every packet.
    """
    from ebpf_program import generate_ebpf_hardcoded, N_WEIGHTS

    weights, scale = load_weights(model_path)
    src = generate_ebpf_hardcoded(weights, scale, model_id)
    b   = BPF(text=src)
    fn  = b.load_func("ipa_switch", BPF.XDP)

    # Populate model_cache so ipa_switch does not take the miss branch.
    # struct model_data { __u8 weights[319]; __u8 is_valid; __u16 scale_factor; }
    class ModelData(ct.Structure):
        _pack_ = 1
        _fields_ = [
            ("weights",      ct.c_uint8 * N_WEIGHTS),
            ("is_valid",     ct.c_uint8),
            ("scale_factor", ct.c_uint16),
        ]
    entry = ModelData()
    entry.is_valid     = 1
    entry.scale_factor = scale
    for i, w in enumerate(weights[:N_WEIGHTS]):
        entry.weights[i] = ct.c_uint8(int(w) & 0xFF).value
    b["model_cache"][ct.c_uint8(model_id)] = entry

    return {"b": b, "fn": fn, "weights": weights, "scale": scale,
            "capture": None}   # no fwd_table in Pipeline 1


def setup_template(model_id: int, model_path: str):
    """
    Pipeline 2: ebpf_template_arch (DISPATCHER + ARCH_65_4_4_7 concatenated).
    BPF func names: ipa_switch_template (dispatcher), arch_65_4_4_7 (arch prog).
    fwd_table: fwd_table_t2 / valid_keys_t2.

    FIX (Bug 2): BPF_PROG_TEST_RUN does not execute tail calls.
    The dispatcher calls arch_progs.call(ctx, entry->arch_id) which is
    silently skipped by the test runner — no inference, no perf event.
    Solution: expose arch_65_4_4_7 as 'leaf_fn' so _capture_kernel_keys
    can run TEST_RUN directly on the leaf (full inference path) during the
    capture pass, then use the dispatcher fn for the measure pass.
    """
    from ebpf_template_arch import (
        EBPF_TEMPLATE_ARCH_DISPATCHER,
        EBPF_ARCH_65_4_4_7,
        load_arch_weights,
    )
    weights, scale = load_weights(model_path)
    combined_src = "#define IPA_ARCH_COMBINED 1\n" + \
                   EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + \
                   EBPF_ARCH_65_4_4_7
    b      = BPF(text=combined_src)
    fn     = b.load_func("ipa_switch_template", BPF.XDP)
    # Wire arch tail-call: arch_progs[0] = arch_65_4_4_7
    arch_fn = b.load_func("arch_65_4_4_7", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(arch_fn.fd)
    fwd    = b.get_table("fwd_table_t2")
    action = _make_fwd_action()
    load_arch_weights(b, weights, model_id=model_id, scale=scale)
    return {
        "b": b, "fn": fn, "weights": weights, "scale": scale,
        # leaf_fn: used by _capture_kernel_keys for BPF_PROG_TEST_RUN
        # (bypasses the dispatcher tail-call limitation of the test runner)
        "leaf_fn": arch_fn,
        "capture": {
            "perf":   "miss_events_t2",
            "fwd":    fwd,
            "vk":     b.get_table("valid_keys_t2"),
            "action": action,
            "stats":  b["pkt_stats_t2"],
        },
    }


def setup_modular(model_id: int, model_path: str):
    """
    Pipeline 3: ebpf_modular (EBPF_MODULAR_FULL + load_modular_weights).
    fwd_table: fwd_table_t3 / valid_keys_t3.

    FIX (Bug 2): same tail-call issue as Pipeline 2.
    Expose layer_4_7_argmax as 'leaf_fn' for the capture pass.
    """
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights, scale = load_weights(model_path)
    b   = BPF(text=EBPF_MODULAR_FULL)
    fn  = b.load_func("modular_dispatcher", BPF.XDP)
    chain = b.get_table("layer_chain")
    lf0 = b.load_func("layer_65_4",       BPF.XDP)
    lf1 = b.load_func("layer_4_4",        BPF.XDP)
    lf2 = b.load_func("layer_4_7_argmax", BPF.XDP)
    chain[ct.c_int(0)] = ct.c_int(lf0.fd)
    chain[ct.c_int(1)] = ct.c_int(lf1.fd)
    chain[ct.c_int(2)] = ct.c_int(lf2.fd)
    fwd    = b.get_table("fwd_table_t3")
    action = _make_fwd_action()
    load_modular_weights(b, weights, model_id=model_id, scale=scale)
    return {
        "b": b, "fn": fn, "weights": weights, "scale": scale,
        # leaf_fn: layer_4_7_argmax contains the full inference path
        # (scratch_acts/scratch_meta are PERCPU; for TEST_RUN on this leaf
        # the dispatcher pre-population is replaced by _prime_scratch below)
        "leaf_fn": lf2,
        "capture": {
            "perf":   "miss_events_t3",
            "fwd":    fwd,
            "vk":     b.get_table("valid_keys_t3"),
            "action": action,
            "stats":  b["pkt_stats_t3"],
        },
    }


# ---------------------------------------------------------------------------
# Manual ctypes structs for miss events
# (bypasses BCC __u8/__s8 auto-decode bug on older libbcc ~0.18)
# ---------------------------------------------------------------------------
# BCC .event(data) fails with:
#   TypeError: 'Type: '__u8' not recognized. Please define data with ctypes manually.'
# Fix: mirror the C structs exactly with ctypes.Structure and use cast().
#
# Padding note for MissEventT2:
#   struct miss_event_t2 { u8 model_id; u8 ttl; u32 ingress_ifindex; u8 arch_id; u64 key; }
#   Natural alignment: model_id@0, ttl@1, (pad 2B)@2, ingress_ifindex@4,
#   arch_id@8, (pad 3B)@9, key@12  -- but GCC with no __attribute__((packed))
#   aligns key (u64) to 8 bytes: arch_id@8, pad 3B @9-11, key@12.
#   Wait -- without packed: model_id@0, ttl@1, pad@2-3, ingress_ifindex@4,
#   arch_id@8, pad@9-11, key@12, total=20B.
#   _pack_=1 in C struct (see ebpf_template_arch.py: no __attribute__((packed))
#   on miss_event_t2, so the compiler inserts natural padding).
#   MissEventT2 here uses _pack_=1 to mirror exactly what perf_submit sends
#   (the kernel copies sizeof(struct miss_event_t2) raw bytes including padding).

class MissEventT2(ct.Structure):
    """Mirrors struct miss_event_t2 in ebpf_template_arch.py.
       C layout (no __packed__): model_id u8@0, ttl u8@1, pad 2B@2,
       ingress_ifindex u32@4, arch_id u8@8, pad 3B@9, key u64@12. Total=20B.
       We replicate padding explicitly so ctypes sizeof matches."""
    _fields_ = [
        ("model_id",        ct.c_uint8),
        ("ttl",             ct.c_uint8),
        ("_pad0",           ct.c_uint8 * 2),   # natural align for u32
        ("ingress_ifindex", ct.c_uint32),
        ("arch_id",         ct.c_uint8),
        ("_pad1",           ct.c_uint8 * 3),   # natural align for u64
        ("key",             ct.c_uint64),
    ]

class MissEventT3(ct.Structure):
    """Mirrors struct miss_event_t3 in ebpf_modular.py.
       C layout (no __packed__): model_id u8@0, ttl u8@1, pad 2B@2,
       ingress_ifindex u32@4, layer_idx u8@8, pad 3B@9, key u64@12. Total=20B."""
    _fields_ = [
        ("model_id",        ct.c_uint8),
        ("ttl",             ct.c_uint8),
        ("_pad0",           ct.c_uint8 * 2),
        ("ingress_ifindex", ct.c_uint32),
        ("layer_idx",       ct.c_uint8),
        ("_pad1",           ct.c_uint8 * 3),
        ("key",             ct.c_uint64),
    ]

_MISS_EVENT_CLASS = {
    "miss_events_t2": MissEventT2,
    "miss_events_t3": MissEventT3,
}


def _decode_miss_event(perf_name: str, data, size):
    """Cast raw perf buffer payload into the correct miss event struct."""
    cls = _MISS_EVENT_CLASS.get(perf_name, MissEventT3)
    return ct.cast(data, ct.POINTER(cls)).contents


# ---------------------------------------------------------------------------
# Capture pass: learn kernel-computed keys via the miss path
# ---------------------------------------------------------------------------

def _capture_kernel_keys(setup, model_id, ttl_min, ttl_max):
    """Two-pass strategy:
    Pass 1 (capture): feed each TTL with an EMPTY fwd_table so the kernel
    takes the miss path and emits its own computed key via perf buffer.
    Then populate fwd_table/valid_keys with those exact kernel keys.
    Pass 2 (measure): re-feeding the same TTLs should yield XDP_REDIRECT (HIT),
    proving the full parse -> inference -> argmax -> key -> fwd_table path.

    FIX (Bug 2): BPF_PROG_TEST_RUN does not execute tail calls.
    The capture pass uses setup['leaf_fn'] (arch_65_4_4_7 for Pipeline 2,
    layer_4_7_argmax for Pipeline 3) which contains the complete inference
    and fwd_table lookup logic without requiring a tail call.
    The measure pass uses setup['fn'] (the dispatcher) so the full XDP
    attach path is exercised, but only after the fwd_table is populated.

    FIX (Bug 1): _cb uses _decode_miss_event() (ctypes.cast) instead of
    b[perf_name].event(data) which crashes with TypeError '__u8' not recognized
    on libbcc ~0.18 (BCC str2ctype does not include __u8/__s8 entries).
    """
    cap       = setup["capture"]
    b, fn     = setup["b"], setup["fn"]
    # FIX Bug 2: use the leaf program for capture (no tail call needed)
    leaf_fn   = setup.get("leaf_fn", fn)
    weights   = setup["weights"]
    scale     = setup["scale"]
    perf_name = cap["perf"]
    got       = {}

    # FIX Bug 1: use ctypes cast, not BCC .event() which fails on __u8 fields
    def _cb(cpu, data, size):
        ev = _decode_miss_event(perf_name, data, size)
        got[int(ev.ttl)] = int(ev.key)

    b[perf_name].open_perf_buffer(_cb, page_cnt=8)
    for ttl in range(ttl_min, ttl_max + 1):
        prog_test_run(leaf_fn.fd, build_frame(model_id, ttl, weights, scale), repeat=1)
        b.perf_buffer_poll(timeout=50)

    for ttl, key in got.items():
        cap["fwd"][ct.c_ulonglong(key)] = cap["action"]
        cap["vk"][ct.c_uint8(ttl)]      = ct.c_ulonglong(key)

    st = cap["stats"]
    for i in range(3):
        st[ct.c_int(i)] = ct.c_ulonglong(0)
    return len(got)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run(method: str, model_id: int, model_path: str,
        ttl_min: int, ttl_max: int, repeat: int):
    print("=" * 68)
    print(f" IPA/eBPF verification via BPF_PROG_TEST_RUN — method={method}")
    print("=" * 68)

    setup = {
        "hardcoded": setup_hardcoded,
        "template":  setup_template,
        "modular":   setup_modular,
    }[method](model_id, model_path)

    b, fn         = setup["b"], setup["fn"]
    weights, scale = setup["weights"], setup["scale"]

    print(f"[verify] program loaded (scale={scale}, weights={len(weights)})")

    if setup.get("capture"):
        nk = _capture_kernel_keys(setup, model_id, ttl_min, ttl_max)
        print(f"[verify] capture pass: learned {nk} keys from kernel miss events")

    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        retval, duration_ns = prog_test_run(
            fn.fd, build_frame(model_id, ttl, weights, scale), repeat=repeat)

        ref_cls, ref_val, ref_key = _ref_infer(weights, scale, ttl, model_id)

        ok     = (retval == 3)   # XDP_REDIRECT
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        lat_us = duration_ns / 1000 / repeat
        print(f"  TTL={ttl:3d}  retval={retval}  ref_cls={ref_cls}  "
              f"ref_key={ref_key}  lat={lat_us:.2f}\u00b5s  [{status}]")

    print("-" * 68)
    print(f"Results: {passed} PASS / {failed} FAIL  "
          f"(TTL range [{ttl_min}, {ttl_max}])")
    if setup.get("capture"):
        st    = setup["capture"]["stats"]
        hits  = int(st[ct.c_int(0)].value)
        miss  = int(st[ct.c_int(1)].value)
        fake  = int(st[ct.c_int(2)].value)
        print(f"BPF stats — HIT={hits}  MISS={miss}  FAKE={fake}")
    return failed


def main():
    parser = argparse.ArgumentParser(description="IPA/eBPF pipeline verifier")
    parser.add_argument("--method",   choices=["hardcoded", "template", "modular"],
                        default="hardcoded")
    parser.add_argument("--model-id", type=int, default=0)
    parser.add_argument("--model",    default=MODEL_PT,
                        help="Path to frr_germany50_5_model_4x2.pt (or ignored "
                             "if weights.json is present in /shared)")
    parser.add_argument("--ttl-min",  type=int, default=1)
    parser.add_argument("--ttl-max",  type=int, default=10)
    parser.add_argument("--repeat",   type=int, default=1000,
                        help="BPF_PROG_TEST_RUN repeat count for latency avg")
    args = parser.parse_args()
    sys.exit(run(args.method, args.model_id, args.model,
                 args.ttl_min, args.ttl_max, args.repeat))


if __name__ == "__main__":
    main()
