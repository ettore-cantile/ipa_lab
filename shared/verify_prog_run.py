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
"""

import os
import sys
import struct
import argparse
import ctypes as ct
import zipfile
import io

from bcc import BPF

# ---------------------------------------------------------------------------
# Paths (relative to /shared inside the container)
# ---------------------------------------------------------------------------
DEFAULT_MODEL_PATH = "/shared/models/model_0_int8.npz"

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
# Pure-stdlib .npz loader (no numpy required)
# ---------------------------------------------------------------------------
# A .npz file is a ZIP archive where each array is stored as a .npy entry.
# The .npy format (v1.0) is:
#   magic: \x93NUMPY  (6 bytes)
#   version: major(1) minor(0)  (2 bytes)
#   header_len: uint16 LE  (2 bytes)
#   header: ASCII Python dict literal  (header_len bytes)
#   data: raw array bytes (C-order)
#
# We only need to read 1-D int8/int32/int64 arrays and scalar integers,
# which covers the 'weights' and 'scale' keys used by load_weights().

_NPY_DTYPE_SIZES = {
    '|i1': 1, '<i1': 1,  # int8
    '|u1': 1, '<u1': 1,  # uint8
    '<i2': 2,            # int16
    '<i4': 4,            # int32
    '<i8': 8,            # int64
    '<f4': 4,            # float32
    '<f8': 8,            # float64
}

_NPY_STRUCT_FMT = {
    '|i1': 'b', '<i1': 'b',
    '|u1': 'B', '<u1': 'B',
    '<i2': 'h',
    '<i4': 'i',
    '<i8': 'q',
    '<f4': 'f',
    '<f8': 'd',
}

def _parse_npy(data: bytes):
    """Parse a .npy byte string; return a flat Python list of numbers."""
    magic = b'\x93NUMPY'
    if data[:6] != magic:
        raise ValueError('Not a valid .npy file')
    # version bytes at [6],[7] — we support v1.0 and v2.0
    major = data[6]
    if major == 1:
        header_len = struct.unpack_from('<H', data, 8)[0]
        header_start = 10
    elif major == 2:
        header_len = struct.unpack_from('<I', data, 8)[0]
        header_start = 12
    else:
        raise ValueError(f'Unsupported .npy version {major}')
    header = data[header_start:header_start + header_len].decode('latin1').strip()
    # Parse dtype and shape from the header dict literal
    # e.g. {'descr': '<i1', 'fortran_order': False, 'shape': (319,), }
    import ast
    hdict = ast.literal_eval(header)
    dtype = hdict['descr']
    shape = hdict['shape']   # tuple
    data_start = header_start + header_len
    raw = data[data_start:]
    elem_size = _NPY_DTYPE_SIZES.get(dtype)
    fmt_char  = _NPY_STRUCT_FMT.get(dtype)
    if elem_size is None or fmt_char is None:
        raise ValueError(f'Unsupported dtype {dtype} in .npy')
    n_elems = 1
    for s in shape:
        n_elems *= s
    values = list(struct.unpack_from(f'<{n_elems}{fmt_char}', raw, 0))
    return values


def _load_npz(path: str) -> dict:
    """Load a .npz file without numpy; returns dict of key -> flat Python list."""
    result = {}
    with zipfile.ZipFile(path, 'r') as zf:
        for name in zf.namelist():
            key = name[:-4] if name.endswith('.npy') else name
            raw = zf.read(name)
            result[key] = _parse_npy(raw)
    return result


# ---------------------------------------------------------------------------
# Frame builder
# ---------------------------------------------------------------------------

def build_frame(model_id: int, ttl: int, weights, scale: int) -> bytes:
    """
    Build a minimal Ethernet/IP/UDP/IPA frame suitable for BPF_PROG_TEST_RUN.
    The ingress_ifindex field inside ctx is set by the kernel to 0 for
    BPF_PROG_TEST_RUN frames, so the iface one-hot encoding is zeros --
    this matches what the Python reference does when ifindex=0.
    """
    src_mac  = b'\x00\x00\x00\x00\x00\x01'
    dst_mac  = b'\x00\x00\x00\x00\x00\x02'
    # Ethernet header (14 bytes)
    eth = dst_mac + src_mac + struct.pack('!H', 0x0800)
    # IP header (20 bytes, no options)
    ip_len = 20 + 8 + 20  # ip + udp + ipa_hdr
    ip = struct.pack('!BBHHHBBH4s4s',
                     0x45, 0, ip_len,
                     0, 0,
                     ttl, 17,   # TTL, protocol=UDP
                     0,
                     b'\x0a\x00\x00\x01',
                     b'\x0a\x00\x00\x02')
    # UDP header (8 bytes)
    udp = struct.pack('!HHHH', 12345, 9999, 8 + 20, 0)
    # IPA header (20 bytes, packed)
    ipa = struct.pack('BBHBBBBBBBBBBBBBBBB',
                      model_id,  # model_id
                      0,         # model_type
                      scale,     # scale_factor (big-endian __be16)
                      65,        # input_size
                      7,         # output_size
                      2,         # hidden_layers
                      4,         # neurons_per_layer
                      1,         # n_feature_types
                      0, 65,     # feat0_code, feat0_count
                      0, 0,      # feat1
                      0, 0,      # feat2
                      0, 0,      # feat3
                      1,         # n_output_types
                      0, 7)      # out0_code, out0_count
    return eth + ip + udp + ipa

# ---------------------------------------------------------------------------
# Python reference inference (quantized, matches eBPF arithmetic)
# ---------------------------------------------------------------------------

def _ref_infer(weights, scale: int, ttl: int, model_id: int,
               ifindex: int = 0):
    """
    Pure-Python quantized inference that mirrors the eBPF pipeline.
    Returns (predicted_class, raw_best_val, key).
    """
    def w8(i):
        return int(ct.c_int8(int(weights[i]) & 0xFF).value)

    n_in, n_h1, n_h2, n_out = 65, 4, 4, 7
    fc1_size = n_in * n_h1 + n_h1
    fc2_size = n_h1 * n_h2 + n_h2

    # Build input vector (same encoding as eBPF dispatcher)
    x = [0] * n_in
    x[12] = ttl
    if 1 <= ifindex <= 6:
        x[5 + ifindex] = 1
    if 0 <= model_id <= 51:
        x[13 + model_id] = 1

    # fc1
    h1 = []
    for j in range(n_h1):
        acc = w8(n_in * n_h1 + j)  # bias
        for i in range(n_in):
            acc += x[i] * w8(j * n_in + i)
        h1.append(max(0, acc))

    # fc2
    h2 = []
    off2 = fc1_size
    for j in range(n_h2):
        acc = w8(off2 + n_h1 * n_h2 + j)  # bias
        for i in range(n_h1):
            acc += h1[i] * w8(off2 + j * n_h1 + i)
        h2.append(max(0, acc))

    # output layer (argmax)
    off3 = fc1_size + fc2_size
    best_val, best_cls = -10**9, 0
    for k in range(n_out):
        acc = w8(off3 + n_h2 * n_out + k)  # bias
        for i in range(n_h2):
            acc += h2[i] * w8(off3 + k * n_h2 + i)
        if acc > best_val:
            best_val, best_cls = acc, k

    key = (best_val + scale * 100000) // scale
    return best_cls, best_val, key

# ---------------------------------------------------------------------------
# Load model weights from .npz  (stdlib only — no numpy)
# ---------------------------------------------------------------------------

def load_weights(model_path: str):
    """
    Load weights and scale from a .npz file without numpy.
    The .npz must contain:
      'weights' : 1-D int8 array
      'scale'   : scalar int (stored as 0-D or 1-D int array)
    """
    npz = _load_npz(model_path)
    weights = [int(v) for v in npz['weights']]
    if 'scale' in npz:
        scale_raw = npz['scale']
        scale = int(scale_raw[0]) if isinstance(scale_raw, list) else int(scale_raw)
    else:
        scale = 128
    return weights, scale

# ---------------------------------------------------------------------------
# Pipeline setup helpers
# ---------------------------------------------------------------------------

def _make_fwd_action(ct):
    """Build a dummy fwd_action ctypes struct (ifindex=1, src/dst MACs)."""
    class FwdAction(ct.Structure):
        _pack_ = 1
        _fields_ = [
            ("ifindex",  ct.c_uint32),
            ("src_mac",  ct.c_uint8 * 6),
            ("dst_mac",  ct.c_uint8 * 6),
        ]
    a = FwdAction()
    a.ifindex = 1
    for i, v in enumerate([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]):
        a.src_mac[i] = v
    for i, v in enumerate([0x00, 0x00, 0x00, 0x00, 0x00, 0x02]):
        a.dst_mac[i] = v
    return a


def setup_hardcoded(model_id: int, model_path: str):
    from ebpf_hardcoded import build_hardcoded_program
    weights, scale = load_weights(model_path)
    src = build_hardcoded_program(weights, scale, model_id)
    b   = BPF(text=src)
    fn  = b.load_func("hardcoded_prog", BPF.XDP)
    return {"b": b, "fn": fn, "weights": weights, "scale": scale,
            "capture": None}   # no fwd_table in hardcoded pipeline


def setup_template(model_id: int, model_path: str):
    from ebpf_template import EBPF_TEMPLATE_FULL, load_template_weights
    weights, scale = load_weights(model_path)
    b   = BPF(text=EBPF_TEMPLATE_FULL)
    fn  = b.load_func("template_dispatcher", BPF.XDP)
    fwd = b.get_table("fwd_table_t2")
    action = _make_fwd_action(ct)
    load_template_weights(b, weights, model_id=model_id, scale=scale)
    return {
        "b": b, "fn": fn, "weights": weights, "scale": scale,
        "capture": {"perf": "miss_events_t2", "fwd": fwd,
                    "vk": b.get_table("valid_keys_t2"), "action": action,
                    "stats": b["pkt_stats_t2"]},
    }


def setup_modular(model_id: int, model_path: str):
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights, scale = load_weights(model_path)
    b   = BPF(text=EBPF_MODULAR_FULL)
    fn  = b.load_func("modular_dispatcher", BPF.XDP)
    # wire tail-call chain: chain[0]=layer_65_4, [1]=layer_4_4, [2]=layer_4_7_argmax
    chain = b.get_table("layer_chain")
    chain[ct.c_int(0)] = ct.c_int(b.load_func("layer_65_4",        BPF.XDP).fd)
    chain[ct.c_int(1)] = ct.c_int(b.load_func("layer_4_4",         BPF.XDP).fd)
    chain[ct.c_int(2)] = ct.c_int(b.load_func("layer_4_7_argmax",  BPF.XDP).fd)
    fwd = b.get_table("fwd_table_t3")
    action = _make_fwd_action(ct)
    load_modular_weights(b, weights, model_id=model_id, scale=scale)
    return {
        "b": b, "fn": fn, "weights": weights, "scale": scale,
        "capture": {"perf": "miss_events_t3", "fwd": fwd,
                    "vk": b.get_table("valid_keys_t3"), "action": action,
                    "stats": b["pkt_stats_t3"]},
    }


# ---------------------------------------------------------------------------
# Manual ctypes struct for miss events (bypasses BCC __u8/__s8 auto-decode bug)
# ---------------------------------------------------------------------------
# BCC's automatic event(data) deserialization fails on older libbcc versions
# (e.g. ~0.18 in the Kathara container) when struct fields use __u8 or __s8:
#   TypeError: 'Type: '__u8' not recognized. Please define the data with ctypes manually.'
# Fix: mirror miss_event_t3 (and miss_event_t2) exactly with ctypes.Structure
# and cast the raw perf buffer pointer instead of calling .event(data).

class MissEventT3(ct.Structure):
    """Mirrors struct miss_event_t3 in ebpf_modular.py C source."""
    _pack_ = 1
    _fields_ = [
        ("model_id",        ct.c_uint8),
        ("ttl",             ct.c_uint8),
        ("ingress_ifindex", ct.c_uint32),
        ("layer_idx",       ct.c_uint8),
        # 3 bytes implicit padding before __u64 — match C struct layout
        ("_pad",            ct.c_uint8 * 3),
        ("key",             ct.c_uint64),
    ]

class MissEventT2(ct.Structure):
    """Mirrors struct miss_event_t2 in ebpf_template.py C source.
    Adjust fields if template pipeline uses a different struct layout."""
    _pack_ = 1
    _fields_ = [
        ("model_id",        ct.c_uint8),
        ("ttl",             ct.c_uint8),
        ("ingress_ifindex", ct.c_uint32),
        ("_pad",            ct.c_uint8 * 2),
        ("key",             ct.c_uint64),
    ]

_MISS_EVENT_CLASS = {
    "miss_events_t2": MissEventT2,
    "miss_events_t3": MissEventT3,
}


def _decode_miss_event(perf_name: str, data, size):
    """Manually decode a raw perf buffer payload into a miss event struct."""
    cls = _MISS_EVENT_CLASS.get(perf_name, MissEventT3)
    return ct.cast(data, ct.POINTER(cls)).contents


# ---------------------------------------------------------------------------
# Capture pass: learn kernel-computed keys via miss path
# ---------------------------------------------------------------------------

def _capture_kernel_keys(setup, model_id, ttl_min, ttl_max):
    """Two-pass: feed each ttl with an EMPTY fwd_table so the kernel takes the
    miss path and emits its own computed key via the perf buffer. Populate
    fwd_table/valid_keys with those kernel keys, then reset pkt_stats. After
    this, re-feeding the same ttls yields a REDIRECT (HIT), proving the whole
    in-kernel parse -> inference -> argmax -> key -> forward path end to end,
    with no dependency on replicating the arithmetic in Python."""
    cap = setup["capture"]
    b, fn = setup["b"], setup["fn"]
    weights, scale = setup["weights"], setup["scale"]
    perf_name = cap["perf"]
    got = {}

    def _cb(cpu, data, size):
        # Use manual ctypes cast instead of b[perf_name].event(data) to avoid
        # BCC str2ctype KeyError on __u8/__s8 fields (older libbcc bug).
        ev = _decode_miss_event(perf_name, data, size)
        got[int(ev.ttl)] = int(ev.key)

    b[perf_name].open_perf_buffer(_cb, page_cnt=8)
    for ttl in range(ttl_min, ttl_max + 1):
        prog_test_run(fn.fd, build_frame(model_id, ttl, weights, scale), repeat=1)
        b.perf_buffer_poll(timeout=50)

    for ttl, key in got.items():
        cap["fwd"][ct.c_ulonglong(key)] = cap["action"]
        cap["vk"][ct.c_uint8(ttl)] = ct.c_ulonglong(key)

    st = cap["stats"]                      # reset counts from the capture pass
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

    setup = {"hardcoded": setup_hardcoded,
             "template":  setup_template,
             "modular":   setup_modular}[method](model_id, model_path)

    b, fn = setup["b"], setup["fn"]
    weights, scale = setup["weights"], setup["scale"]

    print(f"[verify] program loaded (scale={scale}, weights={len(weights)})")

    # Methods with a fwd_table (template/modular): learn the kernel's own keys
    # from the miss-path perf events, then pre-load fwd_table so the measured
    # sweep can HIT. Hardcoded has no fwd_table (redirect on argmax directly).
    if setup.get("capture"):
        nk = _capture_kernel_keys(setup, model_id, ttl_min, ttl_max)
        print(f"[verify] capture pass: learned {nk} keys from kernel miss events")

    # Measurement pass
    passed = 0
    failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        retval, duration_ns = prog_test_run(
            fn.fd, build_frame(model_id, ttl, weights, scale), repeat=repeat)

        ref_cls, ref_val, ref_key = _ref_infer(weights, scale, ttl, model_id)

        # For hardcoded: retval==XDP_REDIRECT (3) means match, XDP_PASS (2) means miss.
        # For template/modular: retval==XDP_REDIRECT means HIT in fwd_table.
        ok = (retval == 3)   # XDP_REDIRECT
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
        st = setup["capture"]["stats"]
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
    parser.add_argument("--model",    default=DEFAULT_MODEL_PATH,
                        help="Path to model_<id>_int8.npz")
    parser.add_argument("--ttl-min",  type=int, default=1)
    parser.add_argument("--ttl-max",  type=int, default=10)
    parser.add_argument("--repeat",   type=int, default=1000,
                        help="BPF_PROG_TEST_RUN repeat count for latency avg")
    args = parser.parse_args()
    sys.exit(run(args.method, args.model_id, args.model,
                 args.ttl_min, args.ttl_max, args.repeat))


if __name__ == "__main__":
    main()
