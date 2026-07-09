#!/usr/bin/env python3
"""
verify_prog_run.py — Network-independent verification of the IPA/eBPF pipelines
via the kernel BPF_PROG_TEST_RUN facility.

Why this exists
---------------
The Kathara integration test (test_kathara.sh) proved the pipeline CODE is
correct (compiles, loads, would parse+infer+redirect), but the Kathara
`katharanp` collision-domain fabric does not deliver our unicast UDP:9999
packets to frankfurt (ICMP traverses, UDP does not — an environment quirk,
not a code bug). So "TRUE HIT = 0" reflects "no packet arrived", not a
pipeline defect.

BPF_PROG_TEST_RUN sidesteps the network entirely: it feeds a crafted IPA
packet straight into the loaded XDP program IN THE KERNEL, runs the real
inference, and returns the XDP action + per-run duration. This deterministically
demonstrates, for each design-space method, that a packet is:
  1. RECEIVED  — parsed through eth/ip/udp/ipa headers (reaches inference)
  2. DISPATCHED— inference runs, argmax picks a class, an action is taken
     (XDP_REDIRECT = forward on the chosen egress port  -> "hit"
      XDP_DROP     = class 6 chosen                      -> "drop")
and yields a key professor metric for free: per-packet latency (ns).

Usage (run as root, inside the frankfurt container or any BCC-capable host):
    sudo python3 /shared/verify_prog_run.py --method hardcoded
    sudo python3 /shared/verify_prog_run.py --method hardcoded --repeat 200000

Note on ingress_ifindex: the simple BPF_PROG_TEST_RUN path does not set
xdp_md.ingress_ifindex (it stays 0), so the ingress-iface one-hot feature is
absent; the node one-hot (model_id) and ttl still drive the inference, which
is enough to show the pipeline parses + classifies + dispatches per input.
"""

import argparse
import ctypes as ct
import os
import socket
import struct
import sys

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)
os.chdir(SHARED_DIR)

from bcc import BPF

N_WEIGHTS = 319

# XDP return codes
XDP_ABORTED  = 0
XDP_DROP     = 1
XDP_PASS     = 2
XDP_TX       = 3
XDP_REDIRECT = 4
XDP_NAME = {0: "ABORTED", 1: "DROP", 2: "PASS", 3: "TX", 4: "REDIRECT"}


# ---------------------------------------------------------------------------
# Packet construction — a real IPA/UDP frame matching send_ipa.py + the parser
# ---------------------------------------------------------------------------
def build_ipa_header(model_id: int, scale_factor: int) -> bytes:
    """21-byte IPA header (identical layout to send_ipa.build_ipa_header)."""
    return struct.pack(
        ">BBBHBBBBB" "BBBBBBBB" "BBB",
        model_id & 0xFF, 0x00, 7, scale_factor & 0xFFFF,
        65, 7, 2, 4, 4,
        0x01, 1, 0x02, 1, 0x03, 6, 0x04, 52,
        1, 0x01, 7,
    )


def build_frame(model_id: int, ttl: int, weights_int8: list, scale: int,
                dport: int = 9999) -> bytes:
    """Full L2 frame: Ethernet + IPv4 + UDP + IPA header + 319 weight bytes."""
    ipa = build_ipa_header(model_id, scale)
    weights = bytes((int(w) & 0xFF) for w in weights_int8[:N_WEIGHTS])
    payload = ipa + weights

    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", 40000, dport, udp_len, 0)

    ip_tot = 20 + udp_len
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, ip_tot, 0x0000, 0x0000,
        ttl & 0xFF, 17, 0x0000,
        socket.inet_aton("10.0.0.233"),
        socket.inet_aton("10.0.0.234"),
    )
    eth = struct.pack(
        "!6s6sH",
        b"\x02\x00\x00\x00\x00\x02",   # dst MAC (dummy)
        b"\x02\x00\x00\x00\x00\x01",   # src MAC (dummy)
        0x0800,                        # EtherType IPv4
    )
    return eth + ip + udp + payload


# ---------------------------------------------------------------------------
# BPF_PROG_TEST_RUN via the raw bpf() syscall
#
# The container's libbcc does not export bpf_prog_test_run, so we invoke the
# bpf(2) syscall directly through ctypes — always available, no libbcc symbol
# needed. We build the BPF_PROG_TEST_RUN member of union bpf_attr by hand.
# ---------------------------------------------------------------------------
_NR_bpf = 321            # __NR_bpf on x86_64 (this lab is x86_64)
BPF_PROG_TEST_RUN = 10   # bpf() command


class _BpfAttrTestRun(ct.Structure):
    # Natural alignment matches the kernel's __aligned_u64 fields (no _pack_).
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


_libc = ct.CDLL("libc.so.6", use_errno=True)
_libc.syscall.restype = ct.c_long
_libc.syscall.argtypes = [ct.c_long, ct.c_long, ct.c_void_p, ct.c_ulong]


def prog_test_run(prog_fd: int, frame: bytes, repeat: int = 1):
    """Run the XDP program on `frame` via bpf(BPF_PROG_TEST_RUN).
    Returns (retval, duration_ns)."""
    data_in = ct.create_string_buffer(frame, len(frame))
    out_cap = len(frame) + 256
    data_out = ct.create_string_buffer(out_cap)

    attr = _BpfAttrTestRun()
    attr.prog_fd = prog_fd
    attr.data_in = ct.cast(data_in, ct.c_void_p).value
    attr.data_size_in = len(frame)
    attr.data_out = ct.cast(data_out, ct.c_void_p).value
    attr.data_size_out = out_cap
    attr.repeat = repeat

    ct.set_errno(0)
    ret = _libc.syscall(_NR_bpf, BPF_PROG_TEST_RUN, ct.byref(attr), ct.sizeof(attr))
    if ret < 0:
        e = ct.get_errno()
        raise OSError(e, f"bpf(BPF_PROG_TEST_RUN) failed: {os.strerror(e)}")
    return attr.retval, attr.duration


# ---------------------------------------------------------------------------
# Reference int8 inference — mirrors the kernel MLP (65-4-4-7) EXACTLY.
#
# Same weight layout for Pipeline 2 (arch_65_4_4_7) and Pipeline 3 (layer
# blocks): fc1 w@0 b@260, fc2 w@264 b@280, out w@284 b@312. Under
# BPF_PROG_TEST_RUN ctx->ingress_ifindex is 0, so the iface one-hot is
# absent (iface=0 -> skipped), matching the kernel. node = model_id.
#
# Computing the key here and pre-loading fwd_table/valid_keys with it means a
# kernel REDIRECT (HIT) can only happen if the kernel's key == this key, i.e.
# the whole parse+inference+argmax+dispatch path is bit-exact. That makes the
# HIT count a rigorous cross-check, not just a "packet was seen" signal.
# ---------------------------------------------------------------------------
_FC1_W, _FC1_B = 0, 260
_FC2_W, _FC2_B = 264, 280
_OUT_W, _OUT_B = 284, 312
_OUTPUT_OFFSET = 100000


def _ref_infer(weights: list, scale: int, ttl: int, node: int, iface: int = 0):
    """Return (argmax_class, fwd_key) exactly as the kernel computes them."""
    def s(i):
        return ct.c_int8(int(weights[i]) & 0xFF).value

    h1 = []
    for j in range(4):
        acc = s(_FC1_B + j)
        acc += ttl * s(_FC1_W + j * 65 + 12)
        if 1 <= iface <= 6:
            acc += s(_FC1_W + j * 65 + 5 + iface)
        if 0 <= node <= 51:
            acc += s(_FC1_W + j * 65 + 13 + node)
        h1.append(acc if acc > 0 else 0)

    h2 = []
    for j in range(4):
        acc = s(_FC2_B + j)
        for i in range(4):
            acc += h1[i] * s(_FC2_W + j * 4 + i)
        h2.append(acc if acc > 0 else 0)

    best_val, best_cls = -9999999, 0
    for k in range(7):
        acc = s(_OUT_B + k)
        for i in range(4):
            acc += h2[i] * s(_OUT_W + k * 4 + i)
        if acc > best_val:
            best_val, best_cls = acc, k

    key = (best_val + _OUTPUT_OFFSET * scale) // scale
    return best_cls, key


def _load_json_weights():
    """Shared weights.json (int8) + scale_factor from weights_float.json."""
    import json
    from common import load_weights
    weights = load_weights(os.path.join(SHARED_DIR, "weights.json"))
    with open(os.path.join(SHARED_DIR, "weights_float.json")) as f:
        scale = json.load(f)["scale_factor"]
    return weights, scale


# ---------------------------------------------------------------------------
# Method 1 — Hardcoded pipeline setup
# ---------------------------------------------------------------------------
def setup_hardcoded(model_id: int, model_path: str):
    from ebpf_program import load_and_generate

    # Default egress ifindex table (cls 0-5 -> arbitrary values; the actual
    # forwarding target is irrelevant for TEST_RUN, only the argmax matters).
    ebpf_src, weights_int8, scale = load_and_generate(
        model_path, model_id, ifindex_table=[2, 3, 4, 5, 6, 7]
    )
    b = BPF(text=ebpf_src)
    fn = b.load_func("ipa_switch", BPF.XDP)

    # Populate model_cache so the model is considered valid.
    class ModelData(ct.Structure):
        _fields_ = [
            ("weights", ct.c_uint8 * 319),
            ("is_valid", ct.c_uint8),
            ("scale_factor", ct.c_uint16),
        ]

    entry = ModelData()
    for i, w in enumerate(weights_int8[:319]):
        entry.weights[i] = ct.c_uint8(int(w) & 0xFF).value
    entry.is_valid = 1
    entry.scale_factor = scale
    b["model_cache"][ct.c_uint8(model_id)] = entry

    def read_class_hist():
        cls = b["cls_stats"]
        return [cls[i].value for i in range(7)]

    def read_debug():
        d = b["debug_stats"]
        return {
            "seen": d[0].value, "reached_model_cache": d[7].value,
            "not_udp": d[3].value, "wrong_port": d[5].value,
        }

    return {
        "b": b, "fn": fn, "weights": weights_int8, "scale": scale,
        "kernel_cls_hist": read_class_hist, "read_debug": read_debug,
        "read_hits": None, "py_class": None,
    }


# ---------------------------------------------------------------------------
# Method 2 — Pre-built architectural template setup
# ---------------------------------------------------------------------------
def setup_template(model_id: int, model_path: str):
    from ebpf_template_arch import (
        EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_65_4_4_7, load_arch_weights,
    )
    weights, scale = _load_json_weights()

    b = BPF(text=EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_65_4_4_7)
    load_arch_weights(b, weights, model_id=model_id, scale=scale)

    fn_arch = b.load_func("arch_65_4_4_7", BPF.XDP)
    b.get_table("arch_progs")[ct.c_int(0)] = ct.c_int(fn_arch.fd)
    fn = b.load_func("ipa_switch_template", BPF.XDP)

    _populate_fwd(b, "fwd_table_t2", "valid_keys_t2", weights, scale, model_id)

    def read_hits():
        st = b["pkt_stats_t2"]
        return st[0].value, st[1].value, st[2].value  # HIT, MISS, FAKE

    return {
        "b": b, "fn": fn, "weights": weights, "scale": scale,
        "kernel_cls_hist": None, "read_debug": None,
        "read_hits": read_hits,
        "py_class": lambda ttl: _ref_infer(weights, scale, ttl, model_id)[0],
    }


# ---------------------------------------------------------------------------
# Method 3 — Modular layer-block pipeline setup
# ---------------------------------------------------------------------------
def setup_modular(model_id: int, model_path: str):
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights, scale = _load_json_weights()

    b = BPF(text=EBPF_MODULAR_FULL)
    load_modular_weights(b, weights, model_id=model_id, scale=scale)

    fn_l0 = b.load_func("layer_65_4",       BPF.XDP)
    fn_l1 = b.load_func("layer_4_4",        BPF.XDP)
    fn_l2 = b.load_func("layer_4_7_argmax", BPF.XDP)
    chain = b.get_table("layer_chain")
    chain[ct.c_int(0)] = ct.c_int(fn_l0.fd)
    chain[ct.c_int(1)] = ct.c_int(fn_l1.fd)
    chain[ct.c_int(2)] = ct.c_int(fn_l2.fd)
    fn = b.load_func("modular_dispatcher", BPF.XDP)

    _populate_fwd(b, "fwd_table_t3", "valid_keys_t3", weights, scale, model_id)

    def read_hits():
        st = b["pkt_stats_t3"]
        return st[0].value, st[1].value, st[2].value  # HIT, MISS, FAKE

    return {
        "b": b, "fn": fn, "weights": weights, "scale": scale,
        "kernel_cls_hist": None, "read_debug": None,
        "read_hits": read_hits,
        "py_class": lambda ttl: _ref_infer(weights, scale, ttl, model_id)[0],
    }


def _populate_fwd(b, fwd_name, vk_name, weights, scale, model_id):
    """Pre-load fwd_table/valid_keys with the Python-computed key for every
    ttl 0..255, so a kernel HIT proves the kernel key == reference key."""
    fwd = b.get_table(fwd_name)
    vk = b.get_table(vk_name)
    action = fwd.Leaf()
    action.ifindex = 1  # any valid ifindex; only "did it redirect" matters
    for ttl in range(0, 256):
        _cls, key = _ref_infer(weights, scale, ttl, model_id)
        fwd[ct.c_ulonglong(key)] = action
        vk[ct.c_uint8(ttl)] = ct.c_ulonglong(key)


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
    print(f"[verify] feeding IPA packets for ttl {ttl_min}..{ttl_max} "
          f"(model_id={model_id})\n")

    action_count = {XDP_REDIRECT: 0, XDP_DROP: 0, XDP_PASS: 0, XDP_ABORTED: 0}
    n = 0
    for ttl in range(ttl_min, ttl_max + 1):
        frame = build_frame(model_id, ttl, weights, scale)
        retval, _ = prog_test_run(fn.fd, frame, repeat=1)
        action_count[retval] = action_count.get(retval, 0) + 1
        n += 1

    hits   = action_count.get(XDP_REDIRECT, 0)
    drops  = action_count.get(XDP_DROP, 0)
    passes = action_count.get(XDP_PASS, 0)

    # Latency: many repeats on one representative packet, kernel-averaged.
    lat_frame = build_frame(model_id, (ttl_min + ttl_max) // 2, weights, scale)
    _, dur_ns = prog_test_run(fn.fd, lat_frame, repeat=repeat)

    print("  Per-packet XDP action (one packet per ttl):")
    print(f"    REDIRECT (forwarded / HIT) : {hits:>4}  ({100*hits/max(n,1):.0f}%)")
    print(f"    DROP     (class 6 chosen)  : {drops:>4}  ({100*drops/max(n,1):.0f}%)")
    print(f"    PASS     (parse/cache miss): {passes:>4}  ({100*passes/max(n,1):.0f}%)")
    print(f"    TOTAL packets fed          : {n:>4}")
    print()

    # -- Reception proof --
    print("  Reception proof:")
    if setup["read_debug"]:                     # hardcoded: dedicated counters
        dbg = setup["read_debug"]()
        print(f"    reached_model_cache = {dbg['reached_model_cache']}  "
              f"(parsed eth/ip/udp/ipa and hit inference)")
        print(f"    not_udp={dbg['not_udp']}  wrong_port={dbg['wrong_port']}  "
              f"seen={dbg['seen']}")
    else:                                       # template/modular: kernel HIT map
        kh, km, kf = setup["read_hits"]()
        print(f"    kernel pkt_stats [HIT={kh} MISS={km} FAKE={kf}]")
        print(f"    HIT means: parsed headers, ran inference (incl. tail calls),"
              f" argmax key MATCHED the reference key -> redirected.")
    print()

    # -- Dispatch proof (argmax class distribution) --
    print("  Dispatch proof (argmax class distribution over the ttl sweep):")
    labels = ["eth0", "eth1", "eth2", "eth3", "eth4", "eth5", "DROP"]
    if setup["kernel_cls_hist"]:                # hardcoded: kernel histogram
        cls_hist = setup["kernel_cls_hist"]()
        src_note = "(from kernel cls_stats)"
    else:                                       # template/modular: reference argmax
        cls_hist = [0] * 7
        for ttl in range(ttl_min, ttl_max + 1):
            cls_hist[setup["py_class"](ttl)] += 1
        src_note = "(reference argmax, confirmed by kernel HITs)"
    print(f"    {src_note}")
    ctot = sum(cls_hist) or 1
    for i, c in enumerate(cls_hist):
        bar = "#" * int(34 * c / ctot)
        print(f"    cls {i} -> {labels[i]:5s} : {c:>4}  {bar}")
    print()

    print(f"  Per-packet latency  : {dur_ns} ns  "
          f"(avg over {repeat} in-kernel runs)")
    if dur_ns > 0:
        print(f"  Throughput estimate : {1e9/dur_ns/1e6:.2f} Mpps (single core, "
              f"inference only)")
    print()

    verdict = "PASS" if (passes == 0 and (hits + drops) == n) else "CHECK"
    print("=" * 68)
    if verdict == "PASS":
        print(f" VERIFY PASSED — all {n} packets received & dispatched "
              f"(hits={hits}, drops={drops})")
        print(" The pipeline parses, runs inference and takes a per-class "
              "action for every packet.")
    else:
        print(f" VERIFY CHECK — passes={passes}, redirects={hits}, drops={drops} "
              f"of {n}.")
        if setup["read_hits"] is not None:
            print(" A PASS here means the kernel key did NOT match the reference "
                  "key -> the in-kernel inference diverged from _ref_infer.")
    print("=" * 68)
    return 0 if verdict == "PASS" else 1


def main():
    ap = argparse.ArgumentParser(description="Verify IPA/eBPF pipelines via BPF_PROG_TEST_RUN")
    ap.add_argument("--method", default="hardcoded",
                    choices=["hardcoded", "template", "modular"])
    ap.add_argument("--model-id", type=int, default=0)
    ap.add_argument("--model", default=None, help="Path to .pt checkpoint")
    ap.add_argument("--ttl-min", type=int, default=30)
    ap.add_argument("--ttl-max", type=int, default=64)
    ap.add_argument("--repeat", type=int, default=100000,
                    help="in-kernel repeats for the latency measurement")
    args = ap.parse_args()

    model_path = args.model or os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
    sys.exit(run(args.method, args.model_id, model_path,
                 args.ttl_min, args.ttl_max, args.repeat))


if __name__ == "__main__":
    main()
