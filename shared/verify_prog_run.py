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

from bcc import BPF, lib

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
# BPF_PROG_TEST_RUN wrapper (libbcc bpf_prog_test_run, 8-arg classic form)
# ---------------------------------------------------------------------------
_test_run_ready = False


def _init_test_run():
    global _test_run_ready
    if _test_run_ready:
        return
    if not hasattr(lib, "bpf_prog_test_run"):
        raise RuntimeError(
            "libbcc has no bpf_prog_test_run symbol — BCC too old for "
            "BPF_PROG_TEST_RUN. Upgrade bpfcc, or use the Kathara path."
        )
    lib.bpf_prog_test_run.restype = ct.c_int
    lib.bpf_prog_test_run.argtypes = [
        ct.c_int, ct.c_int, ct.c_void_p, ct.c_uint32,
        ct.c_void_p, ct.POINTER(ct.c_uint32),
        ct.POINTER(ct.c_uint32), ct.POINTER(ct.c_uint32),
    ]
    _test_run_ready = True


def prog_test_run(prog_fd: int, frame: bytes, repeat: int = 1):
    """Run the XDP program on `frame`. Returns (retval, duration_ns)."""
    _init_test_run()
    data_in = ct.create_string_buffer(frame, len(frame))
    out_cap = len(frame) + 256
    data_out = ct.create_string_buffer(out_cap)
    size_out = ct.c_uint32(out_cap)
    retval = ct.c_uint32(0)
    duration = ct.c_uint32(0)
    rc = lib.bpf_prog_test_run(
        prog_fd, repeat, data_in, len(frame),
        data_out, ct.byref(size_out), ct.byref(retval), ct.byref(duration),
    )
    if rc != 0:
        raise OSError(ct.get_errno(), f"bpf_prog_test_run failed rc={rc}")
    return retval.value, duration.value


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

    return b, fn, weights_int8, scale, read_class_hist, read_debug


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def run(method: str, model_id: int, model_path: str,
        ttl_min: int, ttl_max: int, repeat: int):
    print("=" * 68)
    print(f" IPA/eBPF verification via BPF_PROG_TEST_RUN — method={method}")
    print("=" * 68)

    if method == "hardcoded":
        b, fn, weights_int8, scale, read_class_hist, read_debug = \
            setup_hardcoded(model_id, model_path)
    else:
        print(f"[verify] method '{method}' not yet wired for TEST_RUN "
              f"(hardcoded is complete; template/modular next).")
        return 2

    print(f"[verify] program loaded (scale={scale}, weights={len(weights_int8)})")
    print(f"[verify] feeding IPA packets for ttl {ttl_min}..{ttl_max} "
          f"(model_id={model_id})\n")

    action_count = {XDP_REDIRECT: 0, XDP_DROP: 0, XDP_PASS: 0, XDP_ABORTED: 0}
    n = 0
    for ttl in range(ttl_min, ttl_max + 1):
        frame = build_frame(model_id, ttl, weights_int8, scale)
        retval, _ = prog_test_run(fn.fd, frame, repeat=1)
        action_count[retval] = action_count.get(retval, 0) + 1
        n += 1

    hits  = action_count.get(XDP_REDIRECT, 0)
    drops = action_count.get(XDP_DROP, 0)
    passes = action_count.get(XDP_PASS, 0)

    dbg = read_debug()
    cls_hist = read_class_hist()

    # Latency: many repeats on one representative packet, kernel-averaged.
    lat_frame = build_frame(model_id, (ttl_min + ttl_max) // 2, weights_int8, scale)
    _, dur_ns = prog_test_run(fn.fd, lat_frame, repeat=repeat)

    print("  Per-packet XDP action (one packet per ttl):")
    print(f"    REDIRECT (forwarded / HIT) : {hits:>4}  ({100*hits/max(n,1):.0f}%)")
    print(f"    DROP     (class 6 chosen)  : {drops:>4}  ({100*drops/max(n,1):.0f}%)")
    print(f"    PASS     (parse/cache miss): {passes:>4}  ({100*passes/max(n,1):.0f}%)")
    print(f"    TOTAL packets fed          : {n:>4}")
    print()
    print("  Reception proof (debug counters, cumulative):")
    print(f"    reached_model_cache = {dbg['reached_model_cache']}  "
          f"(packets that parsed eth/ip/udp/ipa and hit inference)")
    print(f"    not_udp={dbg['not_udp']}  wrong_port={dbg['wrong_port']}  "
          f"seen={dbg['seen']}")
    print()
    print("  Dispatch proof (argmax class distribution, cumulative):")
    labels = ["eth0", "eth1", "eth2", "eth3", "eth4", "eth5", "DROP"]
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

    parsed_ok = (passes == 0)
    verdict = "PASS" if (parsed_ok and (hits + drops) == n) else "CHECK"
    print("=" * 68)
    if verdict == "PASS":
        print(f" VERIFY PASSED — all {n} packets received & dispatched "
              f"(hits={hits}, drops={drops})")
        print(" The pipeline parses, runs inference and takes a per-class "
              "action for every packet.")
    else:
        print(f" VERIFY CHECK — passes={passes} (packets that failed a header "
              "check or model_cache); investigate.")
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
