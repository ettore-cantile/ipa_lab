#!/usr/bin/env python3
"""
method4_hardcoded.py  —  Pipeline 1: Hardcoded Model

Design space position:
  Maximum performance, minimum flexibility.
  Each model -> a dedicated eBPF program with weights hardcoded as signed-char
  literals in the C source. Fully unrolled inference, no BPF map lookup for the
  weights, a single tail call.

  Action: after argmax the program issues bpf_redirect towards the ifindex
  hardcoded for the chosen class (no fwd_table lookup).
  cls 0-5 -> corresponding egress iface, cls 6 -> XDP_DROP.

Kathara topology (XDP on frankfurt):
  frankfurt eth1 = ingress from darmstadt (10.0.0.234/30, link l59)
  frankfurt eth0 = other link (fallback)
  Classes 0-5 map to the ifindex of frankfurt's interfaces, resolved at
  runtime via socket.if_nametoindex.

Usage (via execute_pipeline.py):
    python3 execute_pipeline.py --method hardcoded
    python3 execute_pipeline.py --method hardcoded --model-id 0 --iface eth1

Direct run:
    sudo python3 shared/methods/method4_hardcoded.py --iface eth1 --model-id 0
"""

import os
import sys
import time
import socket
import ctypes
import argparse

SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)
os.chdir(SHARED_DIR)

from bcc import BPF
from ebpf_program import load_and_generate
from extract_weights import extract_weights_int8


DEFAULT_IFACES = ["eth0", "eth1", "eth2", "eth3", "eth4", "eth5"]


def _build_ifindex_table(iface_names: list) -> list:
    """
    Build a list of 6 kernel ifindex values for the given interface names.
    Missing interfaces fall back to ifindex of eth0 (or 2 if eth0 missing).
    """
    fallback = 2
    try:
        fallback = socket.if_nametoindex("eth0")
    except OSError:
        pass

    result = []
    for name in iface_names[:6]:
        try:
            result.append(socket.if_nametoindex(name))
        except OSError:
            result.append(fallback)
    while len(result) < 6:
        result.append(fallback)
    return result


def run(
    model_id: int = 0,
    iface: str = "eth1",
    model_path: str = None,
    egress_ifaces: list = None,
) -> None:
    """
    Load Pipeline 1 (hardcoded) on `iface`.

    Args:
        model_id      : model identifier embedded in the eBPF program
        iface         : ingress interface to attach XDP to (default eth1 on frankfurt)
        model_path    : path to .pt checkpoint; defaults to the shared one
        egress_ifaces : list of up to 6 interface names that map to cls 0-5.
                        Defaults to [eth0, eth1, eth2, eth3, eth4, eth5].
    """
    if model_path is None:
        model_path = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
    if egress_ifaces is None:
        egress_ifaces = DEFAULT_IFACES

    # ------------------------------------------------------------------
    # Step 1: resolve egress ifindex table at runtime
    # ------------------------------------------------------------------
    ifindex_table = _build_ifindex_table(egress_ifaces)
    print(f"[P1-hardcoded] Egress ifindex table (cls 0-5):")
    for cls_i, (name, idx) in enumerate(zip(egress_ifaces[:6], ifindex_table)):
        print(f"  cls {cls_i} -> {name} (ifindex={idx})")
    print(f"  cls 6 -> XDP_DROP")

    # ------------------------------------------------------------------
    # Step 2: generate hardcoded eBPF source from real model weights
    # ------------------------------------------------------------------
    print(f"\n[P1-hardcoded] Generating eBPF source from {model_path} ...")
    ebpf_src, weights_int8, scale = load_and_generate(
        model_path, model_id, ifindex_table=ifindex_table
    )
    print(f"[P1-hardcoded] scale={scale}, weights={len(weights_int8)}, "
          f"source={len(ebpf_src)} chars")

    # ------------------------------------------------------------------
    # Step 3: compile + load via BCC
    # ------------------------------------------------------------------
    print(f"[P1-hardcoded] Loading eBPF program (verifier check) ...")
    b = BPF(text=ebpf_src)
    fn = b.load_func("ipa_switch", BPF.XDP)
    print(f"[P1-hardcoded] Verifier: OK — program fd={fn.fd}")

    # ------------------------------------------------------------------
    # Step 4: populate model_cache so model_miss_event is NOT triggered
    # ------------------------------------------------------------------
    class ModelData(ctypes.Structure):
        _fields_ = [
            ("weights",      ctypes.c_uint8 * 319),
            ("is_valid",     ctypes.c_uint8),
            ("scale_factor", ctypes.c_uint16),
        ]

    entry = ModelData()
    for i, w in enumerate(weights_int8[:319]):
        entry.weights[i] = ctypes.c_uint8(w & 0xFF).value
    entry.is_valid     = 1
    entry.scale_factor = scale
    b["model_cache"][ctypes.c_uint8(model_id)] = entry
    print(f"[P1-hardcoded] model_cache[{model_id}] populated (is_valid=1, scale={scale})")

    # ------------------------------------------------------------------
    # Step 5: attach XDP on ingress iface
    #
    # FIX: attach in SKB/generic mode (XDP_FLAGS_SKB_MODE = 2), NOT native.
    # The ingress iface here is a veth (Kathara collision domain). A NATIVE
    # XDP program on one end of a veth pair breaks UNICAST reception from
    # the peer/bridge: unless XDP is attached to BOTH veth ends, unicast
    # frames forwarded to the XDP-enabled end are dropped by the veth path
    # BEFORE the program runs (multicast/broadcast — OSPF/ARP — still flood
    # through, which is exactly what tcpdump showed: OSPF/ARP arrive, the
    # unicast UDP:9999 IPA packets do not). Generic/SKB-mode XDP runs after
    # the normal veth delivery (in netif_receive_skb), so unicast packets
    # reach the program; bpf_redirect() is supported in generic mode too.
    # ------------------------------------------------------------------
    XDP_FLAGS_SKB_MODE = 2
    b.attach_xdp(iface, fn, flags=XDP_FLAGS_SKB_MODE)
    print(f"\n[P1-hardcoded] XDP attached to {iface} (SKB/generic mode) — running (Ctrl-C to stop)")
    print(f"[P1-hardcoded] Design: 0 weight-map lookups, 0 fwd_table lookups, ~780 insns")
    print(f"[P1-hardcoded] Egress port chosen dynamically by inference (best_cls -> switch(cls))")
    print()
    print(f"  {'TRUE HIT':>12} {'MISS':>10} {'DROP':>10}  {'cls0':>6} {'cls1':>6} {'cls2':>6} {'cls3':>6} {'cls4':>6} {'cls5':>6} {'cls6':>6}")
    print("  " + "-" * 88)

    # ------------------------------------------------------------------
    # Step 6: stats loop — show hit/miss/drop + per-class distribution
    # ------------------------------------------------------------------
    prev_stats = [0, 0, 0]
    prev_cls   = [0] * 7
    try:
        while True:
            time.sleep(1)
            pkt_stats = b["pkt_stats"]
            cls_stats = b["cls_stats"]
            cur_stats = [pkt_stats[i].value for i in range(3)]
            cur_cls   = [cls_stats[i].value  for i in range(7)]

            # chosen port = cls with highest delta in last second
            delta_cls   = [cur_cls[i]   - prev_cls[i]   for i in range(7)]
            chosen_cls  = delta_cls.index(max(delta_cls)) if any(delta_cls) else -1
            chosen_iface = egress_ifaces[chosen_cls] if 0 <= chosen_cls <= 5 else "DROP"

            print(
                f"  {cur_stats[0]:>12} {cur_stats[1]:>10} {cur_stats[2]:>10}  "
                + "".join(f"{cur_cls[i]:>6}" for i in range(7))
                + f"   chosen_port={chosen_iface}",
                end="\r",
            )

            # Diagnostic breakdown of WHY packets never reach pkt_stats
            # (e.g. all zeros -- wrong protocol/port, or never reaching
            # eth1 at all). Printed on its own real newline (leading \n
            # forces a clean line break even after the \r above) so it
            # survives a plain `tail`/log read, unlike the \r-refreshed
            # line above.
            debug_stats = b["debug_stats"]
            dbg = [debug_stats[i].value for i in range(8)]
            print(
                f"\n  DEBUG: seen={dbg[0]} eth_fail={dbg[1]} ip_fail={dbg[2]} "
                f"not_udp={dbg[3]} udp_fail={dbg[4]} wrong_port={dbg[5]} "
                f"ipa_fail={dbg[6]} reached_model_cache={dbg[7]}"
            )

            prev_stats = cur_stats
            prev_cls   = cur_cls
    except KeyboardInterrupt:
        pass
    finally:
        b.remove_xdp(iface, flags=XDP_FLAGS_SKB_MODE)
        print(f"\n[P1-hardcoded] XDP removed from {iface}")
        _print_final_stats(b, egress_ifaces)


def _print_final_stats(b, egress_ifaces):
    pkt_stats = b["pkt_stats"]
    cls_stats = b["cls_stats"]
    hit, miss, drop = (pkt_stats[i].value for i in range(3))
    total = hit + miss + drop
    print()
    print("=" * 56)
    print("Pipeline 1 — Hardcoded — final stats")
    print(f"  TRUE HIT  (redirect) : {hit:>10}  ({100*hit/max(total,1):.1f}%)")
    print(f"  MISS      (no cache) : {miss:>10}  ({100*miss/max(total,1):.1f}%)")
    print(f"  DROP      (cls 6)    : {drop:>10}  ({100*drop/max(total,1):.1f}%)")
    print(f"  TOTAL                : {total:>10}")
    print()
    print("  Per-class egress port distribution:")
    cls_total = sum(cls_stats[i].value for i in range(7))
    for i in range(6):
        cnt  = cls_stats[i].value
        name = egress_ifaces[i] if i < len(egress_ifaces) else f"eth{i}"
        bar  = "#" * int(40 * cnt / max(cls_total, 1))
        print(f"    cls {i} -> {name:6s} : {cnt:>8}  {bar}")
    drop_cnt = cls_stats[6].value if 6 < len(cls_stats) else drop
    print(f"    cls 6 -> DROP   : {drop_cnt:>8}")
    print()
    debug_stats = b["debug_stats"]
    dbg = [debug_stats[i].value for i in range(8)]
    print("  Debug breakdown (why packets never reached pkt_stats, if 0):")
    print(f"    seen={dbg[0]} eth_fail={dbg[1]} ip_fail={dbg[2]} not_udp={dbg[3]} "
          f"udp_fail={dbg[4]} wrong_port={dbg[5]} ipa_fail={dbg[6]} "
          f"reached_model_cache={dbg[7]}")
    print("=" * 56)


# ---------------------------------------------------------------------------
# Direct CLI run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pipeline 1: Hardcoded eBPF XDP")
    parser.add_argument("--iface",    default="eth1",   help="Ingress interface (default: eth1)")
    parser.add_argument("--model-id", type=int, default=0, help="Model ID")
    parser.add_argument("--model",    default=None,     help="Path to .pt checkpoint")
    parser.add_argument("--egress-ifaces", nargs="+",
                        default=DEFAULT_IFACES,
                        help="Egress interfaces for cls 0-5 (default: eth0..eth5)")
    parser.add_argument("--verify-only", action="store_true",
                        help="Load+verify eBPF program but do NOT attach XDP")
    args = parser.parse_args()

    if args.verify_only:
        model_path = args.model or os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
        ifindex_table = _build_ifindex_table(args.egress_ifaces)
        print(f"[verify-only] ifindex_table={ifindex_table}")
        src, w, s = load_and_generate(model_path, args.model_id, ifindex_table=ifindex_table)
        print(f"[verify-only] scale={s}, weights={len(w)}, source_chars={len(src)}")
        b = BPF(text=src)
        fn = b.load_func("ipa_switch", BPF.XDP)
        print(f"[verify-only] Verifier PASSED — fd={fn.fd}")
        sys.exit(0)

    run(
        model_id=args.model_id,
        iface=args.iface,
        model_path=args.model,
        egress_ifaces=args.egress_ifaces,
    )
