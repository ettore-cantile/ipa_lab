#!/usr/bin/env python3
"""
method4_hardcoded.py  —  Pipeline 1: Hardcoded Model

Design space position:
  Maximum performance, minimum flexibility.
  Each model -> a dedicated eBPF program with weights hardcoded as signed-char
  literals in the C source. Fully unrolled inference, no BPF map lookup for the
  weights, a single tail call.

  Action: after argmax the program looks up mac_table[class] (real
  per-class ifindex + resolved src/dst MAC), rewrites the Ethernet header,
  and bpf_redirects -- same mac_table pattern as P2/P3, so P1 also leaves
  the packet with a correct L2 next-hop MAC, not just the original one.
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
import ctypes
import argparse

SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)
os.chdir(SHARED_DIR)

from bcc import BPF
from ebpf_program import load_and_generate
from extract_weights import extract_weights_int8
from common import resolve_egress_mac, resolve_ifindex


DEFAULT_IFACES = ["eth0", "eth1", "eth2", "eth3", "eth4", "eth5"]


def _build_ifindex_table(iface_names: list) -> list:
    """
    Build a list of 6 (resolved_name, kernel_ifindex) tuples for cls 0-5,
    via common.resolve_ifindex(name, fallback="eth0") -- resolved_name is
    the REAL interface that resolved (iface_names[cls] if it exists on
    this node, otherwise the fallback). Returning the name alongside the
    ifindex (not just the ifindex) matters: a node may not have all 6
    interfaces (e.g. frankfurt only has a few real links), and any caller
    that later does /sys/class/net/<name>/... (see resolve_egress_mac())
    must use the interface that ACTUALLY exists, not the requested one
    that silently fell back to a different ifindex.
    """
    result = [resolve_ifindex(name, fallback="eth0") for name in iface_names[:6]]
    while len(result) < 6:
        result.append(resolve_ifindex("eth0", fallback="eth0"))
    return result


def _populate_mac_table_hardcoded(b: BPF, ifindex_table: list):
    """Install mac_table: egress class (0..5, the argmax output) ->
    {ifindex, src_mac, dst_mac}. Unlike P2/P3 (single shared egress iface),
    P1 supports a DISTINCT egress interface per class, so each class
    resolves its own src/dst MAC. ifindex_table entries are (name, idx)
    pairs from _build_ifindex_table() -- name is the interface that
    ACTUALLY exists on this node (already fallback-resolved), so
    resolve_egress_mac() never gets asked for a nonexistent interface."""
    from ctypes import Structure, c_uint8, c_uint32

    class _FwdAction(Structure):
        _pack_ = 1
        _fields_ = [("ifindex", c_uint32), ("src_mac", c_uint8 * 6), ("dst_mac", c_uint8 * 6)]

    mac = b.get_table("mac_table")
    for cls, (iface, idx) in enumerate(ifindex_table):
        src_mac, dst_mac = resolve_egress_mac(iface)
        action = _FwdAction(ifindex=idx)
        for i in range(6):
            action.src_mac[i] = src_mac[i]
            action.dst_mac[i] = dst_mac[i]
        mac[c_uint32(cls)] = action
        print(f"  cls {cls} -> {iface} (ifindex={idx}) "
              f"src={':'.join(f'{x:02x}' for x in src_mac)} "
              f"dst={':'.join(f'{x:02x}' for x in dst_mac)}")


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

    # No fallback for the ingress/attach target: silently attaching XDP to
    # a DIFFERENT interface than requested would be worse than a loud,
    # actionable error (see resolve_ifindex() docstring in common.py).
    iface, _ = resolve_ifindex(iface)

    # ------------------------------------------------------------------
    # Step 1: resolve egress ifindex table at runtime
    # ------------------------------------------------------------------
    resolved_table = _build_ifindex_table(egress_ifaces)  # [(name, ifindex), ...]
    ifindex_table = [idx for _, idx in resolved_table]    # ints only, for the C codegen
    print(f"[P1-hardcoded] Egress ifindex table (cls 0-5):")
    for cls_i, (name, idx) in enumerate(resolved_table):
        requested = egress_ifaces[cls_i] if cls_i < len(egress_ifaces) else "?"
        note = "" if name == requested else f" (fallback, {requested} not found on this node)"
        print(f"  cls {cls_i} -> {name} (ifindex={idx}){note}")
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
    model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
    fn = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ctypes.c_int(model_id)] = ctypes.c_int(model_fn.fd)
    print(f"[P1-hardcoded] Verifier: OK — dispatcher fd={fn.fd}, model_{model_id} fd={model_fn.fd}")

    # ------------------------------------------------------------------
    # Step 3.5: populate mac_table (real per-class src/dst MAC + ifindex)
    # ------------------------------------------------------------------
    print(f"[P1-hardcoded] mac_table (per-class egress + MAC):")
    _populate_mac_table_hardcoded(b, resolved_table)

    # ------------------------------------------------------------------
    # Step 4: seed link_state and start the carrier monitor
    # ------------------------------------------------------------------
    from link_state_monitor import init_link_state_up, start_monitor_thread
    init_link_state_up(b, egress_ifaces)
    stop_monitor = start_monitor_thread(b, egress_ifaces, interval=1.0)
    print(f"[P1-hardcoded] link_state seeded (all up); carrier monitor running")

    # ------------------------------------------------------------------
    # Step 5: attach XDP on ingress iface (SKB/generic mode)
    # ------------------------------------------------------------------
    XDP_FLAGS_SKB_MODE = 2
    b.attach_xdp(iface, fn, flags=XDP_FLAGS_SKB_MODE)
    print(f"\n[P1-hardcoded] XDP attached to {iface} (SKB/generic mode) — running (Ctrl-C to stop)")
    print(f"[P1-hardcoded] Design: dispatcher -> 1 tail call -> model_{model_id} "
          f"(0 weight-map lookups, fully unrolled)")
    print(f"[P1-hardcoded] Egress port chosen dynamically by inference (best_cls -> mac_table[cls])")
    print()
    print(f"  {'TRUE HIT':>12} {'MISS':>10} {'DROP':>10}")
    print("  " + "-" * 34)

    # ------------------------------------------------------------------
    # Step 6: stats loop
    # ------------------------------------------------------------------
    try:
        while True:
            time.sleep(1)
            pkt_stats = b["pkt_stats"]
            cur = [pkt_stats[i].value for i in range(3)]
            print(
                f"\r  {cur[0]:>12} {cur[1]:>10} {cur[2]:>10}",
                end="", flush=True,
            )
            print()
    except KeyboardInterrupt:
        pass
    finally:
        stop_monitor.set()
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
    print(f"  MISS      (no mac_table entry): {miss:>10}  ({100*miss/max(total,1):.1f}%)")
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
        resolved_table = _build_ifindex_table(args.egress_ifaces)
        ifindex_table = [idx for _, idx in resolved_table]
        print(f"[verify-only] ifindex_table={resolved_table}")
        src, w, s = load_and_generate(model_path, args.model_id, ifindex_table=ifindex_table)
        print(f"[verify-only] scale={s}, weights={len(w)}, source_chars={len(src)}")
        b = BPF(text=src)
        model_fn = b.load_func(f"model_{args.model_id}", BPF.XDP)
        fn = b.load_func("ipa_switch_hardcoded", BPF.XDP)
        print(f"[verify-only] Verifier PASSED — dispatcher fd={fn.fd}, model_{args.model_id} fd={model_fn.fd}")
        sys.exit(0)

    run(
        model_id=args.model_id,
        iface=args.iface,
        model_path=args.model,
        egress_ifaces=args.egress_ifaces,
    )
