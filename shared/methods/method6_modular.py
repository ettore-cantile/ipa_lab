#!/usr/bin/env python3
"""
Method 6 - Modular Neural Pipeline  (Pipeline 3)

Design space position: maximum flexibility, lower performance.

This method demonstrates the third point in the IPA/eBPF design space:
  - Neural inference decomposed into reusable eBPF layer-block programs
  - Each block: one linear transformation + ReLU (or argmax for output)
  - Intermediate activations transit via BPF_PERCPU_ARRAY scratch map
  - Layer chain: dispatcher -> layer_65_4 -> layer_4_4 -> layer_4_7_argmax
  - Maximum flexibility: change architecture = change layer_chain + weights
  - Model update cost: bpf_map_update_elem() for layer_weights +
    optionally layer_chain entries for architecture changes

Compatibility notes with the existing codebase:
  - Uses common.py helpers: load_weights, attach_xdp, detach_xdp
  - Reads weights from weights.json (same file as Method 1/2/5)
  - Uses scale_factor from weights_float.json
  - Attaches to iface param (default: INGRESS_IFACE from common.py)
  - pkt_stats_t3 + mac_table_t3 (class -> ifindex + MACs) used as separate maps
  - All four programs (dispatcher + 3 layers) compiled from EBPF_MODULAR_FULL
    so BCC sees them as a single compilation unit — no separate .o files needed

Files used (paths resolved relative to this file, not hardcoded /shared/):
  ../weights.json       : int8 weights (319 values)
  ../weights_float.json : float weights + scale_factor
"""
import ctypes
import socket
import os
import sys
import json
import time
from bcc import BPF
from ebpf_modular import (
    EBPF_MODULAR_FULL,
    load_modular_weights,
)
from common import (
    load_weights, attach_xdp, detach_xdp,
    EGRESS_IFACE, INGRESS_IFACE,
    resolve_egress_mac,
)

# Resolve the shared/ directory relative to this file regardless of cwd.
# Inside Kathara: /shared/methods/method6_modular.py -> /shared/
# Outside Kathara: resolved the same way via __file__.
_SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _populate_mac_t3(b: BPF, egress_iface: str, egress_ifindex: int):
    """Install mac_table_t3: egress class (0..5, the argmax output) ->
    {ifindex, src_mac, dst_mac}. The NN decides the port; this map only
    resolves the L2 next-hop. src_mac/dst_mac are resolved from the kernel
    (own iface MAC + ARP table for the neighbor), not hardcoded constants.
    All classes point to the same egress iface in this lab; a real
    deployment maps each class to its own neighbour + MACs."""
    src_mac, dst_mac = resolve_egress_mac(egress_iface)
    mac    = b.get_table("mac_table_t3")
    action = mac.Leaf()
    action.ifindex = egress_ifindex
    for i in range(6):
        action.src_mac[i] = src_mac[i]
        action.dst_mac[i] = dst_mac[i]
    for cls in range(6):
        mac[ctypes.c_uint32(cls)] = action
    print(f"[mac_t3] mac_table_t3 loaded: class 0..5 -> ifindex={egress_ifindex} "
          f"src={':'.join(f'{b:02x}' for b in src_mac)} dst={':'.join(f'{b:02x}' for b in dst_mac)}")


def run(model_id: int = 42, iface: str = None):
    """
    iface: network interface to attach XDP to.
           Defaults to INGRESS_IFACE from common.py if not specified.
           Pass the correct interface for the lab topology (e.g. 'eth0' for
           darmstadt->frankfurt direct link l59 in lab.conf).
    """
    ingress_iface = iface if iface else INGRESS_IFACE
    weights_path = os.path.join(_SHARED_DIR, "weights.json")
    float_path   = os.path.join(_SHARED_DIR, "weights_float.json")
    print(f"[Method 6 - Modular Pipeline] | model_id: {model_id} | iface: {ingress_iface}")

    if not os.path.exists(float_path):
        print(f"[ERROR] {float_path} not found. Run extract_weights.py first.")
        sys.exit(1)

    with open(float_path) as f:
        float_data = json.load(f)

    SCALE_FACTOR = float_data["scale_factor"]
    cp_weights   = float_data["weights"][:4]

    integer_weights = load_weights(weights_path)
    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Total weights : {len(integer_weights)}")
    print(f"  Ingress iface : {ingress_iface} (ifindex={socket.if_nametoindex(ingress_iface)})")

    # Compile all four eBPF functions from the combined source
    b = BPF(text=EBPF_MODULAR_FULL)

    # Populate layer_registry and layer_weights
    load_modular_weights(b, integer_weights, model_id=model_id, scale=SCALE_FACTOR)

    # Wire up the tail-call chain:
    #   layer_chain[0] = layer_65_4
    #   layer_chain[1] = layer_4_4
    #   layer_chain[2] = layer_4_7_argmax
    fn_l0 = b.load_func("layer_65_4",      BPF.XDP)
    fn_l1 = b.load_func("layer_4_4",       BPF.XDP)
    fn_l2 = b.load_func("layer_4_7_argmax",BPF.XDP)
    chain  = b.get_table("layer_chain")
    chain[ctypes.c_int(0)] = ctypes.c_int(fn_l0.fd)
    chain[ctypes.c_int(1)] = ctypes.c_int(fn_l1.fd)
    chain[ctypes.c_int(2)] = ctypes.c_int(fn_l2.fd)

    # Attach modular_dispatcher as the XDP entry point
    fn_disp = b.load_func("modular_dispatcher", BPF.XDP)

    # Populate the L2 next-hop dictionary (class -> ifindex + MACs)
    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    _populate_mac_t3(b, EGRESS_IFACE, egress_ifindex)

    # Seed link_state (egress up/down feature [0..5]) and start carrier monitor.
    from link_state_monitor import init_link_state_up, start_monitor_thread
    init_link_state_up(b)
    stop_monitor = start_monitor_thread(b, interval=1.0)
    print("[Method 6] link_state seeded (all up); carrier monitor running")

    attach_xdp(b, fn_disp, iface=ingress_iface)

    print("[Method 6] Pipeline 3 (Modular) running. "
          "Stats: pkt_stats_t3 [HIT | MISS | DROP]")
    print(f"  Tail call chain: modular_dispatcher "
          f"-> layer_65_4 -> layer_4_4 -> layer_4_7_argmax  (4 tail calls total)")

    stats = b.get_table("pkt_stats_t3")
    dbg   = b.get_table("debug_stats_t3")
    print(f"\n{'TRUE HIT':<22} | {'MISS':<22} | {'DROP':<20}")
    print("-" * 70)
    try:
        while True:
            time.sleep(1)
            try:
                hits   = stats[stats.Key(0)].value
                misses = stats[stats.Key(1)].value
                drops  = stats[stats.Key(2)].value
                print(f"\r{hits:<22} | {misses:<22} | {drops:<20}",
                      end="", flush=True)
                d = [dbg[dbg.Key(i)].value for i in range(14)]
                print(
                    f"\n  DEBUG: disp_seen={d[0]} eth_fail={d[1]} ip_fail={d[2]} "
                    f"not_udp={d[3]} udp_fail={d[4]} wrong_port={d[5]} "
                    f"ipa_fail={d[6]} no_registry={d[7]} disp_tailed={d[8]} "
                    f"L0_enter={d[9]} L0_tailed={d[12]} L1_enter={d[10]} "
                    f"L1_tailed={d[13]} L2_enter={d[11]}"
                )
            except Exception:
                pass
    except KeyboardInterrupt:
        stop_monitor.set()
        detach_xdp(b, iface=ingress_iface)
        print("\n\nXDP removed. Exiting.")
