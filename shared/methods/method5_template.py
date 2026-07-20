#!/usr/bin/env python3
"""
Method 5 - Pre-built Architectural Template  (Pipeline 2)

Design space position: medium flexibility, high/intermediate performance.

This method demonstrates the second point in the IPA/eBPF design space:
  - One eBPF program for the whole "2 hidden-layer MLP" architecture family
    (arch_generic_2layer) -- input/output are protocol-fixed (65/7), hidden
    widths n_h1/n_h2 are read at runtime, any widths up to the compiled
    ceiling (T2_MAX_H1/T2_MAX_H2 in ebpf_template_arch.py) run unmodified
  - Weights are NOT hardcoded: they are stored in a BPF_ARRAY map
  - No recompilation needed to change weights, hidden widths, or to switch
    models that share the same 2-hidden-layer topology
  - One tail call: dispatcher -> arch program
  - Model update cost: only bpf_map_update_elem() calls

Compatibility notes with the existing codebase:
  - Uses common.py helpers: load_weights, resolve_egress_mac, attach_xdp, detach_xdp
  - Reads weights from weights.json (same file as Method 1/2)
  - Uses scale_factor from weights_float.json (same as Method 1)
  - Attaches to iface param (default: INGRESS_IFACE from common.py)
  - pkt_stats_t2 map is used instead of pkt_stats
  - mac_table_t2 (class -> ifindex + MACs) resolves the L2 next-hop after argmax

Files used (paths resolved relative to this file, not hardcoded /shared/):
  ../weights.json       : int8 weights (319 values)
  ../weights_float.json : float weights + scale_factor
"""
import ctypes
import socket
import os
import sys
import json
from bcc import BPF
from ebpf_template_arch import (
    EBPF_TEMPLATE_ARCH_DISPATCHER,
    EBPF_ARCH_GENERIC_2LAYER,
    load_arch_weights,
    arch_weight_count,
    N_WEIGHTS_T2,
)
from common import (
    load_weights, attach_xdp,
    EGRESS_IFACE, INGRESS_IFACE,
    resolve_egress_mac, resolve_ifindex,
)

# Resolve the shared/ directory relative to this file regardless of cwd.
_SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(model_id: int = 42, iface: str = None, model_ids: list = None,
        hidden_dims: list = None):
    ingress_iface = iface if iface else INGRESS_IFACE
    ingress_iface, _ = resolve_ifindex(ingress_iface)
    ids = list(model_ids) if model_ids else [model_id]
    dims = list(hidden_dims) if hidden_dims else [(4, 4)] * len(ids)
    if len(dims) != len(ids):
        raise ValueError(f"hidden_dims has {len(dims)} entries, expected {len(ids)} (one per model_id)")
    weights_path = os.path.join(_SHARED_DIR, "weights.json")
    float_path   = os.path.join(_SHARED_DIR, "weights_float.json")
    print(f"[Method 5 - Arch Template] | model_ids: {ids} | iface: {ingress_iface}")

    if not os.path.exists(float_path):
        print(f"[ERROR] {float_path} not found. Run extract_weights.py first.")
        sys.exit(1)

    with open(float_path) as f:
        float_data = json.load(f)

    SCALE_FACTOR = float_data["scale_factor"]
    cp_weights   = float_data["weights"][:4]

    integer_weights = load_weights(weights_path)

    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Total weights : {len(integer_weights)} (expected {N_WEIGHTS_T2})")
    print(f"  Ingress iface : {ingress_iface} (ifindex={socket.if_nametoindex(ingress_iface)})")

    combined_src = ("#define IPA_ARCH_COMBINED 1\n"
                    + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_GENERIC_2LAYER)
    b = BPF(text=combined_src)

    weight_offset = 0
    for mid, (n_h1, n_h2) in zip(ids, dims):
        load_arch_weights(b, integer_weights, model_id=mid, scale=SCALE_FACTOR,
                          weight_offset=weight_offset, n_h1=n_h1, n_h2=n_h2)
        weight_offset += arch_weight_count(n_h1, n_h2)

    fn_arch = b.load_func("arch_generic_2layer", BPF.XDP)
    arch_progs = b.get_table("arch_progs")
    arch_progs[ctypes.c_int(0)] = ctypes.c_int(fn_arch.fd)

    fn_dispatcher = b.load_func("ipa_switch_template", BPF.XDP)

    from common import install_mac_per_class, start_mac_refresh_thread
    mac_info = install_mac_per_class(b, "mac_table_t2", n_fwd=6)
    if mac_info["pending"]:
        start_mac_refresh_thread(b, "mac_table_t2", mac_info["pending"], interval=5.0)

    from link_state_monitor import init_link_state_up, start_monitor_thread
    init_link_state_up(b)
    stop_monitor = start_monitor_thread(b, interval=1.0)
    print("[Method 5] link_state seeded (all up); carrier monitor running")

    attach_xdp(b, fn_dispatcher, iface=ingress_iface)

    print("[Method 5] Pipeline 2 (Arch Template) running. "
          "Stats: pkt_stats_t2 [HIT | MISS | DROP]")

    import time
    from common import detach_xdp
    stats = b.get_table("pkt_stats_t2")
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
            except Exception:
                pass
    except KeyboardInterrupt:
        stop_monitor.set()
        detach_xdp(b, iface=ingress_iface)
        print("\n\nXDP removed. Exiting.")
