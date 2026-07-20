#!/usr/bin/env python3
"""
Method 6 - Modular Neural Pipeline  (Pipeline 3)

Design space position: maximum flexibility, lower performance.

This method demonstrates the third point in the IPA/eBPF design space:
  - Neural inference decomposed into a chain of tail calls across TWO
    generic layer programs: layer_first (always hop 0, sparse read of the
    protocol-fixed 65-feature IPA vector) and layer_hidden (hop 1..N-1,
    dense n_in -> n_out). Either one argmaxes + forwards instead of
    continuing the chain if it's the model's last layer.
  - Intermediate activations transit via BPF_PERCPU_ARRAY scratch map
  - Layer chain: dispatcher -> layer_first -> layer_hidden -> ... (as
    many layer_hidden hops as the model needs, read from a per-model registry)
  - Maximum flexibility: change architecture (depth AND width) = change the
    registered (n_in, n_out) list + weights for that model_id; no eBPF
    recompilation, same 2 compiled programs for any shape within the
    compiled ceilings (ML1_MAX_H1/MLH_MAX_H in ebpf_modular.py)
  - Model update cost: bpf_map_update_elem() for layer_weights + layer_shapes

Compatibility notes with the existing codebase:
  - Uses common.py helpers: load_weights, attach_xdp, detach_xdp
  - Reads weights from weights.json (same file as Method 1/2/5)
  - Uses scale_factor from weights_float.json
  - Attaches to iface param (default: INGRESS_IFACE from common.py)
  - pkt_stats_t3 + mac_table_t3 (class -> ifindex + MACs) used as separate maps
  - All three programs (dispatcher + layer_first + layer_hidden) compiled
    from EBPF_MODULAR_FULL so BCC sees them as a single compilation unit

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
    resolve_egress_mac, resolve_ifindex,
)

_SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(model_id: int = 42, iface: str = None, model_ids: list = None,
        layer_dims_by_model: list = None):
    ingress_iface = iface if iface else INGRESS_IFACE
    ingress_iface, _ = resolve_ifindex(ingress_iface)
    ids = list(model_ids) if model_ids else [model_id]
    dims_by_model = (list(layer_dims_by_model) if layer_dims_by_model
                     else [[(65, 4), (4, 4), (4, 7)]] * len(ids))
    if len(dims_by_model) != len(ids):
        raise ValueError(f"layer_dims_by_model has {len(dims_by_model)} entries, expected {len(ids)} (one per model_id)")
    weights_path = os.path.join(_SHARED_DIR, "weights.json")
    float_path   = os.path.join(_SHARED_DIR, "weights_float.json")
    print(f"[Method 6 - Modular Pipeline] | model_ids: {ids} | iface: {ingress_iface}")

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

    b = BPF(text=EBPF_MODULAR_FULL)

    base_offset = 0
    for mid, layer_dims in zip(ids, dims_by_model):
        consumed = load_modular_weights(b, integer_weights, model_id=mid, scale=SCALE_FACTOR,
                                        layer_dims=layer_dims, base_offset=base_offset)
        base_offset += consumed

    fn_first  = b.load_func("layer_first",  BPF.XDP)
    fn_hidden = b.load_func("layer_hidden", BPF.XDP)
    chain = b.get_table("layer_chain")
    chain[ctypes.c_int(0)] = ctypes.c_int(fn_first.fd)
    for i in range(1, 16):
        chain[ctypes.c_int(i)] = ctypes.c_int(fn_hidden.fd)

    fn_disp = b.load_func("modular_dispatcher", BPF.XDP)

    from common import install_mac_per_class, start_mac_refresh_thread
    mac_info = install_mac_per_class(b, "mac_table_t3", n_fwd=6)
    if mac_info["pending"]:
        start_mac_refresh_thread(b, "mac_table_t3", mac_info["pending"], interval=5.0)

    from link_state_monitor import init_link_state_up, start_monitor_thread
    init_link_state_up(b)
    stop_monitor = start_monitor_thread(b, interval=1.0)
    print("[Method 6] link_state seeded (all up); carrier monitor running")

    attach_xdp(b, fn_disp, iface=ingress_iface)

    print("[Method 6] Pipeline 3 (Modular) running. "
          "Stats: pkt_stats_t3 [HIT | MISS | DROP]")
    print(f"  Tail call chain: modular_dispatcher -> layer_first -> layer_hidden (x n_layers-1 "
          f"per model, per-model depth read from layer_registry)")

    stats = b.get_table("pkt_stats_t3")
    print(f"\n{'TRUE HIT':>12} {'MISS':>10} {'DROP':>10}")
    print("-" * 34)
    try:
        while True:
            time.sleep(1)
            try:
                hits   = stats[stats.Key(0)].value
                misses = stats[stats.Key(1)].value
                drops  = stats[stats.Key(2)].value
                print(f"\r{hits:>12} {misses:>10} {drops:>10}",
                      end="", flush=True)
                print()
            except Exception:
                pass
    except KeyboardInterrupt:
        stop_monitor.set()
        detach_xdp(b, iface=ingress_iface)
        print("\n\nXDP removed. Exiting.")
