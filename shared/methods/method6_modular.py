#!/usr/bin/env python3
"""
Method 6 - Modular Neural Pipeline  (Pipeline 3)

Design space position: maximum flexibility, lower performance.

This method demonstrates the third point in the IPA/eBPF design space:
  - Neural inference decomposed into a chain of tail calls, ALL of them the
    SAME generic layer program (layer_generic): one linear transformation
    n_in -> n_out + ReLU, or argmax + forward if it's the model's last layer
  - Intermediate activations transit via BPF_PERCPU_ARRAY scratch map
  - Layer chain: dispatcher -> layer_generic -> layer_generic -> ... (as
    many hops as the model has layers, read from a per-model registry)
  - Maximum flexibility: change architecture (depth AND width) = change the
    registered (n_in, n_out) list + weights for that model_id; no eBPF
    recompilation, same compiled program for any shape within the compiled
    ceilings (ML_MAX_IN/ML_MAX_OUT in ebpf_modular.py)
  - Model update cost: bpf_map_update_elem() for layer_weights + layer_shapes

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

_SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _populate_mac_t3(b: BPF, egress_iface: str, egress_ifindex: int):
    """Install mac_table_t3: egress class (0..5) -> {ifindex, src_mac, dst_mac}."""
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


def run(model_id: int = 42, iface: str = None, model_ids: list = None,
        layer_dims_by_model: list = None):
    """
    iface: network interface to attach XDP to.
           Defaults to INGRESS_IFACE from common.py if not specified.
    model_ids: optional list of model_id's to register concurrently, all
           sharing the same compiled layer_generic program -- depth and
           width may differ per model (see layer_dims_by_model), since the
           "is this the last layer" decision is made at runtime from data,
           not from which program is wired at a given tail-call slot.
           Each gets its own, non-overlapping slice of layer_weights, so the
           dispatcher can serve several models in the same run without a
           reload. Defaults to [model_id] (single-model, backward compatible).
    layer_dims_by_model: optional list of per-model layer_dims (one entry
           per model_ids[i]), each a list of (n_in, n_out) tuples -- see
           load_modular_weights() in ebpf_modular.py. Defaults to the
           checked-in 65-4-4-7 shape for every model
           ([[(65,4),(4,4),(4,7)]] * len(ids)).
           NOTE: today only one trained model (65-4-4-7) is checked into the
           repo, so multiple model_ids with the default shape only exercise
           the registry/dispatch mechanism with repeated weights -- pass a
           real per-model layer_dims/weights source to exercise a genuinely
           different architecture.
    """
    ingress_iface = iface if iface else INGRESS_IFACE
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

    # Compile both eBPF functions (dispatcher + the one generic layer
    # program) from the combined source
    b = BPF(text=EBPF_MODULAR_FULL)

    # Populate layer_registry/layer_shapes/layer_weights: one non-overlapping
    # weight block per model_id, sized to that model's own depth/width.
    base_offset = 0
    for mid, layer_dims in zip(ids, dims_by_model):
        consumed = load_modular_weights(b, integer_weights, model_id=mid, scale=SCALE_FACTOR,
                                        layer_dims=layer_dims, base_offset=base_offset)
        base_offset += consumed

    # Wire the tail-call chain: every slot points at the SAME generic
    # program. Which hop is "the last layer" is decided at runtime per
    # model (layer_idx+1 == n_layers), not by which program sits at a given
    # slot -- so this wiring never needs to change when a model's depth
    # differs from another concurrently-registered model's depth.
    fn_generic = b.load_func("layer_generic", BPF.XDP)
    chain = b.get_table("layer_chain")
    for i in range(16):  # LAYER_CHAIN_SIZE in ebpf_modular.py
        chain[ctypes.c_int(i)] = ctypes.c_int(fn_generic.fd)

    # Attach modular_dispatcher as the XDP entry point
    fn_disp = b.load_func("modular_dispatcher", BPF.XDP)

    # Populate the L2 next-hop dictionary
    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    _populate_mac_t3(b, EGRESS_IFACE, egress_ifindex)

    # Seed link_state and start carrier monitor
    from link_state_monitor import init_link_state_up, start_monitor_thread
    init_link_state_up(b)
    stop_monitor = start_monitor_thread(b, interval=1.0)
    print("[Method 6] link_state seeded (all up); carrier monitor running")

    attach_xdp(b, fn_disp, iface=ingress_iface)

    print("[Method 6] Pipeline 3 (Modular) running. "
          "Stats: pkt_stats_t3 [HIT | MISS | DROP]")
    print(f"  Tail call chain: modular_dispatcher -> layer_generic (x n_layers per model, "
          f"per-model depth read from layer_registry)")

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
