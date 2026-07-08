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
  - Attaches to INGRESS_IFACE (eth1), redirects to EGRESS_IFACE (eth2)
  - pkt_stats_t3, fwd_table_t3, valid_keys_t3 used as separate maps
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
    EGRESS_IFACE, INGRESS_IFACE, OFFSET,
    SRC_MAC, DST_MAC,
)

# Resolve the shared/ directory relative to this file regardless of cwd.
# Inside Kathara: /shared/methods/method6_modular.py -> /shared/
# Outside Kathara: resolved the same way via __file__.
_SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _build_fwd_action_t3(b: BPF, egress_ifindex: int):
    fwd    = b.get_table("fwd_table_t3")
    action = fwd.Leaf()
    action.ifindex = egress_ifindex
    for i in range(6):
        action.src_mac[i] = SRC_MAC[i]
        action.dst_mac[i] = DST_MAC[i]
    return action


def _populate_fwd_t3(b: BPF, action, cp_weights: list, scale_factor: int):
    """
    Pre-populate fwd_table_t3 and valid_keys_t3 for TTL 30-64.
    Key formula is identical to Pipeline 1/2 for fair comparison.
    """
    fwd    = b.get_table("fwd_table_t3")
    vk     = b.get_table("valid_keys_t3")
    if_idx = socket.if_nametoindex(INGRESS_IFACE)

    for ttl in range(30, 65):
        iv = [42, ttl, if_idx, 65]
        output_raw = sum(
            v * ctypes.c_int8(int(w)).value
            for v, w in zip(iv, cp_weights)
        )
        key = (output_raw + OFFSET * scale_factor) // scale_factor
        fwd[ctypes.c_ulonglong(key)] = action
        vk[ctypes.c_uint8(ttl)]      = ctypes.c_ulonglong(key)

    print(f"[fwd_t3] fwd_table_t3 and valid_keys_t3 loaded for TTL 30-64 [integer/modular]")


def run(model_id: int = 42):
    weights_path = os.path.join(_SHARED_DIR, "weights.json")
    float_path   = os.path.join(_SHARED_DIR, "weights_float.json")
    print(f"[Method 6 - Modular Pipeline] | model_id: {model_id}")

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

    # Populate forwarding tables
    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = _build_fwd_action_t3(b, egress_ifindex)
    _populate_fwd_t3(b, action, cp_weights, SCALE_FACTOR)

    attach_xdp(b, fn_disp)

    print("[Method 6] Pipeline 3 (Modular) running. "
          "Stats: pkt_stats_t3 [HIT | FAKE | MISS]")
    print(f"  Tail call chain: modular_dispatcher "
          f"-> layer_65_4 -> layer_4_4 -> layer_4_7_argmax  (4 tail calls total)")

    stats = b.get_table("pkt_stats_t3")
    print(f"\n{'TRUE HIT':<22} | {'FAKE HIT':<22} | {'MISS':<20}")
    print("-" * 70)
    try:
        while True:
            time.sleep(1)
            try:
                true_hits = stats[stats.Key(0)].value
                misses    = stats[stats.Key(1)].value
                fake_hits = stats[stats.Key(2)].value
                print(f"\r{true_hits:<22} | {fake_hits:<22} | {misses:<20}",
                      end="", flush=True)
            except Exception:
                pass
    except KeyboardInterrupt:
        detach_xdp(b)
        print("\n\nXDP removed. Exiting.")
