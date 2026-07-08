"""
Method 5 - Pre-built Architectural Template  (Pipeline 2)

Design space position: medium flexibility, high/intermediate performance.

This method demonstrates the second point in the IPA/eBPF design space:
  - One eBPF program per architecture shape (arch_65_4_4_7)
  - Weights are NOT hardcoded: they are stored in a BPF_ARRAY map
  - No recompilation needed to change weights or to switch models
    that share the same architecture shape
  - One tail call: dispatcher -> arch program
  - Model update cost: only bpf_map_update_elem() calls

Compatibility notes with the existing codebase:
  - Uses common.py helpers: load_bpf, build_fwd_action,
    populate_fwd_and_valid_keys, attach_xdp, stats_loop
  - Reads weights from weights.json (same file as Method 1/2)
  - Uses scale_factor from weights_float.json (same as Method 1)
  - Attaches to INGRESS_IFACE (eth1), redirects to EGRESS_IFACE (eth2)
  - pkt_stats_t2 map is used instead of pkt_stats
  - fwd_table_t2 / valid_keys_t2 used instead of fwd_table / valid_keys

Files used:
  /shared/weights.json       : int8 weights (319 values)
  /shared/weights_float.json : float weights + scale_factor
"""
import ctypes
import socket
import os
import sys
import json
from bcc import BPF
from ebpf_template_arch import (
    EBPF_TEMPLATE_ARCH_DISPATCHER,
    EBPF_ARCH_65_4_4_7,
    load_arch_weights,
    N_WEIGHTS_T2,
)
from common import (
    load_weights, build_fwd_action,
    populate_fwd_and_valid_keys,
    attach_xdp, stats_loop,
    EGRESS_IFACE, INGRESS_IFACE,
)


def _build_fwd_action_t2(b: BPF, egress_ifindex: int):
    """Same as common.build_fwd_action but targets fwd_table_t2."""
    from common import SRC_MAC, DST_MAC
    fwd    = b.get_table("fwd_table_t2")
    action = fwd.Leaf()
    action.ifindex = egress_ifindex
    for i in range(6):
        action.src_mac[i] = SRC_MAC[i]
        action.dst_mac[i] = DST_MAC[i]
    return action


def _populate_fwd_t2(b: BPF, action, cp_weights: list, scale_factor: int):
    """
    Pre-populate fwd_table_t2 and valid_keys_t2 for TTL 30-64.
    Uses integer arithmetic (QAT-compatible) for key computation,
    matching the arch_65_4_4_7 kernel which does integer inference.
    """
    fwd = b.get_table("fwd_table_t2")
    vk  = b.get_table("valid_keys_t2")
    if_idx = socket.if_nametoindex(INGRESS_IFACE)
    from common import OFFSET

    for ttl in range(30, 65):
        iv = [42, ttl, if_idx, 65]
        # Integer key matching kernel formula: (sum(iv*w) + OFFSET*scale) / scale
        output_raw = sum(
            v * ctypes.c_int8(int(w)).value
            for v, w in zip(iv, cp_weights)
        )
        key = (output_raw + OFFSET * scale_factor) // scale_factor
        fwd[ctypes.c_ulonglong(key)] = action
        vk[ctypes.c_uint8(ttl)]      = ctypes.c_ulonglong(key)

    print(f"[fwd_t2] fwd_table_t2 and valid_keys_t2 loaded for TTL 30-64 [integer/template]")


def run(model_id: int = 42):
    weights_path = "/shared/weights.json"
    float_path   = "/shared/weights_float.json"
    print(f"[Method 5 - Arch Template] | model_id: {model_id}")

    if not os.path.exists(float_path):
        print(f"[ERROR] {float_path} not found. Run extract_weights.py first.")
        sys.exit(1)

    with open(float_path) as f:
        float_data = json.load(f)

    SCALE_FACTOR = float_data["scale_factor"]
    cp_weights   = float_data["weights"][:4]   # first 4 weights for fwd key

    integer_weights = load_weights(weights_path)

    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Total weights : {len(integer_weights)} (expected {N_WEIGHTS_T2})")

    # Load the combined dispatcher + arch program
    # BCC compiles both functions from the concatenated source.
    combined_src = EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_65_4_4_7
    b = BPF(text=combined_src)

    # Populate arch_registry and arch_weights map
    load_arch_weights(b, integer_weights, model_id=model_id, scale=SCALE_FACTOR)

    # Register arch_65_4_4_7 function in the arch_progs tail-call map
    fn_arch = b.load_func("arch_65_4_4_7", BPF.XDP)
    arch_progs = b.get_table("arch_progs")
    arch_progs[ctypes.c_int(0)] = ctypes.c_int(fn_arch.fd)

    # Attach dispatcher as the XDP entry point
    fn_dispatcher = b.load_func("ipa_switch_template", BPF.XDP)

    # Populate forwarding tables
    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = _build_fwd_action_t2(b, egress_ifindex)
    _populate_fwd_t2(b, action, cp_weights, SCALE_FACTOR)

    attach_xdp(b, fn_dispatcher)

    print("[Method 5] Pipeline 2 (Arch Template) running. "
          "Stats: pkt_stats_t2 [HIT | FAKE | MISS]")

    # stats_loop reads pkt_stats by default; override for t2
    import time
    from common import detach_xdp
    stats = b.get_table("pkt_stats_t2")
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
