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
# Inside Kathara: this file lives at /shared/methods/method5_template.py
# Outside Kathara: path is resolved the same way via __file__.
_SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _populate_mac_t2(b: BPF, egress_iface: str, egress_ifindex: int):
    """Install mac_table_t2: egress class (0..5, the argmax output) ->
    {ifindex, src_mac, dst_mac}. The NN decides the port; this map only
    resolves the L2 next-hop. No key computation, no per-TTL validation.
    src_mac/dst_mac are resolved from the kernel (own iface MAC + ARP table
    for the neighbor), not hardcoded constants. In this lab all classes
    point to the same egress iface (single next-hop); a real deployment
    would map each class to its own neighbour + MACs."""
    src_mac, dst_mac = resolve_egress_mac(egress_iface)
    mac    = b.get_table("mac_table_t2")
    action = mac.Leaf()
    action.ifindex = egress_ifindex
    for i in range(6):
        action.src_mac[i] = src_mac[i]
        action.dst_mac[i] = dst_mac[i]
    for cls in range(6):
        mac[ctypes.c_uint32(cls)] = action
    print(f"[mac_t2] mac_table_t2 loaded: class 0..5 -> ifindex={egress_ifindex} "
          f"src={':'.join(f'{b:02x}' for b in src_mac)} dst={':'.join(f'{b:02x}' for b in dst_mac)}")


def run(model_id: int = 42, iface: str = None, model_ids: list = None,
        hidden_dims: list = None):
    """
    iface: network interface to attach XDP to.
           Defaults to INGRESS_IFACE from common.py if not specified.
           Pass the correct interface for the lab topology (e.g. 'eth0' for
           darmstadt->frankfurt direct link l59 in lab.conf).
    model_ids: optional list of model_id's to register concurrently, all
           sharing the arch_generic_2layer program (same 2-hidden-layer
           topology, hidden widths may differ per model -- see hidden_dims).
           Each gets its own, non-overlapping slice of the arch_weights map,
           so the dispatcher can serve several models in the same run without
           a reload -- the flexibility hardcoded Pipeline 1 cannot offer.
           Defaults to [model_id] (single-model, backward compatible).
    hidden_dims: optional list of (n_h1, n_h2) tuples, one per entry in
           model_ids/ids, for models whose hidden widths differ from the
           checked-in weights.json (65-4-4-7). Must fit under T2_MAX_H1/
           T2_MAX_H2 (ebpf_template_arch.py) -- load_arch_weights() raises
           a clear error otherwise instead of silently corrupting the map.
           Defaults to (4, 4) for every model, matching weights.json.
           NOTE: today only one trained model (65-4-4-7) is checked into the
           repo, so this only demonstrates the registry/dispatch mechanism
           with repeated weights -- wire a real per-model weights source
           (distinct weights.json per model_id) to exercise it for real.
    """
    ingress_iface = iface if iface else INGRESS_IFACE
    # No fallback here: silently attaching XDP to a DIFFERENT interface than
    # requested would be worse than a loud, actionable error (see
    # resolve_ifindex() docstring in common.py).
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
    cp_weights   = float_data["weights"][:4]   # first 4 weights for fwd key

    integer_weights = load_weights(weights_path)

    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Total weights : {len(integer_weights)} (expected {N_WEIGHTS_T2})")
    print(f"  Ingress iface : {ingress_iface} (ifindex={socket.if_nametoindex(ingress_iface)})")

    # Load the combined dispatcher + arch program
    # BCC compiles both functions from the concatenated source.
    # EBPF_ARCH_GENERIC_2LAYER re-declares the shared structs/maps behind
    # #ifndef IPA_ARCH_COMBINED; define it so the concatenation compiles once
    # (without it BCC errors "redefinition of 'ipa_hdr'" etc.).
    combined_src = ("#define IPA_ARCH_COMBINED 1\n"
                    + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_GENERIC_2LAYER)
    b = BPF(text=combined_src)

    # Populate arch_registry, arch_weights and model_desc: one non-overlapping
    # weight block per model_id, sized to that model's own hidden widths, all
    # pointing at the same generic arch program. load_arch_weights also seeds
    # model_desc (default 65-feature descriptor) so the leaf builds its IV
    # generically.
    weight_offset = 0
    for mid, (n_h1, n_h2) in zip(ids, dims):
        load_arch_weights(b, integer_weights, model_id=mid, scale=SCALE_FACTOR,
                          weight_offset=weight_offset, n_h1=n_h1, n_h2=n_h2)
        weight_offset += arch_weight_count(n_h1, n_h2)

    # Register arch_generic_2layer function in the arch_progs tail-call map
    fn_arch = b.load_func("arch_generic_2layer", BPF.XDP)
    arch_progs = b.get_table("arch_progs")
    arch_progs[ctypes.c_int(0)] = ctypes.c_int(fn_arch.fd)

    # Attach dispatcher as the XDP entry point
    fn_dispatcher = b.load_func("ipa_switch_template", BPF.XDP)

    # Populate the L2 next-hop dictionary (class -> ifindex + MACs).
    # fallback="eth0": if EGRESS_IFACE doesn't exist on this node (e.g. a
    # topology with fewer real links), any working interface is an
    # acceptable substitute for a mac_table entry -- unlike ingress, this
    # doesn't change where packets are intercepted, just where they'd be
    # redirected on a class that may not even fire in this run.
    egress_iface_resolved, egress_ifindex = resolve_ifindex(EGRESS_IFACE, fallback="eth0")
    _populate_mac_t2(b, egress_iface_resolved, egress_ifindex)

    # Seed link_state (egress up/down feature [0..5]) and start carrier monitor.
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
