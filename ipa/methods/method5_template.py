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

Files used (paths resolved relative to this file, not hardcoded absolute paths):
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
from ebpf_template_arch import (
    EBPF_TEMPLATE_ARCH_DISPATCHER,
    EBPF_ARCH_GENERIC_2LAYER,
    load_arch_weights,
    arch_weight_count,
    MAX_WEIGHT_ENTRIES,
    N_WEIGHTS_T2,
)
from common import (
    load_weights, attach_xdp, detach_xdp, install_node_id, INGRESS_IFACE, resolve_ifindex,
    install_mac_per_port, start_mac_refresh_thread,
)
from link_state_monitor import init_link_state_up, start_monitor_thread
from model_meta import (derive_shape, load_model_meta, load_topology_config,
                        load_class_semantics)
from node_config import NodeConfig
from ebpf_template_arch import load_class_action

# Resolve the shared/ directory relative to this file regardless of cwd.
_SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(model_id: int = 42, iface: str = None, model_ids: list = None,
        hidden_dims: list = None, xdp_mode: str = None):
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

    integer_weights = load_weights(weights_path)

    # Validate instead of only printing the expectation: a short weights.json
    # used to be loaded silently, registering a model whose weight block is
    # partly whatever the previous model left in arch_weights.
    # Every model reads integer_weights from index 0 (weight_offset indexes the
    # BPF map, not this list), so the file only has to satisfy the LARGEST
    # registered model, not their sum.
    per_model = [arch_weight_count(h1, h2) for h1, h2 in dims]
    if len(integer_weights) < max(per_model):
        print(f"[ERROR] {weights_path} holds {len(integer_weights)} weights, "
              f"the largest requested model needs {max(per_model)}. "
              f"Regenerate it with extract_weights.py.")
        sys.exit(1)

    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Total weights : {len(integer_weights)} (expected {N_WEIGHTS_T2})")
    print(f"  Ingress iface : {ingress_iface} (ifindex={socket.if_nametoindex(ingress_iface)})")

    # arch_weights is a single fixed block shared by every registered model, so
    # the number of concurrent model_id's is capped by MAX_WEIGHT_ENTRIES. Check
    # it up front: load_arch_weights would otherwise raise only after the eBPF
    # program is compiled and loaded, leaving a half-registered map behind.
    needed = sum(per_model)
    if needed > MAX_WEIGHT_ENTRIES:
        print(f"[ERROR] {len(ids)} models need {needed} weight slots but "
              f"arch_weights holds only MAX_WEIGHT_ENTRIES={MAX_WEIGHT_ENTRIES}. "
              f"At {N_WEIGHTS_T2} weights per 65-4-4-7 model that is "
              f"{MAX_WEIGHT_ENTRIES // N_WEIGHTS_T2} concurrent models max.")
        sys.exit(1)

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

    # class -> action -> logical port comes from the MODEL descriptor; logical
    # port -> ifindex/MAC from the NODE. Neither is derived from the other, and
    # neither assumes DROP is the last class or that class k lives on eth{k}.
    _shape = derive_shape(load_model_meta(weights_path),
                          topology_config=load_topology_config())
    semantics = load_class_semantics(weights_path, _shape["n_out"])
    print("[Method 5] class semantics:")
    print(semantics.summary())
    node_cfg = NodeConfig.resolve(semantics.logical_ports)
    print(node_cfg.summary())
    for _p in node_cfg.validate(semantics.logical_ports, strict=False):
        print(f"[Method 5] NOTE: {_p}")
    mac_info = install_mac_per_port(b, "mac_table_t2", node_cfg,
                                    semantics.logical_ports)
    install_node_id(b, "node_id_t2", node_cfg,
                    n_nodes=load_topology_config().get("n_nodes"))
    load_class_action(b, "class_action_t2", semantics)
    if mac_info["pending"]:
        start_mac_refresh_thread(b, "mac_table_t2", mac_info["pending"], interval=5.0)

    init_link_state_up(b)
    stop_monitor = start_monitor_thread(b, interval=0.5)
    print("[Method 5] link_state seeded (present interfaces up, absent slots 0); carrier monitor running")

    # attach_xdp raises on failure now, so reaching the serve loop means the
    # program really is on the wire. Everything past the attach runs under
    # try/finally: ANY exit path (Ctrl-C, a map read blowing up, an unexpected
    # error) must still stop the carrier monitor and take the program off the
    # interface. Previously only KeyboardInterrupt detached, so any other
    # exception left a live XDP program on the node with no way to notice.
    try:
        attach_xdp(b, fn_dispatcher, iface=ingress_iface, mode=xdp_mode)
    except Exception:
        stop_monitor.set()
        raise

    try:
        print("[Method 5] Pipeline 2 (Arch Template) running. "
              "Stats: pkt_stats_t2 [HIT | MISS | DROP]")
        stats = b.get_table("pkt_stats_t2")
        print(f"\n{'TRUE HIT':<22} | {'MISS':<22} | {'DROP':<20}")
        print("-" * 70)
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
        pass
    finally:
        stop_monitor.set()
        detach_xdp(b, iface=ingress_iface, mode=xdp_mode)
        print("\n\nXDP removed. Exiting.")
