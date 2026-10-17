#!/usr/bin/env python3
"""method6_modular.py -- deploy of Pipeline 3 (modular) on an interface.
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
    LAYER_CHAIN_SIZE,
    MAX_LAYER_WEIGHT_ENTRIES,
    load_modular_weights,
)
from common import (
    load_weights, attach_xdp, detach_xdp, install_node_id, INGRESS_IFACE, resolve_ifindex,
    install_mac_per_port, install_ingress_port_table,
    start_mac_refresh_thread,
)
from link_state_monitor import init_link_state_up, start_monitor_thread
from model_meta import (derive_shape, load_model_meta, load_topology_config,
                        load_class_semantics)
from node_config import NodeConfig

_SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(model_id: int = 42, iface: str = None, model_ids: list = None,
        layer_dims_by_model: list = None, xdp_mode: str = None):
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

    integer_weights = load_weights(weights_path)

    per_model = [sum(n_in * n_out + n_out for n_in, n_out in layer_dims)
                 for layer_dims in dims_by_model]
    if len(integer_weights) < max(per_model):
        print(f"[ERROR] {weights_path} holds {len(integer_weights)} weights, "
              f"the largest requested model needs {max(per_model)}. "
              f"Regenerate it with extract_weights.py.")
        sys.exit(1)
    map_slots = sum(per_model)
    if map_slots > MAX_LAYER_WEIGHT_ENTRIES:
        print(f"[ERROR] {len(ids)} models need {map_slots} weight slots but "
              f"layer_weights holds only "
              f"MAX_LAYER_WEIGHT_ENTRIES={MAX_LAYER_WEIGHT_ENTRIES}.")
        sys.exit(1)

    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Total weights : {len(integer_weights)} "
          f"(largest model needs {max(per_model)}, "
          f"{map_slots}/{MAX_LAYER_WEIGHT_ENTRIES} map slots used)")
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
    for i in range(1, LAYER_CHAIN_SIZE):
        chain[ctypes.c_int(i)] = ctypes.c_int(fn_hidden.fd)

    fn_disp = b.load_func("modular_dispatcher", BPF.XDP)

    _shape = derive_shape(load_model_meta(weights_path),
                          topology_config=load_topology_config())
    semantics = load_class_semantics(weights_path, _shape["n_out"])
    print("[Method 6] class semantics:")
    print(semantics.summary())
    node_cfg = NodeConfig.resolve(semantics.logical_ports)
    print(node_cfg.summary())
    for _p in node_cfg.validate(semantics.logical_ports, strict=False):
        print(f"[Method 6] NOTE: {_p}")
    mac_info = install_mac_per_port(b, "mac_table_t3", node_cfg,
                                    semantics.logical_ports)
    install_ingress_port_table(b, "ingress_port_t3", node_cfg,
                               semantics.logical_ports)
    install_node_id(b, "node_id_t3", node_cfg,
                    n_nodes=load_topology_config().get("n_nodes"))
    if mac_info["pending"]:
        start_mac_refresh_thread(b, "mac_table_t3", mac_info["pending"], interval=5.0)

    init_link_state_up(b)
    stop_monitor = start_monitor_thread(b, interval=0.5)
    print("[Method 6] link_state seeded (present interfaces up, absent slots 0); carrier monitor running")

    try:
        attach_xdp(b, fn_disp, iface=ingress_iface, mode=xdp_mode)
    except Exception:
        stop_monitor.set()
        raise

    try:
        print("[Method 6] Pipeline 3 (Modular) running. "
              "Stats: pkt_stats_t3 [HIT | MISS | DROP]")
        print("  Tail call chain: modular_dispatcher -> layer_first -> layer_hidden "
              "(x n_layers-1 per model, per-model depth read from layer_registry)")

        stats = b.get_table("pkt_stats_t3")
        print(f"\n{'TRUE HIT':>12} {'MISS':>10} {'DROP':>10}")
        print("-" * 34)
        while True:
            time.sleep(1)
            try:
                from stats_maps import read_counter
                hits, misses, drops = (read_counter(stats, i) for i in range(3))
                print(f"\r{hits:>12} {misses:>10} {drops:>10}",
                      end="", flush=True)
            except Exception:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        stop_monitor.set()
        detach_xdp(b, iface=ingress_iface, mode=xdp_mode)
        print("\n\nXDP removed. Exiting.")
