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
from ebpf_template_arch import load_class_action

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

    # Two different quantities, easy to conflate:
    #   per_model  -- weights each model reads out of integer_weights. Every
    #                 model reads the list from index 0 (base_offset indexes the
    #                 BPF map, not this list), so the file only has to satisfy
    #                 the LARGEST model, not their sum.
    #   map_slots  -- slots each model occupies in the shared layer_weights
    #                 block, at a running base_offset. That IS the sum, and it
    #                 is capped by MAX_LAYER_WEIGHT_ENTRIES.
    # Both used to be unchecked here: a short weights.json was loaded silently
    # and the map cap only surfaced as a ValueError after the eBPF program was
    # already compiled and loaded, leaving a half-registered map behind.
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
    # layer_chain[0] is always layer_first, [1..N-1] always layer_hidden. N is
    # LAYER_CHAIN_SIZE, the BPF_PROG_ARRAY size declared in ebpf_modular.py --
    # was a bare literal 16 here, which would silently stop filling the array
    # (or overrun it) the moment that declaration changed.
    for i in range(1, LAYER_CHAIN_SIZE):
        chain[ctypes.c_int(i)] = ctypes.c_int(fn_hidden.fd)

    fn_disp = b.load_func("modular_dispatcher", BPF.XDP)

    # class -> action -> logical port comes from the MODEL descriptor; logical
    # port -> ifindex/MAC from the NODE. Neither is derived from the other, and
    # neither assumes DROP is the last class or that class k lives on eth{k}.
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
    # The mirror of install_mac_per_port: that one answers "the model chose
    # class k, which interface do I send out of"; this one answers "the packet
    # arrived on interface X, which of my ports is that" -- the question the
    # trained ingress_iface one-hot asks. Without it the map stays empty, every
    # lookup misses, and that feature contributes nothing to any decision --
    # silently, with the suite still green because nothing checked it did.
    install_ingress_port_table(b, "ingress_port_t3", node_cfg,
                               semantics.logical_ports)
    install_node_id(b, "node_id_t3", node_cfg,
                    n_nodes=load_topology_config().get("n_nodes"))
    load_class_action(b, "class_action_t3", semantics)
    if mac_info["pending"]:
        start_mac_refresh_thread(b, "mac_table_t3", mac_info["pending"], interval=5.0)

    init_link_state_up(b)
    stop_monitor = start_monitor_thread(b, interval=0.5)
    print("[Method 6] link_state seeded (present interfaces up, absent slots 0); carrier monitor running")

    # attach_xdp raises on failure now, so reaching the serve loop means the
    # program really is on the wire. Everything past the attach runs under
    # try/finally: ANY exit path (Ctrl-C, a map read blowing up, an unexpected
    # error) must still stop the carrier monitor and take the program off the
    # interface. Previously only KeyboardInterrupt detached, so any other
    # exception left a live XDP program on the node with no way to notice.
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
                hits   = stats[stats.Key(0)].value
                misses = stats[stats.Key(1)].value
                drops  = stats[stats.Key(2)].value
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
