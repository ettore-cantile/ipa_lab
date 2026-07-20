#!/usr/bin/env python3
"""
method4_hardcoded.py — Pipeline 1: Hardcoded Model loader (BCC path).

Loads a PyTorch checkpoint, generates a weights-literal eBPF XDP program,
compiles it with BCC (clang at runtime), and attaches it to an interface.

Topology dimensions (n_interfaces, n_nodes, n_queues) are read from
topology_config.json — a file that describes the NETWORK TOPOLOGY shared
by all nodes in the same deployment, not a per-node property. If the file
does not exist the code falls back to DEFAULT_TOPOLOGY_CONFIG (historical
6/52 defaults).

Usage:
    sudo python3 shared/methods/method4_hardcoded.py --iface eth0
    sudo python3 shared/methods/method4_hardcoded.py \\
        --model shared/frr_germany50_5_model_4x2.pt \\
        --topology-config /etc/ipa/topology_config.json
    sudo python3 shared/methods/method4_hardcoded.py --verify-only \\
        --model shared/frr_germany50_5_model_4x2.pt
"""

import os
import sys
import argparse

SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

_DEFAULT_TOPOLOGY_CONFIG_PATH = "/etc/ipa/topology_config.json"

from model_meta import (
    load_model_meta,
    load_topology_config,
    derive_shape,
    verify_shape_vs_checkpoint,
)


def _build_parser():
    ap = argparse.ArgumentParser(
        description="Pipeline 1 — Hardcoded Model (BCC literal path)"
    )
    ap.add_argument("--model", default="shared/frr_germany50_5_model_4x2.pt",
                    help="Path to the .pt checkpoint")
    ap.add_argument(
        "--topology-config",
        default=_DEFAULT_TOPOLOGY_CONFIG_PATH,
        dest="topology_config",
        help=(
            f"Path to topology_config.json (default: {_DEFAULT_TOPOLOGY_CONFIG_PATH}). "
            "Provides authoritative n_interfaces / n_nodes / n_queues for the "
            "network topology. Falls back to built-in defaults if absent."
        ),
    )
    ap.add_argument("--iface", default="eth0", help="Interface to attach XDP to")
    ap.add_argument("--verify-only", action="store_true",
                    help="Derive shape, verify checkpoint, generate C source, "
                         "run the BPF verifier — but do NOT attach to any interface")
    ap.add_argument("--model-id", type=int, default=0)
    return ap


def run(args=None):
    ap = _build_parser()
    args = ap.parse_args(args)

    model_path = args.model

    # ------------------------------------------------------------------
    # Step 1: load topology_config (authoritative network dimensions) and
    # model_meta (per-model feature descriptor), then derive the shape.
    # topology_config is the authoritative source for n_interfaces /
    # n_nodes / n_queues; any such keys in model_meta.json are ignored.
    # ------------------------------------------------------------------
    topo_cfg = load_topology_config(args.topology_config)
    meta     = load_model_meta(model_path)
    shape    = derive_shape(meta, topology_config=topo_cfg)

    # ------------------------------------------------------------------
    # Step 2: verify that the checkpoint was trained with the same N_IN
    # that topology_config + feature types produce. Raises a clear
    # ValueError if they differ, before any C is generated.
    # ------------------------------------------------------------------
    verify_shape_vs_checkpoint(shape, model_path)

    # ------------------------------------------------------------------
    # Step 3: generate the eBPF C source, compile, attach (or just verify).
    # ------------------------------------------------------------------
    from ebpf_program import load_and_generate

    # ifindex_table maps each kernel ingress ifindex -> logical port for the
    # ingress_iface one-hot. Size it to that feature (0 if the model doesn't
    # use it); the default [2, 2+size) convention matches ebpf_program's
    # generator and the kernel tests (verify_prog_run). None -> generator
    # applies the same default.
    iface_size = next(
        (f["size"] for f in shape["features"] if f["type"] == "ingress_iface"), 0)
    ifindex_table = list(range(2, 2 + max(iface_size, 1)))

    ebpf_src, weights_int8, scale = load_and_generate(
        model_path=model_path,
        model_id=args.model_id,
        ifindex_table=ifindex_table,
        meta=meta,
        topology_config=topo_cfg,
    )

    if args.verify_only:
        _verify_only(shape, ebpf_src, weights_int8, scale, ifindex_table)
        return

    _attach(ebpf_src, args.iface, shape, model_id=args.model_id)


def _verify_only(shape, ebpf_src, weights_int8, scale, ifindex_table):
    """Run the BPF verifier without attaching to any interface."""
    from bcc import BPF
    print(f"[verify-only] shape={shape}")
    print(f"[verify-only] ifindex_table={ifindex_table}")
    print(f"DIM INPUT: {shape['n_in']}")
    print(f"[verify-only] scale={scale}, weights={len(weights_int8)}, "
          f"source_chars={len(ebpf_src)}")
    b = BPF(text=ebpf_src)
    dispatcher_fn = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    model_fn      = b.load_func("model_0", BPF.XDP)
    print(f"[verify-only] Verifier PASSED — dispatcher fd={dispatcher_fn.fd}, "
          f"model_0 fd={model_fn.fd}")


def _attach(ebpf_src, iface, shape, model_id=0):
    """Compile, wire the tail-call (dispatcher -> model_progs[model_id] ->
    model_<id>), seed link_state + mac_table, attach to *iface* and show live
    pkt_stats (HIT|MISS|DROP) -- same live behaviour as the template/modular
    pipelines. Without wiring model_progs + seeding the maps the dispatcher's
    tail call falls through to XDP_PASS and never infers/forwards."""
    from bcc import BPF
    import ctypes, time
    from common import (
        attach_xdp, resolve_ifindex, install_mac_per_class,
        start_mac_refresh_thread, neighbor_mac, DST_MAC,
    )

    iface, _ = resolve_ifindex(iface)
    print(f"[method4] Compiling hardcoded program, shape="
          f"{shape['n_in']}-{'-'.join(map(str, shape['hidden_dims']))}-{shape['n_out']}")
    b = BPF(text=ebpf_src)

    # Wire the tail-call: dispatcher -> model_progs[model_id] -> model_<id>.
    model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
    disp_fn  = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ctypes.c_int(model_id)] = ctypes.c_int(model_fn.fd)

    # Seed link_state (all egress links up) + start the carrier monitor.
    try:
        from link_state_monitor import init_link_state_up, start_monitor_thread
        init_link_state_up(b)
        start_monitor_thread(b, interval=1.0)
        print("[method4] link_state seeded (all up); carrier monitor running")
    except Exception as e:
        print(f"[method4] link_state seed skipped ({e})")

    # Populate mac_table: DISTINCT egress port per class (class i -> eth<i>,
    # ARP-resolved). n_out-1 forward classes, last class = DROP.
    n_fwd = shape["n_out"] - 1
    installed = install_mac_per_class(b, "mac_table", n_fwd=n_fwd)

    # Start background MAC refresh thread for any iface that got a fallback
    # MAC at startup (ARP not yet resolved). The thread re-reads /proc/net/arp
    # every 5 s and updates the BPF map entry as soon as the real MAC appears,
    # without requiring manual ARP warmup (ping) before launching the pipeline.
    fallback_ifaces = [
        (cls, f"eth{cls}")
        for cls in range(n_fwd)
        if neighbor_mac(f"eth{cls}") in (None, DST_MAC)
    ]
    if fallback_ifaces:
        start_mac_refresh_thread(b, "mac_table", fallback_ifaces, interval=5.0)
        print(f"[method4] MAC refresh thread started for: "
              f"{[ifc for _, ifc in fallback_ifaces]}")

    attach_xdp(b, disp_fn, iface=iface)
    print(f"[method4] Pipeline 1 (hardcoded) running on {iface}. "
          f"Stats: pkt_stats [HIT | MISS | DROP]. Ctrl-C to detach.")

    stats = b["pkt_stats"]
    print(f"\n{'HIT':<16}{'MISS':<16}{'DROP':<16}")
    print("-" * 48)
    try:
        while True:
            time.sleep(1)
            hit  = stats[stats.Key(0)].value
            miss = stats[stats.Key(1)].value
            drop = stats[stats.Key(2)].value
            print(f"\r{hit:<16}{miss:<16}{drop:<16}", end="", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            b.remove_xdp(iface, 0)
        except Exception:
            pass
        print(f"\n[method4] XDP program detached from {iface}.")


if __name__ == "__main__":
    run()
