#!/usr/bin/env python3
"""
method4_hardcoded.py — Pipeline 1: Hardcoded Model, BCC compile-and-verify path.

Loads a PyTorch checkpoint, generates a weights-literal eBPF XDP program and
compiles it with BCC (clang at runtime) to run the in-kernel verifier on it.
It does NOT attach to an interface: live deploy of the hardcoded pipeline is
done exclusively via the AOT-literal loader (method4_hardcoded_aot.py), which
replaced BCC as the sole datapath backend. BCC remains here — and in the test
suite — only to compile-and-verify the generated C offline.

Topology dimensions (n_interfaces, n_nodes, n_queues) are read from
topology_config.json — a file that describes the NETWORK TOPOLOGY shared
by all nodes in the same deployment, not a per-node property. If the file
does not exist the code falls back to DEFAULT_TOPOLOGY_CONFIG (historical
6/52 defaults).

Usage:
    sudo python3 shared/methods/method4_hardcoded.py --verify-only \\
        --model shared/frr_germany50_5_model_4x2.pt \\
        --topology-config /etc/ipa/topology_config.json
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
    ap.add_argument("--iface", default="eth0",
                    help="Accepted for CLI compatibility; unused (this path never "
                         "attaches — live deploy is AOT via method4_hardcoded_aot.py)")
    ap.add_argument("--verify-only", action="store_true",
                    help="Kept for backward compatibility; this path is always "
                         "verify-only now (generate C + run the BPF verifier, no attach)")
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

    # This module is now the BCC *compile-and-verify* path only. Live deploy of
    # the hardcoded pipeline is done exclusively via AOT-literal
    # (method4_hardcoded_aot.py), so BCC no longer attaches to an interface;
    # the old BCC live-attach was removed once AOT replaced it as the sole
    # datapath backend. BCC stays here (and in the test suite) purely to
    # compile the generated C and run the in-kernel verifier offline.
    if not args.verify_only:
        print("[method4] NOTE: hardcoded live deploy is AOT-only "
              "(method4_hardcoded_aot.py / execute_pipeline.py --method hardcoded). "
              "Running the BCC verifier check instead of attaching.")
    _verify_only(shape, ebpf_src, weights_int8, scale, ifindex_table)


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


if __name__ == "__main__":
    run()
