#!/usr/bin/env python3
"""
execute_pipeline.py  —  Design-space pipeline launcher
=======================================================
Entry point unificato per tutte e tre le pipeline del design space:

  --method hardcoded   Pipeline 1: Hardcoded model
                       (pesi come letterali C, inferenza unrolled,
                        1 tail call, 0 weight map lookup)

  --method template    Pipeline 2: Pre-built architectural template
                       (BPF_ARRAY per i pesi, 1 tail call,
                        update modello = bpf_map_update_elem)

  --method modular     Pipeline 3: Modular neural pipeline
                       (BPF_PERCPU_ARRAY scratch, N tail calls,
                        massima flessibilità runtime)

Usage:
    sudo python3 shared/execute_pipeline.py --method hardcoded [--iface eth0] [--model-id 0]
    sudo python3 shared/execute_pipeline.py --method template  [--iface eth0] [--model-id 0]
    sudo python3 shared/execute_pipeline.py --method modular   [--iface eth0] [--model-id 0]

Note:
    - Richiede root (XDP attach)
    - Il modello .pt deve essere in shared/frr_germany50_5_model_4x2.pt
    - Methods 1-4 originali (PTQ, QAT, OpenFlow, IPA Demo) sono nel main branch
"""

import argparse
import os
import sys
import runpy

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)
os.chdir(SHARED_DIR)


def main():
    parser = argparse.ArgumentParser(
        description="IPA/eBPF design-space pipeline launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Pipeline trade-off summary:
  hardcoded : massime prestazioni  | minima flessibilità   | 0 weight lookup
  template  : prestazioni medie    | flessibilità media    | BPF_ARRAY lookup
  modular   : prestazioni inferiori| massima flessibilità  | PERCPU_ARRAY + N tail calls

Per il benchmark comparativo completo:
  sudo python3 shared/pipeline_benchmark.py --pipeline all --iface eth0
        """
    )
    parser.add_argument(
        "--method",
        choices=["hardcoded", "template", "modular"],
        default="hardcoded",
        help="Pipeline to run (default: hardcoded)"
    )
    parser.add_argument(
        "--iface",
        default="eth0",
        help="Network interface for XDP attach (default: eth0)"
    )
    parser.add_argument(
        "--model-id",
        type=int,
        default=0,
        help="Model ID to register (default: 0)"
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Path to .pt checkpoint (default: shared/frr_germany50_5_model_4x2.pt)"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Load and verify eBPF program without attaching XDP (safe for testing)"
    )
    args = parser.parse_args()

    model_path = args.model or os.path.join(
        SHARED_DIR, "frr_germany50_5_model_4x2.pt"
    )
    if not os.path.exists(model_path):
        print(f"[ERROR] Model not found: {model_path}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Step 1: extract weights (produces weights.json + weights_float.json)
    # ------------------------------------------------------------------
    print("=" * 60)
    print(f"[pipeline] method={args.method}  iface={args.iface}  model_id={args.model_id}")
    print(f"[pipeline] Step 1 — extracting weights from {model_path}")
    print("=" * 60)
    runpy.run_path(
        os.path.join(SHARED_DIR, "extract_weights.py"),
        run_name="__main__"
    )
    weights_path = os.path.join(SHARED_DIR, "weights.json")
    if not os.path.exists(weights_path):
        print("[ERROR] weights.json not generated — exiting.")
        sys.exit(1)
    print(f"[pipeline] weights.json OK ({os.path.getsize(weights_path)} bytes)")

    # ------------------------------------------------------------------
    # Step 2: launch the chosen pipeline
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    print(f"[pipeline] Step 2 — launching Pipeline {'1' if args.method == 'hardcoded' else '2' if args.method == 'template' else '3'} ({args.method})")
    print("=" * 60)

    if args.method == "hardcoded":
        # Pipeline 1 — pesi hardcoded nel sorgente C, inferenza unrolled
        from methods.method4_hardcoded import run
        if args.verify_only:
            sys.argv = ["method4_hardcoded.py", "--verify-only",
                        "--iface", args.iface,
                        "--model-id", str(args.model_id)]
            if args.model:
                sys.argv += ["--model", args.model]
            runpy.run_path(
                os.path.join(SHARED_DIR, "methods", "method4_hardcoded.py"),
                run_name="__main__"
            )
        else:
            run(model_id=args.model_id, iface=args.iface, model_path=model_path)

    elif args.method == "template":
        # Pipeline 2 — architectural template, pesi in BPF_ARRAY
        from methods.method5_template import run
        run(args.model_id)

    else:
        # Pipeline 3 — modular layers, scratch map, N tail calls
        from methods.method6_modular import run
        run(args.model_id)


if __name__ == "__main__":
    main()
