#!/usr/bin/env python3
"""
execute_pipeline.py
==================
IPA pipeline entry point for each Kathara node.

Flow:
    1. extract_weights.py  -> reads frr_germany50_5_model_4x2.pt
                           -> writes weights.json (int8 weights)
    2. switch_core.py      -> reads weights.json
                           -> loads the eBPF fwd_table
                           -> attaches the XDP program on eth1
                           -> runs the switch in a loop

Usage:
    python3 /shared/execute_pipeline.py

Quantization/design-space method:
    python3 /shared/execute_pipeline.py --method post       # default (Method 1 PTQ)
    python3 /shared/execute_pipeline.py --method qat        # Method 2 QAT
    python3 /shared/execute_pipeline.py --method openflow   # Method 3 OpenFlow
    python3 /shared/execute_pipeline.py --method ipa_demo   # Method 4 IPA Demo
    python3 /shared/execute_pipeline.py --method template   # Method 5 Arch Template (Pipeline 2)
    python3 /shared/execute_pipeline.py --method modular    # Method 6 Modular (Pipeline 3)
"""

import argparse
import os
import sys
import runpy

# ------------------------------------------------------------
# Ensure shared/ is on the import path for sub-scripts
# ------------------------------------------------------------
SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)
os.chdir(SHARED_DIR)  # all scripts use relative paths


def main():
    parser = argparse.ArgumentParser(description="Pipeline IPA: weights extraction + XDP switch")
    parser.add_argument(
        "--method",
        choices=["post", "qat", "openflow", "ipa_demo", "template", "modular"],
        default="post",
        help=(
            "Design-space method: "
            "'post' (default) = Method 1 PTQ, "
            "'qat' = Method 2 QAT, "
            "'openflow' = Method 3, "
            "'ipa_demo' = Method 4, "
            "'template' = Method 5 Arch Template (Pipeline 2), "
            "'modular' = Method 6 Modular Pipeline (Pipeline 3)"
        )
    )
    args = parser.parse_args()

    # ----------------------------------------------------------
    # Step 1: extract integer weights -> weights.json
    # (skip for template/modular: they call extract_weights_int8
    #  directly at runtime, but we still produce weights.json for
    #  consistency with the rest of the codebase)
    # ----------------------------------------------------------
    print("=" * 60)
    print(f"[pipeline] Step 1 — extracting weights (method={args.method})")
    print("=" * 60)

    if args.method == "qat":
        qat_model_path = os.path.join(SHARED_DIR, "frr_qat_model.pt")
        if not os.path.exists(qat_model_path):
            print(f"[WARNING] {qat_model_path} not found, using Method 1 model.")
        else:
            os.environ["FRR_MODEL_PATH"] = qat_model_path
            os.environ["FRR_MODEL_TYPE"] = "qat"

    # Always run extract_weights to produce weights.json
    runpy.run_path(os.path.join(SHARED_DIR, "extract_weights.py"), run_name="__main__")

    weights_path = os.path.join(SHARED_DIR, "weights.json")
    if not os.path.exists(weights_path):
        print("[ERROR] weights.json was not generated — exiting.")
        sys.exit(1)
    print(f"[pipeline] weights.json OK ({os.path.getsize(weights_path)} bytes)")

    # ----------------------------------------------------------
    # Step 2: start the XDP switch (blocking loop)
    # ----------------------------------------------------------
    print()
    print("=" * 60)
    print(f"[pipeline] Step 2 — starting XDP switch (method={args.method})")
    print("=" * 60)

    # Map --method to the switch_core.py flag
    method_flag_map = {
        "post":     "ptq",
        "qat":      "qat",
        "openflow": "openflow",
        "ipa_demo": "ipa_demo",
        "template": "template",
        "modular":  "modular",
    }
    switch_flag = method_flag_map[args.method]

    # Inject sys.argv for switch_core.py which reads sys.argv[1]
    sys.argv = ["switch_core.py", switch_flag]
    runpy.run_path(os.path.join(SHARED_DIR, "switch_core.py"), run_name="__main__")


if __name__ == "__main__":
    main()
