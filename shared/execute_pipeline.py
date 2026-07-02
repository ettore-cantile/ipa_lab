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

Optionally pass the quantization method:
    python3 /shared/execute_pipeline.py --method post   # default (Method 1)
    python3 /shared/execute_pipeline.py --method qat    # Method 2 (QAT)
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
        choices=["post", "qat"],
        default="post",
        help="Quantization method: 'post' (default) = Method 1, 'qat' = Method 2"
    )
    args = parser.parse_args()

    # ----------------------------------------------------------
    # Step 1: extract integer weights -> weights.json
    # ----------------------------------------------------------
    print("=" * 60)
    print(f"[pipeline] Step 1 — extracting weights (method={args.method})")
    print("=" * 60)

    if args.method == "qat":
        # Method 2: load the QAT model if it exists, otherwise fallback
        qat_model_path = os.path.join(SHARED_DIR, "frr_qat_model.pt")
        if not os.path.exists(qat_model_path):
            print(f"[WARNING] {qat_model_path} not found, using Method 1 model.")
        else:
            # Redefine the environment variable read by extract_weights.py
            os.environ["FRR_MODEL_PATH"] = qat_model_path
            os.environ["FRR_MODEL_TYPE"] = "qat"

    # Execute extract_weights.py in the same process
    runpy.run_path(os.path.join(SHARED_DIR, "extract_weights.py"), run_name="__main__")

    # Verify that weights.json was produced
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
    print("[pipeline] Step 2 — starting XDP switch (switch_core.py)")
    print("=" * 60)
    runpy.run_path(os.path.join(SHARED_DIR, "switch_core.py"), run_name="__main__")


if __name__ == "__main__":
    main()
