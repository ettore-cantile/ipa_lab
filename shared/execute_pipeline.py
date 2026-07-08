#!/usr/bin/env python3
"""
execute_pipeline.py  (design-space-docs branch)
================================================
Entry point for the two new design-space pipelines.

Flow:
    1. Loads the .pt model and extracts int8 weights
    2. Starts the chosen XDP pipeline in a blocking loop

Usage:
    python3 /shared/execute_pipeline.py --method template   # Pipeline 2 (default)
    python3 /shared/execute_pipeline.py --method modular    # Pipeline 3

Methods 1-4 live in the main branch.
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
        description="IPA design-space pipelines: template (P2) or modular (P3)"
    )
    parser.add_argument(
        "--method",
        choices=["template", "modular"],
        default="template",
        help="'template' = Pipeline 2 (arch template), 'modular' = Pipeline 3 (modular layers)"
    )
    args = parser.parse_args()

    # Step 1: extract weights -> weights.json + weights_float.json
    print("=" * 60)
    print(f"[pipeline] Step 1 — extracting weights")
    print("=" * 60)
    runpy.run_path(os.path.join(SHARED_DIR, "extract_weights.py"), run_name="__main__")

    weights_path = os.path.join(SHARED_DIR, "weights.json")
    if not os.path.exists(weights_path):
        print("[ERROR] weights.json not generated — exiting.")
        sys.exit(1)
    print(f"[pipeline] weights.json OK ({os.path.getsize(weights_path)} bytes)")

    # Step 2: start the XDP switch
    print()
    print("=" * 60)
    print(f"[pipeline] Step 2 — starting XDP switch (method={args.method})")
    print("=" * 60)
    sys.argv = ["switch_core.py", args.method]
    runpy.run_path(os.path.join(SHARED_DIR, "switch_core.py"), run_name="__main__")


if __name__ == "__main__":
    main()
