#!/usr/bin/env python3
"""
switch_core.py  —  IPA Switch entry point (design-space-docs branch)

Supports all three design-space pipelines:

  python3 switch_core.py hardcoded [model_id]   # Pipeline 1
  python3 switch_core.py template  [model_id]   # Pipeline 2
  python3 switch_core.py modular   [model_id]   # Pipeline 3

Preferred entry point: execute_pipeline.py (handles weight extraction too).
Methods 1-4 originali (PTQ, QAT, OpenFlow, IPA Demo) sono nel main branch.
"""
import sys
import os

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

METHOD_FLAG = sys.argv[1] if len(sys.argv) > 1 else "hardcoded"
MODEL_ID    = int(sys.argv[2]) if len(sys.argv) > 2 else 0

if METHOD_FLAG == "hardcoded":
    from methods.method4_hardcoded import run
elif METHOD_FLAG == "modular":
    from methods.method6_modular import run
else:  # template (default)
    from methods.method5_template import run

run(MODEL_ID)
