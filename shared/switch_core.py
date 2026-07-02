#!/usr/bin/env python3
"""
IPA Switch - Entry Point

Utilizzo:
  Metodo 1 (PTQ):           python3 switch_core.py
  Metodo 2 (QAT):           python3 switch_core.py weights_method2.json
  Metodo 3 (OpenFlow-like): python3 switch_core.py weights.json openflow
"""
import sys
from common import load_bpf, load_weights, populate_model_cache, attach_xdp, stats_loop

WEIGHTS_FILE = sys.argv[1] if len(sys.argv) > 1 else "weights.json"
METHOD_FLAG  = sys.argv[2] if len(sys.argv) > 2 else ""

if METHOD_FLAG == "openflow":
    from methods.method3_openflow import run
elif WEIGHTS_FILE == "weights.json":
    from methods.method1_ptq import run
else:
    from methods.method2_qat import run

run(WEIGHTS_FILE)
