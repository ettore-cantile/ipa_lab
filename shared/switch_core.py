#!/usr/bin/env python3
"""
IPA Switch - Entry Point

Usage:
  Method 1 (PTQ):           python3 switch_core.py
  Method 2 (QAT):           python3 switch_core.py weights_method2.json
  Method 3 (OpenFlow-like): python3 switch_core.py weights.json openflow
  Method 4 (IPA Demo):      python3 switch_core.py weights_method2.json ipa_demo
"""
import sys

WEIGHTS_FILE = sys.argv[1] if len(sys.argv) > 1 else "weights.json"
METHOD_FLAG  = sys.argv[2] if len(sys.argv) > 2 else ""

if METHOD_FLAG == "openflow":
    from methods.method3_openflow import run
elif METHOD_FLAG == "ipa_demo":
    from methods.method4_ipa_demo import run
elif WEIGHTS_FILE == "weights.json":
    from methods.method1_ptq import run
else:
    from methods.method2_qat import run

run(WEIGHTS_FILE)
