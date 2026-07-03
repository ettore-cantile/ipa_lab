#!/usr/bin/env python3
"""
IPA Switch - Entry Point

Usage:
  Method 1 (PTQ):           python3 switch_core.py ptq
  Method 2 (QAT):           python3 switch_core.py qat
  Method 3 (OpenFlow-like): python3 switch_core.py openflow
  Method 4 (IPA Demo):      python3 switch_core.py ipa_demo
  Custom model_id:          python3 switch_core.py openflow 99
"""
import sys

METHOD_FLAG = sys.argv[1] if len(sys.argv) > 1 else "ptq"
MODEL_ID    = int(sys.argv[2]) if len(sys.argv) > 2 else 42

if METHOD_FLAG == "openflow":
    from methods.method3_openflow import run
elif METHOD_FLAG == "ipa_demo":
    from methods.method4_ipa_demo import run
elif METHOD_FLAG == "qat":
    from methods.method2_qat import run
else:  # ptq (default)
    from methods.method1_ptq import run

run(MODEL_ID)
