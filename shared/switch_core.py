#!/usr/bin/env python3
"""
IPA Switch - Entry Point (design-space-docs branch)

This branch contains only the two new pipelines requested by the professor:

  Pipeline 2 - Pre-built Architectural Template:
      python3 switch_core.py template
      python3 switch_core.py template 42     # custom model_id

  Pipeline 3 - Modular Neural Pipeline:
      python3 switch_core.py modular
      python3 switch_core.py modular 42

Methods 1-4 (PTQ, QAT, OpenFlow, IPA Demo) live in the main branch.
"""
import sys

METHOD_FLAG = sys.argv[1] if len(sys.argv) > 1 else "template"
MODEL_ID    = int(sys.argv[2]) if len(sys.argv) > 2 else 42

if METHOD_FLAG == "modular":
    from methods.method6_modular import run
else:  # template (default)
    from methods.method5_template import run

run(MODEL_ID)
