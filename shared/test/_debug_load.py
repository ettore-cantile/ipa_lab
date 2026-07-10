#!/usr/bin/env python3
"""One-off diagnostic: load layer_first with full verifier log_level=2
so the kernel's real rejection reason prints instead of BCC's generic
E2BIG guess message. Not part of the normal test suite -- delete after use."""
import os
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _dir in (SHARED_DIR, _TEST_DIR):
    if _dir not in sys.path:
        sys.path.insert(0, _dir)
os.chdir(SHARED_DIR)

from bcc import BPF
from ebpf_modular import EBPF_MODULAR_FULL

print("[debug] compiling...", flush=True)
b = BPF(text=EBPF_MODULAR_FULL, debug=0x10)
print("[debug] compiled OK, loading layer_first...", flush=True)
try:
    fn = b.load_func("layer_first", BPF.XDP)
    print("[debug] LOAD OK:", fn, flush=True)
except Exception as e:
    print("[debug] LOAD FAILED:", repr(e), flush=True)
    raise
