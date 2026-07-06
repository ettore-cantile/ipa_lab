"""
Method 1 - PTQ (Post-Training Quantization)

The CP populates fwd_table with keys computed from the original FLOAT weights.
The kernel uses int8 weights -> keys diverge because of quantization error.
This produces FAKE HIT events (packets redirected on the wrong key) and MISS
events (TTL values whose float key does not collide with any entry).
Goal: measure the impact of PTQ error compared with Method 2 (QAT).

scale_factor note:
  SCALE_FACTOR is read from weights_float.json, where extract_weights.py
  computed it as floor(127 / max|w|). This is the same value used to quantize
  weights.json -> model_cache and kernel are aligned.
  The CP uses original float weights for fwd_table keys
  (integer_arithmetic=False) -> intentional divergence -> FAKE HIT.

Files used:
  /shared/weights.json       : int8 weights for the kernel model_cache
  /shared/weights_float.json : original float weights + scale_factor
"""
import ctypes
import socket
import os
import sys
import json
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, populate_fwd_and_valid_keys,
    attach_xdp, stats_loop, EGRESS_IFACE
)


def run(model_id: int = 42):
    weights_path = "/shared/weights.json"
    float_path   = "/shared/weights_float.json"
    print(f"[Method 1 - PTQ] | model_id: {model_id}")

    if not os.path.exists(float_path):
        print(f"[ERROR] {float_path} not found. Run extract_weights.py first.")
        sys.exit(1)

    with open(float_path) as f:
        float_data = json.load(f)

    SCALE_FACTOR = float_data["scale_factor"]  # computed by extract_weights.py
    cp_weights   = float_data["weights"][:4]   # original float weights

    integer_weights = load_weights(weights_path)
    int8_equiv = [ctypes.c_int8(int(round(w * SCALE_FACTOR))).value / SCALE_FACTOR
                  for w in cp_weights]
    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}  (from weights_float.json)")
    print(f"  Float weights : {[f'{w:.6f}' for w in cp_weights]}")
    print(f"  Int8 equiv    : {[f'{w:.6f}' for w in int8_equiv]}")
    print(f"  Quant error   : {[f'{abs(a-b):.6f}' for a, b in zip(cp_weights, int8_equiv)]}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, model_id, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)

    # integer_arithmetic=False: keys computed from original floats
    # -> divergence from the kernel (which uses int8) -> visible FAKE HIT events
    populate_fwd_and_valid_keys(b, action, cp_weights, SCALE_FACTOR,
                                integer_arithmetic=False)

    attach_xdp(b, fn)
    stats_loop(b)
