"""
Method 1 — PTQ (Post-Training Quantization)

The fwd_table is pre-populated with keys computed from original FLOAT weights.
The kernel uses int8 weights -> keys diverge due to quantization error.
This produces FAKE HITs (packets redirected on the wrong key) and
MISSes (TTLs whose float key does not collide with any entry).
This is the expected Method 1 behavior: it measures the PTQ quantization impact.

Weights files: weights.json + weights_float.json
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


def run(weights_file: str = "weights.json", model_id: int = 42):
    weights_path = f"/shared/{weights_file}"
    float_path   = "/shared/weights_float.json"
    print(f"[Method 1 - PTQ] | Weights file: {weights_file} | model_id: {model_id}")

    if not os.path.exists(float_path):
        print(f"[ERROR] {float_path} not found. Run extract_weights.py first.")
        sys.exit(1)

    with open(float_path) as f:
        float_data = json.load(f)
    SCALE_FACTOR = float_data["scale_factor"]
    cp_weights   = float_data["weights"][:4]   # float originali

    integer_weights = load_weights(weights_path)
    int8_equiv = [ctypes.c_int8(int(w)).value / SCALE_FACTOR for w in integer_weights[:4]]
    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Float weights : {[f'{w:.6f}' for w in cp_weights]}")
    print(f"  Int8 equiv    : {[f'{w:.6f}' for w in int8_equiv]}")
    print(f"  Quant error   : {[f'{abs(a-b):.6f}' for a, b in zip(cp_weights, int8_equiv)]}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, model_id, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)

    # integer_arithmetic=False: usa float originali per le chiavi
    # -> divergenza intenzionale rispetto al kernel -> FAKE HIT visibili
    populate_fwd_and_valid_keys(b, action, cp_weights, SCALE_FACTOR,
                                integer_arithmetic=False)

    attach_xdp(b, fn)
    stats_loop(b)
