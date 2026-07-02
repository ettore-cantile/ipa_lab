"""
Metodo 1 — PTQ (Post-Training Quantization)
La fwd_table viene pre-popolata all'avvio per TTL 30-64.
File pesi: weights.json  +  weights_float.json
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


def run(weights_file: str = "weights.json"):
    weights_path = f"/shared/{weights_file}"
    float_path   = "/shared/weights_float.json"
    print(f"[Metodo 1 - PTQ] | File pesi: {weights_file}")

    if not os.path.exists(float_path):
        print(f"[ERRORE] {float_path} non trovato. Esegui prima extract_weights.py")
        sys.exit(1)

    with open(float_path) as f:
        float_data = json.load(f)
    SCALE_FACTOR = float_data["scale_factor"]
    cp_weights   = float_data["weights"][:4]

    integer_weights = load_weights(weights_path)
    int8_equiv = [ctypes.c_int8(int(w)).value / SCALE_FACTOR for w in integer_weights[:4]]
    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Pesi float    : {[f'{w:.6f}' for w in cp_weights]}")
    print(f"  Equiv int8    : {[f'{w:.6f}' for w in int8_equiv]}")
    print(f"  Errore quant. : {[f'{abs(a-b):.6f}' for a, b in zip(cp_weights, int8_equiv)]}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, 42, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)
    populate_fwd_and_valid_keys(b, action, cp_weights, SCALE_FACTOR)

    attach_xdp(b, fn)
    stats_loop(b)
