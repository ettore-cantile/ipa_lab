"""
Metodo 1 — PTQ (Post-Training Quantization)
La fwd_table viene pre-popolata all'avvio per TTL 30-64.
File pesi: weights.json  +  weights_float.json
"""
import ctypes
import socket
import os
import sys
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, attach_xdp, stats_loop,
    INGRESS_IFACE, EGRESS_IFACE, OFFSET
)


def run(weights_file: str = "weights.json"):
    weights_path = f"/shared/{weights_file}"
    float_path   = "/shared/weights_float.json"

    print(f"[Metodo 1 - PTQ] | File pesi: {weights_file}")

    if not os.path.exists(float_path):
        print(f"[ERRORE] {float_path} non trovato. Esegui prima extract_weights.py")
        sys.exit(1)

    import json
    with open(float_path) as f:
        float_data = json.load(f)

    SCALE_FACTOR = float_data["scale_factor"]
    cp_weights   = float_data["weights"][:4]
    print(f"  SCALE_FACTOR = {SCALE_FACTOR}")
    print(f"  Pesi float   : {[f'{w:.6f}' for w in cp_weights]}")

    integer_weights = load_weights(weights_path)
    int8_equiv = [ctypes.c_int8(int(w)).value / SCALE_FACTOR for w in integer_weights[:4]]
    print(f"  Equiv int8   : {[f'{w:.6f}' for w in int8_equiv]}")
    print(f"  Errore quant.: {[f'{abs(a-b):.6f}' for a,b in zip(cp_weights, int8_equiv)]}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, 42, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action         = build_fwd_action(b, egress_ifindex)
    fwd            = b.get_table("fwd_table")
    if_index_eth1  = socket.if_nametoindex(INGRESS_IFACE)

    print("Popolamento fwd_table (TTL 30-64)...")
    for ttl in range(30, 65):
        iv          = [42, ttl, if_index_eth1, 4]
        ideal_raw   = sum(v * w for v, w in zip(iv, cp_weights))
        key         = int(ideal_raw) + OFFSET
        fwd[ctypes.c_ulonglong(key)] = action
    print("fwd_table pronta.")

    attach_xdp(b, fn)
    stats_loop(b)
