"""
Metodo 2 — QAT (Quantization-Aware Training)
La fwd_table viene pre-popolata con SCALE_FACTOR fisso = 128.
File pesi: weights_method2.json
"""
import ctypes
import socket
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, attach_xdp, stats_loop,
    INGRESS_IFACE, EGRESS_IFACE, OFFSET
)

SCALE_FACTOR = 128


def run(weights_file: str = "weights_method2.json"):
    weights_path = f"/shared/{weights_file}"
    print(f"[Metodo 2 - QAT] | File pesi: {weights_file}")

    integer_weights = load_weights(weights_path)
    cp_weights = [ctypes.c_int8(int(w)).value / SCALE_FACTOR
                  for w in integer_weights[:4]]
    print(f"  SCALE_FACTOR = {SCALE_FACTOR}")
    print(f"  Pesi int8/128: {[f'{w:.6f}' for w in cp_weights]}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, 42, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action         = build_fwd_action(b, egress_ifindex)
    fwd            = b.get_table("fwd_table")
    if_index_eth1  = socket.if_nametoindex(INGRESS_IFACE)

    print("Popolamento fwd_table (TTL 30-64)...")
    for ttl in range(30, 65):
        iv        = [42, ttl, if_index_eth1, 4]
        ideal_raw = sum(v * w for v, w in zip(iv, cp_weights))
        key       = int(ideal_raw) + OFFSET
        fwd[ctypes.c_ulonglong(key)] = action
    print("fwd_table pronta.")

    attach_xdp(b, fn)
    stats_loop(b)
