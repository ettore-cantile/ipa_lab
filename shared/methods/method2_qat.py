"""
Method 2 — QAT (Quantization-Aware Training)

SCALE_FACTOR=128 fisso. La fwd_table e' pre-popolata con chiavi
calcolate usando aritmetica intera pura (identica al kernel).
Kernel e CP sono allineati -> quasi tutti TRUE HIT.

File usati:
  /shared/weights_method2.json : pesi int8 (QAT)
"""
import socket
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, populate_fwd_and_valid_keys,
    attach_xdp, stats_loop, EGRESS_IFACE
)

SCALE_FACTOR = 128


def run(model_id: int = 42):
    weights_path = "/shared/weights_method2.json"
    print(f"[Method 2 - QAT] | model_id: {model_id}")

    integer_weights = load_weights(weights_path)
    int8_weights    = [int(w) for w in integer_weights[:4]]
    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Raw int8 weights: {int8_weights}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, model_id, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)

    populate_fwd_and_valid_keys(b, action, int8_weights, SCALE_FACTOR,
                                integer_arithmetic=True)

    attach_xdp(b, fn)
    stats_loop(b)
