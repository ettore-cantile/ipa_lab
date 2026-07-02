"""
Method 2 — QAT (Quantization-Aware Training)

Fixed SCALE_FACTOR = 128. The fwd_table is pre-populated with keys
computed using pure integer arithmetic (identical to the kernel).
Kernel and CP are aligned -> nearly all TRUE HITs.

Weights file: weights_method2.json
"""
import ctypes
import socket
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, populate_fwd_and_valid_keys,
    attach_xdp, stats_loop, EGRESS_IFACE
)

SCALE_FACTOR = 128


def run(weights_file: str = "weights_method2.json"):
    weights_path = f"/shared/{weights_file}"
    print(f"[Method 2 - QAT] | Weights file: {weights_file}")

    integer_weights = load_weights(weights_path)
    int8_weights    = [int(w) for w in integer_weights[:4]]  # raw int8, no divisione
    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Raw int8 weights: {int8_weights}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, 42, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)

    # integer_arithmetic=True: aritmetica intera pura identica al kernel
    # -> TRUE HIT attesi
    populate_fwd_and_valid_keys(b, action, int8_weights, SCALE_FACTOR,
                                integer_arithmetic=True)

    attach_xdp(b, fn)
    stats_loop(b)
