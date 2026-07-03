"""
Method 1 — PTQ (Post-Training Quantization)

Il CP popola la fwd_table con chiavi calcolate dai pesi FLOAT originali.
Il kernel usa i pesi int8 -> le chiavi divergono per errore di quantizzazione.
Questo produce FAKE HIT (pacchetti reindirizzati su chiave sbagliata) e
MISS (TTL per cui la chiave float non collide con nessuna entry).
Scopo: misurare l'impatto dell'errore PTQ rispetto al metodo 2 (QAT).

Nota scale_factor:
  SCALE_FACTOR viene letto da weights_float.json, dove extract_weights.py
  lo ha calcolato come floor(127 / max|w|). Questo e' lo stesso valore
  usato per quantizzare weights.json -> model_cache e kernel sono allineati.
  Il CP usa i pesi float originali per le chiavi della fwd_table
  (integer_arithmetic=False) -> divergenza intenzionale -> FAKE HIT.

File usati:
  /shared/weights.json       : pesi int8 per la model_cache del kernel
  /shared/weights_float.json : pesi float originali + scale_factor
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

    SCALE_FACTOR = float_data["scale_factor"]  # calcolato da extract_weights.py
    cp_weights   = float_data["weights"][:4]   # pesi float originali

    integer_weights = load_weights(weights_path)
    int8_equiv = [ctypes.c_int8(int(round(w * SCALE_FACTOR))).value / SCALE_FACTOR
                  for w in cp_weights]
    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}  (da weights_float.json)")
    print(f"  Float weights : {[f'{w:.6f}' for w in cp_weights]}")
    print(f"  Int8 equiv    : {[f'{w:.6f}' for w in int8_equiv]}")
    print(f"  Quant error   : {[f'{abs(a-b):.6f}' for a, b in zip(cp_weights, int8_equiv)]}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, model_id, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)

    # integer_arithmetic=False: chiavi calcolate con float originali
    # -> divergenza rispetto al kernel (che usa int8) -> FAKE HIT visibili
    populate_fwd_and_valid_keys(b, action, cp_weights, SCALE_FACTOR,
                                integer_arithmetic=False)

    attach_xdp(b, fn)
    stats_loop(b)
