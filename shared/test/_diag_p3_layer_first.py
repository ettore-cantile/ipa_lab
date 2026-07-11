#!/usr/bin/env python3
"""
Throwaway diagnostic: isolates layer_first's OWN computation from the rest
of the chain. _diag_p3_deep.py already proved hop1/hop2/hop3 (layer_hidden)
are correct when given the reference's own h1/h2/h3 -- the bug must be in
layer_first or the layer_first->hop1 handoff.

Trick: register the SAME layer-0 weights (first 330 values of the 4-layer
synthetic model) as a SEPARATE model_id with n_layers=1. layer_first sees
n_layers==1 and treats itself as the LAST layer -- it argmaxes its own 5
outputs directly (h1) instead of continuing the chain, so we can read the
winning class straight from cls_stats and compare to argmax(ref_h1)
without needing to peek into a PERCPU scratch map mid-chain.

Needs Linux + BCC + root. Delete after use.
"""
import os
import sys
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _d in (SHARED_DIR, _TEST_DIR):
    if _d not in sys.path:
        sys.path.insert(0, _d)
os.chdir(SHARED_DIR)

from bcc import BPF
from verify_prog_run import build_frame, prog_test_run, _seed_link_state, _install_mac_table
from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
from verify_multi_model import synth_weights


def s8(v):
    return ct.c_int8(int(v) & 0xFF).value


TTL = 3
DIMS1 = [(65, 5), (5, 6), (6, 4), (4, 7)]
WEIGHTS1 = synth_weights(DIMS1, seed=5678)
LAYER0_WEIGHTS = WEIGHTS1[:330]   # 65*5 + 5 = 330, exactly layer 0's slice

# Reference h1 for model_id=1 (must match the model_id used below, since
# model_id feeds the "node" one-hot feature -- x[13+model_id]).
def ref_h1(weights, ttl, model_id, ifindex=0):
    x = [0] * 65
    for i in range(6):
        x[i] = 1
    x[12] = ttl
    if 1 <= ifindex <= 6:
        x[5 + ifindex] = 1
    if 0 <= model_id <= 51:
        x[13 + model_id] = 1
    n_in, n_out = 65, 5
    bias_off = n_in * n_out
    out = []
    for j in range(n_out):
        acc = s8(weights[bias_off + j])
        for i in range(n_in):
            acc += x[i] * s8(weights[j * n_in + i])
        out.append(acc)  # no ReLU here -- we want the raw pre-activation score to argmax on
    return out


MODEL_ID = 1   # must match the real 4-layer model's id (node feature depends on it)
h1_ref = ref_h1(LAYER0_WEIGHTS, TTL, MODEL_ID)
ref_best = max(range(5), key=lambda j: h1_ref[j])
print(f"[ref] h1 (pre-ReLU, argmax target) = {h1_ref}")
print(f"[ref] argmax(h1) = class {ref_best}\n")

b = BPF(text=EBPF_MODULAR_FULL)
disp_fn   = b.load_func("modular_dispatcher", BPF.XDP)
fn_first  = b.load_func("layer_first",  BPF.XDP)
fn_hidden = b.load_func("layer_hidden", BPF.XDP)
b["layer_chain"][ct.c_int(0)] = ct.c_int(fn_first.fd)
for i in range(1, 16):
    b["layer_chain"][ct.c_int(i)] = ct.c_int(fn_hidden.fd)

# Register model_id=1 as a STANDALONE 1-layer model: layer_first will
# argmax its own output directly instead of continuing the chain.
load_modular_weights(b, LAYER0_WEIGHTS, model_id=MODEL_ID, scale=30,
                     layer_dims=[(65, 5)], base_offset=0)
_seed_link_state(b, 1)
_install_mac_table(b, "mac_table_t3")

frame = build_frame(MODEL_ID, TTL, 30)
ps, cs = b["pkt_stats_t3"], b["cls_stats_t3"]
for i in range(3):
    ps[ct.c_int(i)] = ct.c_ulonglong(0)
for i in range(7):
    cs[ct.c_int(i)] = ct.c_ulonglong(0)

retval, _ = prog_test_run(disp_fn.fd, frame, repeat=1)
counts = [cs[ct.c_int(i)].value for i in range(7)]
fired = [i for i, v in enumerate(counts) if v > 0]
drop = ps[ct.c_int(2)].value
print(f"[kernel] layer_first as sole/last layer: retval={retval}  cls_stats(nonzero)={fired}  drop={drop}")
print(f"[compare] kernel picked class {fired[0] if fired else ('DROP' if drop else '?')}  vs  ref argmax(h1) = class {ref_best}")
