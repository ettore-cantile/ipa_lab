#!/usr/bin/env python3
"""
Throwaway diagnostic for the P3 modular 4-layer FAIL in verify_multi_model.py.

Bisection idea: prime scratch_acts/scratch_meta with the Python reference's
OWN (known-correct) intermediate activations at hop N, then call
layer_hidden directly. Since layer_hidden tail-calls onward by itself for
non-last hops, this doesn't test hop N in isolation -- it tests "hops N..end
of chain", bypassing hops 0..N-1 entirely. Comparing the FINAL result
against the reference at each priming point localizes the bug:
  - prime h1 @ layer_idx=1 -> tests hops 1,2,3 (bypasses layer_first)
  - prime h2 @ layer_idx=2 -> tests hops 2,3
  - prime h3 @ layer_idx=3 -> tests hop 3 alone (last layer, argmax)
If priming h1 gives the CORRECT final class but the full chain (via
dispatcher, layer_first included) does not, the bug is in layer_first's
computation or the layer_first->hop1 handoff. If priming h2 also passes but
h1 does not, the bug is specifically in hop1. Etc.

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
from verify_prog_run import build_frame, prog_test_run, _seed_link_state, _install_mac_table, _percpu_arr
from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
from verify_multi_model import synth_weights


def s8(v):
    return ct.c_int8(int(v) & 0xFF).value


def ref_forward_all(weights, layer_dims, ttl, model_id, ifindex=0):
    x = [0] * 65
    for i in range(6):
        x[i] = 1
    x[12] = ttl
    if 1 <= ifindex <= 6:
        x[5 + ifindex] = 1
    if 0 <= model_id <= 51:
        x[13 + model_id] = 1
    offset, layer_offsets = 0, []
    for (n_in, n_out) in layer_dims:
        layer_offsets.append(offset)
        offset += n_in * n_out + n_out
    acts_by_layer = [x]
    acts = x
    for li, (n_in, n_out) in enumerate(layer_dims):
        woff = layer_offsets[li]
        bias_off = n_in * n_out
        is_last = (li == len(layer_dims) - 1)
        out = []
        for j in range(n_out):
            acc = s8(weights[woff + bias_off + j])
            for i in range(n_in):
                acc += acts[i] * s8(weights[woff + j * n_in + i])
            out.append(acc if is_last else max(0, acc))
        acts_by_layer.append(out)
        acts = out
    return acts_by_layer  # [x, h1, h2, h3, final_scores]


MODEL_ID = 1
TTL = 3
SCALE = 30
DIMS1 = [(65, 5), (5, 6), (6, 4), (4, 7)]
WEIGHTS1 = synth_weights(DIMS1, seed=5678)

x, h1, h2, h3, final = ref_forward_all(WEIGHTS1, DIMS1, TTL, MODEL_ID)
ref_best_cls = max(range(len(final)), key=lambda k: final[k])
print(f"[ref] h1={h1}")
print(f"[ref] h2={h2}")
print(f"[ref] h3={h3}")
print(f"[ref] final={final}")
print(f"[ref] best_cls={ref_best_cls}\n")

b = BPF(text=EBPF_MODULAR_FULL)
disp_fn   = b.load_func("modular_dispatcher", BPF.XDP)
fn_first  = b.load_func("layer_first",  BPF.XDP)
fn_hidden = b.load_func("layer_hidden", BPF.XDP)
b["layer_chain"][ct.c_int(0)] = ct.c_int(fn_first.fd)
for i in range(1, 16):
    b["layer_chain"][ct.c_int(i)] = ct.c_int(fn_hidden.fd)
load_modular_weights(b, WEIGHTS1, model_id=MODEL_ID, scale=SCALE, layer_dims=DIMS1, base_offset=0)
_seed_link_state(b, 1)
_install_mac_table(b, "mac_table_t3")

frame = build_frame(MODEL_ID, TTL, SCALE)
ps, cs = b["pkt_stats_t3"], b["cls_stats_t3"]


def reset():
    for i in range(3):
        ps[ct.c_int(i)] = ct.c_ulonglong(0)
    for i in range(7):
        cs[ct.c_int(i)] = ct.c_ulonglong(0)


def report(label, retval):
    counts = [cs[ct.c_int(i)].value for i in range(7)]
    fired = [i for i, v in enumerate(counts) if v > 0]
    drop = ps[ct.c_int(2)].value
    print(f"[{label}] retval={retval}  cls_stats(nonzero)={fired}  drop={drop}  (ref best_cls={ref_best_cls})")


def prime(vec, layer_idx):
    for i in range(8):
        b["scratch_acts"][ct.c_int(i)] = _percpu_arr(vec[i] if i < len(vec) else 0)
    meta = {0: MODEL_ID, 1: SCALE, 2: layer_idx, 3: 0, 4: TTL}
    for slot, val in meta.items():
        b["scratch_meta"][ct.c_int(slot)] = _percpu_arr(val)


# 1) Full chain, exactly as the real pipeline runs it.
reset()
retval, _ = prog_test_run(disp_fn.fd, frame, repeat=1)
report("full chain (dispatcher -> layer_first -> hop1 -> hop2 -> hop3)", retval)

# 2) Prime with reference h1 at layer_idx=1: bypasses layer_first, tests hop1+hop2+hop3.
reset()
prime(h1, 1)
retval, _ = prog_test_run(fn_hidden.fd, frame, repeat=1)
report("primed ref h1 @ layer_idx=1 (tests hop1,hop2,hop3)", retval)

# 3) Prime with reference h2 at layer_idx=2: bypasses layer_first+hop1, tests hop2+hop3.
reset()
prime(h2, 2)
retval, _ = prog_test_run(fn_hidden.fd, frame, repeat=1)
report("primed ref h2 @ layer_idx=2 (tests hop2,hop3)", retval)

# 4) Prime with reference h3 at layer_idx=3 (last layer): tests hop3 alone.
reset()
prime(h3, 3)
retval, _ = prog_test_run(fn_hidden.fd, frame, repeat=1)
report("primed ref h3 @ layer_idx=3 (tests hop3 alone, argmax)", retval)
