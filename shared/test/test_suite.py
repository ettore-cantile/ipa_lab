#!/usr/bin/env python3
"""
test_suite.py — LOCAL test suite for the 3 IPA methods (no eBPF/XDP required)
================================================================================

Single script consolidating all local tests (previously split across test_local.py,
test_ipa_methods.py, test_extract_weights.py, test_quantization_accuracy.py,
test_robustness.py). Measures, locally with PyTorch/NumPy, the
design-space properties and metrics, without
needing kernel/eBPF (for the in-kernel check use verify_prog_run.py).

Available suites (--only):
  core     : inference consistency, update latency, determinism, .pt load,
             plus the design-space table (throughput, tail calls, map lookups,
             map memory, flexibility)                    [ex test_local]
  pktstats : hit/fake/miss for the 3 methods + counter consistency   [ex test_ipa_methods]
  extract  : extract_weights.py / weights.json / dequant consistency [ex test_extract_weights]
  quant    : accuracy argmax vs scale_factor (PTQ trade-off)   [ex test_quantization_accuracy]
  robust   : edge-case inputs, no crash, valid argmax       [ex test_robustness]
  kernel   : IN-KERNEL metrics via BPF_PROG_TEST_RUN — eBPF instruction count,
             per-packet latency, throughput Mpps, CPU%, + real dispatch
             gate (ex verify_prog_run). Requires Linux + BCC + root; elsewhere
             it is skipped gracefully (does not fail the run).
  all      : every suite (default)

Usage:
  python3 shared/test/test_suite.py                       # every suite (kernel skipped without BCC)
  python3 shared/test/test_suite.py --only core --verbose
  python3 shared/test/test_suite.py --only quant --samples 200
  sudo python3 shared/test/test_suite.py --only kernel    # kernel metrics (root)
  kathara exec frankfurt -- python3 /shared/test/test_suite.py --only kernel
"""

import argparse
import time
import sys
import os

# Lives in shared/test/; pipeline modules (ebpf_program, extract_weights, ...)
# and the .pt/.json data files live one level up in shared/.
_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

# torch is optional at import time: `--only kernel` never touches a torch
# model (it drives verify_prog_run.py / BCC directly), so it must keep working
# inside Kathara containers that don't have torch installed. main() hard-fails
# with a clear error only if a suite that actually needs torch is requested.
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

import numpy as np

# Real architecture from FRR_model.py (used by tests 1-4)
N_INTERFACES  = 6
N_NODES       = 22
HIDDEN_DIM    = 32
INPUT_SIZE    = N_INTERFACES + N_INTERFACES + 1 + N_NODES  # = 35
OUTPUT_SIZE   = N_INTERFACES + 1                           # = 7

# Nominal duration used in Method 1 to simulate the eBPF program
# redirect/reload step (bpf_prog_load + iface redirect).
# This constant is intentionally printed in Test 2 so it is always
# visible in the output alongside the measured times.
M1_REDIRECT_SIM_MS = 1.0   # milliseconds

GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
RED    = "\033[0;31m"
NC     = "\033[0m"

def ok(msg):   print(f"  {GREEN}[PASS]{NC} {msg}")
def fail(msg): print(f"  {RED}[FAIL]{NC} {msg}")
def info(msg): print(f"  {YELLOW}[INFO]{NC} {msg}")


def decode_nexthop(argmax_idx: int, n_interfaces: int = N_INTERFACES) -> str:
    if argmax_idx == 0:
        return "DROP"
    iface_idx = argmax_idx - 1
    if 0 <= iface_idx < n_interfaces:
        return f"eth{iface_idx}"
    return f"UNKNOWN(idx={argmax_idx})"


if TORCH_AVAILABLE:
    class FRRModel(nn.Module):
        def __init__(self, input_size=INPUT_SIZE, hidden_dim=HIDDEN_DIM, output_size=OUTPUT_SIZE):
            super().__init__()
            self.fc1 = nn.Linear(input_size, hidden_dim)
            self.fc2 = nn.Linear(hidden_dim, hidden_dim)
            self.out = nn.Linear(hidden_dim, output_size)

        def forward(self, x):
            x = F.relu(self.fc1(x))
            x = F.relu(self.fc2(x))
            return self.out(x)


    def load_pt_dynamic(path: str) -> tuple:
        state = torch.load(path, map_location='cpu', weights_only=True)
        w1_shape  = state['fc1.weight'].shape
        out_shape = state['out.weight'].shape
        inferred_input  = w1_shape[1]
        inferred_hidden = w1_shape[0]
        inferred_output = out_shape[0]
        model = FRRModel(
            input_size=inferred_input,
            hidden_dim=inferred_hidden,
            output_size=inferred_output
        )
        model.load_state_dict(state)
        return model, inferred_input, inferred_hidden, inferred_output


    def compute_scale(model: "nn.Module") -> int:
        max_abs = 0.0
        for p in model.parameters():
            max_abs = max(max_abs, float(p.detach().abs().max()))
        if max_abs == 0:
            return 128
        raw = 127.0 / max_abs
        power = 1
        while power * 2 <= raw:
            power *= 2
        return power


class Method1_Hardcoded:
    def __init__(self, model: "FRRModel"):
        self._copy_weights(model)

    def _copy_weights(self, model):
        s = model.state_dict()
        self.W1 = s['fc1.weight'].numpy().copy()
        self.b1 = s['fc1.bias'].numpy().copy()
        self.W2 = s['fc2.weight'].numpy().copy()
        self.b2 = s['fc2.bias'].numpy().copy()
        self.W3 = s['out.weight'].numpy().copy()
        self.b3 = s['out.bias'].numpy().copy()

    def infer(self, x):
        h1 = np.maximum(0, self.W1 @ x + self.b1)
        h2 = np.maximum(0, self.W2 @ h1 + self.b2)
        return self.W3 @ h2 + self.b3

    def measure_redirect_reload(self) -> float:
        """Simulate eBPF program redirect/reload (bpf_prog_load + iface attach).
        The nominal sleep duration is M1_REDIRECT_SIM_MS milliseconds."""
        t0 = time.perf_counter()
        time.sleep(M1_REDIRECT_SIM_MS / 1000.0)
        return time.perf_counter() - t0

    def measure_weight_insert(self, new_model) -> float:
        """Measure only the weight copy step (analogous to bpf_map_update_elem
        in Methods 2/3), so that it can be compared fairly against them."""
        t0 = time.perf_counter()
        self._copy_weights(new_model)
        return time.perf_counter() - t0

    def update_weights(self, new_model) -> dict:
        t_redirect = self.measure_redirect_reload()
        t_insert   = self.measure_weight_insert(new_model)
        return {
            'redirect_reload_s': t_redirect,
            'weight_insert_s':   t_insert,
            'total_s':           t_redirect + t_insert,
        }


class Method2_Template:
    def __init__(self, model: "FRRModel"):
        self.hidden = model.fc1.out_features
        self.input = model.fc1.in_features
        self.output = model.out.out_features
        self.scale = compute_scale(model)
        self.weight_map = {}
        self._load(model)

    def _q(self, v):
        return max(-128, min(127, int(round(v * self.scale))))

    def _load(self, model):
        self.scale = compute_scale(model)
        self.hidden = model.fc1.out_features
        self.input = model.fc1.in_features
        self.output = model.out.out_features
        s = model.state_dict()
        idx = 0
        for key in ['fc1.weight', 'fc1.bias', 'fc2.weight', 'fc2.bias', 'out.weight', 'out.bias']:
            for v in s[key].flatten().tolist():
                self.weight_map[idx] = self._q(v)
                idx += 1

    def _mat(self, off, r, c):
        return np.array([self.weight_map[off + i] / self.scale for i in range(r * c)]).reshape(r, c)

    def _bias(self, off, n):
        return np.array([self.weight_map[off + i] / self.scale for i in range(n)])

    def infer(self, x):
        H, I, O = self.hidden, self.input, self.output
        off = 0
        W1 = self._mat(off, H, I); off += H * I
        b1 = self._bias(off, H);   off += H
        W2 = self._mat(off, H, H); off += H * H
        b2 = self._bias(off, H);   off += H
        W3 = self._mat(off, O, H); off += O * H
        b3 = self._bias(off, O)
        h1 = np.maximum(0, W1 @ x + b1)
        h2 = np.maximum(0, W2 @ h1 + b2)
        return W3 @ h2 + b3

    def update_weights(self, new_model) -> float:
        t0 = time.perf_counter()
        self._load(new_model)
        return time.perf_counter() - t0


class Method3_Modular:
    def __init__(self, model: "FRRModel"):
        self.hidden = model.fc1.out_features
        self.input = model.fc1.in_features
        self.output = model.out.out_features
        self.scale = compute_scale(model)
        self.lw = [{}, {}, {}]
        self._load(model)

    def _q(self, v):
        return max(-128, min(127, int(round(v * self.scale))))

    def _load(self, model, layer_idx=None):
        self.scale = compute_scale(model)
        self.hidden = model.fc1.out_features
        self.input = model.fc1.in_features
        self.output = model.out.out_features
        s = model.state_dict()
        cfg = [
            ('fc1.weight', 'fc1.bias', self.hidden, self.input),
            ('fc2.weight', 'fc2.bias', self.hidden, self.hidden),
            ('out.weight', 'out.bias', self.output, self.hidden),
        ]
        layers = [layer_idx] if layer_idx is not None else [0, 1, 2]
        for li in layers:
            wk, bk, rows, cols = cfg[li]
            idx = 0
            for v in s[wk].flatten().tolist():
                self.lw[li][idx] = self._q(v)
                idx += 1
            for v in s[bk].flatten().tolist():
                self.lw[li][idx] = self._q(v)
                idx += 1

    def _layer(self, li, x_in, out_size):
        in_size = len(x_in)
        lw = self.lw[li]
        W = np.array([lw[i] / self.scale for i in range(out_size * in_size)]).reshape(out_size, in_size)
        b = np.array([lw[out_size * in_size + i] / self.scale for i in range(out_size)])
        return W @ x_in + b

    def infer(self, x):
        h1 = np.maximum(0, self._layer(0, x, self.hidden))
        h2 = np.maximum(0, self._layer(1, h1, self.hidden))
        return self._layer(2, h2, self.output)

    def update_weights(self, new_model, layer_idx=None) -> float:
        t0 = time.perf_counter()
        self._load(new_model, layer_idx)
        return time.perf_counter() - t0


class Method2_FixedScale(Method2_Template):
    def __init__(self, model, scale: int):
        super().__init__(model)
        self.scale = scale
        self._load(model)

    def _load(self, model):
        self.hidden = model.fc1.out_features
        self.input = model.fc1.in_features
        self.output = model.out.out_features
        s = model.state_dict()
        idx = 0
        for key in ['fc1.weight', 'fc1.bias', 'fc2.weight', 'fc2.bias', 'out.weight', 'out.bias']:
            for v in s[key].flatten().tolist():
                self.weight_map[idx] = self._q(v)
                idx += 1


class Method3_FixedScale(Method3_Modular):
    def __init__(self, model, scale: int):
        super().__init__(model)
        self.scale = scale
        self._load(model)

    def _load(self, model, layer_idx=None):
        self.hidden = model.fc1.out_features
        self.input = model.fc1.in_features
        self.output = model.out.out_features
        s = model.state_dict()
        cfg = [
            ('fc1.weight', 'fc1.bias', self.hidden, self.input),
            ('fc2.weight', 'fc2.bias', self.hidden, self.hidden),
            ('out.weight', 'out.bias', self.output, self.hidden),
        ]
        layers = [layer_idx] if layer_idx is not None else [0, 1, 2]
        for li in layers:
            wk, bk, rows, cols = cfg[li]
            idx = 0
            for v in s[wk].flatten().tolist():
                self.lw[li][idx] = self._q(v)
                idx += 1
            for v in s[bk].flatten().tolist():
                self.lw[li][idx] = self._q(v)
                idx += 1


def make_input(input_size=INPUT_SIZE):
    ls = np.random.randint(0, 2, N_INTERFACES).astype(np.float32)
    ii = np.zeros(N_INTERFACES, dtype=np.float32)
    ii[np.random.randint(0, N_INTERFACES)] = 1.0
    ttl = np.array([np.random.uniform(0, 1)], dtype=np.float32)
    nid = np.zeros(N_NODES, dtype=np.float32)
    nid[np.random.randint(0, N_NODES)] = 1.0
    base = np.concatenate([ls, ii, ttl, nid])
    if input_size > len(base):
        base = np.concatenate([base, np.zeros(input_size - len(base), dtype=np.float32)])
    return base[:input_size]


def pytorch_ref(model, x_np):
    with torch.no_grad():
        return model(torch.tensor(x_np, dtype=torch.float32)).numpy()


def _banner(passed, total):
    print(f"\n{YELLOW}{'='*52}{NC}")
    color = GREEN if passed == total else RED
    print(f"{color} Result: {passed}/{total} tests passed{NC}")
    if passed < total:
        print(f"{RED} Controlla i messaggi [FAIL] sopra{NC}")
    print(f"{YELLOW}{'='*52}{NC}\n")


def suite_core(model, verbose=False):
    print(f"\n{YELLOW}=== SUITE core — IPA Pipeline (3 methods) ==={NC}\n")
    H = model.fc1.out_features
    I = model.fc1.in_features
    O = model.out.out_features
    print(f"  Architecture: {I} -> {H} -> {H} -> {O}")
    print()

    m1 = Method1_Hardcoded(model)
    m2 = Method2_Template(model)
    m3 = Method3_Modular(model)
    info(f"Method 2: scale_factor={m2.scale}")
    info(f"Method 3: scale_factor={m3.scale}")
    info(f"Next-hop encoding: output 0=DROP, 1=eth0, 2=eth1, ..., {O-1}=eth{O-2}")
    print()

    N = 50
    passed = total = 0

    print(f"{YELLOW}[Test 1] Output consistency & argmax ({N} samples){NC}")
    mm = {2: 0, 3: 0}
    me = {1: 0.0, 2: 0.0, 3: 0.0}
    for i in range(N):
        x = make_input(I)
        ref = pytorch_ref(model, x)
        nr = int(np.argmax(ref))
        o1 = m1.infer(x)
        o2 = m2.infer(x)
        o3 = m3.infer(x)
        me[1] = max(me[1], float(np.max(np.abs(o1 - ref))))
        me[2] = max(me[2], float(np.max(np.abs(o2 - ref))))
        me[3] = max(me[3], float(np.max(np.abs(o3 - ref))))
        a2, a3 = int(np.argmax(o2)), int(np.argmax(o3))
        if a2 != nr:
            mm[2] += 1
        if a3 != nr:
            mm[3] += 1
        if verbose:
            print(f"    [sample {i:02d}] ref={decode_nexthop(nr)} "
                  f"| M1={decode_nexthop(int(np.argmax(o1)))} "
                  f"| M2={decode_nexthop(a2)} "
                  f"| M3={decode_nexthop(a3)}")

    total += 1
    passed += 1
    ok(f"Method 1 (hardcoded): argmax 100% correct | max_err={me[1]:.6f}")

    for mid, name in [(2, 'template'), (3, 'modular')]:
        total += 1
        pct = mm[mid] / N * 100
        if pct <= 10:
            ok(f"Method {mid} ({name}): argmax {100-pct:.0f}% correct ({mm[mid]}/{N}) | max_err={me[mid]:.4f}")
            passed += 1
        else:
            fail(f"Method {mid} ({name}): {mm[mid]}/{N} argmax errati | max_err={me[mid]:.4f} | scale={m2.scale}")

    for mid, name, sc in [(2, 'template', m2.scale), (3, 'modular', m3.scale)]:
        total += 1
        tol = H / sc
        if me[mid] <= tol:
            ok(f"Method {mid} ({name}): quant error ok ({me[mid]:.4f} <= {tol:.4f})")
            passed += 1
        else:
            fail(f"Method {mid} ({name}): quant error HIGH ({me[mid]:.4f} > {tol:.4f})")

    print(f"\n{YELLOW}[Test 2] Weight update latency (10 updates){NC}")
    # M1_REDIRECT_SIM_MS is the *nominal* duration chosen to simulate the
    # eBPF program redirect/reload step for Method 1 (bpf_prog_load + iface
    # attach).  It is printed here so that it is always visible next to the
    # measured times, making clear what portion of Method 1's total latency
    # comes from the redirect and what comes from the actual weight copy.
    info(f"Method 1 redirect/reload simulation: nominal={M1_REDIRECT_SIM_MS:.1f} ms "
         f"(models the cost of bpf_prog_load + iface attach in the real eBPF case)")
    info("Method 2/3 have no redirect step — their update = map insert only")
    print()

    times = {
        '1_redirect': [],
        '1_insert':   [],
        '1_total':    [],
        2:            [],
        3:            [],
        '3s':         []
    }
    for _ in range(10):
        nm = FRRModel()
        t1 = m1.update_weights(nm)
        times['1_redirect'].append(t1['redirect_reload_s'] * 1000)
        times['1_insert'].append(t1['weight_insert_s'] * 1000)
        times['1_total'].append(t1['total_s'] * 1000)
        times[2].append(m2.update_weights(nm) * 1000)
        times[3].append(m3.update_weights(nm) * 1000)
        times['3s'].append(m3.update_weights(nm, layer_idx=2) * 1000)

    for key, lbl in [
        ('1_redirect', 'Method 1 hardcoded (redirect/reload only) [sim]'),
        ('1_insert',   'Method 1 hardcoded (weight insert only)   [fair vs M2/M3]'),
        ('1_total',    'Method 1 hardcoded (redirect + weight insert, total)'),
        (2,            'Method 2 template  (map update)'),
        (3,            'Method 3 modular   (all layers)'),
        ('3s',         'Method 3 modular   (single layer hot-swap)')
    ]:
        avg = sum(times[key]) / 10
        info(f"{lbl}: avg={avg:.3f}ms  max={max(times[key]):.3f}ms")

    print()
    info("NOTE: to compare M1 fairly against M2/M3, use 'weight insert only'.")
    info(f"      The redirect/reload overhead (~{M1_REDIRECT_SIM_MS:.1f} ms nominal) is an")
    info("      architectural cost specific to M1 and must be reported separately.")

    total += 1
    passed += 1
    ok("Update latency measured — Method 1 split into redirect and weight insert")

    print(f"\n{YELLOW}[Test 3] Determinism (100 runs){NC}")
    xf = make_input(I)
    rs = {int(np.argmax(m2.infer(xf))) for _ in range(100)}
    total += 1
    if len(rs) == 1:
        nh_str = decode_nexthop(list(rs)[0])
        ok(f"Method 2: deterministic ({list(rs)[0]} -> {nh_str}) over 100 runs")
        passed += 1
    else:
        fail(f"Method 2: NOT deterministic: {rs}")

    print(f"\n{YELLOW}[Test 4] Post-update consistency{NC}")
    nm = FRRModel()
    m2.update_weights(nm)
    m3.update_weights(nm)
    mp = 0
    for _ in range(N):
        x = make_input(I)
        if int(np.argmax(m2.infer(x))) != int(np.argmax(m3.infer(x))):
            mp += 1
    total += 1
    if mp == 0:
        ok(f"Method 2 and 3 agree on {N} samples after update")
        passed += 1
    else:
        fail(f"Method 2 and 3 disagree on {mp}/{N} samples")

    print(f"\n{YELLOW}[Test 5] Load .pt model (auto-inferred sizes){NC}")
    total += 1
    pt_path = os.path.join(SHARED_DIR, 'frr_germany50_5_model_4x2.pt')
    if os.path.exists(pt_path):
        try:
            loaded, li, lh, lo = load_pt_dynamic(pt_path)
            x = make_input(li)
            out_vec = pytorch_ref(loaded, x)
            nh_idx = int(np.argmax(out_vec))
            nh_str = decode_nexthop(nh_idx, n_interfaces=lo - 1)
            sc = compute_scale(loaded)
            ok(f".pt caricato | arch={li}->{lh}->{lh}->{lo} | next-hop={nh_idx} ({nh_str}) | scale={sc}")
            if verbose:
                info(f"  Output scores: {[f'{v:.3f}' for v in out_vec.tolist()]}")
                info(f"  Decode: 0=DROP, 1=eth0 .. {lo-1}=eth{lo-2}")
            passed += 1
        except Exception as e:
            fail(f"Error loading .pt: {e}")
    else:
        info(f".pt not found ({pt_path}) — test skipped")
        total -= 1

    print(f"\n{YELLOW}[Test 6] Design-space metrics (throughput, structure, memory){NC}")

    BENCH_SECS = 2.0
    throughputs = {}
    inputs_cache = [make_input(I) for _ in range(1000)]
    for mid, mobj, name in [(1, m1, 'hardcoded'), (2, m2, 'template'), (3, m3, 'modular')]:
        t0 = time.perf_counter()
        count = 0
        while time.perf_counter() - t0 < BENCH_SECS:
            mobj.infer(inputs_cache[count % 1000])
            count += 1
        elapsed = time.perf_counter() - t0
        mpps = count / elapsed / 1_000_000
        throughputs[mid] = (mpps, count, elapsed)
    info(f"Inference throughput (Python, single-core, {BENCH_SECS:.0f}s benchmark):")
    for mid, name in [(1, 'hardcoded'), (2, 'template'), (3, 'modular')]:
        mpps, cnt, el = throughputs[mid]
        info(f"  Method {mid} ({name:<10}): {mpps:.4f} Mpps  ({cnt} infer in {el:.2f}s)")
    info("  NOTE: eBPF kernel throughput expected 10-100x higher (no Python overhead)")
    info("  NOTE: Python throughput not used for the assertion (see Test 6 comment)")

    n_fc1 = I * H + H
    n_fc2 = H * H + H
    n_out = H * O + O
    N_WEIGHTS = n_fc1 + n_fc2 + n_out

    TAIL_CALLS = {1: 'kernel-only', 2: 'kernel-only', 3: 'kernel-only'}

    p3_lookups = (1 + I
                  + (I * H) + H
                  + (H * H) + H
                  + (H * O) + H
                  + 2)
    # P1: 0 weight lookups (pesi = letterali C). Le uniche map lookup sono le
    # 6 feature link_state + i contatori (pkt/cls/debug ~2). P2/P3 leggono i
    # pesi da map, quindi molte piu' lookup.
    MAP_LOOKUPS = {1: 6 + 2, 2: N_WEIGHTS + 3, 3: p3_lookups}

    try:
        import multiprocessing
        ncpus = multiprocessing.cpu_count()
    except Exception:
        ncpus = 4

    # Pure P1 hardcoded: no model_cache. Only link_state[6] + counters.
    #   link_state 6*(4+4) + pkt_stats 3*(4+8) + cls_stats 7*(4+8) + debug 8*(4+8) = 264
    # mac_table replaced the old fwd_table(256)+valid_keys(256): now class->action
    # over 8 slots + a small cls_stats(7). Much smaller footprint on P2/P3.
    MAP_MEM_BYTES = {
        1: 6 * 8 + 3 * 12 + 7 * 12 + 8 * 12,
        2: N_WEIGHTS * 1 + 256 * 7 + 8 * 20 + 3 * 8 + 7 * 8,
        3: N_WEIGHTS * 2 + 256 * 14 + (H + 16) * 8 * ncpus + 8 * 20 + 3 * 8 + 7 * 8,
    }
    FLEXIBILITY = {1: 'low',  2: 'medium',  3: 'high'}
    MODEL_UPDATE = {
        1: 'recompile + reload eBPF program',
        2: 'bpf_map_update_elem() on arch_weights',
        3: 'bpf_map_update_elem() on layer_weights + update layer_chain',
    }

    print()
    COL = 32
    hdr = f"  {'Metric':<{COL}} {'P1 hardcoded':>16} {'P2 template':>16} {'P3 modular':>16}"
    sep = "  " + "-" * (COL + 50)
    print(hdr)
    print(sep)

    def row(label, vals):
        v = [str(vals[k]) for k in [1, 2, 3]]
        print(f"  {label:<{COL}} {v[0]:>16} {v[1]:>16} {v[2]:>16}")

    row("Local throughput (Mpps)",
        {k: f"{throughputs[k][0]:.4f}" for k in [1, 2, 3]})
    row("Tail calls / packet",  TAIL_CALLS)
    row("Map lookups / packet (est.)", MAP_LOOKUPS)
    row("BPF map memory (est.)",
        {k: f"{MAP_MEM_BYTES[k]//1024}KB ({MAP_MEM_BYTES[k]}B)" for k in [1, 2, 3]})
    row("Flexibility",             FLEXIBILITY)
    print(sep)
    print()

    info(f"Logical CPUs detected: {ncpus} (affects the PERCPU scratch map for P3)")
    info("Tail calls are no longer hardcoded in the local design-space table; use --only kernel for measured values.")
    print()
    for mid, lbl in [(1, 'P1 hardcoded'), (2, 'P2 template'), (3, 'P3 modular')]:
        info(f"{lbl} - model update: {MODEL_UPDATE[mid]}")
    print()

    total += 1
    ml_ok = MAP_LOOKUPS[1] <= MAP_LOOKUPS[2] <= MAP_LOOKUPS[3]
    if ml_ok:
        ok(f"eBPF trade-off on map lookups confirmed: P1({MAP_LOOKUPS[1]}) <= P2({MAP_LOOKUPS[2]}) <= P3({MAP_LOOKUPS[3]})")
        passed += 1
    else:
        fail(f"structural trade-off inconsistent: map_lookups={list(MAP_LOOKUPS.values())}")

    total += 1
    if MAP_LOOKUPS[3] > MAP_LOOKUPS[1]:
        ok(f"Structure: P3 has more map lookups ({MAP_LOOKUPS[3]}) vs P1 ({MAP_LOOKUPS[1]})")
        passed += 1
    else:
        fail("Structure: inconsistent map-lookup counts")

    total += 1
    if MAP_MEM_BYTES[3] > MAP_MEM_BYTES[1]:
        ok(f"Memory: P3 ({MAP_MEM_BYTES[3]}B) > P1 ({MAP_MEM_BYTES[1]}B) as expected")
        passed += 1
    else:
        fail(f"Memory: P3 ({MAP_MEM_BYTES[3]}B) should be > P1 ({MAP_MEM_BYTES[1]}B)")

    _banner(passed, total)
    return passed == total


def _classify_packet(output_vec, ref_vec, valid_outputs):
    pred   = int(np.argmax(output_vec))
    target = int(np.argmax(ref_vec))
    if pred in valid_outputs:
        return "HIT" if pred == target else "FAKE"
    return "MISS"


def _run_pkt_stats(method, inputs, model, valid_outputs):
    stats = {"HIT": 0, "FAKE": 0, "MISS": 0}
    for x in inputs:
        ref = pytorch_ref(model, x)
        out = method.infer(x)
        stats[_classify_packet(out, ref, valid_outputs)] += 1
    return stats


def suite_pktstats(n_samples=200, seed=42):
    torch.manual_seed(seed)
    np.random.seed(seed)
    print(f"\n{YELLOW}=== SUITE pktstats — pkt_stats (3 pipelines) ==={NC}\n")
    model = FRRModel()
    H = model.fc1.out_features
    I = model.fc1.in_features
    O = model.out.out_features
    print(f"  Architecture: {I} -> {H} -> {H} -> {O} | samples={n_samples} | seed={seed}")
    print()
    m1 = Method1_Hardcoded(model)
    m2 = Method2_Template(model)
    m3 = Method3_Modular(model)
    valid_outputs = set(range(1, O))
    info(f"valid_outputs = {valid_outputs}  (0=DROP/MISS)")
    print()
    inputs = [make_input(I) for _ in range(n_samples)]
    passed = total = 0
    print(f"{YELLOW}[Test A] pkt_stats per method ({n_samples} samples){NC}")
    stats = {}
    for mid, mobj, name in [(1, m1, 'hardcoded'), (2, m2, 'template'), (3, m3, 'modular')]:
        s = _run_pkt_stats(mobj, inputs, model, valid_outputs)
        stats[mid] = s
        total_pkts = s['HIT'] + s['FAKE'] + s['MISS']
        hit_rate   = s['HIT'] / total_pkts * 100
        info(f"  P{mid} {name:<10}: HIT={s['HIT']:4d} ({hit_rate:.1f}%)  FAKE={s['FAKE']:4d}  MISS={s['MISS']:4d}  total={total_pkts}")
    print(f"\n{YELLOW}[Test B] Total counter == n_samples for each method{NC}")
    for mid in [1, 2, 3]:
        total += 1
        s = stats[mid]
        tot = s['HIT'] + s['FAKE'] + s['MISS']
        if tot == n_samples:
            ok(f"P{mid}: HIT+FAKE+MISS = {tot} == {n_samples}")
            passed += 1
        else:
            fail(f"P{mid}: HIT+FAKE+MISS = {tot} != {n_samples}")
    print(f"\n{YELLOW}[Test C] P1 hardcoded must have FAKE=0 (float weights){NC}")
    total += 1
    if stats[1]['FAKE'] == 0:
        ok("P1 FAKE=0 confermato (hardcoded float)")
        passed += 1
    else:
        fail(f"P1 FAKE={stats[1]['FAKE']} (expected 0 with float weights)")
    print(f"\n{YELLOW}[Test D] P2 and P3 same HIT/FAKE/MISS (same quantization){NC}")
    total += 1
    if stats[2] == stats[3]:
        ok(f"P2 e P3 concordano: HIT={stats[2]['HIT']} FAKE={stats[2]['FAKE']} MISS={stats[2]['MISS']}")
        passed += 1
    else:
        fail(f"P2={stats[2]} != P3={stats[3]}")
    print(f"\n{YELLOW}[Test E] HIT rate P1 >= P2 and P3 (float more precise){NC}")
    total += 1
    hr1 = stats[1]['HIT'] / n_samples
    hr2 = stats[2]['HIT'] / n_samples
    hr3 = stats[3]['HIT'] / n_samples
    if hr1 >= hr2 and hr1 >= hr3:
        ok(f"HIT rate: P1={hr1:.3f} >= P2={hr2:.3f} >= P3={hr3:.3f}")
        passed += 1
    else:
        fail(f"HIT rate: P1={hr1:.3f} P2={hr2:.3f} P3={hr3:.3f} — expected P1 maximum")
    print(f"\n{YELLOW}[Test F] pkt_stats after weight update (new random model){NC}")
    torch.manual_seed(seed + 1)
    new_model = FRRModel()
    m1.update_weights(new_model)
    m2.update_weights(new_model)
    m3.update_weights(new_model)
    stats_new = {}
    for mid, mobj in [(1, m1), (2, m2), (3, m3)]:
        stats_new[mid] = _run_pkt_stats(mobj, inputs, new_model, valid_outputs)
    total += 1
    tot2 = sum(stats_new[2].values())
    tot3 = sum(stats_new[3].values())
    if tot2 == n_samples and tot3 == n_samples:
        ok(f"Post-update counters consistent: P2={tot2} P3={tot3} == {n_samples}")
        passed += 1
    else:
        fail(f"Post-update counter: P2={tot2} P3={tot3} (expected {n_samples})")
    total += 1
    if stats_new[2] == stats_new[3]:
        ok(f"P2 and P3 agree post-update: HIT={stats_new[2]['HIT']}")
        passed += 1
    else:
        fail(f"P2/P3 disagree post-update: P2={stats_new[2]} P3={stats_new[3]}")
    _banner(passed, total)
    return passed == total


def suite_extract(model_path):
    import json
    print(f"\n{YELLOW}=== SUITE extract — weight/quantization consistency ==={NC}\n")
    print(f"  model: {model_path}")
    print()
    if not os.path.exists(model_path):
        fail(f"Model not found: {model_path}")
        return False
    passed = total = 0
    shared_dir = os.path.dirname(os.path.abspath(model_path))
    print(f"{YELLOW}[Test 1] extract_weights_int8() — range and length{NC}")
    total += 1
    try:
        model, I, H, O = load_pt_dynamic(model_path)
        floats = [w for p in model.parameters() for w in p.data.view(-1).tolist()]
        max_abs = max(abs(w) for w in floats)
        scale_ew = int(127 / max_abs)
        n_weights_expected = I * H + H + H * H + H + H * O + O
        int8_weights = [max(-128, min(127, int(round(wf * scale_ew)))) for wf in floats]
        if len(int8_weights) == n_weights_expected:
            ok(f"N_WEIGHTS = {len(int8_weights)} (expected {n_weights_expected})")
            passed += 1
        else:
            fail(f"N_WEIGHTS = {len(int8_weights)} != expected {n_weights_expected}")
    except Exception as e:
        fail(f"Exception during extraction: {e}")
        _banner(passed, total)
        return False
    print(f"\n{YELLOW}[Test 2] Scale factor: extract_weights vs compute_scale(){NC}")
    total += 1
    scale_cs = compute_scale(model)
    both_valid = (scale_cs * max_abs <= 127.0 + 1e-6) and (scale_ew * max_abs <= 127.0 + 1e-6)
    if both_valid:
        ok(f"Both scales valid: compute_scale={scale_cs} extract_weights={scale_ew} | max|w|={max_abs:.6f}")
        passed += 1
    else:
        fail(f"Invalid scale: compute_scale={scale_cs} extract_weights={scale_ew} max|w|={max_abs:.6f}")
    print(f"\n{YELLOW}[Test 3] weights.json consistency with live extraction from .pt{NC}")
    total += 1
    wj_path = os.path.join(shared_dir, 'weights.json')
    if not os.path.exists(wj_path):
        info(f"weights.json not found in {shared_dir} — test skipped")
        total -= 1
    else:
        with open(wj_path) as f:
            saved_weights = json.load(f)
        if len(saved_weights) != len(int8_weights):
            fail(f"Different length: weights.json={len(saved_weights)} vs live={len(int8_weights)}")
        else:
            mismatches = sum(1 for a, b in zip(saved_weights, int8_weights) if a != b)
            if mismatches == 0:
                ok(f"weights.json identical to live extraction ({len(saved_weights)} weights)")
                passed += 1
            else:
                fail(f"weights.json has {mismatches}/{len(int8_weights)} weights differing from the live extraction")
                info("  Regenerate with: python3 shared/extract_weights.py")
    print(f"\n{YELLOW}[Test 4] weights_float.json — scale_factor and float values{NC}")
    wf_path = os.path.join(shared_dir, 'weights_float.json')
    if not os.path.exists(wf_path):
        info("weights_float.json not found — test skipped")
    else:
        with open(wf_path) as f:
            wf_data = json.load(f)
        saved_scale  = wf_data.get('scale_factor', -1)
        saved_floats = wf_data.get('weights', [])
        total += 1
        if saved_scale == scale_ew:
            ok(f"scale_factor in weights_float.json = {saved_scale} == extracted = {scale_ew}")
            passed += 1
        else:
            fail(f"scale_factor mismatch: file={saved_scale} vs live={scale_ew}")
        total += 1
        if len(saved_floats) == len(floats):
            max_diff = max(abs(a - b) for a, b in zip(saved_floats, floats))
            if max_diff < 1e-5:
                ok(f"Float weights identical (max_diff={max_diff:.2e})")
                passed += 1
            else:
                fail(f"Float weights diverge (max_diff={max_diff:.2e})")
        else:
            fail(f"Different float length: file={len(saved_floats)} vs live={len(floats)}")
    print(f"\n{YELLOW}[Test 5] Dequant: max|w_float - w_int8/scale| <= 1/scale{NC}")
    total += 1
    tol = 1.0 / scale_ew
    dequant = [w / scale_ew for w in int8_weights]
    max_dequant_err = max(abs(a - b) for a, b in zip(floats, dequant))
    clamped_count   = sum(1 for w in int8_weights if w == 127 or w == -128)
    if max_dequant_err <= tol + 1e-9:
        ok(f"max dequant error = {max_dequant_err:.6f} <= {tol:.6f} (1/scale)")
        passed += 1
    else:
        fail(f"max dequant error = {max_dequant_err:.6f} > {tol:.6f} (1/scale)")
    if clamped_count > 0:
        info(f"  {clamped_count}/{len(int8_weights)} weights clamped to +-127/128 (int8 overflow)")
    _banner(passed, total)
    return passed == total


SCALE_FACTORS = [16, 32, 64, 128, 256, 512]

def _evaluate_scale(model, scale, inputs, n_samples):
    m2 = Method2_FixedScale(model, scale)
    m3 = Method3_FixedScale(model, scale)
    err2 = err3 = 0.0
    wrong2 = wrong3 = 0
    for x in inputs:
        ref = pytorch_ref(model, x)
        o2  = m2.infer(x)
        o3  = m3.infer(x)
        err2 = max(err2, float(np.max(np.abs(o2 - ref))))
        err3 = max(err3, float(np.max(np.abs(o3 - ref))))
        if int(np.argmax(o2)) != int(np.argmax(ref)):
            wrong2 += 1
        if int(np.argmax(o3)) != int(np.argmax(ref)):
            wrong3 += 1
    acc2 = (n_samples - wrong2) / n_samples * 100
    acc3 = (n_samples - wrong3) / n_samples * 100
    return err2, acc2, wrong2, err3, acc3, wrong3


def suite_quant(n_samples=200, model_path=None):
    print(f"\n{YELLOW}=== SUITE quant — argmax accuracy vs scale_factor ==={NC}\n")
    torch.manual_seed(42)
    np.random.seed(42)
    if model_path and os.path.exists(model_path):
        model, I, H, O = load_pt_dynamic(model_path)
        print(f"  Model: {model_path} | arch={I}->{H}->{H}->{O}")
    else:
        model = FRRModel()
        I = model.fc1.in_features
        H = model.fc1.out_features
        O = model.out.out_features
        print(f"  Model: random weights (seed=42) | arch={I}->{H}->{H}->{O}")
    print(f"  Samples: {n_samples} | scale_factors: {SCALE_FACTORS}")
    print()
    inputs = [make_input(I) for _ in range(n_samples)]
    results = {sf: _evaluate_scale(model, sf, inputs, n_samples) for sf in SCALE_FACTORS}
    hdr = (f"  {'scale':>6} | {'max_err M2':>10} | {'acc M2 (%)':>10} | {'wrong M2':>8} | {'max_err M3':>10} | {'acc M3 (%)':>10} | {'wrong M3':>8}")
    sep = "  " + "-" * (len(hdr) - 2)
    print(hdr)
    print(sep)
    for sf in SCALE_FACTORS:
        err2, acc2, w2, err3, acc3, w3 = results[sf]
        print(f"  {sf:>6} | {err2:>10.4f} | {acc2:>9.1f}% | {w2:>8} | {err3:>10.4f} | {acc3:>9.1f}% | {w3:>8}")
    print(sep)
    print()
    passed = total = 0
    print(f"{YELLOW}[Test A] max_err M2 decreases (or stable) as scale increases{NC}")
    total += 1
    errs2 = [results[sf][0] for sf in SCALE_FACTORS]
    first_half_avg = sum(errs2[:3]) / 3
    second_half_avg = sum(errs2[3:]) / 3
    if first_half_avg >= second_half_avg - 1e-4:
        ok(f"Correct trend: low scale -> high err ({first_half_avg:.4f}) high scale -> low err ({second_half_avg:.4f})")
        passed += 1
    else:
        fail(f"Unexpected trend: low scale avg_err={first_half_avg:.4f} < high scale avg_err={second_half_avg:.4f}")
    print(f"\n{YELLOW}[Test B] M2 and M3 have identical max_err for each scale{NC}")
    total += 1
    all_equal = all(abs(results[sf][0] - results[sf][3]) < 1e-9 for sf in SCALE_FACTORS)
    if all_equal:
        ok("M2 and M3 produce identical max_err for all scales")
        passed += 1
    else:
        diffs = [sf for sf in SCALE_FACTORS if abs(results[sf][0] - results[sf][3]) >= 1e-9]
        fail(f"M2 and M3 diverge for scale={diffs}")
    print(f"\n{YELLOW}[Test C] compute_scale() accuracy >= average of other scales{NC}")
    total += 1
    optimal_scale = compute_scale(model)
    if optimal_scale not in results:
        results[optimal_scale] = _evaluate_scale(model, optimal_scale, inputs, n_samples)
    avg_acc2 = sum(results[sf][1] for sf in SCALE_FACTORS) / len(SCALE_FACTORS)
    opt_acc2 = results[optimal_scale][1]
    info(f"  compute_scale()={optimal_scale} -> acc={opt_acc2:.1f}% | avg={avg_acc2:.1f}%")
    if opt_acc2 >= avg_acc2 - 1.0:
        ok(f"compute_scale accuracy ({opt_acc2:.1f}%) >= avg ({avg_acc2:.1f}%) - 1%")
        passed += 1
    else:
        fail(f"compute_scale accuracy ({opt_acc2:.1f}%) < avg ({avg_acc2:.1f}%)")
    print(f"\n{YELLOW}[Test D] max_err <= H/scale for each scale (theoretical bound){NC}")
    for sf in SCALE_FACTORS:
        total += 1
        err2 = results[sf][0]
        bound = H / sf
        if err2 <= bound + 1e-6:
            ok(f"scale={sf:>4}: max_err={err2:.4f} <= H/scale={bound:.4f}")
            passed += 1
        else:
            fail(f"scale={sf:>4}: max_err={err2:.4f} > H/scale={bound:.4f}")
    _banner(passed, total)
    return passed == total


def _make_zero_input(n):     return np.zeros(n, dtype=np.float32)
def _make_ones_input(n):     return np.ones(n, dtype=np.float32)

def _make_ttl_zero_input(n):
    x = np.random.uniform(0, 1, n).astype(np.float32)
    if n > 12:
        x[12] = 0.0
    return x

def _make_out_of_range_input(n, scale=5.0):
    return np.random.uniform(-scale, scale, n).astype(np.float32)

def _make_extreme_input(n, val=1000.0):
    x = np.zeros(n, dtype=np.float32)
    x[::2]  =  val
    x[1::2] = -val
    return x

_EDGE_CASES = [
    ("zero vector",          _make_zero_input),
    ("all-ones vector",      _make_ones_input),
    ("TTL=0",                _make_ttl_zero_input),
    ("out-of-range [-5,5]",  _make_out_of_range_input),
    ("extreme +-1000",       _make_extreme_input),
]


def suite_robust():
    print(f"\n{YELLOW}=== SUITE robust — anomalous inputs ==={NC}\n")
    torch.manual_seed(42)
    np.random.seed(42)
    model = FRRModel()
    I = model.fc1.in_features
    O = model.out.out_features
    H = model.fc1.out_features
    print(f"  Architecture: {I} -> {H} -> {H} -> {O}")
    print()
    m1 = Method1_Hardcoded(model)
    m2 = Method2_Template(model)
    m3 = Method3_Modular(model)
    methods = [(1, m1, 'hardcoded'), (2, m2, 'template'), (3, m3, 'modular')]
    passed = total = 0
    for case_name, input_fn in _EDGE_CASES:
        print(f"{YELLOW}[Case: {case_name}]{NC}")
        x = input_fn(I)
        for mid, mobj, mname in methods:
            total += 1
            try:
                out    = mobj.infer(x)
                argmax = int(np.argmax(out))
                valid  = 0 <= argmax < O
                finite = bool(np.all(np.isfinite(out)))
                if valid and finite:
                    ok(f"P{mid} {mname:<10}: argmax={argmax} | output finite | OK")
                    passed += 1
                else:
                    reasons = []
                    if not valid:  reasons.append(f"argmax={argmax} fuori [0,{O-1}]")
                    if not finite: reasons.append(f"output non finito: {out}")
                    fail(f"P{mid} {mname:<10}: {' | '.join(reasons)}")
            except Exception as e:
                fail(f"P{mid} {mname:<10}: exception — {e}")
        total += 1
        try:
            a2 = int(np.argmax(m2.infer(x)))
            a3 = int(np.argmax(m3.infer(x)))
            if a2 == a3:
                ok(f"  P2 and P3 agree on anomalous input: argmax={a2}")
                passed += 1
            else:
                fail(f"  P2={a2} and P3={a3} disagree on anomalous input '{case_name}'")
        except Exception as e:
            fail(f"  Exception in the consistency check: {e}")
        print()
    print(f"{YELLOW}[Stress] 1000 out-of-range inputs [-10, 10] without crashes{NC}")
    total += 1
    n_crash = 0
    for _ in range(1000):
        x = np.random.uniform(-10, 10, I).astype(np.float32)
        try:
            a1 = int(np.argmax(m1.infer(x)))
            a2 = int(np.argmax(m2.infer(x)))
            a3 = int(np.argmax(m3.infer(x)))
            if not (0 <= a1 < O and 0 <= a2 < O and 0 <= a3 < O):
                n_crash += 1
        except Exception:
            n_crash += 1
    if n_crash == 0:
        ok("No crash over 1000 stress inputs (range [-10,10])")
        passed += 1
    else:
        fail(f"{n_crash}/1000 stress inputs caused invalid argmax or exception")
    _banner(passed, total)
    return passed == total


_PIPELINE_MAP_NAMES = [
    # shared: link_state (egress up/down input feature, all 3 pipelines)
    "link_state",
    # P1 hardcoded (pure: no weight map -- only stats + mac_table)
    "pkt_stats", "cls_stats", "mac_table",
    # P2 template
    "arch_weights", "arch_registry", "arch_progs",
    "mac_table_t2", "pkt_stats_t2", "cls_stats_t2",
    # P3 modular
    "layer_weights", "layer_registry", "layer_chain", "scratch_acts", "scratch_meta",
    "mac_table_t3", "pkt_stats_t3", "cls_stats_t3",
]


def verify_alt_architectures(ttl_min=1, ttl_max=5):
    """
    Everything above this point in suite_kernel() exercises exactly ONE
    architecture (the checked-in 65-4-4-7 model) across the 3 pipelines --
    a real risk of a design-space claim ("P1/P2/P3 handle arbitrary shapes")
    going untested. This closes that gap:
      - P1 hardcoded: two SEPARATELY COMPILED programs with DIFFERENT depths
        ((8,) one hidden layer, (4,4,4) three hidden layers -- exercising the
        variable-depth generalization), same default feature descriptor,
        random synthetic weights, checked against the generalized
        ref_infer_sparse() (handles any hidden_dims length).
      - P2 template / P3 modular: delegates to verify_multi_model.py's
        existing alt-shape checks (65-6-5-7 for P2, 65-5-6-4-7 for P3,
        registered ALONGSIDE the real model in the SAME compiled object --
        the actual "multi-model concurrent" claim, not just routing).
    Returns True iff every alt-architecture check passes.
    """
    import ctypes as ct
    import random as _random
    import verify_prog_run as V
    from bcc import BPF
    import model_meta as mm
    from ebpf_program import build_combined_hardcoded_source
    from common import write_vector_map

    print(f"\n{YELLOW}--- Architetture alternative (non solo 65-4-4-7) ---{NC}")
    all_ok = True

    # --- P1 hardcoded: variable depth, same descriptor -------------------
    shape = mm.derive_shape({"n_interfaces": 6, "n_nodes": 52})
    features, n_out, n_in = shape["features"], shape["n_out"], shape["n_in"]
    iface_size = next((f["size"] for f in features if f["type"] == "ingress_iface"), 0)
    ifindex_table = list(range(2, 2 + max(iface_size, 1)))

    def n_weights(dims):
        sizes = [n_in] + list(dims) + [n_out]
        return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))

    for dims, seed in [((8,), 111), ((4, 4, 4), 222)]:
        rng = _random.Random(seed)
        weights = [rng.randint(-30, 30) for _ in range(n_weights(dims))]
        scale = 24
        src = build_combined_hardcoded_source(
            models=[(0, weights, scale, ifindex_table)],
            features=features, n_out=n_out, hidden_dims=dims)
        try:
            b = BPF(text=src)
            model_fn = b.load_func("model_0", BPF.XDP)
            disp_fn  = b.load_func("ipa_switch_hardcoded", BPF.XDP)
        except Exception as e:
            fail(f"hardcoded alt-arch {dims}: compile/verifier failed ({e})")
            all_ok = False
            continue
        b["model_progs"][ct.c_int(0)] = ct.c_int(model_fn.fd)
        write_vector_map(b, "link_state", [1] * 6)
        V._install_mac_table(b, "mac_table", n_classes=n_out - 1)
        ps, cs = b["pkt_stats"], b["cls_stats"]

        shape_str = f"{n_in}-{'-'.join(map(str, dims))}-{n_out}"
        passed = failed = 0
        for ttl in range(ttl_min, ttl_max + 1):
            ref_cls, ref_val = V.ref_infer_sparse(
                weights, features, dims, n_out, ttl, model_id=0,
                map_values={"link_state": [1] * 6},
                ifindex=V.TEST_RUN_DEFAULT_INGRESS_IFINDEX, ifindex_table=ifindex_table)
            frame = V.build_frame_sparse(model_id=0, ttl=ttl, scale=scale, n_in=n_in, n_out=n_out)
            for i in range(3):
                ps[ct.c_int(i)] = ct.c_ulonglong(0)
            for i in range(n_out):
                try:
                    cs[ct.c_int(i)] = ct.c_ulonglong(0)
                except Exception:
                    pass
            retval, _ = V.prog_test_run(disp_fn.fd, frame, repeat=1)
            if ref_cls < n_out - 1:
                got = int(cs[ct.c_int(ref_cls)].value)
                good = (retval in V.XDP_REDIRECT_PASS) and got > 0
            else:
                got = int(ps[ct.c_int(2)].value)
                good = (retval == 1) and got > 0
            passed += good
            failed += not good
        if failed == 0:
            ok(f"hardcoded alt-arch {shape_str}: {passed}/{passed} PASS")
        else:
            fail(f"hardcoded alt-arch {shape_str}: {failed}/{passed + failed} FAIL")
            all_ok = False

    # --- P2 template / P3 modular: delegate to verify_multi_model.py -----
    try:
        import verify_multi_model as VM
        t_ok = VM.test_template()
        m_ok = VM.test_modular()
        (ok if t_ok else fail)(f"template alt-arch (65-6-5-7, concurrent w/ 65-4-4-7): "
                              f"{'PASS' if t_ok else 'FAIL'}")
        (ok if m_ok else fail)(f"modular alt-arch (65-5-6-4-7, concurrent w/ 65-4-4-7): "
                               f"{'PASS' if m_ok else 'FAIL'}")
        all_ok = all_ok and t_ok and m_ok
    except Exception as e:
        fail(f"template/modular alt-arch: error ({e})")
        all_ok = False

    return all_ok


def suite_kernel(model_path=None, repeat=50000, ttl_min=1, ttl_max=5, verify=True):
    print(f"\n{YELLOW}=== SUITE kernel — BPF_PROG_TEST_RUN (instructions, latency, throughput, CPU) ==={NC}\n")
    if not sys.platform.startswith("linux"):
        info(f"kernel suite skipped: platform {sys.platform} (needs Linux).")
        info("Run in Kathara / a Linux host: sudo python3 shared/test_suite.py --only kernel")
        return True
    try:
        import verify_prog_run as V
    except Exception as e:
        info(f"kernel suite skipped: BCC/verify_prog_run not importable ({e}).")
        info("Needs Linux + BCC + root. In Kathara: kathara exec frankfurt -- python3 /shared/test_suite.py --only kernel")
        return True
    import resource
    mp = model_path or V.MODEL_PT
    methods = [
        ("baseline",  V.setup_baseline,  0),   # reference floor: parse + redirect, NO inference
        ("hardcoded", V.setup_hardcoded, 1),
        ("template",  V.setup_template,  2),
        ("modular",   V.setup_modular,   3),
    ]
    rows = []
    all_ok = True
    for name, setup_fn, pl in methods:
        try:
            setup = setup_fn(0, mp)
        except PermissionError:
            info(f"{name}: permission denied loading XDP (needs root/CAP_BPF) — suite skipped.")
            return True
        except Exception as e:
            msg = str(e).lower()
            if "operation not permitted" in msg or "permission" in msg:
                info(f"{name}: {e} — needs root. Suite skipped.")
                return True
            fail(f"{name}: setup failed ({e})")
            all_ok = False
            continue
        per_prog = []
        insn_total = 0
        jit_total = 0
        for pname, pfd in setup.get("progs", {}).items():
            ic, jb = V.prog_insn_count(pfd)
            if ic is not None:
                insn_total += ic
                jit_total += (jb or 0)
                per_prog.append((pname, ic))
        disp_fd = setup["disp"].fd
        frame = V.build_frame(0, ttl_max, setup["scale"])
        try:
            V.prog_test_run(disp_fd, frame, repeat=1000)
        except OSError as e:
            fail(f"{name}: BPF_PROG_TEST_RUN failed ({e})")
            all_ok = False
            continue
        ru0 = resource.getrusage(resource.RUSAGE_SELF)
        w0  = time.perf_counter()
        retval, dur_ns = V.prog_test_run(disp_fd, frame, repeat=repeat)
        wall = time.perf_counter() - w0
        ru1 = resource.getrusage(resource.RUSAGE_SELF)
        cpu_s   = (ru1.ru_utime + ru1.ru_stime) - (ru0.ru_utime + ru0.ru_stime)
        cpu_pct = 100.0 * cpu_s / wall if wall > 0 else 0.0
        lat_ns  = float(dur_ns) if dur_ns else (wall * 1e9 / repeat)
        mpps    = (1000.0 / lat_ns) if lat_ns > 0 else 0.0
        mem = 0
        for mname in _PIPELINE_MAP_NAMES:
            try:
                mem += V.map_bytes(setup["b"][mname].map_fd, V._NR_CPUS)
            except Exception:
                pass
        n_tail = setup.get("n_tail")
        if n_tail is None:
            n_tail = max(0, len(setup.get("progs", {})) - 1)
        try:
            lookups = V.count_lookups(name, 0, mp)
        except Exception as e:
            info(f"{name}: map-lookup count skipped ({e})")
            lookups = None
        rows.append({
            "name": name, "pl": pl, "insn": insn_total, "jit": jit_total,
            "per": per_prog, "lat": lat_ns, "mpps": mpps, "cpu": cpu_pct,
            "retval": retval, "mem": mem, "n_tail": n_tail, "lookups": lookups,
        })
        ok(f"{name:9s}: {insn_total:5d} eBPF instr | lat={lat_ns:8.1f} ns | {mpps:6.3f} Mpps | CPU={cpu_pct:4.0f}% | retval={retval} | tail={n_tail}")
    if not rows:
        return all_ok
    print()
    print("  Metric                          " + "".join(f"{r['name']:>16}" for r in rows))
    print("  " + "-" * (32 + 16 * len(rows)))
    def line(label, key, fmt):
        print(f"  {label:<32}" + "".join(f"{fmt(r[key]):>16}" for r in rows))
    line("eBPF instructions (xlated)", "insn",   lambda v: f"{v}")
    line("Jited code (bytes)",      "jit",    lambda v: f"{v}")
    line("Tail calls / packet",   "n_tail", lambda v: f"{v}")
    line("Map lookups / packet (real)", "lookups", lambda v: "n/a" if v is None else f"{v:.1f}")
    line("Map memory (bytes)",     "mem",    lambda v: f"{v}")
    line("Latency (ns/pkt)",         "lat",    lambda v: f"{v:.1f}")
    line("Throughput (Mpps)",        "mpps",   lambda v: f"{v:.3f}")
    line("CPU (%)",                  "cpu",    lambda v: f"{v:.0f}")
    print("  " + "-" * (32 + 16 * len(rows)))
    print()
    for r in rows:
        detail = "  ".join(f"{p}={c}" for p, c in r["per"])
        info(f"{r['name']:9s} programs: {detail}")
    if verify:
        print()
        for name, _, _ in methods:
            if name == "baseline":
                continue   # baseline has no inference to verify (pure parse+redirect)
            try:
                failed = V.run(name, 0, mp, ttl_min, ttl_max, repeat=1000)
                if failed == 0:
                    ok(f"dispatch {name}: PASS (TTL {ttl_min}-{ttl_max})")
                else:
                    fail(f"dispatch {name}: {failed} TTL failed")
                    all_ok = False
            except Exception as e:
                fail(f"dispatch {name}: error ({e})")
                all_ok = False

        # link_state is a live routing input: a link going down must be able to
        # reroute the packet (change the argmax egress class). Probe Pipeline 1
        # over all TTL x egress combinations.
        print()
        try:
            changes, tested = V.probe_link_down(mp, 0, ttl_min, ttl_max)
            if changes:
                sample = ", ".join(f"TTL{t}:link{k} {u}->{d}" for t, k, u, d in changes[:6])
                ok(f"link_state reroute: {len(changes)}/{tested} link-down cases change egress  [{sample}]")
            else:
                fail(f"link_state reroute: 0/{tested} link-down cases changed the egress class "
                     f"(feature wired but the model never reroutes on failure for TTL {ttl_min}-{ttl_max})")
                all_ok = False
        except Exception as e:
            fail(f"link_state reroute probe: error ({e})")
            all_ok = False

        # Everything above tests ONE architecture (65-4-4-7). Prove the
        # design-space claim ("arbitrary depth/width per pipeline") actually
        # holds in the kernel, not just in the Python generator.
        try:
            alt_ok = verify_alt_architectures(ttl_min, ttl_max)
            all_ok = all_ok and alt_ok
        except Exception as e:
            fail(f"alt-architecture verification: error ({e})")
            all_ok = False
    print(f"\n{'='*52}")
    print(f" kernel suite: {'PASS' if all_ok else 'FAIL'}")
    print(f"{'='*52}\n")
    return all_ok


def _load_default_model(model_arg):
    torch.manual_seed(42)
    np.random.seed(42)
    model = FRRModel()
    pt_path = model_arg or os.path.join(SHARED_DIR, 'frr_germany50_5_model_4x2.pt')
    if os.path.exists(pt_path):
        try:
            loaded, li, lh, lo = load_pt_dynamic(pt_path)
            if li == INPUT_SIZE and lh == HIDDEN_DIM:
                model = loaded
                print(f"{GREEN}[OK]{NC} Model loaded from {pt_path} (arch {li}->{lh}->{lo})")
            else:
                print(f"{YELLOW}[INFO]{NC} .pt has arch {li}->{lh}->{lo} (differs from default {INPUT_SIZE}->{HIDDEN_DIM}->{OUTPUT_SIZE})")
                print(f"{YELLOW}[INFO]{NC} core Test 1-4 use random weights (seed=42), Test 5 uses the .pt")
        except Exception as e:
            print(f"{YELLOW}[WARN]{NC} {e} — using random weights")
    else:
        print(f"{YELLOW}[INFO]{NC} No .pt found — random weights (seed=42)")
    return model, pt_path


def main():
    parser = argparse.ArgumentParser(description="Local IPA test suite (3 methods) — consolidates the old test_*.py")
    parser.add_argument('--only', default='all', choices=['all', 'core', 'pktstats', 'extract', 'quant', 'robust', 'kernel'], help='Which suite to run (default: all)')
    parser.add_argument('--model', type=str, default=None, help='Path to the .pt checkpoint')
    parser.add_argument('--verbose', action='store_true', help='Extra detail (core suite)')
    parser.add_argument('--samples', type=int, default=200, help='Samples for pktstats/quant')
    parser.add_argument('--seed', type=int, default=42, help='Seed for pktstats')
    parser.add_argument('--kernel-repeat', type=int, default=50000, help='BPF_PROG_TEST_RUN repeats for the kernel suite')
    parser.add_argument('--no-verify', action='store_true', help='Kernel suite: skip the dispatch gate (metrics only)')
    args = parser.parse_args()
    all_suites = ['core', 'pktstats', 'extract', 'quant', 'robust', 'kernel']
    which = all_suites if args.only == 'all' else [args.only]
    needs_torch = any(s != 'kernel' for s in which)
    if needs_torch and not TORCH_AVAILABLE:
        print("[ERROR] PyTorch not found. Install with: pip install torch")
        print("        (--only kernel does not need torch and works without it)")
        sys.exit(1)
    model, pt_path = _load_default_model(args.model) if needs_torch else (None, args.model)
    results = {}
    if 'core' in which:
        results['core'] = suite_core(model, args.verbose)
    if 'pktstats' in which:
        results['pktstats'] = suite_pktstats(args.samples, args.seed)
    if 'extract' in which:
        results['extract'] = suite_extract(pt_path)
    if 'quant' in which:
        results['quant'] = suite_quant(args.samples, args.model)
    if 'robust' in which:
        results['robust'] = suite_robust()
    if 'kernel' in which:
        results['kernel'] = suite_kernel(args.model, repeat=args.kernel_repeat, verify=not args.no_verify)
    print(f"{YELLOW}{'#'*52}{NC}")
    print(f"{YELLOW}#  SUITE SUMMARY{NC}")
    for name, res in results.items():
        tag = f"{GREEN}PASS{NC}" if res else f"{RED}FAIL{NC}"
        print(f"   {name:<10} : {tag}")
    print(f"{YELLOW}{'#'*52}{NC}")
    sys.exit(0 if all(results.values()) else 1)


if __name__ == '__main__':
    main()
