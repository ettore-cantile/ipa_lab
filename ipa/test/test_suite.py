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
  python3 ipa/test/test_suite.py                       # every suite (kernel skipped without BCC)
  python3 ipa/test/test_suite.py --only core --verbose
  python3 ipa/test/test_suite.py --only quant --samples 200
  sudo python3 ipa/test/test_suite.py --only kernel    # kernel metrics (root)
  sudo python3 ipa/test/test_suite.py --only kernel     # any Linux host + BCC
"""

import argparse
import time
import sys
import os

# Lives in ipa/test/; pipeline modules (ebpf_program, extract_weights, ...)
# and the .pt/.json data files live one level up in shared/.
_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

# torch is optional at import time: `--only kernel` never touches a torch
# model (it drives verify_prog_run.py / BCC directly), so it must keep working
# on nodes that don't have torch installed. main() hard-fails
# with a clear error only if a suite that actually needs torch is requested.
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

import numpy as np

# Reference architecture: RESOLVED FROM THE DESCRIPTOR, not written here.
#
# This block used to hold `N_INTERFACES = 6`, `N_NODES = 22`, `HIDDEN_DIM = 32`,
# `INPUT_SIZE = 35`, `OUTPUT_SIZE = 7` -- a shape that exists in no pipeline.
# The checkpoint is 65-4-4-7, so `_load_default_model`'s guard
#     if li == INPUT_SIZE and lh == HIDDEN_DIM
# read `65 == 35 and 4 == 32` and was UNSATISFIABLE: the checkpoint was loaded,
# discarded, and four of the six suites ran random weights on a 35-32-32-7
# model instead. Worse, the class semantics printed alongside them came out
# drop_class=6 while the real model's is 5.
#
# Everything now comes from model_meta (features -> n_in, declared n_out,
# declared hidden_dims), so the "default" architecture IS the descriptor's
# architecture and the guard can actually hold.
def reference_shape() -> dict:
    """{n_in, n_out, hidden_dims} for the model this repo is configured for.

    Resolved once per call from model_meta.json + the topology config. No
    module-level constants: a constant here is a scenario assumption frozen at
    import time, which is exactly what went wrong.
    """
    import model_meta as _mm
    shape = _mm.derive_shape(_mm.load_model_meta(
                                 os.path.join(SHARED_DIR, "weights.json")),
                             topology_config=_mm.load_topology_config())
    return {"n_in": shape["n_in"], "n_out": shape["n_out"],
            "hidden_dims": list(shape["hidden_dims"])}

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


def suite_semantics(n_out: int):
    """Semantics for a model of width `n_out`, from the descriptor if it fits.

    model_meta.json is the authority when its n_out matches. Otherwise the
    reference FORWARD.../DROP-last layout is returned AND announced, because a
    guess that is printed can be contradicted by the reader; a guess that is
    silent (the old behaviour) cannot.
    """
    from class_semantics import ClassSemantics
    try:
        import model_meta as _mm
        meta = _mm.load_model_meta(os.path.join(SHARED_DIR, "weights.json"))
        if meta.get("class_semantics"):
            sem = ClassSemantics.from_json(meta)
            if sem.n_out == n_out:
                return sem
            info(f"  descriptor declares n_out={sem.n_out}, this model has "
                 f"n_out={n_out}: descriptor not applicable")
    except Exception as e:
        info(f"  could not read class_semantics from the descriptor: {e}")
    info(f"  falling back to the reference layout for n_out={n_out}: "
         f"FORWARD 0..{n_out - 2}, DROP {n_out - 1} (ASSUMED, not declared)")
    return ClassSemantics.forward_then_drop(n_out - 1, drop_class=n_out - 1,
                                            n_out=n_out)


def decode_nexthop(argmax_idx: int, semantics=None) -> str:
    """Render a predicted class, keeping class / action / port distinct.

    The previous body was `if argmax_idx == 0: return "DROP"` followed by
    `eth{argmax_idx - 1}` -- an abandoned convention (DROP=0, ports shifted by
    one) that no other part of the system used, so class 2 was printed as
    "eth1" while the datapath forwarded it out port 2. It never entered an
    assertion, so nothing failed; the logs were simply wrong.

    With `semantics` the output is the full chain. Without it, the class index
    is printed as an index and NOT decorated with an interface name -- refusing
    to guess is the point.
    """
    if semantics is not None:
        from class_semantics import format_decision
        return format_decision(argmax_idx, semantics)
    return f"class={argmax_idx} action=? (no semantics supplied)"


if TORCH_AVAILABLE:
    class FRRModel(nn.Module):
        """Two-hidden-layer MLP matching the pipelines' shape family.

        The defaults come from the DESCRIPTOR, resolved at construction time,
        not from module constants fixed at import time. `FRRModel()` therefore
        builds the architecture this repo is actually configured for.
        """

        def __init__(self, input_size=None, hidden_dim=None, output_size=None):
            if input_size is None or hidden_dim is None or output_size is None:
                _r = reference_shape()
                input_size  = _r["n_in"]        if input_size  is None else input_size
                hidden_dim  = _r["hidden_dims"][0] if hidden_dim is None else hidden_dim
                output_size = _r["n_out"]       if output_size is None else output_size
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


    def fresh_like(model: "nn.Module") -> "FRRModel":
        """A newly initialised model of the SAME shape as `model`.

        The "weight update" tests used a bare `FRRModel()`, which was a
        different architecture from the one under test whenever the two
        disagreed. Deriving the shape from the model keeps an update test an
        update test instead of a silent architecture swap.
        """
        return FRRModel(input_size=model.fc1.in_features,
                        hidden_dim=model.fc1.out_features,
                        output_size=model.out.out_features)


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


def _feature_groups(n_in: int):
    """[(kind, size)] for the descriptor's features, truncated/padded to n_in.

    Read from model_meta's FEATURE_CATALOG so the generated vector respects
    each feature's STRUCTURE (a one-hot gets exactly one 1, a dense_vector gets
    per-slot 0/1, a scalar gets a normalised value). Cached per n_in.
    """
    if n_in in _FEATURE_GROUPS_CACHE:
        return _FEATURE_GROUPS_CACHE[n_in]
    import model_meta as _mm
    try:
        shape = _mm.derive_shape(_mm.load_model_meta(
                                     os.path.join(SHARED_DIR, "weights.json")),
                                 topology_config=_mm.load_topology_config())
        groups = [(_mm.FEATURE_CATALOG[f["type"]]["kind"], f["size"])
                  for f in shape["features"]]
        if sum(g[1] for g in groups) != n_in:
            # A model of a different width than the descriptor (the alt-arch
            # sweeps). No structure is known for it, so say so by treating the
            # whole vector as one dense block rather than inventing groups.
            groups = [("dense_vector_map", n_in)]
    except Exception:
        groups = [("dense_vector_map", n_in)]
    _FEATURE_GROUPS_CACHE[n_in] = groups
    return groups


_FEATURE_GROUPS_CACHE = {}


def make_input(input_size=None):
    """A random input vector that respects the descriptor's feature structure.

    Was: 6 link_state bits + 6 iface one-hot + 1 ttl + 22 node one-hot, i.e.
    `N_INTERFACES`/`N_NODES` frozen at import time, zero-padded or truncated to
    whatever width the caller asked for. Padding a 35-wide vector out to 65
    fed the model 30 structural zeros where the node one-hot belongs, so no
    generated input ever exercised the node feature at all.
    """
    if input_size is None:
        input_size = reference_shape()["n_in"]
    parts = []
    for kind, size in _feature_groups(input_size):
        if kind == "onehot":
            v = np.zeros(size, dtype=np.float32)
            v[np.random.randint(0, size)] = 1.0
        elif kind == "scalar":
            v = np.random.uniform(0.0, 1.0, size).astype(np.float32)
        else:                                    # dense_vector_map
            v = np.random.randint(0, 2, size).astype(np.float32)
        parts.append(v)
    base = np.concatenate(parts) if parts else np.zeros(0, dtype=np.float32)
    if input_size > len(base):
        base = np.concatenate([base,
                               np.zeros(input_size - len(base), dtype=np.float32)])
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
    # Was: "output 0=DROP, 1=eth0, 2=eth1, ...". That is the abandoned
    # DROP=0/ports-shifted-by-one convention no part of the datapath ever
    # implemented -- printed for long enough to be quoted as fact.
    for _l in suite_semantics(O).summary().splitlines():
        info(_l)
    print()

    N = 50
    passed = total = 0

    print(f"{YELLOW}[Test 1] Output consistency & argmax ({N} samples){NC}")
    mm = {1: 0, 2: 0, 3: 0}
    me = {1: 0.0, 2: 0.0, 3: 0.0}
    ref_range = 0.0
    for i in range(N):
        x = make_input(I)
        ref = pytorch_ref(model, x)
        nr = int(np.argmax(ref))
        o1 = m1.infer(x)
        o2 = m2.infer(x)
        o3 = m3.infer(x)
        ref_range = max(ref_range, float(np.max(ref) - np.min(ref)))
        me[1] = max(me[1], float(np.max(np.abs(o1 - ref))))
        me[2] = max(me[2], float(np.max(np.abs(o2 - ref))))
        me[3] = max(me[3], float(np.max(np.abs(o3 - ref))))
        a1, a2, a3 = int(np.argmax(o1)), int(np.argmax(o2)), int(np.argmax(o3))
        if a1 != nr:
            mm[1] += 1
        if a2 != nr:
            mm[2] += 1
        if a3 != nr:
            mm[3] += 1
        if verbose:
            _rs = suite_semantics(O)
            print(f"    [sample {i:02d}] ref={decode_nexthop(nr, _rs)} "
                  f"| M1={decode_nexthop(a1, _rs)} "
                  f"| M2={decode_nexthop(a2, _rs)} "
                  f"| M3={decode_nexthop(a3, _rs)}")

    # Method 1's agreement used to be asserted without ever being computed: mm
    # had no key 1, the loop never compared a1 against nr, and the line below
    # printed "argmax 100% correct" with an unconditional passed += 1. It could
    # not fail. It is a real (if trivially satisfied) check now.
    #
    # What it does and does NOT establish: Method1_Hardcoded here holds the
    # model's FLOAT weights and does a float matmul, so it is numerically the
    # same computation as pytorch_ref -- agreement is expected by construction
    # and max_err is ~0. This is a self-consistency check on the harness, NOT
    # evidence about the deployed int8-literal Pipeline 1. That evidence comes
    # from the kernel suite, which compares the real XDP program's argmax
    # against an independent integer Python reference (verify_prog_run.ref_infer).
    total += 1
    if mm[1] == 0:
        passed += 1
        ok(f"Method 1 (float reference, no quantization): argmax {N}/{N} == PyTorch "
           f"| max_err={me[1]:.6f}  [harness self-check; quantized P1 is covered by --only kernel]")
    else:
        fail(f"Method 1 (float reference): {mm[1]}/{N} argmax differ from PyTorch "
             f"| max_err={me[1]:.6f} -- the float path must match exactly, this is a harness bug")

    for mid, name in [(2, 'template'), (3, 'modular')]:
        total += 1
        pct = mm[mid] / N * 100
        if pct <= 10:
            ok(f"Method {mid} ({name}): argmax {100-pct:.0f}% correct ({mm[mid]}/{N}) | max_err={me[mid]:.4f}")
            passed += 1
        else:
            fail(f"Method {mid} ({name}): {mm[mid]}/{N} argmax errati | max_err={me[mid]:.4f} | scale={m2.scale}")

    # Quantisation error, judged RELATIVE to the model's own output range.
    #
    # The bound used to be `tol = H / scale`, which is not a bound on anything:
    # it ignores the input width and magnitude, and it ignores that the error
    # compounds through three layers. It only ever passed because the suite was
    # secretly running a 35-32-32-7 random model at scale=512, where H/sc came
    # out 0.0625 and the error happened to be smaller. On the real checkpoint
    # (H=4, scale=16) the same formula gives 0.25 against a measured 3.08 --
    # not a regression, just the first time the number was computed on the
    # model the datapath runs.
    #
    # An absolute logit error is meaningless without a scale to compare it to,
    # so the scale used is the reference output's own range. What actually
    # matters for forwarding is the ARGMAX, checked separately above.
    rel_tol = 0.05
    for mid, name, sc in [(2, 'template', m2.scale), (3, 'modular', m3.scale)]:
        total += 1
        tol = rel_tol * ref_range if ref_range > 0 else float("inf")
        rel = me[mid] / ref_range if ref_range > 0 else 0.0
        if me[mid] <= tol:
            ok(f"Method {mid} ({name}): quant error {me[mid]:.4f} = {rel*100:.1f}% "
               f"of the output range ({ref_range:.2f}) <= {rel_tol*100:.0f}% | scale={sc}")
            passed += 1
        else:
            fail(f"Method {mid} ({name}): quant error {me[mid]:.4f} = {rel*100:.1f}% "
                 f"of the output range ({ref_range:.2f}) > {rel_tol*100:.0f}% | scale={sc}")

    print(f"\n{YELLOW}[Test 2] Weight update latency (10 updates){NC}")
    # M1_REDIRECT_SIM_MS is a PLACEHOLDER sleep, not a measurement, and it is
    # three orders of magnitude below the real thing. Stating that loudly here
    # matters: the numbers below would otherwise read as "Method 1 updates in
    # ~1 ms", the exact opposite of the design-space result the kernel suite
    # actually measures (regenerating the C, running clang and reloading the
    # program costs ~1.1-1.3 s -- see the "[M1 update timing]" line in
    # --only kernel, and bench_model_add.py for the per-phase breakdown).
    # The placeholder is kept small deliberately so --only core stays fast;
    # only the M2/M3 numbers in this test are real measurements.
    info(f"Method 1 redirect/reload: PLACEHOLDER sleep of {M1_REDIRECT_SIM_MS:.1f} ms — NOT a measurement.")
    info("      The REAL cost (regenerate C + clang + reload) is ~1.1-1.3 s, i.e. ~1000x this")
    info("      placeholder. Measured by: --only kernel ([M1 update timing]) and bench_model_add.py.")
    info("      Do NOT quote the Method 1 rows below as a result.")
    info("Method 2/3 have no redirect step — their update = map insert only (these ARE measured)")
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
        nm = fresh_like(model)
        t1 = m1.update_weights(nm)
        times['1_redirect'].append(t1['redirect_reload_s'] * 1000)
        times['1_insert'].append(t1['weight_insert_s'] * 1000)
        times['1_total'].append(t1['total_s'] * 1000)
        times[2].append(m2.update_weights(nm) * 1000)
        times[3].append(m3.update_weights(nm) * 1000)
        times['3s'].append(m3.update_weights(nm, layer_idx=2) * 1000)

    # Headline statistic is the MINIMUM, matching bench_model_add.py and the
    # kernel suite: the noise here is one-sided (scheduler/interrupts can only
    # slow a sample down, never speed it below its true cost), and the mean is
    # dominated by the first update, which pays first-touch page faults the
    # later ones do not. avg/max are kept alongside for transparency.
    for key, lbl in [
        ('1_redirect', 'Method 1 hardcoded (redirect/reload)      [PLACEHOLDER, not measured]'),
        ('1_insert',   'Method 1 hardcoded (weight insert only)   [fair vs M2/M3]'),
        ('1_total',    'Method 1 hardcoded (redirect + insert)    [PLACEHOLDER-dominated]'),
        (2,            'Method 2 template  (map update)'),
        (3,            'Method 3 modular   (all layers)'),
        ('3s',         'Method 3 modular   (single layer hot-swap)')
    ]:
        vals = times[key]
        info(f"{lbl}: min={min(vals):.3f}ms  avg={sum(vals)/len(vals):.3f}ms  max={max(vals):.3f}ms")

    print()
    info("NOTE: to compare M1 fairly against M2/M3, use 'weight insert only'.")
    info("      M1's real architectural cost is the recompile+reload, which this suite")
    info("      does NOT measure — see --only kernel / bench_model_add.py.")

    total += 1
    passed += 1
    ok("Update latency measured for M2/M3 (M1 redirect is a placeholder — see --only kernel)")

    print(f"\n{YELLOW}[Test 3] Determinism (100 runs){NC}")
    xf = make_input(I)
    rs = {int(np.argmax(m2.infer(xf))) for _ in range(100)}
    total += 1
    if len(rs) == 1:
        nh_str = decode_nexthop(list(rs)[0], suite_semantics(O))
        ok(f"Method 2: deterministic ({list(rs)[0]} -> {nh_str}) over 100 runs")
        passed += 1
    else:
        fail(f"Method 2: NOT deterministic: {rs}")

    print(f"\n{YELLOW}[Test 4] Post-update consistency{NC}")
    nm = fresh_like(model)
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
    pt_path = default_checkpoint()
    if os.path.exists(pt_path):
        try:
            loaded, li, lh, lo = load_pt_dynamic(pt_path)
            x = make_input(li)
            out_vec = pytorch_ref(loaded, x)
            nh_idx = int(np.argmax(out_vec))
            # `lo` is the loaded model's output width; the semantics come
            # from the descriptor when it matches, never from lo - 1.
            _sem = suite_semantics(lo)
            nh_str = decode_nexthop(nh_idx, _sem)
            sc = compute_scale(loaded)
            ok(f".pt caricato | arch={li}->{lh}->{lh}->{lo} | next-hop={nh_idx} ({nh_str}) | scale={sc}")
            if verbose:
                info(f"  Output scores: {[f'{v:.3f}' for v in out_vec.tolist()]}")
                for _l in _sem.summary().splitlines():
                    info(_l)
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

    # ------------------------------------------------------------------
    # BPF map footprint, itemised per declared map.
    #
    # This used to be three hand-written expressions scaled by N_WEIGHTS, which
    # understated P2 and P3 by roughly 4x and P1 by 5x. Two reasons:
    #   * arch_weights / layer_weights are ONE struct-valued entry of a FIXED
    #     size (MAX_WEIGHT_ENTRIES / MAX_LAYER_WEIGHT_ENTRIES bytes), not
    #     N_WEIGHTS bytes: the block is allocated whole regardless of how many
    #     weights the registered model actually uses.
    #   * the registry/dispatch maps were missing entirely -- model_progs (256
    #     slots) on P1, model_desc + arch_registry on P2, model_desc +
    #     layer_registry + layer_shapes on P3. Those dominate P2/P3.
    #
    # Each line is (map name, key_size, value_size, max_entries, per_cpu) taken
    # straight from the BPF_* declaration in the corresponding eBPF source, and
    # costed with EXACTLY the formula the kernel-suite measurement uses on the
    # real map (verify_prog_run.map_bytes):
    #     (key_size + value_size * ncpus_if_percpu) * max_entries
    # so this userspace estimate and the kernel-measured figure are directly
    # comparable instead of counting different things.
    #
    # Struct sizes (all packed, or all-__u8 hence alignment 1):
    #   fwd_action 4+6+6=16     ls_vec 4*6=24        qs_vec 4*4=16
    #   feat_ent 4, model_desc 4+4*4=20              arch_entry 1+4+2+1+1=9
    #   layer_model_entry 2+1=3 layer_shape_key 2    layer_shape_entry 2+2+4=8
    #   act_vec 8*SCRATCH_ACT_SIZE=1024
    #
    # This is the DECLARED capacity of the maps, not kernel RSS: the kernel adds
    # per-element bookkeeping (bucket/link overhead on hash maps), so the real
    # figure is higher. It is a like-for-like comparison across the three
    # pipelines, which is what the design-space table is for.
    # lookup_ctr is excluded: it only exists under IPA_COUNT_LOOKUPS
    # (measurement builds), never in the programs these numbers describe.
    MAX_WEIGHT_ENTRIES       = 1024   # aw_blk in ebpf_template_arch.py
    MAX_LAYER_WEIGHT_ENTRIES = 2048   # lw_blk in ebpf_modular.py
    ACT_VEC_BYTES            = 8 * 128  # act_vec: long long v[SCRATCH_ACT_SIZE]
    mac_capacity             = max(8, O)

    #                  name             key  value                     entries  percpu
    MAP_BREAKDOWN = {
        1: [("link_state",               4,  24,                        1,      False),
            ("pkt_stats",                4,  8,                         3,      False),
            ("cls_stats",                4,  8,                         O,      False),
            ("mac_table",                4,  16,                        mac_capacity, False),
            ("model_progs",              4,  4,                         256,    False)],
        2: [("arch_weights",             4,  MAX_WEIGHT_ENTRIES,        1,      False),
            ("link_state",               4,  24,                        1,      False),
            ("queue_state",              4,  16,                        1,      False),
            ("model_desc",               1,  20,                        256,    False),
            ("arch_registry",            1,  9,                         256,    False),
            ("arch_progs",               4,  4,                         8,      False),
            ("mac_table_t2",             4,  16,                        8,      False),
            ("pkt_stats_t2",             4,  8,                         3,      False),
            ("cls_stats_t2",             4,  8,                         7,      False)],
        3: [("layer_weights",            4,  MAX_LAYER_WEIGHT_ENTRIES,  1,      False),
            ("scratch_acts",             4,  ACT_VEC_BYTES,             1,      True),
            ("scratch_meta",             4,  8,                         16,     True),
            ("link_state",               4,  24,                        1,      False),
            ("queue_state",              4,  16,                        1,      False),
            ("model_desc",               1,  20,                        256,    False),
            ("layer_registry",           1,  3,                         256,    False),
            ("layer_shapes",             2,  8,                         512,    False),
            ("layer_chain",              4,  4,                         16,     False),
            ("mac_table_t3",             4,  16,                        8,      False),
            ("pkt_stats_t3",             4,  8,                         3,      False),
            ("cls_stats_t3",             4,  8,                         7,      False)],
    }

    def _map_bytes(key, val, entries, percpu):
        return (key + val * (ncpus if percpu else 1)) * entries

    MAP_MEM_BYTES = {k: sum(_map_bytes(ks, vs, n, pc) for _, ks, vs, n, pc in v)
                     for k, v in MAP_BREAKDOWN.items()}
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
    row("BPF map memory (declared)",
        {k: f"{MAP_MEM_BYTES[k]//1024}KB ({MAP_MEM_BYTES[k]}B)" for k in [1, 2, 3]})
    row("Flexibility",             FLEXIBILITY)
    print(sep)
    print()

    info("BPF map memory breakdown (declared capacity per map, "
         "excludes kernel per-element overhead):")
    for mid, lbl in [(1, 'P1 hardcoded'), (2, 'P2 template'), (3, 'P3 modular')]:
        parts = ", ".join(f"{name}={_map_bytes(ks, vs, n, pc)}B"
                          for name, ks, vs, n, pc in MAP_BREAKDOWN[mid])
        info(f"  {lbl:<12}: {parts} = {MAP_MEM_BYTES[mid]}B")
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


def _classify_packet(output_vec, ref_vec, semantics):
    """HIT / FAKE / MISS for one prediction.

    `semantics` replaces a `valid_outputs` set that was built as
    `set(range(1, O))` and labelled "0=DROP/MISS" -- the abandoned DROP=0
    convention again. A forwarded packet is a HIT when it matches the
    reference and FAKE otherwise; anything the semantics do not declare
    FORWARD (DROP or UNUSED) is a MISS, because no packet left the node.
    """
    pred   = int(np.argmax(output_vec))
    target = int(np.argmax(ref_vec))
    if semantics.action_of(pred) == "FORWARD":
        return "HIT" if pred == target else "FAKE"
    return "MISS"


def _run_pkt_stats(method, inputs, model, semantics):
    stats = {"HIT": 0, "FAKE": 0, "MISS": 0}
    for x in inputs:
        ref = pytorch_ref(model, x)
        out = method.infer(x)
        stats[_classify_packet(out, ref, semantics)] += 1
    return stats


def suite_pktstats(model, n_samples=200, seed=42):
    """`model` is the checkpoint main() loaded.

    This used to build its own `FRRModel()`, which -- with the module constants
    that used to live at the top of this file -- meant a random 35-32-32-7
    model unrelated to anything the datapath runs.
    """
    torch.manual_seed(seed)
    np.random.seed(seed)
    print(f"\n{YELLOW}=== SUITE pktstats — pkt_stats (3 pipelines) ==={NC}\n")
    H = model.fc1.out_features
    I = model.fc1.in_features
    O = model.out.out_features
    print(f"  Architecture: {I} -> {H} -> {H} -> {O} | samples={n_samples} | seed={seed}")
    print()
    m1 = Method1_Hardcoded(model)
    m2 = Method2_Template(model)
    m3 = Method3_Modular(model)
    pkt_sem = suite_semantics(O)
    info(f"FORWARD classes (counted as HIT/FAKE): {pkt_sem.forward_classes}")
    info(f"non-forwarding classes (counted as MISS): "
         f"{sorted(set(range(O)) - set(pkt_sem.forward_classes))}")
    print()
    inputs = [make_input(I) for _ in range(n_samples)]
    passed = total = 0
    print(f"{YELLOW}[Test A] pkt_stats per method ({n_samples} samples){NC}")
    stats = {}
    for mid, mobj, name in [(1, m1, 'hardcoded'), (2, m2, 'template'), (3, m3, 'modular')]:
        s = _run_pkt_stats(mobj, inputs, model, pkt_sem)
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
    new_model = fresh_like(model)
    m1.update_weights(new_model)
    m2.update_weights(new_model)
    m3.update_weights(new_model)
    stats_new = {}
    for mid, mobj in [(1, m1), (2, m2), (3, m3)]:
        stats_new[mid] = _run_pkt_stats(mobj, inputs, new_model, pkt_sem)
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


# Candidate int8 scales. A scale is REPRESENTABLE for a given model only while
# scale * max|w| <= 127; past that, weights saturate at +-127 and the error is
# dominated by clamping, not by rounding. The sweep keeps the saturating scales
# in the table (they show the cliff) but excludes them from the assertions:
# asserting "error decreases as scale increases" across a clamping boundary is
# asserting something false.
#
# This used to be a bare list of six scales with no notion of representability,
# which passed only because the suite was secretly running a random
# 35-32-32-7 model whose max|w| ~ 0.2 made every scale up to 512 valid. The
# real checkpoint has max|w| = 5.1, so only scales up to 24 are representable.
SCALE_CANDIDATES = [8, 16, 32, 64, 128, 256, 512]


def _split_scales(model):
    """(representable, saturating) candidate scales for this model."""
    max_abs = max(float(p.detach().abs().max()) for p in model.parameters())
    rep = [sf for sf in SCALE_CANDIDATES if sf * max_abs <= 127.0 + 1e-9]
    sat = [sf for sf in SCALE_CANDIDATES if sf not in rep]
    return rep, sat, max_abs


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


def suite_quant(model, n_samples=200, model_path=None):
    """`model` is the checkpoint main() loaded.

    The old body re-loaded the .pt itself when `--model` was given and fell
    back to a random `FRRModel()` otherwise, so the DEFAULT run measured
    quantisation error on random weights. Quantisation error depends entirely
    on the weight distribution, so that number described nothing.
    """
    print(f"\n{YELLOW}=== SUITE quant — argmax accuracy vs scale_factor ==={NC}\n")
    torch.manual_seed(42)
    np.random.seed(42)
    I = model.fc1.in_features
    H = model.fc1.out_features
    O = model.out.out_features
    print(f"  Model: {model_path or '(in-memory)'} | arch={I}->{H}->{H}->{O}")
    rep_scales, sat_scales, max_abs = _split_scales(model)
    print(f"  max|w| = {max_abs:.4f} -> largest representable scale = "
          f"{int(127.0 / max_abs)}")
    print(f"  representable scales (asserted on): {rep_scales}")
    print(f"  saturating scales (shown, not asserted): {sat_scales}")
    print(f"  Samples: {n_samples}")
    print()
    if not rep_scales:
        fail(f"no candidate scale is representable for max|w|={max_abs:.4f}; "
             f"widen SCALE_CANDIDATES")
        _banner(0, 1)
        return False
    inputs = [make_input(I) for _ in range(n_samples)]
    results = {sf: _evaluate_scale(model, sf, inputs, n_samples)
               for sf in SCALE_CANDIDATES}
    ref_range = 0.0
    for x in inputs[:50]:
        r = pytorch_ref(model, x)
        ref_range = max(ref_range, float(np.max(r) - np.min(r)))
    hdr = (f"  {'scale':>6} | {'max_err M2':>10} | {'acc M2 (%)':>10} | {'wrong M2':>8} | {'max_err M3':>10} | {'acc M3 (%)':>10} | {'wrong M3':>8}")
    sep = "  " + "-" * (len(hdr) - 2)
    print(hdr)
    print(sep)
    for sf in SCALE_CANDIDATES:
        err2, acc2, w2, err3, acc3, w3 = results[sf]
        tag = "" if sf in rep_scales else "  <- saturating"
        print(f"  {sf:>6} | {err2:>10.4f} | {acc2:>9.1f}% | {w2:>8} | "
              f"{err3:>10.4f} | {acc3:>9.1f}% | {w3:>8}{tag}")
    print(sep)
    print()
    passed = total = 0
    print(f"{YELLOW}[Test A] max_err decreases as scale increases "
          f"(representable scales only){NC}")
    total += 1
    if len(rep_scales) < 2:
        info(f"  only {len(rep_scales)} representable scale(s) -- no trend to check")
        passed += 1
    else:
        errs = [results[sf][0] for sf in rep_scales]
        # Monotone non-increasing, with a small slack for sampling noise.
        bad = [(rep_scales[i], errs[i], rep_scales[i + 1], errs[i + 1])
               for i in range(len(errs) - 1) if errs[i + 1] > errs[i] + 1e-3]
        if not bad:
            ok("error falls with scale: " +
               ", ".join(f"{sf}:{e:.4f}" for sf, e in zip(rep_scales, errs)))
            passed += 1
        else:
            fail("error rises with scale between representable scales: " +
                 ", ".join(f"{a}({ea:.4f})->{b}({eb:.4f})" for a, ea, b, eb in bad))
    print(f"\n{YELLOW}[Test B] M2 and M3 have identical max_err for each scale{NC}")
    total += 1
    all_equal = all(abs(results[sf][0] - results[sf][3]) < 1e-9
                    for sf in SCALE_CANDIDATES)
    if all_equal:
        ok("M2 and M3 produce identical max_err for all scales")
        passed += 1
    else:
        diffs = [sf for sf in SCALE_CANDIDATES
                 if abs(results[sf][0] - results[sf][3]) >= 1e-9]
        fail(f"M2 and M3 diverge for scale={diffs}")
    print(f"\n{YELLOW}[Test C] compute_scale() accuracy >= average of other scales{NC}")
    total += 1
    optimal_scale = compute_scale(model)
    if optimal_scale not in results:
        results[optimal_scale] = _evaluate_scale(model, optimal_scale, inputs, n_samples)
    avg_acc2 = sum(results[sf][1] for sf in rep_scales) / len(rep_scales)
    opt_acc2 = results[optimal_scale][1]
    info(f"  compute_scale()={optimal_scale} -> acc={opt_acc2:.1f}% | avg={avg_acc2:.1f}%")
    if opt_acc2 >= avg_acc2 - 1.0:
        ok(f"compute_scale accuracy ({opt_acc2:.1f}%) >= avg ({avg_acc2:.1f}%) - 1%")
        passed += 1
    else:
        fail(f"compute_scale accuracy ({opt_acc2:.1f}%) < avg ({avg_acc2:.1f}%)")
    # Test D used to assert `max_err <= H / scale`, which is not a bound on
    # this quantity at all: no dependence on the input width or magnitude, and
    # none on how the error compounds across layers. It passed only because the
    # suite was secretly running a random 35-32-32-7 model at scale 512.
    #
    # Two replacements were tried and rejected before this one:
    #   - a propagated worst case (product of layer row sums): mathematically
    #     valid but ~1.5e3 against a measured 5.2, so passing it proves nothing;
    #   - a flat "<= 5% of the output range": an invented constant, and scale=8
    #     lands at 5.1%, so the threshold decides the verdict, not the model.
    #
    # What the datapath actually depends on is ONE scale -- the one the control
    # plane picks -- and only through the ARGMAX, since that is all that reaches
    # a forwarding decision. So that is what is asserted. The other scales stay
    # in the table above as the sensitivity curve.
    print(f"\n{YELLOW}[Test D] argmax accuracy at the scale the control plane "
          f"selects{NC}")
    total += 1
    sel = compute_scale(model)
    if sel not in results:
        results[sel] = _evaluate_scale(model, sel, inputs, n_samples)
    err_sel, acc_sel, wrong_sel = results[sel][0], results[sel][1], results[sel][2]
    rel_sel = err_sel / ref_range if ref_range > 0 else 0.0
    ACC_MIN = 90.0
    if acc_sel >= ACC_MIN:
        ok(f"scale={sel}: argmax {acc_sel:.1f}% correct ({wrong_sel}/{n_samples} "
           f"wrong) >= {ACC_MIN:.0f}% | max_err={err_sel:.4f} "
           f"({rel_sel * 100:.1f}% of the {ref_range:.1f} output range)")
        passed += 1
    else:
        fail(f"scale={sel}: argmax only {acc_sel:.1f}% correct "
             f"({wrong_sel}/{n_samples} wrong) < {ACC_MIN:.0f}% | "
             f"max_err={err_sel:.4f}")
    info("  the remaining scales are the sensitivity curve, not requirements:")
    for sf in SCALE_CANDIDATES:
        e, a = results[sf][0], results[sf][1]
        tag = "" if sf in rep_scales else " (saturating)"
        mark = "  <- selected" if sf == sel else ""
        info(f"    scale={sf:>4}: max_err={e:>9.4f}  argmax acc={a:>5.1f}%{tag}{mark}")
    if sat_scales:
        info(f"  scales {sat_scales} saturate int8 for this model "
             f"(scale*max|w| > 127): their error is clamping, not rounding")
    if not sat_scales:
        info("  every candidate scale is representable for this model")
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


def suite_robust(model):
    """`model` is the checkpoint main() loaded -- see suite_pktstats."""
    print(f"\n{YELLOW}=== SUITE robust — anomalous inputs ==={NC}\n")
    torch.manual_seed(42)
    np.random.seed(42)
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


# Every map a pipeline declares, summed by map_bytes() from the kernel's own
# BPF_OBJ_GET_INFO_BY_FD. A name absent from a given pipeline is skipped by the
# try/except at the call site, so one list covers all three.
#
# This list was previously INCOMPLETE, and since the lookup failure is silently
# swallowed, the omissions did not show up as errors -- they just made the
# reported footprint smaller than the real one. Missing were: model_progs
# (P1's 256-slot BPF_PROG_ARRAY, the single largest P1 map), queue_state and
# model_desc (P2 and P3), and layer_shapes (P3's 512-entry map). Keep this list
# in sync with the BPF_* declarations in the three eBPF sources.
_PIPELINE_MAP_NAMES = [
    # shared inputs: link_state (egress up/down) and queue_state (synthetic)
    "link_state", "queue_state",
    # shared per-model descriptor registry (P2 + P3)
    "model_desc",
    # P1 hardcoded (no weight map -- weights are C literals)
    "pkt_stats", "cls_stats", "mac_table", "model_progs",
    # P2 template
    "arch_weights", "arch_registry", "arch_progs",
    "mac_table_t2", "pkt_stats_t2", "cls_stats_t2",
    # P3 modular
    "layer_weights", "layer_registry", "layer_shapes", "layer_chain",
    "scratch_acts", "scratch_meta",
    "mac_table_t3", "pkt_stats_t3", "cls_stats_t3",
]


# TTL sweeps start at 2, not 1: a forwarding hop now decrements the TTL and
# refuses to forward a packet whose TTL would reach 0 (see ipa_ttl_dec in the
# eBPF sources). TTL=1 is therefore a legitimate NON-forward, and including it
# in a sweep that asserts 'the packet was redirected' would fail by design.
# TTL=1 is covered separately by the dedicated expiry test.
def verify_alt_architectures(ttl_min=2, ttl_max=6):
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
    import model_meta as mm
    import p1_aot
    from common import write_vector_map

    print(f"\n{YELLOW}--- Architetture alternative (non solo 65-4-4-7) ---{NC}")
    all_ok = True

    # --- P1 hardcoded: variable depth, same descriptor -------------------
    shape = mm.derive_shape({"n_interfaces": 6, "n_nodes": 52})
    features, n_out, n_in = shape["features"], shape["n_out"], shape["n_in"]

    # link_state width from the resolved descriptor, not a literal 6.
    _ls_size = next((f["size"] for f in features if f["type"] == "link_state"), 0)

    def n_weights(dims):
        sizes = [n_in] + list(dims) + [n_out]
        return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))

    for dims, seed in [((8,), 111), ((4, 4, 4), 222)]:
        rng = _random.Random(seed)
        weights = [rng.randint(-30, 30) for _ in range(n_weights(dims))]
        scale = 24
        # ONE semantics object feeds both the generated switch and the
        # expectations below, so the test cannot pass by agreeing with itself
        # about a convention the datapath does not implement.
        alt_sem = suite_semantics(n_out)
        try:
            # The AOT object, as P1 is deployed (p1_aot).
            aot = p1_aot.load_p1([(0, weights, scale)], features=features,
                                 n_out=n_out, hidden_dims=dims,
                                 semantics=alt_sem)
        except Exception as e:
            fail(f"hardcoded alt-arch {dims}: compile/verifier failed ({e})")
            all_ok = False
            continue
        b, disp_fn = aot["b"], aot["disp"]
        write_vector_map(b, "link_state", [1] * _ls_size)
        V._install_mac_table(b, "mac_table", semantics=alt_sem)
        ps, cs = b["pkt_stats"], b["cls_stats"]

        shape_str = f"{n_in}-{'-'.join(map(str, dims))}-{n_out}"
        passed = failed = 0
        for ttl in range(ttl_min, ttl_max + 1):
            ref_cls, ref_val = V.ref_infer_sparse(
                weights, features, dims, n_out, ttl, model_id=0,
                map_values={"link_state": [1] * _ls_size},
                # No ingress_port entry is installed for these alt-arch
                # programs, so the datapath resolves no logical port and the
                # ingress_iface one-hot stays empty. The reference must say the
                # same thing, or the two disagree about a feature neither is
                # exercising.
                ingress_port=0, scale=scale)
            frame = V.build_frame_sparse(model_id=0, ttl=ttl, scale=scale, n_in=n_in, n_out=n_out)
            for i in range(3):
                ps[ct.c_int(i)] = ct.c_ulonglong(0)
            for i in range(n_out):
                try:
                    cs[ct.c_int(i)] = ct.c_ulonglong(0)
                except Exception:
                    pass
            retval, _ = V.prog_test_run(disp_fn.fd, frame, repeat=1)
            # Expectation from the DECLARED action. The old `ref_cls <
            # n_out - 1` scored a FORWARD expectation against the checked-in
            # model's DROP class 5 and a DROP expectation against its untrained
            # class 6 -- exactly backwards on both.
            _act = alt_sem.action_of(ref_cls)
            if _act == "FORWARD":
                got = V._read_u64(cs, ref_cls)
                good = (retval in V.XDP_REDIRECT_PASS) and got > 0
            elif _act == "DROP":
                got = V._read_u64(ps, 2)
                good = (retval == 1) and got > 0
            else:
                got = V._read_u64(cs, ref_cls)
                good = (retval == 2) and got > 0   # UNUSED -> XDP_PASS
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


# TTL sweeps start at 2, not 1: a forwarding hop now decrements the TTL and
# refuses to forward a packet whose TTL would reach 0 (see ipa_ttl_dec in the
# eBPF sources). TTL=1 is therefore a legitimate NON-forward, and including it
# in a sweep that asserts 'the packet was redirected' would fail by design.
# TTL=1 is covered separately by the dedicated expiry test.
def suite_kernel(model_path=None, repeat=50000, ttl_min=2, ttl_max=6, verify=True, trials=7):
    print(f"\n{YELLOW}=== SUITE kernel — BPF_PROG_TEST_RUN (instructions, latency, throughput, CPU) ==={NC}\n")
    if not sys.platform.startswith("linux"):
        info(f"kernel suite skipped: platform {sys.platform} (needs Linux).")
        info("Run on a Linux host: sudo python3 ipa/test/test_suite.py --only kernel")
        return True
    try:
        import verify_prog_run as V
    except Exception as e:
        info(f"kernel suite skipped: BCC/verify_prog_run not importable ({e}).")
        info("Needs Linux + BCC + root: sudo python3 ipa/test/test_suite.py --only kernel")
        return True
    mp = model_path or V.MODEL_PT
    methods = [
        ("baseline",  V.setup_baseline,  0),   # reference floor: parse + redirect, NO inference
        # P1.5 as DEPLOYED: the AOT object (gen_full_c + loader_aot, through
        # p1_aot). Until 2026-09-23 this row was the BCC build, which never
        # reaches a node; the two agreed within noise (claims.md B3).
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
        try:
            # Warm-up, chunked for the same reason as the measurement below:
            # the packet is mutated, so one long repeat would just exercise the
            # TTL-expired path and leave the counters dirty.
            V.prog_test_run_bench(disp_fd,
                                  lambda: V.build_frame(0, V.BENCH_TTL, setup["scale"]),
                                  1000, max_chunks=2)
        except OSError as e:
            fail(f"{name}: BPF_PROG_TEST_RUN failed ({e})")
            all_ok = False
            continue
        # A SINGLE BPF_PROG_TEST_RUN sample is not trustworthy: system noise
        # (scheduler preemption, interrupts, an unrelated process on the same
        # host) is ONE-SIDED -- it can only slow a trial down, never speed one
        # up below the true cost -- which is exactly why this table's
        # throughput used to look wildly different run to run (e.g. hardcoded
        # swinging 10-25 Mpps, baseline 10-50 Mpps). MIN across `trials`
        # independent measurements is the standard fix for this (same
        # reasoning as hyperfine / Google Benchmark, and the same fix already
        # applied in bench_depth_vs_width.py after it hit the identical issue).
        #
        # NOTE on the baseline's role: it is by far the cheapest program here
        # (129 instructions), and correspondingly the NOISIEST in relative
        # terms -- across runs its (max-min)/min has been ~112% against 31-38%
        # for the three pipelines. Its minimum therefore needs MORE trials than
        # theirs to settle, which is why a "latency normalized on the baseline"
        # column was removed from the reported table: dividing every pipeline
        # by the least stable measurement propagates that instability to the
        # whole column. Report absolute latency plus the machine, and use the
        # baseline as a qualitative floor.
        #
        # There used to be a "CPU (%)" column here, computed as the process's
        # (utime+stime) over the wall time of this loop. It has been REMOVED,
        # deliberately -- do not re-add it. All the work happens inside a
        # blocking bpf_prog_test_run() syscall, so that ratio does not measure
        # how much CPU the eBPF program costs; it measures how much of the wall
        # time the scheduler left this single thread on-CPU. It came out
        # non-monotonic (template below both baseline and hardcoded despite
        # costing 4x the latency) and non-reproducible across runs (59% then
        # 47% for the same pipeline), i.e. it reported system interference, not
        # a property of the pipeline. Per-pipeline CPU cost is already captured
        # by the latency and instruction columns.
        # Chunked: the datapath mutates the packet (TTL decrement) and
        # BPF_PROG_TEST_RUN does NOT restore the buffer between repetitions, so
        # a single repeat=50000 would spend ~99.5% of its runs on the
        # TTL-expired short-circuit and report that as the pipeline's latency.
        # prog_test_run_bench() re-supplies a pristine TTL=255 frame every 200
        # runs, keeping every measured run on the real inference path.
        samples = []
        w0  = time.perf_counter()
        _mk = lambda: V.build_frame(0, V.BENCH_TTL, setup["scale"])
        for _ in range(trials):
            retval, dur_ns = V.prog_test_run_bench(disp_fd, _mk, repeat)
            samples.append(dur_ns)
        wall = time.perf_counter() - w0
        samples.sort()
        lat_min, lat_p50, lat_max = samples[0], samples[trials // 2], samples[-1]
        lat_ns  = float(lat_min) if lat_min else (wall * 1e9 / (repeat * trials))
        # NOT a measured throughput. This is 1/latency: the rate a single core
        # would reach IF packets were processed strictly back-to-back with no
        # I/O, no queueing and no loss -- and, under BPF_PROG_TEST_RUN, without
        # bpf_redirect ever executing, which is the most expensive part of the
        # real forwarding path. It is an upper bound derived from the latency
        # column, useful for comparing the three pipelines against each other,
        # and NOT comparable with the zero-loss throughput figures reported in
        # the literature (RFC 2544), which are measured with real traffic.
        # See docs/metodologia_test.pdf.
        mpps    = (1000.0 / lat_ns) if lat_ns > 0 else 0.0
        # Sum the kernel's own view of every map this pipeline declares. A name
        # this pipeline does not have raises and is skipped -- that is expected,
        # one list covers all three. Record WHICH maps were counted so the total
        # is auditable: the previous version swallowed the misses with no record,
        # which is how four maps stayed missing from the reported footprint
        # without anyone noticing (see _PIPELINE_MAP_NAMES).
        mem = 0
        mem_parts = []
        for mname in _PIPELINE_MAP_NAMES:
            try:
                mb = V.map_bytes(setup["b"][mname].map_fd, V._NR_CPUS)
            except Exception:
                continue
            mem += mb
            mem_parts.append((mname, mb))
        info(f"{name}: map memory {mem}B from {len(mem_parts)} maps -- "
             + ", ".join(f"{n}={v}B" for n, v in mem_parts))
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
            "per": per_prog, "lat": lat_ns, "mpps": mpps,
            "retval": retval, "mem": mem, "n_tail": n_tail, "lookups": lookups,
            "lat_p50": lat_p50, "lat_max": lat_max,
            "spread": (lat_max - lat_min) / lat_min * 100.0 if lat_min else 0.0,
        })
        ok(f"{name:9s}: {insn_total:5d} eBPF instr | lat={lat_ns:8.1f} ns (min of {trials})"
           f" [p50={lat_p50:.0f} max={lat_max:.0f}] | {mpps:6.3f} Mpps | retval={retval} | tail={n_tail}")
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
    line(f"Latency (ns/pkt, min of {trials})", "lat", lambda v: f"{v:.1f}")
    line("  ...p50",                 "lat_p50", lambda v: f"{v:.1f}")
    line("  ...max",                 "lat_max", lambda v: f"{v:.1f}")
    # Relative spread makes explicit which row is a reliable measurement and
    # which is not: the cheaper the program, the wider its spread, and the
    # baseline is consistently the worst of the four.
    line("  ...spread (max-min)/min %", "spread", lambda v: f"{v:.0f}%")
    line("Inference rate (Mpps, 1/latency)", "mpps", lambda v: f"{v:.3f}")
    print("  " + "-" * (32 + 16 * len(rows)))
    print()
    print("  NOTE: 'eBPF instructions' is the STATIC size of the loaded program, not the")
    print("        number executed per packet. Pipeline 1 unrolls a 52-case switch for the")
    print("        node one-hot of which exactly ONE case runs, so its executed path is a")
    print("        fraction of the count shown; dividing instructions by latency would give")
    print("        an impossible instructions-per-cycle figure. See docs/testing.md.")
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

        # A forwarding hop must behave like a router towards the TTL: decrement
        # it, fix the IP checksum, and refuse to forward a packet whose TTL
        # would reach 0. Checked against the packet the program really produced,
        # so a missing checksum fix cannot pass unnoticed.
        print()
        for name, _, _ in methods:
            if name == "baseline":
                continue
            try:
                np_, nf_, det = V.verify_ttl_handling(name, 0, mp)
                for line in det:
                    info(f"  {line}")
                if nf_ == 0:
                    ok(f"TTL handling {name}: {np_}/{np_} (decrement + checksum + expiry)")
                else:
                    fail(f"TTL handling {name}: {nf_} check(s) failed")
                    all_ok = False
            except Exception as e:
                fail(f"TTL handling {name}: error ({e})")
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


def default_checkpoint() -> str:
    """The checkpoint the suites run, resolved by model_meta."""
    import model_meta as _mm
    return _mm.default_checkpoint()


def _load_default_model(model_arg):
    """The model the torch suites run on: the checkpoint, whatever its shape.

    The previous body compared the checkpoint's shape against the module
    constants and DISCARDED it on mismatch, keeping a random `FRRModel()`.
    With INPUT_SIZE=35/HIDDEN_DIM=32 against a 65-4-4-7 checkpoint the guard
    could never hold, so the suites always ran random weights on an
    architecture no pipeline implements. There is no shape gate any more: the
    suites are shape-agnostic (every one of them reads I/H/O off the model),
    so a checkpoint of any shape is simply used.
    """
    torch.manual_seed(42)
    np.random.seed(42)
    pt_path = model_arg or default_checkpoint()
    if os.path.exists(pt_path):
        try:
            model, li, lh, lo = load_pt_dynamic(pt_path)
            print(f"{GREEN}[OK]{NC} Model loaded from {pt_path} "
                  f"(arch {li}->{lh}->{lh}->{lo})")
            return model, pt_path
        except Exception as e:
            print(f"{YELLOW}[WARN]{NC} could not load {pt_path}: {e}")
    else:
        print(f"{YELLOW}[INFO]{NC} No checkpoint at {pt_path}")
    r = reference_shape()
    print(f"{YELLOW}[INFO]{NC} falling back to random weights (seed=42) on the "
          f"DESCRIPTOR's shape {r['n_in']}->{r['hidden_dims'][0]}->{r['n_out']} "
          f"-- not on a shape written into this file")
    return FRRModel(), pt_path


def main():
    parser = argparse.ArgumentParser(description="Local IPA test suite (3 methods) — consolidates the old test_*.py")
    parser.add_argument('--only', default='all', choices=['all', 'core', 'pktstats', 'extract', 'quant', 'robust', 'kernel'], help='Which suite to run (default: all)')
    parser.add_argument('--model', type=str, default=None, help='Path to the .pt checkpoint')
    parser.add_argument('--verbose', action='store_true', help='Extra detail (core suite)')
    parser.add_argument('--samples', type=int, default=200, help='Samples for pktstats/quant')
    parser.add_argument('--seed', type=int, default=42, help='Seed for pktstats')
    parser.add_argument('--kernel-repeat', type=int, default=50000, help='BPF_PROG_TEST_RUN repeats for the kernel suite')
    parser.add_argument('--kernel-trials', type=int, default=7, help='Independent min-of-N trials per pipeline (fixes run-to-run volatility, see suite_kernel docstring)')
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
        results['pktstats'] = suite_pktstats(model, args.samples, args.seed)
    if 'extract' in which:
        results['extract'] = suite_extract(pt_path)
    if 'quant' in which:
        results['quant'] = suite_quant(model, args.samples, pt_path)
    if 'robust' in which:
        results['robust'] = suite_robust(model)
    if 'kernel' in which:
        results['kernel'] = suite_kernel(args.model, repeat=args.kernel_repeat, verify=not args.no_verify, trials=args.kernel_trials)
    print(f"{YELLOW}{'#'*52}{NC}")
    print(f"{YELLOW}#  SUITE SUMMARY{NC}")
    for name, res in results.items():
        tag = f"{GREEN}PASS{NC}" if res else f"{RED}FAIL{NC}"
        print(f"   {name:<10} : {tag}")
    print(f"{YELLOW}{'#'*52}{NC}")
    sys.exit(0 if all(results.values()) else 1)


if __name__ == '__main__':
    main()
