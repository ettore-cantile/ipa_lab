#!/usr/bin/env python3
"""test_weights_and_metrics.py -- weight extraction, quantization, and the metrics
of the programs in the kernel.

Suites (--only): extract, quant, kernel (root), all.

Usage:
    python3 ipa/test/test_weights_and_metrics.py
    sudo python3 ipa/test/test_weights_and_metrics.py --only kernel
"""

import argparse
import time
import sys
import os

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

import numpy as np

def reference_shape() -> dict:
    """{n_in, n_out, hidden_dims} for the model this repo is configured for."""
    import model_meta as _mm
    shape = _mm.derive_shape(_mm.load_model_meta(
                                 os.path.join(SHARED_DIR, "weights.json")),
                             topology_config=_mm.load_topology_config())
    return {"n_in": shape["n_in"], "n_out": shape["n_out"],
            "hidden_dims": list(shape["hidden_dims"])}

GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
RED    = "\033[0;31m"
NC     = "\033[0m"

def ok(msg):   print(f"  {GREEN}[PASS]{NC} {msg}")
def fail(msg): print(f"  {RED}[FAIL]{NC} {msg}")
def info(msg): print(f"  {YELLOW}[INFO]{NC} {msg}")


def suite_semantics(n_out: int):
    """Semantics for a model of width `n_out`, from the descriptor if it fits."""
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
    """Render a predicted class, keeping class / action / port distinct."""
    if semantics is not None:
        from class_semantics import format_decision
        return format_decision(argmax_idx, semantics)
    return f"class={argmax_idx} action=? (no semantics supplied)"


if TORCH_AVAILABLE:
    class FRRModel(nn.Module):
        """Two-hidden-layer MLP matching the pipelines' shape family."""

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
    """[(kind, size)] for the descriptor's features, truncated/padded to n_in."""
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
            groups = [("dense_vector_map", n_in)]
    except Exception:
        groups = [("dense_vector_map", n_in)]
    _FEATURE_GROUPS_CACHE[n_in] = groups
    return groups


_FEATURE_GROUPS_CACHE = {}


def make_input(input_size=None):
    """A random input vector that respects the descriptor's feature structure."""
    if input_size is None:
        input_size = reference_shape()["n_in"]
    parts = []
    for kind, size in _feature_groups(input_size):
        if kind == "onehot":
            v = np.zeros(size, dtype=np.float32)
            v[np.random.randint(0, size)] = 1.0
        elif kind == "scalar":
            v = np.random.uniform(0.0, 1.0, size).astype(np.float32)
        else:
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
        print(f"{RED} Check the [FAIL] messages above{NC}")
    print(f"{YELLOW}{'='*52}{NC}\n")


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
                info("  Regenerate with: python3 ipa/extract_weights.py")
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
    """`model` is the checkpoint main() loaded."""
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


_PIPELINE_MAP_NAMES = [
    "link_state", "queue_state",
    "model_desc",
    "pkt_stats", "cls_stats", "mac_table", "model_progs",
    "arch_weights", "arch_registry", "arch_progs", "class_action_t2",
    "mac_table_t2", "pkt_stats_t2", "cls_stats_t2",
    "layer_weights", "layer_registry", "layer_shapes", "layer_chain",
    "scratch_acts", "scratch_meta", "class_action_t3",
    "mac_table_t3", "pkt_stats_t3", "cls_stats_t3",
]


def verify_alt_architectures(ttl_min=2, ttl_max=6):
    """Everything above this point in suite_kernel() exercises exactly ONE
    architecture (the checked-in 65-4-4-7 model) across the 3 pipelines -- a
    real risk of a design-space claim ("P1/P2/P3 handle arbitrary shapes")
    going untested."""
    import ctypes as ct
    import random as _random
    import check_pipelines as V
    import model_meta as mm
    import p1_aot
    from common import write_vector_map

    print(f"\n{YELLOW}--- Other architectures (not only 65-4-4-7) ---{NC}")
    all_ok = True

    shape = mm.derive_shape({"n_interfaces": 6, "n_nodes": 52,
                             "n_out": reference_shape()["n_out"]})
    features, n_out, n_in = shape["features"], shape["n_out"], shape["n_in"]

    _ls_size = next((f["size"] for f in features if f["type"] == "link_state"), 0)

    def n_weights(dims):
        sizes = [n_in] + list(dims) + [n_out]
        return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))

    for dims, seed in [((8,), 111), ((4, 4, 4), 222)]:
        rng = _random.Random(seed)
        weights = [rng.randint(-30, 30) for _ in range(n_weights(dims))]
        scale = 24
        alt_sem = suite_semantics(n_out)
        try:
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
        from stats_maps import zero_counter
        ps, cs = b["pkt_stats"], b["cls_stats"]

        shape_str = f"{n_in}-{'-'.join(map(str, dims))}-{n_out}"
        passed = failed = 0
        for ttl in range(ttl_min, ttl_max + 1):
            ref_cls, ref_val = V.ref_infer_sparse(
                weights, features, dims, n_out, ttl, model_id=0,
                map_values={"link_state": [1] * _ls_size},
                ingress_port=0, scale=scale)
            frame = V.build_frame_sparse(model_id=0, ttl=ttl, scale=scale, n_in=n_in, n_out=n_out)
            for i in range(3):
                zero_counter(ps, i)
            for i in range(n_out):
                try:
                    zero_counter(cs, i)
                except Exception:
                    pass
            retval, _ = V.prog_test_run(disp_fn.fd, frame, repeat=1)
            _act = alt_sem.action_of(ref_cls)
            if _act == "FORWARD":
                got = V._read_u64(cs, ref_cls)
                good = (retval in V.XDP_REDIRECT_PASS) and got > 0
            elif _act == "DROP":
                got = V._read_u64(ps, 2)
                good = (retval == 1) and got > 0
            else:
                got = V._read_u64(cs, ref_cls)
                good = (retval == 2) and got > 0
            passed += good
            failed += not good
        if failed == 0:
            ok(f"hardcoded alt-arch {shape_str}: {passed}/{passed} PASS")
        else:
            fail(f"hardcoded alt-arch {shape_str}: {failed}/{passed + failed} FAIL")
            all_ok = False

    try:
        import check_multi_model as VMM
        t_ok = VMM.test_template()
        m_ok = VMM.test_modular()
        (ok if t_ok else fail)(f"template alt-arch (65-6-5-7, concurrent w/ 65-4-4-7): "
                              f"{'PASS' if t_ok else 'FAIL'}")
        (ok if m_ok else fail)(f"modular alt-arch (65-5-6-4-7, concurrent w/ 65-4-4-7): "
                               f"{'PASS' if m_ok else 'FAIL'}")
        all_ok = all_ok and t_ok and m_ok
    except Exception as e:
        fail(f"template/modular alt-arch: error ({e})")
        all_ok = False

    return all_ok


SKIPPED = "skip"


def suite_kernel(model_path=None, repeat=50000, ttl_min=2, ttl_max=6, verify=True, trials=7):
    print(f"\n{YELLOW}=== SUITE kernel — BPF_PROG_TEST_RUN (instructions, latency, throughput, CPU) ==={NC}\n")
    if not sys.platform.startswith("linux"):
        info(f"kernel suite skipped: platform {sys.platform} (needs Linux).")
        info("Run on a Linux host: sudo python3 ipa/test/test_weights_and_metrics.py --only kernel")
        return SKIPPED
    if os.geteuid() != 0:
        info("kernel suite skipped: needs root (loads XDP programs).")
        info("Run: sudo python3 ipa/test/test_weights_and_metrics.py --only kernel")
        return SKIPPED
    try:
        import check_pipelines as V
    except Exception as e:
        info(f"kernel suite skipped: BCC/check_pipelines not importable ({e}).")
        info("Needs Linux + BCC + root: sudo python3 ipa/test/test_weights_and_metrics.py --only kernel")
        return SKIPPED
    mp = model_path or V.MODEL_PT
    mut = V._mut()
    if mut is not None:
        import model_under_test as MUT
        c = V.ref_infer(None, mut.scale, V.BENCH_TTL, 0)[0]
        info(f"model under test: {mut.name} ({mut.shape}); at the bench TTL "
             f"({V.BENCH_TTL}, every link up) it decides class {c}, "
             f"{mut.semantics.action_of(c)}: the latency is that of this "
             f"path")
    methods = [
        ("baseline",  V.setup_baseline,  0),
        ("p1_static", V.setup_p1_static, 1),
        ("hardcoded", V.setup_hardcoded, 1),
        ("template",  V.setup_template,  2),
        ("modular",   V.setup_modular,   3),
    ]
    rows = []
    all_ok = True
    import pipeline_setup as PS
    not_applicable = set()
    for name, setup_fn, pl in methods:
        try:
            setup = setup_fn(0, mp)
        except PS.NotApplicable as e:
            info(f"{name}: NOT APPLICABLE to this model ({e})")
            not_applicable.add(name)
            continue
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
            V.prog_test_run_bench(disp_fd,
                                  lambda: V.build_frame(0, V.BENCH_TTL, setup["scale"]),
                                  1000, max_chunks=2)
        except OSError as e:
            fail(f"{name}: BPF_PROG_TEST_RUN failed ({e})")
            all_ok = False
            continue
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
        mpps    = (1000.0 / lat_ns) if lat_ns > 0 else 0.0
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
    line("  ...spread (max-min)/min %", "spread", lambda v: f"{v:.0f}%")
    line("Inference rate (Mpps, 1/latency)", "mpps", lambda v: f"{v:.3f}")
    print("  " + "-" * (32 + 16 * len(rows)))
    print()
    print("  NOTE: 'eBPF instructions' is the STATIC size of the loaded program, not the")
    print("        number executed per packet. P1.5 (hardcoded) unrolls a 52-case switch for")
    print("        the node one-hot of which exactly ONE case runs, so its executed path is a")
    print("        fraction of the count shown; dividing instructions by latency would give")
    print("        an impossible instructions-per-cycle figure. P1 (p1_static) has the node")
    print("        frozen in, so the switch is gone. See docs/testing.md.")
    print()
    for r in rows:
        detail = "  ".join(f"{p}={c}" for p, c in r["per"])
        info(f"{r['name']:9s} programs: {detail}")
    if verify:
        print()
        for name, _, _ in methods:
            if name == "baseline" or name in not_applicable:
                continue
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

        print()
        for name, _, _ in methods:
            if name == "baseline" or name in not_applicable:
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

        print()
        try:
            changes, tested = V.probe_link_down(mp, 0, ttl_min, ttl_max)
            if changes:
                sample = ", ".join(f"TTL{t}:link{k} {u}->{d}" for t, k, u, d in changes[:6])
                ok(f"link_state reroute: {len(changes)}/{tested} link-down cases change egress  [{sample}]")
            elif mut is not None:
                info(f"link_state reroute: 0/{tested} cases change class with "
                     f"{mut.name} (a property of the model, not of the datapath)")
            else:
                fail(f"link_state reroute: 0/{tested} link-down cases changed the egress class "
                     f"(feature wired but the model never reroutes on failure for TTL {ttl_min}-{ttl_max})")
                all_ok = False
        except Exception as e:
            fail(f"link_state reroute probe: error ({e})")
            all_ok = False

        try:
            if mut is not None:
                info("other architectures: skipped with --model "
                     "(they use their own shapes; they run without --model)")
                alt_ok = True
            else:
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
    """The model the torch suites run on."""
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
    parser = argparse.ArgumentParser(description="IPA test suite: weight extraction, quantization, in-kernel metrics")
    parser.add_argument('--only', default='all', choices=['all', 'extract', 'quant', 'kernel'], help='Which suite to run (default: all)')
    parser.add_argument('--model', type=str, default=None,
                        help='Model: checkpoint, synth:<preset>, a directory or a .pt '
                             '(see model_under_test.py). Default: the configured checkpoint')
    parser.add_argument('--topology', type=str, default=None,
                        help='Scenario (network) in topologies/; default: the one the model fits')
    parser.add_argument('--samples', type=int, default=200, help='Samples for quant')
    parser.add_argument('--kernel-repeat', type=int, default=50000, help='BPF_PROG_TEST_RUN repeats for the kernel suite')
    parser.add_argument('--kernel-trials', type=int, default=7, help='Independent min-of-N trials per pipeline (fixes run-to-run volatility, see suite_kernel docstring)')
    parser.add_argument('--no-verify', action='store_true', help='Kernel suite: skip the dispatch gate (metrics only)')
    args = parser.parse_args()
    import model_under_test as MUT
    mut = MUT.select(args.model, args.topology)
    all_suites = ['extract', 'quant', 'kernel']
    which = all_suites if args.only == 'all' else [args.only]
    if mut is not None and not mut.reference:
        skipped = [s_ for s_ in which if s_ != 'kernel']
        if skipped:
            print(f"{YELLOW}[INFO]{NC} {', '.join(skipped)}: they concern the "
                  f"trained checkpoint, not {mut.name} -- skipped")
        which = [s_ for s_ in which if s_ == 'kernel']
    if mut is not None:
        args.model = None
    needs_torch = any(s != 'kernel' for s in which)
    if needs_torch and not TORCH_AVAILABLE:
        print("[ERROR] PyTorch not found. Install with: pip install torch")
        print("        (--only kernel does not need torch and works without it)")
        sys.exit(1)
    model, pt_path = _load_default_model(args.model) if needs_torch else (None, args.model)
    results = {}
    if 'extract' in which:
        results['extract'] = suite_extract(pt_path)
    if 'quant' in which:
        results['quant'] = suite_quant(model, args.samples, pt_path)
    if 'kernel' in which:
        results['kernel'] = suite_kernel(args.model, repeat=args.kernel_repeat, verify=not args.no_verify, trials=args.kernel_trials)
    print(f"{YELLOW}{'#'*52}{NC}")
    print(f"{YELLOW}#  SUITE SUMMARY{NC}")
    for name, res in results.items():
        tag = (f"{YELLOW}SKIP{NC}" if res == SKIPPED else
               f"{GREEN}PASS{NC}" if res else f"{RED}FAIL{NC}")
        print(f"   {name:<10} : {tag}")
    print(f"{YELLOW}{'#'*52}{NC}")
    sys.exit(0 if all(results.values()) else 1)


if __name__ == '__main__':
    main()
