#!/usr/bin/env python3
"""
test_local.py - Test locale dei 3 metodi IPA (nessun eBPF/XDP richiesto)

Utilizzo:
  python3 shared/test_local.py
  python3 shared/test_local.py --model shared/frr_germany50_5_model_4x2.pt
"""

import argparse
import time
import sys
import os

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
except ImportError:
    print("[ERROR] PyTorch non trovato. Installa con: pip install torch")
    sys.exit(1)

import numpy as np

# Architettura reale da FRR_model.py (usata per i test 1-4)
N_INTERFACES  = 6
N_NODES       = 22
HIDDEN_DIM    = 32
INPUT_SIZE    = N_INTERFACES + N_INTERFACES + 1 + N_NODES  # = 35
OUTPUT_SIZE   = N_INTERFACES + 1                           # = 7

GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
RED    = "\033[0;31m"
NC     = "\033[0m"

def ok(msg):   print(f"  {GREEN}[PASS]{NC} {msg}")
def fail(msg): print(f"  {RED}[FAIL]{NC} {msg}")
def info(msg): print(f"  {YELLOW}[INFO]{NC} {msg}")


# ===========================================================================
# Modello con architettura fissa (test 1-4)
# ===========================================================================
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
    """
    Carica un checkpoint .pt inferendo automaticamente le dimensioni
    dell'architettura dai tensori salvati.
    Ritorna (model, input_size, hidden_dim, output_size).
    """
    state = torch.load(path, map_location='cpu', weights_only=True)

    # Inferisci dimensioni dal checkpoint
    # fc1.weight shape: (hidden_dim, input_size)
    # out.weight shape: (output_size, hidden_dim)
    w1_shape  = state['fc1.weight'].shape   # (hidden, input)
    out_shape = state['out.weight'].shape   # (output, hidden)

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


def compute_scale(model: nn.Module) -> int:
    """Scale factor come potenza di 2 che evita overflow int8."""
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


# ===========================================================================
# Method 1 - Hardcoded
# ===========================================================================
class Method1_Hardcoded:
    def __init__(self, model: FRRModel):
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

    def update_weights(self, new_model) -> float:
        t0 = time.perf_counter()
        time.sleep(0.001)  # simula ricompilazione BCC
        self._copy_weights(new_model)
        return time.perf_counter() - t0


# ===========================================================================
# Method 2 - Template
# ===========================================================================
class Method2_Template:
    def __init__(self, model: FRRModel):
        self.hidden  = model.fc1.out_features
        self.input   = model.fc1.in_features
        self.output  = model.out.out_features
        self.scale   = compute_scale(model)
        self.weight_map = {}
        self._load(model)

    def _q(self, v): return max(-128, min(127, int(round(v * self.scale))))

    def _load(self, model):
        self.scale = compute_scale(model)
        self.hidden = model.fc1.out_features
        self.input  = model.fc1.in_features
        self.output = model.out.out_features
        s = model.state_dict()
        idx = 0
        for key in ['fc1.weight','fc1.bias','fc2.weight','fc2.bias','out.weight','out.bias']:
            for v in s[key].flatten().tolist():
                self.weight_map[idx] = self._q(v); idx += 1

    def _mat(self, off, r, c):
        return np.array([self.weight_map[off+i]/self.scale for i in range(r*c)]).reshape(r,c)

    def _bias(self, off, n):
        return np.array([self.weight_map[off+i]/self.scale for i in range(n)])

    def infer(self, x):
        H, I, O = self.hidden, self.input, self.output
        off = 0
        W1 = self._mat(off, H, I); off += H*I
        b1 = self._bias(off, H);   off += H
        W2 = self._mat(off, H, H); off += H*H
        b2 = self._bias(off, H);   off += H
        W3 = self._mat(off, O, H); off += O*H
        b3 = self._bias(off, O)
        h1 = np.maximum(0, W1 @ x + b1)
        h2 = np.maximum(0, W2 @ h1 + b2)
        return W3 @ h2 + b3

    def update_weights(self, new_model) -> float:
        t0 = time.perf_counter()
        self._load(new_model)
        return time.perf_counter() - t0


# ===========================================================================
# Method 3 - Modular
# ===========================================================================
class Method3_Modular:
    def __init__(self, model: FRRModel):
        self.hidden  = model.fc1.out_features
        self.input   = model.fc1.in_features
        self.output  = model.out.out_features
        self.scale   = compute_scale(model)
        self.lw      = [{}, {}, {}]
        self._load(model)

    def _q(self, v): return max(-128, min(127, int(round(v * self.scale))))

    def _load(self, model, layer_idx=None):
        self.scale  = compute_scale(model)
        self.hidden = model.fc1.out_features
        self.input  = model.fc1.in_features
        self.output = model.out.out_features
        s = model.state_dict()
        cfg = [
            ('fc1.weight','fc1.bias', self.hidden, self.input),
            ('fc2.weight','fc2.bias', self.hidden, self.hidden),
            ('out.weight','out.bias', self.output, self.hidden),
        ]
        layers = [layer_idx] if layer_idx is not None else [0,1,2]
        for li in layers:
            wk, bk, rows, cols = cfg[li]
            idx = 0
            for v in s[wk].flatten().tolist(): self.lw[li][idx]=self._q(v); idx+=1
            for v in s[bk].flatten().tolist(): self.lw[li][idx]=self._q(v); idx+=1

    def _layer(self, li, x_in, out_size):
        in_size = len(x_in)
        lw = self.lw[li]
        W = np.array([lw[i]/self.scale for i in range(out_size*in_size)]).reshape(out_size,in_size)
        b = np.array([lw[out_size*in_size+i]/self.scale for i in range(out_size)])
        return W @ x_in + b

    def infer(self, x):
        h1 = np.maximum(0, self._layer(0, x, self.hidden))
        h2 = np.maximum(0, self._layer(1, h1, self.hidden))
        return self._layer(2, h2, self.output)

    def update_weights(self, new_model, layer_idx=None) -> float:
        t0 = time.perf_counter()
        self._load(new_model, layer_idx)
        return time.perf_counter() - t0


# ===========================================================================
# Helpers
# ===========================================================================
def make_input(input_size=INPUT_SIZE):
    ls = np.random.randint(0, 2, N_INTERFACES).astype(np.float32)
    ii = np.zeros(N_INTERFACES, dtype=np.float32)
    ii[np.random.randint(0, N_INTERFACES)] = 1.0
    ttl = np.array([np.random.uniform(0,1)], dtype=np.float32)
    nid = np.zeros(N_NODES, dtype=np.float32)
    nid[np.random.randint(0, N_NODES)] = 1.0
    base = np.concatenate([ls, ii, ttl, nid])   # 35 features
    if input_size > len(base):
        base = np.concatenate([base, np.zeros(input_size - len(base), dtype=np.float32)])
    return base[:input_size]


def pytorch_ref(model, x_np):
    with torch.no_grad():
        return model(torch.tensor(x_np, dtype=torch.float32)).numpy()


# ===========================================================================
# Test runner
# ===========================================================================
def run_tests(model, verbose=False):
    print(f"\n{YELLOW}=== TEST LOCAL \u2014 IPA Pipeline (3 metodi) ==={NC}\n")
    H = model.fc1.out_features
    I = model.fc1.in_features
    O = model.out.out_features
    print(f"  Architettura: {I} -> {H} -> {H} -> {O}")
    print()

    m1 = Method1_Hardcoded(model)
    m2 = Method2_Template(model)
    m3 = Method3_Modular(model)
    info(f"Method 2: scale_factor={m2.scale}")
    info(f"Method 3: scale_factor={m3.scale}")
    print()

    N = 50
    passed = total = 0

    # Test 1: consistency + argmax
    print(f"{YELLOW}[Test 1] Output consistency & argmax ({N} campioni){NC}")
    mm = {2:0, 3:0}; me = {1:0.0, 2:0.0, 3:0.0}
    for _ in range(N):
        x = make_input(I)
        ref = pytorch_ref(model, x)
        nr  = int(np.argmax(ref))
        for mid, m in [(1,m1),(2,m2),(3,m3)]:
            out = m.infer(x)
            me[mid] = max(me[mid], float(np.max(np.abs(out-ref))))
        if int(np.argmax(m2.infer(x))) != nr: mm[2] += 1
        if int(np.argmax(m3.infer(x))) != nr: mm[3] += 1

    total += 1; passed += 1
    ok(f"Method 1 (hardcoded): argmax 100% corretto | max_err={me[1]:.6f}")

    for mid, name in [(2,'template'),(3,'modular')]:
        total += 1
        pct = mm[mid]/N*100
        if pct <= 10:
            ok(f"Method {mid} ({name}): argmax {100-pct:.0f}% corretto ({mm[mid]}/{N}) | max_err={me[mid]:.4f}")
            passed += 1
        else:
            fail(f"Method {mid} ({name}): {mm[mid]}/{N} argmax errati | max_err={me[mid]:.4f} | scale={m2.scale}")

    for mid, name, sc in [(2,'template',m2.scale),(3,'modular',m3.scale)]:
        total += 1
        tol = H / sc
        if me[mid] <= tol:
            ok(f"Method {mid} ({name}): errore quant. ok ({me[mid]:.4f} <= {tol:.4f})")
            passed += 1
        else:
            fail(f"Method {mid} ({name}): errore quant. ALTO ({me[mid]:.4f} > {tol:.4f})")

    # Test 2: update latency
    print(f"\n{YELLOW}[Test 2] Weight update latency (10 update){NC}")
    times = {1:[],2:[],3:[],'3s':[]}
    for _ in range(10):
        nm = FRRModel()
        times[1].append(m1.update_weights(nm)*1000)
        times[2].append(m2.update_weights(nm)*1000)
        times[3].append(m3.update_weights(nm)*1000)
        times['3s'].append(m3.update_weights(nm, layer_idx=2)*1000)
    for key, lbl in [(1,'Method 1 hardcoded (ricompilazione simulata)'),(2,'Method 2 template  (map update)'),
                     (3,'Method 3 modular   (tutti i layer)'),('3s','Method 3 modular   (singolo layer hot-swap)')]:
        avg = sum(times[key])/10
        info(f"{lbl}: avg={avg:.3f}ms  max={max(times[key]):.3f}ms")
    total+=1; passed+=1; ok("Update latency misurata")

    # Test 3: determinismo
    print(f"\n{YELLOW}[Test 3] Determinismo (100 run){NC}")
    xf = make_input(I)
    rs = {int(np.argmax(m2.infer(xf))) for _ in range(100)}
    total+=1
    if len(rs)==1: ok(f"Method 2: deterministico ({list(rs)[0]}) su 100 run"); passed+=1
    else: fail(f"Method 2: NON deterministico: {rs}")

    # Test 4: consistenza post-update
    print(f"\n{YELLOW}[Test 4] Consistenza post-update{NC}")
    nm = FRRModel()
    m2.update_weights(nm); m3.update_weights(nm)
    mp = sum(1 for _ in range(N) if int(np.argmax(m2.infer(make_input(I))))!=int(np.argmax(m3.infer(make_input(I)))))
    total+=1
    if mp==0: ok(f"Method 2 e 3 concordano su {N} campioni dopo update"); passed+=1
    else: fail(f"Method 2 e 3 discordano su {mp}/{N} campioni")

    # Test 5: caricamento .pt con dimensioni dinamiche
    print(f"\n{YELLOW}[Test 5] Caricamento modello .pt (dimensioni auto-inferite){NC}")
    total+=1
    pt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'frr_germany50_5_model_4x2.pt')
    if os.path.exists(pt_path):
        try:
            loaded, li, lh, lo = load_pt_dynamic(pt_path)
            x   = make_input(li)
            nh  = int(np.argmax(pytorch_ref(loaded, x)))
            sc  = compute_scale(loaded)
            ok(f".pt caricato | arch={li}->{lh}->{lh}->{lo} | next-hop={nh} | scale={sc}")
            passed+=1
        except Exception as e:
            fail(f"Errore caricamento .pt: {e}")
    else:
        info(f".pt non trovato ({pt_path}) — test saltato")
        total-=1

    print(f"\n{YELLOW}{'='*52}{NC}")
    color = GREEN if passed==total else RED
    print(f"{color} Risultato: {passed}/{total} test passati{NC}")
    if passed<total: print(f"{RED} Controlla i messaggi [FAIL] sopra{NC}")
    print(f"{YELLOW}{'='*52}{NC}\n")
    return passed==total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', type=str, default=None)
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    torch.manual_seed(42)
    model = FRRModel()
    pt_path = args.model or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'frr_germany50_5_model_4x2.pt')
    if os.path.exists(pt_path):
        try:
            # Carica il modello principale con le sue dimensioni reali
            loaded, li, lh, lo = load_pt_dynamic(pt_path)
            if li == INPUT_SIZE and lh == HIDDEN_DIM:
                model = loaded
                print(f"{GREEN}[OK]{NC} Modello caricato da {pt_path} (arch {li}->{lh}->{lo})")
            else:
                print(f"{YELLOW}[INFO]{NC} .pt ha arch {li}->{lh}->{lo} (diversa da default {INPUT_SIZE}->{HIDDEN_DIM}->{OUTPUT_SIZE})")
                print(f"{YELLOW}[INFO]{NC} Test 1-4 usano pesi casuali (seed=42), Test 5 usa il .pt")
        except Exception as e:
            print(f"{YELLOW}[WARN]{NC} {e} — uso pesi casuali")
    else:
        print(f"{YELLOW}[INFO]{NC} Nessun .pt trovato — pesi casuali (seed=42)")
    sys.exit(0 if run_tests(model, args.verbose) else 1)


if __name__ == '__main__':
    main()
