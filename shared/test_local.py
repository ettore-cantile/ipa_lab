#!/usr/bin/env python3
"""
test_local.py - Test locale dei 3 metodi IPA (nessun eBPF/XDP richiesto)

Testa:
  - Method 1 (hardcoded):  inferenza con architettura fissa 65-4-4-7
  - Method 2 (template):   stessa arch, pesi caricabili a runtime da dict
  - Method 3 (modular):    tre blocchi layer separati, stato via scratch buffer

Veriifica:
  1. Output consistency  - i 3 metodi producono lo stesso next-hop dato lo stesso input
  2. Weight update cost  - misura latenza di aggiornamento pesi (simula bpf_map_update)
  3. Argmax correctness  - il next-hop scelto corrisponde al neurone con valore massimo
  4. Scale factor        - quantizzazione int8 e dequantizzazione producono errore < 0.05

Utilizzo:
  python3 shared/test_local.py
  python3 shared/test_local.py --model shared/frr_germany50_5_model_4x2.pt
  python3 shared/test_local.py --verbose
"""

import argparse
import json
import math
import time
import sys
import os

try:
    import torch
    import torch.nn as nn
except ImportError:
    print("[ERROR] PyTorch non trovato. Installa con: pip install torch")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configurazione modello (deve corrispondere a frr_germany50_5_model_4x2.pt)
# ---------------------------------------------------------------------------
INPUT_SIZE   = 65
HIDDEN_SIZE  = 4
OUTPUT_SIZE  = 7
SCALE_FACTOR = 128

GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
RED    = "\033[0;31m"
NC     = "\033[0m"


def ok(msg):   print(f"  {GREEN}[PASS]{NC} {msg}")
def fail(msg): print(f"  {RED}[FAIL]{NC} {msg}")
def info(msg): print(f"  {YELLOW}[INFO]{NC} {msg}")


# ===========================================================================
# Definizione del modello FRR (deve combaciare con FRR_model.py)
# ===========================================================================
class FRRModel(nn.Module):
    def __init__(self, input_size=INPUT_SIZE, hidden_size=HIDDEN_SIZE, output_size=OUTPUT_SIZE):
        super().__init__()
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.fc2 = nn.Linear(hidden_size, hidden_size)
        self.fc3 = nn.Linear(hidden_size, output_size)
        self.relu = nn.ReLU()

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        return self.fc3(x)  # logits (no softmax — argmax diretto)


# ===========================================================================
# Method 1 — Hardcoded: architettura fissa, pesi embedding al caricamento
# Simula: eBPF con pesi come costanti C nel sorgente, ricompilazione necessaria
# ===========================================================================
class Method1_Hardcoded:
    """Pesi fissati al momento del caricamento (simulano costanti eBPF)."""

    def __init__(self, model: FRRModel):
        # Snapshot dei pesi al momento del deploy — immutabili
        state = model.state_dict()
        self.W1 = state['fc1.weight'].numpy().copy()
        self.b1 = state['fc1.bias'].numpy().copy()
        self.W2 = state['fc2.weight'].numpy().copy()
        self.b2 = state['fc2.bias'].numpy().copy()
        self.W3 = state['fc3.weight'].numpy().copy()
        self.b3 = state['fc3.bias'].numpy().copy()
        self._compile_time = time.perf_counter()  # simula compile time

    def infer(self, x):
        """Forward pass con pesi hardcoded."""
        import numpy as np
        h1 = np.maximum(0, self.W1 @ x + self.b1)
        h2 = np.maximum(0, self.W2 @ h1 + self.b2)
        out = self.W3 @ h2 + self.b3
        return out

    def update_weights(self, new_model: FRRModel) -> float:
        """Simula aggiornamento: deve ricompilare il programma eBPF.
        Costo = ricompilazione BCC + reload XDP (tipicamente 200-800ms).
        Qui lo simuliamo con un sleep proporzionale."""
        t0 = time.perf_counter()
        # Simula ricompilazione BCC (in realta' sarebbe subprocess + bpf load)
        time.sleep(0.001)  # 1ms placeholder — in produzione ~200-500ms
        state = new_model.state_dict()
        self.W1 = state['fc1.weight'].numpy().copy()
        self.b1 = state['fc1.bias'].numpy().copy()
        self.W2 = state['fc2.weight'].numpy().copy()
        self.b2 = state['fc2.bias'].numpy().copy()
        self.W3 = state['fc3.weight'].numpy().copy()
        self.b3 = state['fc3.bias'].numpy().copy()
        return time.perf_counter() - t0


# ===========================================================================
# Method 2 — Template: architettura fissa, pesi in BPF_ARRAY aggiornabile
# Simula: eBPF con arch template C, pesi in mappa -> solo bpf_map_update
# ===========================================================================
class Method2_Template:
    """Pesi in una 'BPF map' (dict Python) aggiornabile a runtime."""

    def __init__(self, model: FRRModel, scale: int = SCALE_FACTOR):
        self.scale = scale
        self.weight_map = {}  # simula BPF_ARRAY
        self._load_weights(model)

    def _quantize(self, val: float) -> int:
        """Quantizzazione int8 come in eBPF: val * scale -> clamp [-128, 127]."""
        return max(-128, min(127, int(round(val * self.scale))))

    def _load_weights(self, model: FRRModel):
        """Popola weight_map con pesi quantizzati (simula bpf_map_update_elem)."""
        state = model.state_dict()
        idx = 0
        for key in ['fc1.weight', 'fc1.bias', 'fc2.weight', 'fc2.bias',
                    'fc3.weight', 'fc3.bias']:
            for val in state[key].flatten().tolist():
                self.weight_map[idx] = self._quantize(val)
                idx += 1
        self._n_weights = idx

    def _get_matrix(self, offset, rows, cols):
        """Ricostruisce matrice float da weight_map (simula lettura BPF_ARRAY)."""
        import numpy as np
        mat = []
        for i in range(rows * cols):
            mat.append(self.weight_map[offset + i] / self.scale)
        return np.array(mat).reshape(rows, cols)

    def _get_bias(self, offset, size):
        import numpy as np
        return np.array([self.weight_map[offset + i] / self.scale for i in range(size)])

    def infer(self, x):
        import numpy as np
        # Calcola offset per ogni layer
        off = 0
        W1 = self._get_matrix(off, HIDDEN_SIZE, INPUT_SIZE);  off += HIDDEN_SIZE * INPUT_SIZE
        b1 = self._get_bias(off, HIDDEN_SIZE);                off += HIDDEN_SIZE
        W2 = self._get_matrix(off, HIDDEN_SIZE, HIDDEN_SIZE); off += HIDDEN_SIZE * HIDDEN_SIZE
        b2 = self._get_bias(off, HIDDEN_SIZE);                off += HIDDEN_SIZE
        W3 = self._get_matrix(off, OUTPUT_SIZE, HIDDEN_SIZE); off += OUTPUT_SIZE * HIDDEN_SIZE
        b3 = self._get_bias(off, OUTPUT_SIZE)

        h1 = np.maximum(0, W1 @ x + b1)
        h2 = np.maximum(0, W2 @ h1 + b2)
        return W3 @ h2 + b3

    def update_weights(self, new_model: FRRModel) -> float:
        """Aggiornamento pesi via bpf_map_update_elem — nessuna ricompilazione."""
        t0 = time.perf_counter()
        self._load_weights(new_model)  # O(n_weights) map updates
        return time.perf_counter() - t0


# ===========================================================================
# Method 3 — Modular: layer come programmi eBPF separati, tail calls
# Simula: layer_chain[0->1->2], scratch buffer via BPF_PERCPU_ARRAY
# ===========================================================================
class Method3_Modular:
    """Tre layer separati con scratch buffer condiviso (simula tail call chain)."""

    def __init__(self, model: FRRModel, scale: int = SCALE_FACTOR):
        self.scale = scale
        # Ogni layer ha la propria map di pesi
        self.layer_weights = [{}, {}, {}]
        self._load_weights(model)

    def _quantize(self, val: float) -> int:
        return max(-128, min(127, int(round(val * self.scale))))

    def _load_weights(self, model: FRRModel):
        state = model.state_dict()
        layers = [
            ('fc1.weight', 'fc1.bias', HIDDEN_SIZE, INPUT_SIZE),
            ('fc2.weight', 'fc2.bias', HIDDEN_SIZE, HIDDEN_SIZE),
            ('fc3.weight', 'fc3.bias', OUTPUT_SIZE, HIDDEN_SIZE),
        ]
        for li, (wk, bk, rows, cols) in enumerate(layers):
            idx = 0
            for val in model.state_dict()[wk].flatten().tolist():
                self.layer_weights[li][idx] = self._quantize(val)
                idx += 1
            for val in model.state_dict()[bk].flatten().tolist():
                self.layer_weights[li][idx] = self._quantize(val)
                idx += 1

    def _run_layer(self, layer_idx, x_in, out_size):
        import numpy as np
        in_size = len(x_in)
        lw = self.layer_weights[layer_idx]
        W = np.array([lw[i] / self.scale for i in range(out_size * in_size)]).reshape(out_size, in_size)
        b = np.array([lw[out_size * in_size + i] / self.scale for i in range(out_size)])
        out = W @ x_in + b
        return out

    def infer(self, x):
        import numpy as np
        # Scratch buffer: simula BPF_PERCPU_ARRAY tra tail calls
        scratch = x.copy()

        # Layer 0: fc1 + ReLU
        h1 = self._run_layer(0, scratch, HIDDEN_SIZE)
        h1 = np.maximum(0, h1)  # ReLU

        # Layer 1: fc2 + ReLU
        h2 = self._run_layer(1, h1, HIDDEN_SIZE)
        h2 = np.maximum(0, h2)

        # Layer 2: fc3 (output, no ReLU)
        out = self._run_layer(2, h2, OUTPUT_SIZE)
        return out

    def update_weights(self, new_model: FRRModel, layer_idx: int = None) -> float:
        """Aggiorna uno o tutti i layer (simula hot-swap di singolo layer eBPF)."""
        t0 = time.perf_counter()
        if layer_idx is None:
            self._load_weights(new_model)  # aggiorna tutti
        else:
            # Aggiorna solo il layer specificato (vantaggio chiave del metodo 3)
            state = new_model.state_dict()
            layer_keys = [
                ('fc1.weight', 'fc1.bias', HIDDEN_SIZE, INPUT_SIZE),
                ('fc2.weight', 'fc2.bias', HIDDEN_SIZE, HIDDEN_SIZE),
                ('fc3.weight', 'fc3.bias', OUTPUT_SIZE, HIDDEN_SIZE),
            ]
            wk, bk, rows, cols = layer_keys[layer_idx]
            idx = 0
            for val in state[wk].flatten().tolist():
                self.layer_weights[layer_idx][idx] = self._quantize(val)
                idx += 1
            for val in state[bk].flatten().tolist():
                self.layer_weights[layer_idx][idx] = self._quantize(val)
                idx += 1
        return time.perf_counter() - t0


# ===========================================================================
# Test runner
# ===========================================================================
def make_random_input():
    import numpy as np
    return np.random.uniform(-1, 1, INPUT_SIZE).astype(np.float32)


def pytorch_reference(model, x_np):
    """Output di riferimento PyTorch float32."""
    with torch.no_grad():
        t = torch.tensor(x_np, dtype=torch.float32)
        return model(t).numpy()


def run_tests(model, verbose=False):
    import numpy as np
    print(f"\n{YELLOW}=== TEST LOCAL — IPA Pipeline (3 metodi) ==={NC}\n")

    m1 = Method1_Hardcoded(model)
    m2 = Method2_Template(model)
    m3 = Method3_Modular(model)

    N_SAMPLES = 50
    ARGMAX_MISMATCHES = {1: 0, 2: 0, 3: 0}
    MAX_ERR = {1: 0.0, 2: 0.0, 3: 0.0}
    passed = 0
    total  = 0

    # -------------------------------------------------------------------
    # TEST 1: Output consistency + argmax correttezza
    # -------------------------------------------------------------------
    print(f"{YELLOW}[Test 1] Output consistency & argmax ({N_SAMPLES} campioni casuali){NC}")
    for _ in range(N_SAMPLES):
        x = make_random_input()
        ref = pytorch_reference(model, x)
        ref_nh = int(np.argmax(ref))

        for mid, m in [(1, m1), (2, m2), (3, m3)]:
            out = m.infer(x)
            nh  = int(np.argmax(out))
            err = float(np.max(np.abs(out - ref)))
            MAX_ERR[mid] = max(MAX_ERR[mid], err)
            if nh != ref_nh:
                ARGMAX_MISMATCHES[mid] += 1

    for mid, name in [(1,'hardcoded'), (2,'template'), (3,'modular')]:
        mismatches = ARGMAX_MISMATCHES[mid]
        max_err    = MAX_ERR[mid]
        total += 1
        if mismatches == 0:
            ok(f"Method {mid} ({name}): argmax 100% corretto | max_err={max_err:.4f}")
            passed += 1
        else:
            fail(f"Method {mid} ({name}): {mismatches}/{N_SAMPLES} argmax errati | max_err={max_err:.4f}")

    # Soglia errore quantizzazione: con scale=128, errore max atteso < 0.05
    total += 3
    for mid, name in [(2,'template'), (3,'modular')]:
        if MAX_ERR[mid] < 0.05:
            ok(f"Method {mid} ({name}): errore quantizzazione accettabile ({MAX_ERR[mid]:.4f} < 0.05)")
            passed += 2 if mid == 2 else 1
        else:
            fail(f"Method {mid} ({name}): errore quantizzazione ALTO ({MAX_ERR[mid]:.4f} >= 0.05)")
    # method 1 e' float puro, nessun errore di quantizzazione
    total -= 1
    ok(f"Method 1 (hardcoded): nessuna quantizzazione, errore float {MAX_ERR[1]:.6f}")
    passed += 1

    # -------------------------------------------------------------------
    # TEST 2: Weight update latency (simula bpf_map_update vs ricompilazione)
    # -------------------------------------------------------------------
    print(f"\n{YELLOW}[Test 2] Weight update latency (10 update per metodo){NC}")
    N_UPDATES = 10
    update_times = {1: [], 2: [], 3: [], '3_single': []}

    for _ in range(N_UPDATES):
        new_model = FRRModel()
        # Method 1: simula ricompilazione eBPF
        t = m1.update_weights(new_model)
        update_times[1].append(t * 1000)  # ms
        # Method 2: solo map update
        t = m2.update_weights(new_model)
        update_times[2].append(t * 1000)
        # Method 3: tutti i layer
        t = m3.update_weights(new_model)
        update_times[3].append(t * 1000)
        # Method 3: singolo layer (hot-swap parziale)
        t = m3.update_weights(new_model, layer_idx=2)
        update_times['3_single'].append(t * 1000)

    for key, label in [
        (1, 'Method 1 hardcoded (simula ricompilazione)'),
        (2, 'Method 2 template  (solo map update)'),
        (3, 'Method 3 modular   (tutti i layer)'),
        ('3_single', 'Method 3 modular   (singolo layer, hot-swap)'),
    ]:
        avg = sum(update_times[key]) / N_UPDATES
        mx  = max(update_times[key])
        info(f"{label}: avg={avg:.3f}ms  max={mx:.3f}ms")
    passed += 1
    total  += 1
    ok("Update latency misurata")

    # -------------------------------------------------------------------
    # TEST 3: Determinismo — stesso input deve dare stesso output
    # -------------------------------------------------------------------
    print(f"\n{YELLOW}[Test 3] Determinismo (100 run dello stesso input){NC}")
    x_fixed = make_random_input()
    results = set()
    for _ in range(100):
        nh = int(np.argmax(m2.infer(x_fixed)))
        results.add(nh)
    total += 1
    if len(results) == 1:
        ok(f"Method 2: output deterministico ({list(results)[0]}) su 100 run")
        passed += 1
    else:
        fail(f"Method 2: output NON deterministico: {results}")

    # -------------------------------------------------------------------
    # TEST 4: Consistenza metodi 2 e 3 con modello aggiornato
    # -------------------------------------------------------------------
    print(f"\n{YELLOW}[Test 4] Consistenza post-update (stesso modello aggiornato){NC}")
    new_model = FRRModel()
    m2.update_weights(new_model)
    m3.update_weights(new_model)

    mismatches = 0
    for _ in range(N_SAMPLES):
        x = make_random_input()
        nh2 = int(np.argmax(m2.infer(x)))
        nh3 = int(np.argmax(m3.infer(x)))
        if nh2 != nh3:
            mismatches += 1

    total += 1
    if mismatches == 0:
        ok(f"Method 2 e 3 concordano su {N_SAMPLES} campioni dopo update")
        passed += 1
    else:
        fail(f"Method 2 e 3 discordano su {mismatches}/{N_SAMPLES} campioni dopo update")

    # -------------------------------------------------------------------
    # TEST 5: Caricamento modello .pt reale (se fornito)
    # -------------------------------------------------------------------
    print(f"\n{YELLOW}[Test 5] Caricamento modello .pt{NC}")
    total += 1
    pt_path = os.path.join(os.path.dirname(__file__), 'frr_germany50_5_model_4x2.pt')
    if os.path.exists(pt_path):
        try:
            loaded = FRRModel()
            state  = torch.load(pt_path, map_location='cpu', weights_only=True)
            loaded.load_state_dict(state)
            x = make_random_input()
            out = pytorch_reference(loaded, x)
            nh  = int(np.argmax(out))
            ok(f"Modello caricato da {pt_path} | next-hop campione: {nh}")
            passed += 1
        except Exception as e:
            fail(f"Errore caricamento .pt: {e}")
    else:
        info(f"File .pt non trovato in {pt_path} (test saltato)")
        total -= 1

    # -------------------------------------------------------------------
    # Riepilogo
    # -------------------------------------------------------------------
    print(f"\n{YELLOW}{'='*50}{NC}")
    color = GREEN if passed == total else RED
    print(f"{color} Risultato: {passed}/{total} test passati{NC}")
    if passed < total:
        print(f"{RED} Alcuni test falliti — controlla i messaggi sopra{NC}")
    print(f"{YELLOW}{'='*50}{NC}\n")
    return passed == total


def main():
    parser = argparse.ArgumentParser(description="Test locale pipeline IPA")
    parser.add_argument('--model', type=str, default=None,
                        help='Path al file .pt del modello (opzionale)')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    torch.manual_seed(42)

    model = FRRModel()
    if args.model:
        try:
            state = torch.load(args.model, map_location='cpu', weights_only=True)
            model.load_state_dict(state)
            print(f"{GREEN}[OK]{NC} Modello caricato da {args.model}")
        except Exception as e:
            print(f"{RED}[WARN]{NC} Impossibile caricare {args.model}: {e}")
            print(f"{YELLOW}[INFO]{NC} Uso modello con pesi casuali (torch.manual_seed=42)")
    else:
        print(f"{YELLOW}[INFO]{NC} Nessun modello specificato — pesi casuali (seed=42)")
        pt_path = os.path.join(os.path.dirname(__file__), 'frr_germany50_5_model_4x2.pt')
        if os.path.exists(pt_path):
            try:
                state = torch.load(pt_path, map_location='cpu', weights_only=True)
                model.load_state_dict(state)
                print(f"{GREEN}[OK]{NC} Auto-caricato {pt_path}")
            except Exception:
                pass

    success = run_tests(model, verbose=args.verbose)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
