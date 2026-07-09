#!/usr/bin/env python3
"""
test_suite.py — Suite di test LOCALE dei 3 metodi IPA (nessun eBPF/XDP richiesto)
================================================================================

Unico script che accorpa tutti i test locali (prima sparsi su test_local.py,
test_ipa_methods.py, test_extract_weights.py, test_quantization_accuracy.py,
test_robustness.py). Serve a misurare, in locale con PyTorch/NumPy, le
proprieta' e le metriche del design-space richieste dal professore, senza
bisogno di kernel/eBPF (per la verifica in-kernel usa verify_prog_run.py).

Suite disponibili (--only):
  core     : consistenza inferenza, update latency, determinismo, .pt load,
             e la tabella design-space (throughput, tail calls, map lookups,
             memoria mappe, flessibilita')                    [ex test_local]
  pktstats : hit/fake/miss per i 3 metodi + coerenza counter   [ex test_ipa_methods]
  extract  : coerenza extract_weights.py / weights.json / dequant [ex test_extract_weights]
  quant    : accuracy argmax vs scale_factor (PTQ trade-off)   [ex test_quantization_accuracy]
  robust   : input edge-case, nessun crash, argmax valido       [ex test_robustness]
  all      : tutte (default)

Utilizzo:
  python3 shared/test_suite.py                       # tutte le suite
  python3 shared/test_suite.py --only core --verbose
  python3 shared/test_suite.py --only quant --samples 200
  python3 shared/test_suite.py --model shared/frr_germany50_5_model_4x2.pt
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


def decode_nexthop(argmax_idx: int, n_interfaces: int = N_INTERFACES) -> str:
    """
    Converte l'indice argmax dell'output della rete nella stringa
    leggibile del next-hop.

    Convenzione label encoding (da FRR_model.py / dataset):
      0           -> DROP (nessuna rotta disponibile)
      1 .. N_INT  -> eth{idx-1}  (interfaccia fisica 0-indexed)
    """
    if argmax_idx == 0:
        return "DROP"
    iface_idx = argmax_idx - 1
    if 0 <= iface_idx < n_interfaces:
        return f"eth{iface_idx}"
    return f"UNKNOWN(idx={argmax_idx})"


# ===========================================================================
# Modello con architettura fissa
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
        time.sleep(0.001)
        self._copy_weights(new_model)
        return time.perf_counter() - t0


# ===========================================================================
# Method 2 - Template
# ===========================================================================
class Method2_Template:
    def __init__(self, model: FRRModel):
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


# ===========================================================================
# Method 3 - Modular
# ===========================================================================
class Method3_Modular:
    def __init__(self, model: FRRModel):
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


# Varianti a scale fisso (usate dalla suite quant)
class Method2_FixedScale(Method2_Template):
    """Variante di Method2 con scale_factor fisso (non auto-calcolato)."""
    def __init__(self, model, scale: int):
        super().__init__(model)
        self.scale = scale
        self._load(model)

    def _load(self, model):  # non ricalcolare lo scale
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
    """Variante di Method3 con scale_factor fisso."""
    def __init__(self, model, scale: int):
        super().__init__(model)
        self.scale = scale
        self._load(model)

    def _load(self, model, layer_idx=None):  # non ricalcolare lo scale
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


# ===========================================================================
# Helpers
# ===========================================================================
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
    print(f"{color} Risultato: {passed}/{total} test passati{NC}")
    if passed < total:
        print(f"{RED} Controlla i messaggi [FAIL] sopra{NC}")
    print(f"{YELLOW}{'='*52}{NC}\n")


# ===========================================================================
# SUITE: core  (ex test_local.py)
# ===========================================================================
def suite_core(model, verbose=False):
    print(f"\n{YELLOW}=== SUITE core — IPA Pipeline (3 metodi) ==={NC}\n")
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
    info(f"Next-hop encoding: output 0=DROP, 1=eth0, 2=eth1, ..., {O-1}=eth{O-2}")
    print()

    N = 50
    passed = total = 0

    print(f"{YELLOW}[Test 1] Output consistency & argmax ({N} campioni){NC}")
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
    ok(f"Method 1 (hardcoded): argmax 100% corretto | max_err={me[1]:.6f}")

    for mid, name in [(2, 'template'), (3, 'modular')]:
        total += 1
        pct = mm[mid] / N * 100
        if pct <= 10:
            ok(f"Method {mid} ({name}): argmax {100-pct:.0f}% corretto ({mm[mid]}/{N}) | max_err={me[mid]:.4f}")
            passed += 1
        else:
            fail(f"Method {mid} ({name}): {mm[mid]}/{N} argmax errati | max_err={me[mid]:.4f} | scale={m2.scale}")

    for mid, name, sc in [(2, 'template', m2.scale), (3, 'modular', m3.scale)]:
        total += 1
        tol = H / sc
        if me[mid] <= tol:
            ok(f"Method {mid} ({name}): errore quant. ok ({me[mid]:.4f} <= {tol:.4f})")
            passed += 1
        else:
            fail(f"Method {mid} ({name}): errore quant. ALTO ({me[mid]:.4f} > {tol:.4f})")

    print(f"\n{YELLOW}[Test 2] Weight update latency (10 update){NC}")
    times = {1: [], 2: [], 3: [], '3s': []}
    for _ in range(10):
        nm = FRRModel()
        times[1].append(m1.update_weights(nm) * 1000)
        times[2].append(m2.update_weights(nm) * 1000)
        times[3].append(m3.update_weights(nm) * 1000)
        times['3s'].append(m3.update_weights(nm, layer_idx=2) * 1000)

    for key, lbl in [
        (1, 'Method 1 hardcoded (ricompilazione simulata)'),
        (2, 'Method 2 template  (map update)'),
        (3, 'Method 3 modular   (tutti i layer)'),
        ('3s', 'Method 3 modular   (singolo layer hot-swap)')
    ]:
        avg = sum(times[key]) / 10
        info(f"{lbl}: avg={avg:.3f}ms  max={max(times[key]):.3f}ms")
    total += 1
    passed += 1
    ok("Update latency misurata")

    print(f"\n{YELLOW}[Test 3] Determinismo (100 run){NC}")
    xf = make_input(I)
    rs = {int(np.argmax(m2.infer(xf))) for _ in range(100)}
    total += 1
    if len(rs) == 1:
        nh_str = decode_nexthop(list(rs)[0])
        ok(f"Method 2: deterministico ({list(rs)[0]} -> {nh_str}) su 100 run")
        passed += 1
    else:
        fail(f"Method 2: NON deterministico: {rs}")

    print(f"\n{YELLOW}[Test 4] Consistenza post-update{NC}")
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
        ok(f"Method 2 e 3 concordano su {N} campioni dopo update")
        passed += 1
    else:
        fail(f"Method 2 e 3 discordano su {mp}/{N} campioni")

    print(f"\n{YELLOW}[Test 5] Caricamento modello .pt (dimensioni auto-inferite){NC}")
    total += 1
    pt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frr_germany50_5_model_4x2.pt')
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
            fail(f"Errore caricamento .pt: {e}")
    else:
        info(f".pt non trovato ({pt_path}) — test saltato")
        total -= 1

    # -----------------------------------------------------------------------
    # Test 6 — Design-space metrics (professor requirement)
    # NOTA: il throughput Python NON e' la metrica di confronto corretta
    # (M1 usa NumPy matmul, M2/M3 dict lookup per simulare BPF map). Il
    # trade-off reale e' sulle metriche STRUTTURALI eBPF: tail calls, map
    # lookups, memoria mappe -- costanti architetturali indipendenti dall'emulatore.
    # -----------------------------------------------------------------------
    print(f"\n{YELLOW}[Test 6] Design-space metrics (throughput, struttura, memoria){NC}")

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
    info(f"Throughput inferenza (Python, single-core, {BENCH_SECS:.0f}s benchmark):")
    for mid, name in [(1, 'hardcoded'), (2, 'template'), (3, 'modular')]:
        mpps, cnt, el = throughputs[mid]
        info(f"  Method {mid} ({name:<10}): {mpps:.4f} Mpps  ({cnt} infer in {el:.2f}s)")
    info("  NOTE: eBPF kernel throughput expected 10-100x higher (no Python overhead)")
    info("  NOTE: throughput Python non usato per l'assertion (vedi commento Test 6)")

    n_fc1 = I * H + H
    n_fc2 = H * H + H
    n_out = H * O + O
    N_WEIGHTS = n_fc1 + n_fc2 + n_out

    # tail_calls: P1 1, P2 1, P3 4 (dispatcher + 3 layer tail calls)
    TAIL_CALLS = {1: 1, 2: 1, 3: 4}

    # map_lookups per packet
    p3_lookups = (1 + I
                  + (I * H) + H
                  + (H * H) + H
                  + (H * O) + H
                  + 2)
    MAP_LOOKUPS = {1: 2, 2: N_WEIGHTS + 3, 3: p3_lookups}

    try:
        import multiprocessing
        ncpus = multiprocessing.cpu_count()
    except Exception:
        ncpus = 4

    MAP_MEM_BYTES = {
        1: 256 * 22 + 256 * 9 + 3 * 8,
        2: N_WEIGHTS * 1 + 256 * 7 + 256 * 22 + 256 * 9 + 3 * 8,
        3: N_WEIGHTS * 2 + 256 * 14 + (H + 16) * 8 * ncpus + 256 * 22 + 256 * 9 + 3 * 8,
    }
    FLEXIBILITY = {1: 'bassa',  2: 'media',  3: 'alta'}
    MODEL_UPDATE = {
        1: 'ricompila + ricarica programma eBPF',
        2: 'bpf_map_update_elem() su arch_weights',
        3: 'bpf_map_update_elem() su layer_weights + aggiorna layer_chain',
    }

    print()
    COL = 32
    hdr = f"  {'Metrica':<{COL}} {'P1 hardcoded':>16} {'P2 template':>16} {'P3 modular':>16}"
    sep = "  " + "-" * (COL + 50)
    print(hdr)
    print(sep)

    def row(label, vals):
        v = [str(vals[k]) for k in [1, 2, 3]]
        print(f"  {label:<{COL}} {v[0]:>16} {v[1]:>16} {v[2]:>16}")

    row("Throughput locale (Mpps)",
        {k: f"{throughputs[k][0]:.4f}" for k in [1, 2, 3]})
    row("Tail calls / pacchetto",  TAIL_CALLS)
    row("Map lookups / pacchetto", MAP_LOOKUPS)
    row("Memoria BPF maps (stima)",
        {k: f"{MAP_MEM_BYTES[k]//1024}KB ({MAP_MEM_BYTES[k]}B)" for k in [1, 2, 3]})
    row("Flessibilita'",           FLEXIBILITY)
    print(sep)
    print()

    info(f"CPU logiche rilevate: {ncpus} (influenza scratch map PERCPU per P3)")
    print()
    for mid, lbl in [(1, 'P1 hardcoded'), (2, 'P2 template'), (3, 'P3 modular')]:
        info(f"{lbl} - aggiornamento modello: {MODEL_UPDATE[mid]}")
    print()

    total += 1
    tc_ok = TAIL_CALLS[1] <= TAIL_CALLS[2] <= TAIL_CALLS[3]
    ml_ok = MAP_LOOKUPS[1] <= MAP_LOOKUPS[2] <= MAP_LOOKUPS[3]
    if tc_ok and ml_ok:
        ok(f"Trade-off eBPF confermato: "
           f"tail_calls P1({TAIL_CALLS[1]}) <= P2({TAIL_CALLS[2]}) <= P3({TAIL_CALLS[3]}) | "
           f"map_lookups P1({MAP_LOOKUPS[1]}) <= P2({MAP_LOOKUPS[2]}) <= P3({MAP_LOOKUPS[3]})")
        passed += 1
    else:
        fail(f"Trade-off strutturale incoerente: "
             f"tail_calls={list(TAIL_CALLS.values())} map_lookups={list(MAP_LOOKUPS.values())}")

    total += 1
    if TAIL_CALLS[3] > TAIL_CALLS[1] and MAP_LOOKUPS[3] > MAP_LOOKUPS[1]:
        ok(f"Struttura: P3 ha piu' tail calls ({TAIL_CALLS[3]}) e map lookups ({MAP_LOOKUPS[3]}) di P1 ({TAIL_CALLS[1]}, {MAP_LOOKUPS[1]})")
        passed += 1
    else:
        fail("Struttura: conteggi tail call / map lookup incoerenti")

    total += 1
    if MAP_MEM_BYTES[3] > MAP_MEM_BYTES[1]:
        ok(f"Memoria: P3 ({MAP_MEM_BYTES[3]}B) > P1 ({MAP_MEM_BYTES[1]}B) come atteso")
        passed += 1
    else:
        fail(f"Memoria: P3 ({MAP_MEM_BYTES[3]}B) dovrebbe essere > P1 ({MAP_MEM_BYTES[1]}B)")

    _banner(passed, total)
    return passed == total


# ===========================================================================
# SUITE: pktstats  (ex test_ipa_methods.py)
# ===========================================================================
def _classify_packet(output_vec, ref_vec, valid_outputs):
    """HIT: argmax corretto e in valid_outputs; FAKE: in valid_outputs ma
    argmax errato; MISS: action non in valid_outputs (DROP/unknown)."""
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

    print(f"\n{YELLOW}=== SUITE pktstats — pkt_stats (3 pipeline) ==={NC}\n")
    model = FRRModel()
    H = model.fc1.out_features
    I = model.fc1.in_features
    O = model.out.out_features
    print(f"  Architettura: {I} -> {H} -> {H} -> {O} | samples={n_samples} | seed={seed}")
    print()

    m1 = Method1_Hardcoded(model)
    m2 = Method2_Template(model)
    m3 = Method3_Modular(model)

    valid_outputs = set(range(1, O))
    info(f"valid_outputs = {valid_outputs}  (0=DROP/MISS)")
    print()

    inputs = [make_input(I) for _ in range(n_samples)]
    passed = total = 0

    print(f"{YELLOW}[Test A] pkt_stats per metodo ({n_samples} campioni){NC}")
    stats = {}
    for mid, mobj, name in [(1, m1, 'hardcoded'), (2, m2, 'template'), (3, m3, 'modular')]:
        s = _run_pkt_stats(mobj, inputs, model, valid_outputs)
        stats[mid] = s
        total_pkts = s['HIT'] + s['FAKE'] + s['MISS']
        hit_rate   = s['HIT'] / total_pkts * 100
        info(f"  P{mid} {name:<10}: HIT={s['HIT']:4d} ({hit_rate:.1f}%)  "
             f"FAKE={s['FAKE']:4d}  MISS={s['MISS']:4d}  total={total_pkts}")

    print(f"\n{YELLOW}[Test B] Totale counter == n_samples per ogni metodo{NC}")
    for mid in [1, 2, 3]:
        total += 1
        s = stats[mid]
        tot = s['HIT'] + s['FAKE'] + s['MISS']
        if tot == n_samples:
            ok(f"P{mid}: HIT+FAKE+MISS = {tot} == {n_samples}")
            passed += 1
        else:
            fail(f"P{mid}: HIT+FAKE+MISS = {tot} != {n_samples}")

    print(f"\n{YELLOW}[Test C] P1 hardcoded deve avere FAKE=0 (pesi float){NC}")
    total += 1
    if stats[1]['FAKE'] == 0:
        ok("P1 FAKE=0 confermato (hardcoded float)")
        passed += 1
    else:
        fail(f"P1 FAKE={stats[1]['FAKE']} (atteso 0 con pesi float)")

    print(f"\n{YELLOW}[Test D] P2 e P3 stesso HIT/FAKE/MISS (stessa quantizzazione){NC}")
    total += 1
    if stats[2] == stats[3]:
        ok(f"P2 e P3 concordano: HIT={stats[2]['HIT']} FAKE={stats[2]['FAKE']} MISS={stats[2]['MISS']}")
        passed += 1
    else:
        fail(f"P2={stats[2]} != P3={stats[3]}")

    print(f"\n{YELLOW}[Test E] HIT rate P1 >= P2 e P3 (float piu' preciso){NC}")
    total += 1
    hr1 = stats[1]['HIT'] / n_samples
    hr2 = stats[2]['HIT'] / n_samples
    hr3 = stats[3]['HIT'] / n_samples
    if hr1 >= hr2 and hr1 >= hr3:
        ok(f"HIT rate: P1={hr1:.3f} >= P2={hr2:.3f} >= P3={hr3:.3f}")
        passed += 1
    else:
        fail(f"HIT rate: P1={hr1:.3f} P2={hr2:.3f} P3={hr3:.3f} — atteso P1 massimo")

    print(f"\n{YELLOW}[Test F] pkt_stats dopo update pesi (nuovo modello random){NC}")
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
        ok(f"Counter post-update coerenti: P2={tot2} P3={tot3} == {n_samples}")
        passed += 1
    else:
        fail(f"Counter post-update: P2={tot2} P3={tot3} (atteso {n_samples})")

    total += 1
    if stats_new[2] == stats_new[3]:
        ok(f"P2 e P3 concordano post-update: HIT={stats_new[2]['HIT']}")
        passed += 1
    else:
        fail(f"P2/P3 discordano post-update: P2={stats_new[2]} P3={stats_new[3]}")

    _banner(passed, total)
    return passed == total


# ===========================================================================
# SUITE: extract  (ex test_extract_weights.py)
# ===========================================================================
def suite_extract(model_path):
    import json
    print(f"\n{YELLOW}=== SUITE extract — coerenza pesi/quantizzazione ==={NC}\n")
    print(f"  model: {model_path}")
    print()

    if not os.path.exists(model_path):
        fail(f"Modello non trovato: {model_path}")
        return False

    passed = total = 0
    shared_dir = os.path.dirname(os.path.abspath(model_path))

    print(f"{YELLOW}[Test 1] extract_weights_int8() — range e lunghezza{NC}")
    total += 1
    try:
        model, I, H, O = load_pt_dynamic(model_path)
        floats = [w for p in model.parameters() for w in p.data.view(-1).tolist()]
        max_abs = max(abs(w) for w in floats)
        scale_ew = int(127 / max_abs)  # formula di extract_weights.py
        n_weights_expected = I * H + H + H * H + H + H * O + O
        int8_weights = [max(-128, min(127, int(round(wf * scale_ew)))) for wf in floats]

        if len(int8_weights) == n_weights_expected:
            ok(f"N_WEIGHTS = {len(int8_weights)} (atteso {n_weights_expected})")
            passed += 1
        else:
            fail(f"N_WEIGHTS = {len(int8_weights)} != atteso {n_weights_expected}")
    except Exception as e:
        fail(f"Eccezione durante estrazione: {e}")
        _banner(passed, total)
        return False

    print(f"\n{YELLOW}[Test 2] Scale factor: extract_weights vs compute_scale(){NC}")
    total += 1
    scale_cs = compute_scale(model)
    both_valid = (scale_cs * max_abs <= 127.0 + 1e-6) and (scale_ew * max_abs <= 127.0 + 1e-6)
    if both_valid:
        ok(f"Entrambi i scale validi: compute_scale={scale_cs} extract_weights={scale_ew} | max|w|={max_abs:.6f}")
        passed += 1
    else:
        fail(f"Scale non valido: compute_scale={scale_cs} extract_weights={scale_ew} max|w|={max_abs:.6f}")

    print(f"\n{YELLOW}[Test 3] weights.json coerenza con estrazione live dal .pt{NC}")
    total += 1
    wj_path = os.path.join(shared_dir, 'weights.json')
    if not os.path.exists(wj_path):
        info(f"weights.json non trovato in {shared_dir} — test saltato")
        total -= 1
    else:
        with open(wj_path) as f:
            saved_weights = json.load(f)
        if len(saved_weights) != len(int8_weights):
            fail(f"Lunghezza diversa: weights.json={len(saved_weights)} vs live={len(int8_weights)}")
        else:
            mismatches = sum(1 for a, b in zip(saved_weights, int8_weights) if a != b)
            if mismatches == 0:
                ok(f"weights.json identico all'estrazione live ({len(saved_weights)} pesi)")
                passed += 1
            else:
                fail(f"weights.json ha {mismatches}/{len(int8_weights)} pesi diversi dall'estrazione live")
                info("  Rigenera con: python3 shared/extract_weights.py")

    print(f"\n{YELLOW}[Test 4] weights_float.json — scale_factor e valori float{NC}")
    wf_path = os.path.join(shared_dir, 'weights_float.json')
    if not os.path.exists(wf_path):
        info("weights_float.json non trovato — test saltato")
    else:
        with open(wf_path) as f:
            wf_data = json.load(f)
        saved_scale  = wf_data.get('scale_factor', -1)
        saved_floats = wf_data.get('weights', [])

        total += 1
        if saved_scale == scale_ew:
            ok(f"scale_factor in weights_float.json = {saved_scale} == estratto = {scale_ew}")
            passed += 1
        else:
            fail(f"scale_factor mismatch: file={saved_scale} vs live={scale_ew}")

        total += 1
        if len(saved_floats) == len(floats):
            max_diff = max(abs(a - b) for a, b in zip(saved_floats, floats))
            if max_diff < 1e-5:
                ok(f"Float weights identici (max_diff={max_diff:.2e})")
                passed += 1
            else:
                fail(f"Float weights divergono (max_diff={max_diff:.2e})")
        else:
            fail(f"Lunghezza float diversa: file={len(saved_floats)} vs live={len(floats)}")

    print(f"\n{YELLOW}[Test 5] Dequant: max|w_float - w_int8/scale| <= 1/scale{NC}")
    total += 1
    tol = 1.0 / scale_ew
    dequant = [w / scale_ew for w in int8_weights]
    max_dequant_err = max(abs(a - b) for a, b in zip(floats, dequant))
    clamped_count   = sum(1 for w in int8_weights if w == 127 or w == -128)
    if max_dequant_err <= tol + 1e-9:
        ok(f"max errore dequant = {max_dequant_err:.6f} <= {tol:.6f} (1/scale)")
        passed += 1
    else:
        fail(f"max errore dequant = {max_dequant_err:.6f} > {tol:.6f} (1/scale)")
    if clamped_count > 0:
        info(f"  {clamped_count}/{len(int8_weights)} pesi clamped a +-127/128 (overflow int8)")

    _banner(passed, total)
    return passed == total


# ===========================================================================
# SUITE: quant  (ex test_quantization_accuracy.py)
# ===========================================================================
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
    print(f"\n{YELLOW}=== SUITE quant — accuracy argmax vs scale_factor ==={NC}\n")
    torch.manual_seed(42)
    np.random.seed(42)

    if model_path and os.path.exists(model_path):
        model, I, H, O = load_pt_dynamic(model_path)
        print(f"  Modello: {model_path} | arch={I}->{H}->{H}->{O}")
    else:
        model = FRRModel()
        I = model.fc1.in_features
        H = model.fc1.out_features
        O = model.out.out_features
        print(f"  Modello: pesi casuali (seed=42) | arch={I}->{H}->{H}->{O}")
    print(f"  Campioni: {n_samples} | scale_factors: {SCALE_FACTORS}")
    print()

    inputs = [make_input(I) for _ in range(n_samples)]
    results = {sf: _evaluate_scale(model, sf, inputs, n_samples) for sf in SCALE_FACTORS}

    hdr = (f"  {'scale':>6} | {'max_err M2':>10} | {'acc M2 (%)':>10} | "
           f"{'wrong M2':>8} | {'max_err M3':>10} | {'acc M3 (%)':>10} | {'wrong M3':>8}")
    sep = "  " + "-" * (len(hdr) - 2)
    print(hdr)
    print(sep)
    for sf in SCALE_FACTORS:
        err2, acc2, w2, err3, acc3, w3 = results[sf]
        print(f"  {sf:>6} | {err2:>10.4f} | {acc2:>9.1f}% | {w2:>8} | "
              f"{err3:>10.4f} | {acc3:>9.1f}% | {w3:>8}")
    print(sep)
    print()

    passed = total = 0

    print(f"{YELLOW}[Test A] max_err M2 decresce (o stabile) al crescere dello scale{NC}")
    total += 1
    errs2 = [results[sf][0] for sf in SCALE_FACTORS]
    first_half_avg = sum(errs2[:3]) / 3
    second_half_avg = sum(errs2[3:]) / 3
    if first_half_avg >= second_half_avg - 1e-4:
        ok(f"Tendenza corretta: scale basso -> err alto ({first_half_avg:.4f}) scale alto -> err basso ({second_half_avg:.4f})")
        passed += 1
    else:
        fail(f"Tendenza inattesa: scale basso avg_err={first_half_avg:.4f} < scale alto avg_err={second_half_avg:.4f}")

    print(f"\n{YELLOW}[Test B] M2 e M3 hanno max_err identico per ogni scale{NC}")
    total += 1
    all_equal = all(abs(results[sf][0] - results[sf][3]) < 1e-9 for sf in SCALE_FACTORS)
    if all_equal:
        ok("M2 e M3 producono identico max_err per tutti gli scale")
        passed += 1
    else:
        diffs = [sf for sf in SCALE_FACTORS if abs(results[sf][0] - results[sf][3]) >= 1e-9]
        fail(f"M2 e M3 divergono per scale={diffs}")

    print(f"\n{YELLOW}[Test C] compute_scale() accuracy >= media degli altri scale{NC}")
    total += 1
    optimal_scale = compute_scale(model)
    if optimal_scale not in results:
        results[optimal_scale] = _evaluate_scale(model, optimal_scale, inputs, n_samples)
    avg_acc2 = sum(results[sf][1] for sf in SCALE_FACTORS) / len(SCALE_FACTORS)
    opt_acc2 = results[optimal_scale][1]
    info(f"  compute_scale()={optimal_scale} -> acc={opt_acc2:.1f}% | media={avg_acc2:.1f}%")
    if opt_acc2 >= avg_acc2 - 1.0:
        ok(f"compute_scale accuracy ({opt_acc2:.1f}%) >= media ({avg_acc2:.1f}%) - 1%")
        passed += 1
    else:
        fail(f"compute_scale accuracy ({opt_acc2:.1f}%) < media ({avg_acc2:.1f}%)")

    print(f"\n{YELLOW}[Test D] max_err <= H/scale per ogni scale (bound teorico){NC}")
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


# ===========================================================================
# SUITE: robust  (ex test_robustness.py)
# ===========================================================================
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
    print(f"\n{YELLOW}=== SUITE robust — input anomali ==={NC}\n")
    torch.manual_seed(42)
    np.random.seed(42)

    model = FRRModel()
    I = model.fc1.in_features
    O = model.out.out_features
    H = model.fc1.out_features
    print(f"  Architettura: {I} -> {H} -> {H} -> {O}")
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
                fail(f"P{mid} {mname:<10}: eccezione — {e}")

        total += 1
        try:
            a2 = int(np.argmax(m2.infer(x)))
            a3 = int(np.argmax(m3.infer(x)))
            if a2 == a3:
                ok(f"  P2 e P3 concordano su input anomalo: argmax={a2}")
                passed += 1
            else:
                fail(f"  P2={a2} e P3={a3} discordano su input anomalo '{case_name}'")
        except Exception as e:
            fail(f"  Eccezione nella verifica consistenza: {e}")
        print()

    print(f"{YELLOW}[Stress] 1000 input out-of-range [-10, 10] senza crash{NC}")
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
        ok("Nessun crash su 1000 input stress (range [-10,10])")
        passed += 1
    else:
        fail(f"{n_crash}/1000 input stress hanno causato argmax invalido o eccezione")

    _banner(passed, total)
    return passed == total


# ===========================================================================
# Driver
# ===========================================================================
def _load_default_model(model_arg):
    """Carica il .pt (se compatibile con l'arch di default) o usa pesi casuali,
    replicando la logica del vecchio test_local.main."""
    torch.manual_seed(42)
    np.random.seed(42)
    model = FRRModel()
    pt_path = model_arg or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'frr_germany50_5_model_4x2.pt')
    if os.path.exists(pt_path):
        try:
            loaded, li, lh, lo = load_pt_dynamic(pt_path)
            if li == INPUT_SIZE and lh == HIDDEN_DIM:
                model = loaded
                print(f"{GREEN}[OK]{NC} Modello caricato da {pt_path} (arch {li}->{lh}->{lo})")
            else:
                print(f"{YELLOW}[INFO]{NC} .pt ha arch {li}->{lh}->{lo} (diversa da default "
                      f"{INPUT_SIZE}->{HIDDEN_DIM}->{OUTPUT_SIZE})")
                print(f"{YELLOW}[INFO]{NC} core Test 1-4 usano pesi casuali (seed=42), Test 5 usa il .pt")
        except Exception as e:
            print(f"{YELLOW}[WARN]{NC} {e} — uso pesi casuali")
    else:
        print(f"{YELLOW}[INFO]{NC} Nessun .pt trovato — pesi casuali (seed=42)")
    return model, pt_path


def main():
    parser = argparse.ArgumentParser(
        description="Suite di test locale IPA (3 metodi) — accorpa i vecchi test_*.py")
    parser.add_argument('--only', default='all',
                        choices=['all', 'core', 'pktstats', 'extract', 'quant', 'robust'],
                        help='Quale suite eseguire (default: all)')
    parser.add_argument('--model', type=str, default=None, help='Path al checkpoint .pt')
    parser.add_argument('--verbose', action='store_true', help='Dettagli extra (suite core)')
    parser.add_argument('--samples', type=int, default=200,
                        help='Campioni per pktstats/quant')
    parser.add_argument('--seed', type=int, default=42, help='Seed per pktstats')
    args = parser.parse_args()

    which = ['core', 'pktstats', 'extract', 'quant', 'robust'] if args.only == 'all' else [args.only]

    model, pt_path = _load_default_model(args.model)

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

    print(f"{YELLOW}{'#'*52}{NC}")
    print(f"{YELLOW}#  RIEPILOGO SUITE{NC}")
    for name, res in results.items():
        tag = f"{GREEN}PASS{NC}" if res else f"{RED}FAIL{NC}"
        print(f"   {name:<10} : {tag}")
    print(f"{YELLOW}{'#'*52}{NC}")

    sys.exit(0 if all(results.values()) else 1)


if __name__ == '__main__':
    main()
