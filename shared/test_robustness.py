#!/usr/bin/env python3
"""
test_robustness.py  — test di robustezza all'input anomalo
==========================================================
Verifica il comportamento delle 3 pipeline con input edge-case:
  - vettore zero (tutte le feature a 0)
  - TTL = 0 (feature TTL normalizzata a 0)
  - feature fuori range (valori > 1, negativi, NaN-free)
  - vettore tutto 1
  - input con shape corretta ma valori estremi (+/- 1000)

Le pipeline non devono crashare e devono sempre produrre un argmax
valido (0 <= argmax < OUTPUT_SIZE).

Utilizzo:
  python3 shared/test_robustness.py
"""
import sys
import os
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_local import (
    FRRModel, Method1_Hardcoded, Method2_Template, Method3_Modular,
    INPUT_SIZE, OUTPUT_SIZE, HIDDEN_DIM,
    GREEN, YELLOW, RED, NC, ok, fail, info
)
import torch


def make_zero_input(input_size):
    return np.zeros(input_size, dtype=np.float32)

def make_ones_input(input_size):
    return np.ones(input_size, dtype=np.float32)

def make_ttl_zero_input(input_size):
    """Ingresso normale ma con TTL=0 (feature index 12 nella codifica FRR)."""
    x = np.random.uniform(0, 1, input_size).astype(np.float32)
    # TTL e' alla posizione N_INTERFACES*2 = 12 nello schema FRR
    if input_size > 12:
        x[12] = 0.0
    return x

def make_out_of_range_input(input_size, scale=5.0):
    """Feature fuori range [0,1]: valori in [-scale, scale]."""
    return (np.random.uniform(-scale, scale, input_size)).astype(np.float32)

def make_extreme_input(input_size, val=1000.0):
    """Valori estremi +/- 1000."""
    x = np.zeros(input_size, dtype=np.float32)
    x[::2]  =  val
    x[1::2] = -val
    return x


EDGE_CASES = [
    ("zero vector",          make_zero_input),
    ("all-ones vector",      make_ones_input),
    ("TTL=0",                make_ttl_zero_input),
    ("out-of-range [−5,5]",  make_out_of_range_input),
    ("extreme ±1000",        make_extreme_input),
]


def run_tests():
    print(f"\n{YELLOW}=== TEST ROBUSTNESS — input anomali ==={NC}\n")

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

    for case_name, input_fn in EDGE_CASES:
        print(f"{YELLOW}[Case: {case_name}]{NC}")
        x = input_fn(I)
        case_ok = True

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
                    case_ok = False
            except Exception as e:
                fail(f"P{mid} {mname:<10}: eccezione — {e}")
                case_ok = False

        # --- Consistenza tra metodi sullo stesso input anomalo ---
        total += 1
        try:
            o1 = m1.infer(x)
            o2 = m2.infer(x)
            o3 = m3.infer(x)
            a1, a2, a3 = int(np.argmax(o1)), int(np.argmax(o2)), int(np.argmax(o3))
            # P2 e P3 devono concordare (stessa quantizzazione)
            if a2 == a3:
                ok(f"  P2 e P3 concordano su input anomalo: argmax={a2}")
                passed += 1
            else:
                fail(f"  P2={a2} e P3={a3} discordano su input anomalo '{case_name}'")
        except Exception as e:
            fail(f"  Eccezione nella verifica consistenza: {e}")
        print()

    # --- Test extra: nessun crash con 1000 input casuali fuori range ---
    print(f"{YELLOW}[Stress] 1000 input out-of-range [−10, 10] senza crash{NC}")
    total += 1
    n_crash = 0
    for _ in range(1000):
        x = (np.random.uniform(-10, 10, I)).astype(np.float32)
        try:
            a1 = int(np.argmax(m1.infer(x)))
            a2 = int(np.argmax(m2.infer(x)))
            a3 = int(np.argmax(m3.infer(x)))
            if not (0 <= a1 < O and 0 <= a2 < O and 0 <= a3 < O):
                n_crash += 1
        except Exception:
            n_crash += 1
    if n_crash == 0:
        ok(f"Nessun crash su 1000 input stress (range [-10,10])")
        passed += 1
    else:
        fail(f"{n_crash}/1000 input stress hanno causato argmax invalido o eccezione")

    print(f"\n{YELLOW}{'='*52}{NC}")
    color = GREEN if passed == total else RED
    print(f"{color} Risultato: {passed}/{total} test passati{NC}")
    if passed < total:
        print(f"{RED} Controlla i messaggi [FAIL] sopra{NC}")
    print(f"{YELLOW}{'='*52}{NC}\n")
    return passed == total


if __name__ == '__main__':
    sys.exit(0 if run_tests() else 1)
