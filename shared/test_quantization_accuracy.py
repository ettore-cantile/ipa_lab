#!/usr/bin/env python3
"""
test_quantization_accuracy.py  — argmax accuracy vs scale_factor
================================================================
Misura come l'errore di quantizzazione int8 varia al variare dello
scale_factor (16, 32, 64, 128, 256, 512) per i metodi 2 e 3.

Produce una tabella:
  scale  | max_err M2 | argmax_acc M2 | max_err M3 | argmax_acc M3

Questo e' il dato sperimentale richiesto dal professore per dimostrare
il trade-off precisione/flessibilita' nella quantizzazione PTQ.

Utilizzo:
  python3 shared/test_quantization_accuracy.py
  python3 shared/test_quantization_accuracy.py --samples 200 --model shared/frr_germany50_5_model_4x2.pt
"""
import argparse
import sys
import os
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_local import (
    FRRModel, Method2_Template, Method3_Modular,
    make_input, pytorch_ref, load_pt_dynamic,
    INPUT_SIZE, OUTPUT_SIZE, HIDDEN_DIM,
    GREEN, YELLOW, RED, NC, ok, fail, info
)
import torch


SCALE_FACTORS = [16, 32, 64, 128, 256, 512]


class Method2_FixedScale(Method2_Template):
    """Variante di Method2 con scale_factor fisso (non auto-calcolato)."""
    def __init__(self, model, scale: int):
        super().__init__(model)
        self.scale = scale
        self._load(model)  # ricarica con il nuovo scale


class Method3_FixedScale(Method3_Modular):
    """Variante di Method3 con scale_factor fisso."""
    def __init__(self, model, scale: int):
        super().__init__(model)
        self.scale = scale
        self._load(model)  # ricarica con il nuovo scale


def evaluate_scale(model, scale: int, inputs: list, n_samples: int):
    """Valuta Method2 e Method3 con uno scale_factor specifico."""
    m2 = Method2_FixedScale(model, scale)
    m3 = Method3_FixedScale(model, scale)

    err2 = err3 = 0.0
    wrong2 = wrong3 = 0

    for x in inputs:
        ref  = pytorch_ref(model, x)
        o2   = m2.infer(x)
        o3   = m3.infer(x)
        err2 = max(err2, float(np.max(np.abs(o2 - ref))))
        err3 = max(err3, float(np.max(np.abs(o3 - ref))))
        if int(np.argmax(o2)) != int(np.argmax(ref)):
            wrong2 += 1
        if int(np.argmax(o3)) != int(np.argmax(ref)):
            wrong3 += 1

    acc2 = (n_samples - wrong2) / n_samples * 100
    acc3 = (n_samples - wrong3) / n_samples * 100
    return err2, acc2, wrong2, err3, acc3, wrong3


def run_tests(n_samples: int, model_path: str | None):
    print(f"\n{YELLOW}=== TEST QUANTIZATION ACCURACY vs SCALE_FACTOR ==={NC}\n")

    import torch
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
    results = {}

    for sf in SCALE_FACTORS:
        r = evaluate_scale(model, sf, inputs, n_samples)
        results[sf] = r

    # Stampa tabella
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

    # --- Test A: errore decresce al crescere di scale ---
    print(f"{YELLOW}[Test A] max_err M2 decresce (o rimane stabile) al crescere dello scale{NC}")
    total += 1
    errs2 = [results[sf][0] for sf in SCALE_FACTORS]
    # Tollera piccole non-monotonicita' dovute al clamping: verifica solo tendenza
    first_half_avg = sum(errs2[:3]) / 3
    second_half_avg = sum(errs2[3:]) / 3
    if first_half_avg >= second_half_avg - 1e-4:
        ok(f"Tendenza corretta: scale basso -> err alto ({first_half_avg:.4f}) scale alto -> err basso ({second_half_avg:.4f})")
        passed += 1
    else:
        fail(f"Tendenza inattesa: scale basso avg_err={first_half_avg:.4f} < scale alto avg_err={second_half_avg:.4f}")

    # --- Test B: M2 e M3 hanno sempre stesso errore (stessa quantizzazione) ---
    print(f"\n{YELLOW}[Test B] M2 e M3 hanno max_err identico per ogni scale{NC}")
    total += 1
    all_equal = all(abs(results[sf][0] - results[sf][3]) < 1e-9 for sf in SCALE_FACTORS)
    if all_equal:
        ok("M2 e M3 producono identico max_err per tutti gli scale")
        passed += 1
    else:
        diffs = [(sf, results[sf][0], results[sf][3]) for sf in SCALE_FACTORS
                 if abs(results[sf][0] - results[sf][3]) >= 1e-9]
        fail(f"M2 e M3 divergono per scale={[d[0] for d in diffs]}")

    # --- Test C: scale ottimale (compute_scale) non peggiore degli altri ---
    print(f"\n{YELLOW}[Test C] compute_scale() produce accuracy >= media degli altri scale{NC}")
    total += 1
    from test_local import compute_scale
    optimal_scale = compute_scale(model)
    if optimal_scale not in results:
        # Misura anche l'optimal scale se non era nella lista
        r_opt = evaluate_scale(model, optimal_scale, inputs, n_samples)
        results[optimal_scale] = r_opt
    avg_acc2 = sum(results[sf][1] for sf in SCALE_FACTORS) / len(SCALE_FACTORS)
    opt_acc2 = results[optimal_scale][1]
    info(f"  compute_scale()={optimal_scale} -> acc={opt_acc2:.1f}% | media={avg_acc2:.1f}%")
    if opt_acc2 >= avg_acc2 - 1.0:  # tolleranza 1%
        ok(f"compute_scale accuracy ({opt_acc2:.1f}%) >= media ({avg_acc2:.1f}%) - 1%")
        passed += 1
    else:
        fail(f"compute_scale accuracy ({opt_acc2:.1f}%) < media ({avg_acc2:.1f}%)")

    # --- Test D: errore di quantizzazione <= hidden_dim / scale (bound teorico) ---
    print(f"\n{YELLOW}[Test D] max_err <= H/scale per ogni scale (bound teorico di quantizzazione){NC}")
    n_ok = 0
    for sf in SCALE_FACTORS:
        total += 1
        err2 = results[sf][0]
        bound = H / sf
        if err2 <= bound + 1e-6:
            ok(f"scale={sf:>4}: max_err={err2:.4f} <= H/scale={bound:.4f}")
            passed += 1
            n_ok += 1
        else:
            fail(f"scale={sf:>4}: max_err={err2:.4f} > H/scale={bound:.4f}")

    print(f"\n{YELLOW}{'='*52}{NC}")
    color = GREEN if passed == total else RED
    print(f"{color} Risultato: {passed}/{total} test passati{NC}")
    if passed < total:
        print(f"{RED} Controlla i messaggi [FAIL] sopra{NC}")
    print(f"{YELLOW}{'='*52}{NC}\n")
    return passed == total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--samples', type=int, default=200)
    parser.add_argument('--model',   type=str, default=None)
    args = parser.parse_args()
    sys.exit(0 if run_tests(args.samples, args.model) else 1)


if __name__ == '__main__':
    main()
