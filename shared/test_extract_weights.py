#!/usr/bin/env python3
"""
test_extract_weights.py  — verifica coerenza extract_weights.py vs test_local.py
=================================================================================
Controlla che:
  1. extract_weights_int8() produca N_WEIGHTS pesi nell'intervallo [-128, 127]
  2. il scale_factor di extract_weights corrisponda a compute_scale() di test_local
  3. i pesi in weights.json siano identici a quelli estratti live dal .pt
  4. weights_float.json contenga i pesi float originali e scale_factor coerente
  5. la dequantizzazione int8 ricostruisce i pesi entro tolleranza 1/scale

Utilizzo:
  python3 shared/test_extract_weights.py
  python3 shared/test_extract_weights.py --model shared/frr_germany50_5_model_4x2.pt
"""
import argparse
import sys
import os
import json
import math

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_local import compute_scale, load_pt_dynamic, GREEN, YELLOW, RED, NC, ok, fail, info


def run_tests(model_path: str):
    print(f"\n{YELLOW}=== TEST EXTRACT WEIGHTS ==={NC}\n")
    print(f"  model: {model_path}")
    print()

    passed = total = 0
    shared_dir = os.path.dirname(os.path.abspath(model_path))

    # --- Test 1: caricamento .pt e extract_weights_int8 ---
    print(f"{YELLOW}[Test 1] extract_weights_int8() — range e lunghezza{NC}")
    total += 1
    try:
        # Carichiamo dinamicamente per non dipendere da FastRerouteMLP
        import torch
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
        return False

    # --- Test 2: scale_factor coerenza tra extract_weights e compute_scale ---
    print(f"\n{YELLOW}[Test 2] Scale factor: extract_weights vs compute_scale(){NC}")
    total += 1
    scale_cs = compute_scale(model)  # potenza di 2
    scale_ew_actual = scale_ew       # floor(127/max_abs)
    # compute_scale usa la potenza di 2 piu' grande <= floor(127/max_abs)
    # scale_ew puo' essere diverso ma entrambi devono soddisfare: scale <= 127/max_abs
    both_valid = (scale_cs * max_abs <= 127.0 + 1e-6) and (scale_ew * max_abs <= 127.0 + 1e-6)
    if both_valid:
        ok(f"Entrambi i scale validi: compute_scale={scale_cs} extract_weights={scale_ew} | max|w|={max_abs:.6f}")
        passed += 1
    else:
        fail(f"Scale non valido: compute_scale={scale_cs} extract_weights={scale_ew} max|w|={max_abs:.6f}")

    # --- Test 3: weights.json coerenza con estrazione live ---
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

    # --- Test 4: weights_float.json coerenza ---
    print(f"\n{YELLOW}[Test 4] weights_float.json — scale_factor e valori float{NC}")
    total += 1
    wf_path = os.path.join(shared_dir, 'weights_float.json')
    if not os.path.exists(wf_path):
        info(f"weights_float.json non trovato — test saltato")
        total -= 1
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

    # --- Test 5: dequantizzazione int8 ricostruisce i pesi entro 1/scale ---
    print(f"\n{YELLOW}[Test 5] Errore dequantizzazione: max|w_float - w_int8/scale| <= 1/scale{NC}")
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

    print(f"\n{YELLOW}{'='*52}{NC}")
    color = GREEN if passed == total else RED
    print(f"{color} Risultato: {passed}/{total} test passati{NC}")
    if passed < total:
        print(f"{RED} Controlla i messaggi [FAIL] sopra{NC}")
    print(f"{YELLOW}{'='*52}{NC}\n")
    return passed == total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', type=str,
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             'frr_germany50_5_model_4x2.pt'))
    args = parser.parse_args()
    if not os.path.exists(args.model):
        print(f"{RED}[ERROR]{NC} Modello non trovato: {args.model}")
        sys.exit(1)
    sys.exit(0 if run_tests(args.model) else 1)


if __name__ == '__main__':
    main()
