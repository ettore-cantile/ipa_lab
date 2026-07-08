#!/usr/bin/env python3
"""
test_ipa_methods.py  — end-to-end test per i 3 metodi IPA (senza eBPF/XDP)
===========================================================================
Verifica che tutti e 3 i metodi (hardcoded / template / modular) producano
gli stessi pkt_stats (hit / miss / fake) su un campione di pacchetti
simulati, e che i counter siano monotoni e coerenti.

Non richiede hardware eBPF: usa le classi Python di test_local.py.

Utilizzo:
  python3 shared/test_ipa_methods.py
  python3 shared/test_ipa_methods.py --samples 200 --seed 7
"""
import argparse
import sys
import os
import numpy as np
import torch

# Riutilizza classi e helpers di test_local.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_local import (
    FRRModel, Method1_Hardcoded, Method2_Template, Method3_Modular,
    make_input, pytorch_ref, decode_nexthop,
    N_INTERFACES, N_NODES, INPUT_SIZE, OUTPUT_SIZE,
    GREEN, YELLOW, RED, NC, ok, fail, info
)


# ---------------------------------------------------------------------------
# Simulazione pkt_stats (hit / fake / miss) identica alla logica eBPF
# ---------------------------------------------------------------------------
# Convenzione FWD table (simulata):
#   key = (argmax_output) -> azione valida se key != 0 (DROP)
#   valid_keys = insieme di output validi definiti nella fwd_table
# Per la simulazione usiamo tutti gli output != 0 come validi.

def classify_packet(output_vec: np.ndarray,
                    ref_vec: np.ndarray,
                    valid_outputs: set) -> str:
    """
    Classifica il risultato dell'inferenza come HIT / FAKE / MISS.

    HIT  : argmax corretto E presente in valid_outputs
    FAKE : argmax sbagliato MA presente in valid_outputs (forward ma errato)
    MISS : action non in valid_outputs (DROP o unknown key)
    """
    pred   = int(np.argmax(output_vec))
    target = int(np.argmax(ref_vec))
    if pred in valid_outputs:
        if pred == target:
            return "HIT"
        else:
            return "FAKE"
    else:
        return "MISS"


def run_pkt_stats(method, inputs, model, valid_outputs):
    """Ritorna dict con hit/fake/miss counts."""
    stats = {"HIT": 0, "FAKE": 0, "MISS": 0}
    for x in inputs:
        ref  = pytorch_ref(model, x)
        out  = method.infer(x)
        cls  = classify_packet(out, ref, valid_outputs)
        stats[cls] += 1
    return stats


def run_tests(n_samples: int, seed: int):
    torch.manual_seed(seed)
    np.random.seed(seed)

    print(f"\n{YELLOW}=== TEST IPA METHODS — pkt_stats (3 pipeline) ==={NC}\n")
    model = FRRModel()
    H = model.fc1.out_features
    I = model.fc1.in_features
    O = model.out.out_features
    print(f"  Architettura: {I} -> {H} -> {H} -> {O} | samples={n_samples} | seed={seed}")
    print()

    m1 = Method1_Hardcoded(model)
    m2 = Method2_Template(model)
    m3 = Method3_Modular(model)

    # valid_outputs: tutti gli output != 0 (output 0 = DROP / MISS)
    valid_outputs = set(range(1, O))
    info(f"valid_outputs = {valid_outputs}  (0=DROP/MISS)")
    print()

    inputs = [make_input(I) for _ in range(n_samples)]

    passed = total = 0

    # --- Test A: pkt_stats per ciascun metodo ---
    print(f"{YELLOW}[Test A] pkt_stats per metodo ({n_samples} campioni){NC}")
    stats = {}
    for mid, mobj, name in [(1, m1, 'hardcoded'), (2, m2, 'template'), (3, m3, 'modular')]:
        s = run_pkt_stats(mobj, inputs, model, valid_outputs)
        stats[mid] = s
        total_pkts = s['HIT'] + s['FAKE'] + s['MISS']
        hit_rate   = s['HIT'] / total_pkts * 100
        info(f"  P{mid} {name:<10}: HIT={s['HIT']:4d} ({hit_rate:.1f}%)  "
             f"FAKE={s['FAKE']:4d}  MISS={s['MISS']:4d}  total={total_pkts}")

    # --- Test B: counter monotoni (sum = n_samples) ---
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

    # --- Test C: P1 hardcoded deve avere 0 FAKE (pesi float esatti) ---
    print(f"\n{YELLOW}[Test C] P1 hardcoded deve avere FAKE=0 (pesi float, nessuna quantizzazione){NC}")
    total += 1
    if stats[1]['FAKE'] == 0:
        ok(f"P1 FAKE=0 confermato (hardcoded float)")
        passed += 1
    else:
        fail(f"P1 FAKE={stats[1]['FAKE']} (atteso 0 con pesi float)")

    # --- Test D: P2 e P3 devono concordare su HIT+FAKE+MISS ---
    print(f"\n{YELLOW}[Test D] P2 e P3 devono avere stesso HIT/FAKE/MISS (stessa quantizzazione){NC}")
    total += 1
    if stats[2] == stats[3]:
        ok(f"P2 e P3 concordano: HIT={stats[2]['HIT']} FAKE={stats[2]['FAKE']} MISS={stats[2]['MISS']}")
        passed += 1
    else:
        fail(f"P2={stats[2]} != P3={stats[3]}")

    # --- Test E: HIT rate P1 >= HIT rate P2/P3 (float > quantizzato) ---
    print(f"\n{YELLOW}[Test E] HIT rate P1 >= P2 e P3 (float piu' preciso di int8){NC}")
    total += 1
    hr1 = stats[1]['HIT'] / n_samples
    hr2 = stats[2]['HIT'] / n_samples
    hr3 = stats[3]['HIT'] / n_samples
    if hr1 >= hr2 and hr1 >= hr3:
        ok(f"HIT rate: P1={hr1:.3f} >= P2={hr2:.3f} >= P3={hr3:.3f}")
        passed += 1
    else:
        fail(f"HIT rate: P1={hr1:.3f} P2={hr2:.3f} P3={hr3:.3f} — atteso P1 massimo")

    # --- Test F: update pesi e ricontrollo pkt_stats ---
    print(f"\n{YELLOW}[Test F] pkt_stats dopo update pesi (nuovo modello random){NC}")
    torch.manual_seed(seed + 1)
    new_model = FRRModel()
    m1.update_weights(new_model)
    m2.update_weights(new_model)
    m3.update_weights(new_model)
    stats_new = {}
    for mid, mobj in [(1, m1), (2, m2), (3, m3)]:
        s = run_pkt_stats(mobj, inputs, new_model, valid_outputs)
        stats_new[mid] = s
    total += 1
    tot2 = stats_new[2]['HIT'] + stats_new[2]['FAKE'] + stats_new[2]['MISS']
    tot3 = stats_new[3]['HIT'] + stats_new[3]['FAKE'] + stats_new[3]['MISS']
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
    parser.add_argument('--seed',    type=int, default=42)
    args = parser.parse_args()
    sys.exit(0 if run_tests(args.samples, args.seed) else 1)


if __name__ == '__main__':
    main()
