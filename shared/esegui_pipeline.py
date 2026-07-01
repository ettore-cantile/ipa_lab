#!/usr/bin/env python3
"""
esegui_pipeline.py
==================
Punto di ingresso della pipeline IPA su ogni nodo Kathara.

Flusso:
    1. extract_weights.py  -> legge frr_germany50_5_model_4x2.pt
                           -> scrive weights.json (pesi int8)
    2. switch_core.py      -> legge weights.json
                           -> carica la fwd_table eBPF
                           -> attacca il programma XDP su eth1
                           -> fa girare lo switch in loop

Uso:
    python3 /shared/esegui_pipeline.py

Opzionalmente puoi passare il metodo di quantizzazione:
    python3 /shared/esegui_pipeline.py --method post   # default (Metodo 1)
    python3 /shared/esegui_pipeline.py --method qat    # Metodo 2 (QAT)
"""

import argparse
import os
import sys
import runpy

# ------------------------------------------------------------
# Assicura che shared/ sia nel path (per gli import nei sotto-script)
# ------------------------------------------------------------
SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)
os.chdir(SHARED_DIR)  # tutti gli script usano path relativi


def main():
    parser = argparse.ArgumentParser(description="Pipeline IPA: weights extraction + XDP switch")
    parser.add_argument(
        "--method",
        choices=["post", "qat"],
        default="post",
        help="Metodo di quantizzazione: 'post' (default) = Metodo 1, 'qat' = Metodo 2"
    )
    args = parser.parse_args()

    # ----------------------------------------------------------
    # Step 1: estrai i pesi interi -> weights.json
    # ----------------------------------------------------------
    print("=" * 60)
    print(f"[pipeline] Step 1 — estrazione pesi (metodo={args.method})")
    print("=" * 60)

    if args.method == "qat":
        # Metodo 2: carica il modello QAT se esiste, altrimenti fallback
        qat_model_path = os.path.join(SHARED_DIR, "frr_qat_model.pt")
        if not os.path.exists(qat_model_path):
            print(f"[WARNING] {qat_model_path} non trovato, uso il modello Metodo 1.")
        else:
            # Ridefinisce la variabile d'ambiente letta da extract_weights.py
            os.environ["FRR_MODEL_PATH"] = qat_model_path
            os.environ["FRR_MODEL_TYPE"] = "qat"

    # Esegue extract_weights.py nello stesso processo
    runpy.run_path(os.path.join(SHARED_DIR, "extract_weights.py"), run_name="__main__")

    # Verifica che weights.json sia stato prodotto
    weights_path = os.path.join(SHARED_DIR, "weights.json")
    if not os.path.exists(weights_path):
        print("[ERROR] weights.json non generato — esco.")
        sys.exit(1)
    print(f"[pipeline] weights.json OK ({os.path.getsize(weights_path)} bytes)")

    # ----------------------------------------------------------
    # Step 2: avvia lo switch XDP (loop bloccante)
    # ----------------------------------------------------------
    print()
    print("=" * 60)
    print("[pipeline] Step 2 — avvio switch XDP (switch_core.py)")
    print("=" * 60)
    runpy.run_path(os.path.join(SHARED_DIR, "switch_core.py"), run_name="__main__")


if __name__ == "__main__":
    main()
