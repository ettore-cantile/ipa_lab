#!/usr/bin/env python3
"""
diag_model_decisions.py -- what can the trained model actually decide?

Pure userspace: no root, no BCC, no kernel. It replays the SAME integer
arithmetic the eBPF datapath runs (and that verify_prog_run's reference
replicates), sweeping each input feature in turn, and reports how much the
chosen egress class actually varies.

Why this exists. The correctness suite proves all three pipelines compute the
SAME class as an independent reference -- equivalence. It does not ask whether
that class is USEFUL. A model that returns a constant would pass every
equivalence test in the repository. This script asks the other question:

    across the whole input space the lab can actually produce,
    how many distinct egress classes does the model ever emit?

If the answer is one, the datapath is a very fast way of computing a constant,
and no amount of pipeline engineering changes that.

Usage:
    python3 shared/test/diag_model_decisions.py
    python3 shared/test/diag_model_decisions.py --weights /shared/weights.json
"""

import argparse
import json
import os
import sys

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)


def infer(w, ttl, link_state, node, ifindex=None,
          n_in=65, h=4, n_out=7):
    """Integer forward pass, identical in arithmetic to the eBPF datapath.

    Feature layout of the default descriptor (see model_meta): link_state at
    columns 0..5, ingress_iface one-hot at 6..11, ttl at 12, node one-hot at
    13..64. `ifindex=None` means the ingress_iface feature contributes nothing,
    which is what happens on a real Kathara node (the kernel ifindex is far
    outside the one-hot range) -- see the known limitation in the README.
    """
    fc1_w, fc1_b = 0, n_in * h
    fc2_w, fc2_b = fc1_b + h, fc1_b + h + h * h
    out_w, out_b = fc2_b + h, fc2_b + h + h * n_out

    h1 = []
    for j in range(h):
        acc = w[fc1_b + j]
        base = fc1_w + j * n_in
        for i in range(6):
            if link_state[i]:
                acc += link_state[i] * w[base + i]
        if ifindex is not None and 0 <= ifindex < 6:
            acc += w[base + 6 + ifindex]
        acc += ttl * w[base + 12]
        acc += w[base + 13 + node]
        h1.append(acc if acc > 0 else 0)

    h2 = []
    for j in range(h):
        acc = w[fc2_b + j] + sum(h1[i] * w[fc2_w + j * h + i] for i in range(h))
        h2.append(acc if acc > 0 else 0)

    logits = [w[out_b + k] + sum(h2[i] * w[out_w + k * h + i] for i in range(h))
              for k in range(n_out)]
    return max(range(n_out), key=lambda k: logits[k])


def _runs(pairs):
    """Collapse [(x, cls)] into contiguous runs [(x_from, x_to, cls)]."""
    out = []
    for x, c in pairs:
        if out and out[-1][2] == c and out[-1][1] == x - 1:
            out[-1][1] = x
        else:
            out.append([x, x, c])
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--weights", default=os.path.join(SHARED_DIR, "weights.json"))
    p.add_argument("--n-nodes", type=int, default=52)
    args = p.parse_args()

    with open(args.weights) as f:
        w = json.load(f)
    if isinstance(w, dict):
        w = w["weights"]
    print(f"weights: {args.weights}  ({len(w)} int8)\n")

    all_up = [1] * 6
    seen = set()

    # ---------------------------------------------------------------
    print("=" * 66)
    print(" 1. TTL sweep   (all links up, node 0, ingress inert)")
    print("=" * 66)
    pairs = [(t, infer(w, t, all_up, 0)) for t in range(1, 65)]
    for a, b, c in _runs(pairs):
        rng = f"TTL {a}" if a == b else f"TTL {a}-{b}"
        tag = "DROP" if c == 6 else f"egress eth{c}"
        print(f"  {rng:<14} -> class {c}  ({tag})")
    seen |= {c for _, c in pairs}
    print(f"\n  classi distinte su tutto il range TTL: {sorted({c for _, c in pairs})}")
    print(f"  range usato dai sender (30-64)         : "
          f"{sorted({infer(w, t, all_up, 0) for t in range(30, 65)})}")

    # ---------------------------------------------------------------
    print("\n" + "=" * 66)
    print(" 2. Link down   (one link at a time, node 0)")
    print("=" * 66)
    changed = 0
    tested = 0
    for t in (2, 5, 16, 32, 64):
        base = infer(w, t, all_up, 0)
        row = []
        for k in range(6):
            ls = list(all_up)
            ls[k] = 0
            c = infer(w, t, ls, 0)
            seen.add(c)
            tested += 1
            if c != base:
                changed += 1
            row.append(f"link{k}->{c}" + ("*" if c != base else " "))
        print(f"  TTL {t:>2}  base={base}   " + "  ".join(row))
    print(f"\n  casi in cui un guasto cambia l'uscita: {changed}/{tested}"
          "   (* = cambia)")

    # ---------------------------------------------------------------
    print("\n" + "=" * 66)
    print(" 3. Node one-hot   (TTL 32, all links up)")
    print("=" * 66)
    by_node = {}
    for n in range(args.n_nodes):
        c = infer(w, 32, all_up, n)
        by_node.setdefault(c, []).append(n)
        seen.add(c)
    for c in sorted(by_node):
        nodes = by_node[c]
        shown = ", ".join(map(str, nodes[:12])) + (" ..." if len(nodes) > 12 else "")
        print(f"  class {c}: {len(nodes):>2}/{args.n_nodes} nodi  [{shown}]")
    print("\n  NOTA: nel datapath questo indice viene da ipa->model_id, non")
    print("  dall'identita' del nodo. Con un solo model_id registrato tutti i")
    print("  nodi usano la stessa colonna, quindi questa riga mostra cosa")
    print("  ACCADREBBE se la feature fosse cablata, non cosa accade oggi.")

    # ---------------------------------------------------------------
    print("\n" + "=" * 66)
    print(" Riepilogo")
    print("=" * 66)
    print(f"  classi raggiunte in TUTTE le prove sopra: {sorted(seen)}  "
          f"({len(seen)} su {7})")
    live = sorted({infer(w, t, all_up, 0) for t in range(30, 65)})
    print(f"  classi raggiunte nelle condizioni del lab "
          f"(TTL 30-64, link tutti up, un solo model_id): {live}")
    if len(live) == 1:
        print()
        print("  => In esercizio il modello emette UNA SOLA classe. L'uscita non")
        print("     dipende dalla destinazione (non e' una feature) ne' dal nodo")
        print("     (indicizzato da model_id). Il forwarding IPA non puo' quindi")
        print("     consegnare a una destinazione arbitraria: serve un modello")
        print("     addestrato con una feature di destinazione.")
    print()


if __name__ == "__main__":
    main()
