"""
extract_weights.py  (design-space-docs branch)
==============================================
Extracts int8-quantized weights from the FRR model checkpoint.

When run directly:  produces weights.json and weights_float.json
When imported:      provides extract_weights_int8() used by pipeline_benchmark.py
                    and method5/method6.

Architecture fixed to the germany50/5 checkpoint:
  n_interfaces=6, n_nodes=52, hidden_dim=4
  -> 319 total int8 weights  (matches N_WEIGHTS in common.py)

Quantization: PTQ with SCALE_FACTOR = floor(127 / max|w|)
"""
import torch
import json
import os

from FRR_model import FastRerouteMLP

# Architecture constants matching frr_germany50_5_model_4x2.pt
N_INTERFACES = 6
N_NODES      = 52
HIDDEN_DIM   = 4
# fc1(65*4+4=264) + fc2(4*4+4=20) + out(4*7+7=35) = 319 weights


def extract_weights_int8(
    model_path: str = "frr_germany50_5_model_4x2.pt"
) -> list:
    """
    Load a FastRerouteMLP checkpoint and return a flat list of int8 weights.

    Returns:
        list of int in [-128, 127], length 319
    """
    m = FastRerouteMLP(
        n_interfaces=N_INTERFACES,
        n_nodes=N_NODES,
        hidden_dim=HIDDEN_DIM
    )
    m.load_state_dict(torch.load(model_path))

    floats  = [w for p in m.parameters() for w in p.data.view(-1).tolist()]
    max_abs = max(abs(w) for w in floats)
    scale   = int(127 / max_abs)

    return [max(-128, min(127, int(round(wf * scale)))) for wf in floats]


# ---------------------------------------------------------------------------
# __main__: produce weights.json and weights_float.json for the other scripts
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "frr_germany50_5_model_4x2.pt")
    print("Extracting weights from PyTorch model...")

    model = FastRerouteMLP(
        n_interfaces=N_INTERFACES,
        n_nodes=N_NODES,
        hidden_dim=HIDDEN_DIM
    )
    model.load_state_dict(torch.load(MODEL_PATH))

    all_floats   = [w for p in model.parameters() for w in p.data.view(-1).tolist()]
    max_abs      = max(abs(w) for w in all_floats)
    SCALE_FACTOR = int(127 / max_abs)

    print(f"Max |weight| = {max_abs:.6f}")
    print(f"SCALE_FACTOR = {SCALE_FACTOR}")

    integer_weights = []
    for wf in all_floats:
        wi = int(round(wf * SCALE_FACTOR))
        integer_weights.append(max(-128, min(127, wi)))

    clamped = sum(
        1 for w, wf in zip(integer_weights, all_floats)
        if w != int(round(wf * SCALE_FACTOR))
    )
    if clamped:
        print(f"[WARN] {clamped} weights clamped")
    else:
        print("No weights clamped. int8 range respected.")

    out_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(out_dir, "weights.json"), "w") as f:
        json.dump(integer_weights, f)
    with open(os.path.join(out_dir, "weights_float.json"), "w") as f:
        json.dump({"scale_factor": SCALE_FACTOR, "weights": all_floats}, f)

    print(f"Saved {len(integer_weights)} int8 weights -> weights.json")
    print(f"int8 range: min={min(integer_weights)}  max={max(integer_weights)}")
