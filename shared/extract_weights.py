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

Fallback (no torch):
  If torch is not installed (e.g. inside Kathara containers), and a
  precomputed weights.json exists in the same directory, extract_weights_int8()
  returns its contents directly without loading the .pt file.
"""
import json
import os

# Architecture constants matching frr_germany50_5_model_4x2.pt
N_INTERFACES = 6
N_NODES      = 52
HIDDEN_DIM   = 4
# fc1(65*4+4=264) + fc2(4*4+4=20) + out(4*7+7=35) = 319 weights

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_from_json(json_path: str) -> list:
    """Load precomputed int8 weights from weights.json."""
    with open(json_path) as f:
        data = json.load(f)
    # weights.json is a plain list; weights_float.json has {scale_factor, weights}
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "weights" in data:
        # weights_float.json — re-quantize on the fly
        floats  = data["weights"]
        scale   = data.get("scale_factor", 1)
        return [max(-128, min(127, int(round(wf * scale)))) for wf in floats]
    raise ValueError(f"Unrecognized format in {json_path}")


def extract_weights_int8(
    model_path: str = "frr_germany50_5_model_4x2.pt"
) -> list:
    """
    Return a flat list of int8 weights for the FRR model.

    Priority:
      1. If torch is available: load from .pt checkpoint (authoritative).
      2. Else if weights.json exists next to this file: use it (container mode).
      3. Else raise ImportError with a helpful message.

    Returns:
        list of int in [-128, 127], length 319
    """
    # Resolve model path relative to this file if not absolute
    if not os.path.isabs(model_path):
        candidate = os.path.join(SHARED_DIR, model_path)
        if os.path.exists(candidate):
            model_path = candidate

    # --- Path 1: torch available ---
    try:
        import torch
        from FRR_model import FastRerouteMLP

        m = FastRerouteMLP(
            n_interfaces=N_INTERFACES,
            n_nodes=N_NODES,
            hidden_dim=HIDDEN_DIM
        )
        m.load_state_dict(torch.load(model_path, map_location="cpu"))
        floats  = [w for p in m.parameters() for w in p.data.view(-1).tolist()]
        max_abs = max(abs(w) for w in floats)
        scale   = int(127 / max_abs)
        return [max(-128, min(127, int(round(wf * scale)))) for wf in floats]

    except ImportError:
        pass  # torch not installed — fall through to JSON fallback

    # --- Path 2: JSON fallback (no torch) ---
    json_path = os.path.join(SHARED_DIR, "weights.json")
    if os.path.exists(json_path):
        import warnings
        warnings.warn(
            "torch not available — loading precomputed weights from weights.json",
            RuntimeWarning,
            stacklevel=2,
        )
        return _load_from_json(json_path)

    raise ImportError(
        "torch is not installed and weights.json not found in {}. "
        "Either install torch or generate weights.json first with: "
        "python3 extract_weights.py".format(SHARED_DIR)
    )


# ---------------------------------------------------------------------------
# __main__: produce weights.json and weights_float.json
# Requires torch — intended to run on the host, not inside Kathara.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        import torch
        from FRR_model import FastRerouteMLP
    except ImportError as e:
        print(f"ERROR: {e}")
        print("Run this script on the host (not inside Kathara) where torch is installed.")
        raise SystemExit(1)

    MODEL_PATH = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
    print("Extracting weights from PyTorch model...")

    model = FastRerouteMLP(
        n_interfaces=N_INTERFACES,
        n_nodes=N_NODES,
        hidden_dim=HIDDEN_DIM
    )
    model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))

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

    with open(os.path.join(SHARED_DIR, "weights.json"), "w") as f:
        json.dump(integer_weights, f)
    with open(os.path.join(SHARED_DIR, "weights_float.json"), "w") as f:
        json.dump({"scale_factor": SCALE_FACTOR, "weights": all_floats}, f)

    print(f"Saved {len(integer_weights)} int8 weights -> weights.json")
    print(f"int8 range: min={min(integer_weights)}  max={max(integer_weights)}")
