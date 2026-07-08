import torch
import json
import os
import sys

from FRR_model import FastRerouteMLP

# ---------------------------------------------------------------------------
# Architecture constants — must match the .pt checkpoint
# frr_germany50_5_model_4x2.pt was trained with n_nodes=52, hidden_dim=4
# This gives: fc1(65*4+4=264) + fc2(4*4+4=20) + out(4*7+7=35) = 319 weights
# ---------------------------------------------------------------------------
N_INTERFACES = 6
N_NODES      = 52
HIDDEN_DIM   = 4
# Total weights = 319  (same as N_WEIGHTS in common.py)

print("Extracting weights from PyTorch model...")

model = FastRerouteMLP(n_interfaces=N_INTERFACES, n_nodes=N_NODES, hidden_dim=HIDDEN_DIM)
model.load_state_dict(torch.load("frr_germany50_5_model_4x2.pt"))

# ---------------------------------------------------------------------------
# Method 1 - PTQ: SCALE_FACTOR computed automatically from the maximum weight.
#
# SCALE_FACTOR = floor(127 / max(|w|))
# Ensures no weight exceeds int8 range [-128, 127] after multiplication,
# eliminating clamping that would cause TABLE MISS.
#
# The SCALE_FACTOR is saved in weights_float.json along with the original
# float weights, and is written into the IPA header 'scaling' field by send_ipa.
# The kernel reads it from the header and uses it as a divisor (instead of shift).
# ---------------------------------------------------------------------------

all_floats = [w for param in model.parameters() for w in param.data.view(-1).tolist()]
max_abs    = max(abs(w) for w in all_floats)
SCALE_FACTOR = int(127 / max_abs)

print(f"Max |weight| = {max_abs:.6f}")
print(f"SCALE_FACTOR = floor(127 / {max_abs:.6f}) = {SCALE_FACTOR}")

integer_weights = []
for w_float in all_floats:
    w_int = int(round(w_float * SCALE_FACTOR))
    w_int = max(-128, min(127, w_int))  # safety clamp (should not trigger)
    integer_weights.append(w_int)

# Verify that no weight was clamped
clamped = sum(1 for w, wf in zip(integer_weights, all_floats)
              if w != int(round(wf * SCALE_FACTOR)))
if clamped:
    print(f"[WARN] {clamped} weights clamped (max_abs may not be the true maximum)")
else:
    print("No weights were clamped. int8 range respected for all weights.")

# int8 weights -> eBPF kernel
with open("weights.json", "w") as f:
    json.dump(integer_weights, f)

# original float weights + SCALE_FACTOR -> control plane for Method 1
with open("weights_float.json", "w") as f:
    json.dump({"scale_factor": SCALE_FACTOR, "weights": all_floats}, f)

print(f"Saved {len(integer_weights)} int8 weights -> weights.json")
print(f"Saved float weights + scale_factor={SCALE_FACTOR} -> weights_float.json")
print(f"int8 range: min={min(integer_weights)}  max={max(integer_weights)}")


# ---------------------------------------------------------------------------
# extract_weights_int8(model_path) — callable API used by pipeline_benchmark.py
#
# Returns a flat list of int8 weights for the given .pt checkpoint.
# Uses the same PTQ logic as above (SCALE_FACTOR = floor(127 / max|w|)).
# ---------------------------------------------------------------------------
def extract_weights_int8(model_path: str = "frr_germany50_5_model_4x2.pt") -> list:
    """
    Load a FastRerouteMLP checkpoint and return a flat list of int8 weights.

    Architecture is fixed to the germany50/5 model dimensions:
      n_interfaces=6, n_nodes=52, hidden_dim=4
    which produces exactly 319 weights matching N_WEIGHTS in common.py.

    Args:
        model_path: path to the .pt state-dict file

    Returns:
        list of int in [-128, 127], length 319
    """
    _model = FastRerouteMLP(
        n_interfaces=N_INTERFACES,
        n_nodes=N_NODES,
        hidden_dim=HIDDEN_DIM
    )
    _model.load_state_dict(torch.load(model_path))

    _floats = [w for p in _model.parameters() for w in p.data.view(-1).tolist()]
    _max_abs = max(abs(w) for w in _floats)
    _scale   = int(127 / _max_abs)

    _int8 = []
    for wf in _floats:
        wi = int(round(wf * _scale))
        _int8.append(max(-128, min(127, wi)))

    return _int8
