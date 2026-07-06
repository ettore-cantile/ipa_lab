import torch
import json

from FRR_model import FastRerouteMLP

print("Extracting weights from PyTorch model...")

model = FastRerouteMLP(n_interfaces=6, n_nodes=52, hidden_dim=4)
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
