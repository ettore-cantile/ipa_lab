import torch
import json

from FRR_model import FastRerouteMLP

print("Extracting weights from PyTorch model...")

model = FastRerouteMLP(n_interfaces=6, n_nodes=52, hidden_dim=4)
model.load_state_dict(torch.load("frr_germany50_5_model_4x2.pt"))

# ---------------------------------------------------------------------------
# Metodo 1 — PTQ: Post-Training Quantization
#   I pesi float vengono quantizzati DOPO il training.
#   SCALE_FACTOR = 128 = 2^7 -> shift di 7 bit nel kernel.
#   Il control plane usa i float ORIGINALI (weights_float.json) per calcolare
#   le chiavi della fwd_table con precisione piena. La differenza tra i float
#   originali e i loro equivalenti int8/128 causa i TABLE MISS reali del PTQ.
# ---------------------------------------------------------------------------
SCALE_FACTOR = 128

integer_weights = []
float_weights   = []

for param in model.parameters():
    for w_float in param.data.view(-1).tolist():
        float_weights.append(w_float)
        w_int = int(round(w_float * SCALE_FACTOR))
        w_int = max(-128, min(127, w_int))
        integer_weights.append(w_int)

# Pesi int8 -> kernel eBPF (Metodo 1)
with open("weights.json", "w") as f:
    json.dump(integer_weights, f)

# Pesi float originali -> control plane Metodo 1
with open("weights_float.json", "w") as f:
    json.dump(float_weights, f)

print(f"SCALE_FACTOR = {SCALE_FACTOR}  (SCALE_SHIFT = 7 nel kernel eBPF)")
print(f"Saved {len(integer_weights)} int8 weights  -> weights.json")
print(f"Saved {len(float_weights)} float weights -> weights_float.json")
print(f"Range int8:  min={min(integer_weights)}  max={max(integer_weights)}")
print(f"Range float: min={min(float_weights):.4f}  max={max(float_weights):.4f}")
