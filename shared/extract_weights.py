import torch
import json
import os

# Import the model structure from the local file
from FRR_model import FastRerouteMLP

print("Extracting weights from PyTorch model...")

# Initialize and load the model
model = FastRerouteMLP(n_interfaces=6, n_nodes=52, hidden_dim=4)
model.load_state_dict(torch.load("frr_germany50_5_model_4x2.pt"))

# ---------------------------------------------------------------------------
# Quantization: Metodo 1 — Fixed-point int8 con SCALE_FACTOR = 128 (= 2^7)
#
# Ogni peso float w viene mappato su:   w_int = round(w * 128)
# e clampato al range int8 [-128, +127] per non andare in overflow nel kernel.
#
# Nel kernel eBPF i pesi sono letti come (int)(int8_t)weight[i] e il prodotto
# accumulato viene diviso per 128 (>> 7) solo alla fine, prima del lookup.
# Usando una potenza di 2 come scala la divisione e' esatta via bit-shift.
# ---------------------------------------------------------------------------
SCALE_FACTOR = 128   # 2^7  =>  shift right di 7 bit nel kernel

integer_weights = []
float_weights = []

for param in model.parameters():
    for weight_float in param.data.view(-1).tolist():
        # Salva il peso float originale (prima della quantizzazione)
        float_weights.append(weight_float)

        weight_int = int(round(weight_float * SCALE_FACTOR))
        # Clamp a int8: se il peso float supera +-1 viene saturato, non wrappato
        weight_int = max(-128, min(127, weight_int))
        integer_weights.append(weight_int)

# Pesi quantizzati int8 -> usati dal kernel eBPF
with open("weights.json", "w") as f:
    json.dump(integer_weights, f)

# Pesi float originali -> usati dal control plane Python per il lookup preciso
with open("weights_float.json", "w") as f:
    json.dump(float_weights, f)

print(f"SCALE_FACTOR = {SCALE_FACTOR}  (shift = 7 bit nel kernel eBPF)")
print(f"Extraction complete! Saved {len(integer_weights)} weights to weights.json")
print(f"Float weights saved to weights_float.json ({len(float_weights)} values)")
print(f"Range int8 effettivo: min={min(integer_weights)}  max={max(integer_weights)}")
print(f"Range float originale: min={min(float_weights):.4f}  max={max(float_weights):.4f}")
