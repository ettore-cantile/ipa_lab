import torch
import json

from FRR_model import FastRerouteMLP

print("Extracting weights from PyTorch model...")

model = FastRerouteMLP(n_interfaces=6, n_nodes=52, hidden_dim=4)
model.load_state_dict(torch.load("frr_germany50_5_model_4x2.pt"))

# ---------------------------------------------------------------------------
# Metodo 1 - PTQ: SCALE_FACTOR calcolato automaticamente dal peso massimo.
#
# SCALE_FACTOR = floor(127 / max(|w|))
# Garantisce che nessun peso superi il range int8 [-128, 127] dopo la
# moltiplicazione, eliminando il clamp che causava i TABLE MISS.
#
# Il SCALE_FACTOR viene salvato in weights_float.json insieme ai pesi float
# originali, e viene scritto nel campo 'scaling' dell'IPA header da send_ipa.
# Il kernel lo legge dall'header e lo usa come divisore (non piu' shift).
# ---------------------------------------------------------------------------

all_floats = [w for param in model.parameters() for w in param.data.view(-1).tolist()]
max_abs    = max(abs(w) for w in all_floats)
SCALE_FACTOR = int(127 / max_abs)

print(f"Max |weight| = {max_abs:.6f}")
print(f"SCALE_FACTOR = floor(127 / {max_abs:.6f}) = {SCALE_FACTOR}")

integer_weights = []
for w_float in all_floats:
    w_int = int(round(w_float * SCALE_FACTOR))
    w_int = max(-128, min(127, w_int))  # safety clamp (non dovrebbe scattare)
    integer_weights.append(w_int)

# Verifica che nessun peso sia stato clampato
clamped = sum(1 for w, wf in zip(integer_weights, all_floats)
              if w != int(round(wf * SCALE_FACTOR)))
if clamped:
    print(f"[WARN] {clamped} pesi clampati (max_abs potrebbe non essere il vero massimo)")
else:
    print("Nessun peso clampato. Range int8 rispettato per tutti i pesi.")

# Pesi int8 -> kernel eBPF
with open("weights.json", "w") as f:
    json.dump(integer_weights, f)

# Pesi float originali + SCALE_FACTOR -> control plane Metodo 1
with open("weights_float.json", "w") as f:
    json.dump({"scale_factor": SCALE_FACTOR, "weights": all_floats}, f)

print(f"Saved {len(integer_weights)} int8 weights  -> weights.json")
print(f"Saved float weights + scale_factor={SCALE_FACTOR} -> weights_float.json")
print(f"Range int8: min={min(integer_weights)}  max={max(integer_weights)}")
