import torch
import json
import os

# Import the model structure from the local file
from FRR_model import FastRerouteMLP

print("Extracting weights from PyTorch model...")

# Initialize and load the model
model = FastRerouteMLP(n_interfaces=6, n_nodes=52, hidden_dim=4)
model.load_state_dict(torch.load("frr_germany50_5_model_4x2.pt"))

# Quantization parameters
SCALE_FACTOR = 100
integer_weights = []

# Convert all float parameters to scaled integers
for param in model.parameters():
    for weight_float in param.data.view(-1).tolist():
        weight_int = int(weight_float * SCALE_FACTOR)
        integer_weights.append(weight_int)

# Save the pure integers into a lightweight JSON file in the shared directory
with open("weights.json", "w") as f:
    json.dump(integer_weights, f)

print(f"Extraction complete! Saved {len(integer_weights)} weights to weights.json")