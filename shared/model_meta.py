"""
model_meta.py — Per-model scenario metadata (shared by extract_weights.py,
ebpf_program.py, methods/method4_hardcoded.py and send_ipa.py).

Generalizes the input-vector/output-class shape that used to be hardcoded as
N_IN=65 / N_OUT=7 across every pipeline. A model directory can carry a
`model_meta.json` next to its weights (`weights_float.json` / `.pt`) describing
which "scenario" it belongs to:

  "sparse" (default, backward compatible with the one FRR model checked into
    the repo): the feature vector is derived on the datapath from packet
    metadata itself (link_state map + ingress ifindex + ttl + model_id), the
    same encoding Pipeline 1 has always used:
      N_IN  = 2*n_interfaces + 1 + n_nodes
              (link_state[n_interfaces] + iface one-hot[n_interfaces] + ttl[1]
               + node one-hot[n_nodes])
      N_OUT = n_interfaces + 1   (n_interfaces egress classes + 1 drop class)
    n_interfaces/n_nodes replace the old fixed constants 6/52.

  "dense": no FRR-specific semantics assumed. n_in/n_out are declared directly
    by the model; the actual per-packet feature vector travels in the IPA
    packet payload (quantized int8, length n_in) instead of being derived from
    packet metadata.

Absence of a model_meta.json means "sparse, n_interfaces=6, n_nodes=52" —
today's exact behavior, so existing callers/checkpoints need no migration.
"""

import json
import os

DEFAULT_META = {
    "scenario": "sparse",
    "n_interfaces": 6,
    "n_nodes": 52,
    "hidden_dims": [4, 4],
}

# Compiled ceilings for the "dense" route (verifier needs compile-time bounds
# on generated loops; these are generous relative to a 65-4-4-7 baseline).
MAX_N_IN  = 128
MAX_N_OUT = 32


def _meta_path_for(model_path: str) -> str:
    """model_meta.json lives next to the model's weights/.pt file."""
    return os.path.join(os.path.dirname(os.path.abspath(model_path)), "model_meta.json")


def load_model_meta(model_path: str) -> dict:
    """
    Load model_meta.json next to `model_path`. Missing file/fields fall back
    to DEFAULT_META (today's sparse/6/52/[4,4] behavior) so existing models
    keep working unmodified.
    """
    meta = dict(DEFAULT_META)
    path = _meta_path_for(model_path)
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        meta.update(data)
    return meta


def derive_shape(meta: dict) -> dict:
    """
    Resolve a model_meta dict into concrete {"n_in", "n_out", "hidden_dims"}.

    scenario == "sparse": derived from n_interfaces/n_nodes via the FRR
      feature-encoding formula (see module docstring) -- default
      n_interfaces=6, n_nodes=52 reproduces the historical N_IN=65/N_OUT=7.
    scenario == "dense": n_in/n_out are read directly from meta (no derived
      formula -- the model declares its own shape), bounded by MAX_N_IN/
      MAX_N_OUT.
    """
    scenario = meta.get("scenario", "sparse")
    hidden_dims = meta.get("hidden_dims", [4, 4])

    if scenario == "sparse":
        n_interfaces = meta["n_interfaces"]
        n_nodes      = meta["n_nodes"]
        n_in  = 2 * n_interfaces + 1 + n_nodes
        n_out = n_interfaces + 1
        return {
            "n_in": n_in, "n_out": n_out, "hidden_dims": hidden_dims,
            "n_interfaces": n_interfaces, "n_nodes": n_nodes,
        }

    if scenario == "dense":
        n_in  = meta["n_in"]
        n_out = meta["n_out"]
        if n_in <= 0 or n_in > MAX_N_IN:
            raise ValueError(f"dense scenario n_in={n_in} outside [1, {MAX_N_IN}]")
        if n_out <= 0 or n_out > MAX_N_OUT:
            raise ValueError(f"dense scenario n_out={n_out} outside [1, {MAX_N_OUT}]")
        return {"n_in": n_in, "n_out": n_out, "hidden_dims": hidden_dims}

    raise ValueError(f"unknown scenario {scenario!r} (expected 'sparse' or 'dense')")
