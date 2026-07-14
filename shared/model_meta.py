"""
model_meta.py — Per-model feature descriptor + per-node feature dimensions
(shared by extract_weights.py, ebpf_program.py, methods/method4_hardcoded.py).

Pipeline 1 (hardcoded) builds the model's input vector (IV) ON THE NODE from
information the switch already has locally: some from the packet in transit
(TTL), some from node/network state (interface up/down, ingress port, current
node, queue occupancy). Different models may use DIFFERENT SETS of feature
types (the professor's scenario: M1 might use {link_state, ttl, node}, M2
{ingress_iface, ttl, queue_occupancy}...). The switch as a whole supports the
union of all registered models' feature types; each generated program builds
only the subset its model needs.

Two separate concerns:

  * PER-NODE / PER-NETWORK: the DIMENSION of each feature type. A feature's
    size is a property of where the model runs, NOT of the model: link_state
    has one slot per egress interface OF THIS NODE, node one-hot has one slot
    per node IN THIS NETWORK, etc. All models operating on the same node/
    network see the SAME size for the same feature type. This lives in a
    node config (DEFAULT_NODE_CONFIG, overridable per model_meta.json via a
    "node_config" key for testing different topologies).

  * PER-MODEL: which feature TYPES the model uses (an ordered list, the order
    the model was trained on) and its output width n_out. This is the model
    descriptor: model_meta.json's "features" list.

A model_meta.json therefore looks like:
    {
      "features": ["link_state", "ingress_iface", "ttl", "node"],
      "n_out": 7,
      "hidden_dims": [4, 4]
    }
N_IN = sum of the (node-derived) sizes of those feature types.

Absence of a "features" list falls back to the historical fixed encoding
[link_state, ingress_iface, ttl, node] with n_out = n_interfaces+1, so a model
with no descriptor (the checked-in 65-4-4-7 model, node config 6/52)
reproduces the original N_IN=65/N_OUT=7 program.
"""

import json
import os

# Per-node / per-network feature dimensions. A feature type's size is looked
# up here (see FEATURE_CATALOG[..]["dim_key"]), NOT declared per model:
# n_interfaces = egress interfaces of THIS node, n_nodes = nodes in THIS
# network, n_queues = queues of THIS node. Defaults reproduce the historical
# 6-interface / 52-node topology. Override per model via a "node_config" key
# in model_meta.json (e.g. to test a different topology).
DEFAULT_NODE_CONFIG = {
    "n_interfaces": 6,
    "n_nodes": 52,
    "n_queues": 4,
}

DEFAULT_META = {
    "n_interfaces": 6,   # kept for backward compat with callers reading it directly
    "n_nodes": 52,
    "hidden_dims": [4, 4],
}

# Compile-time ceiling for the generated first-layer dot product (verifier
# needs a bound; generous relative to a 65-input baseline).
MAX_N_IN  = 128
MAX_N_OUT = 32

# ---------------------------------------------------------------------------
# Feature catalog: the feature *types* the switch knows how to build locally.
# Each entry declares:
#   kind     -- how the feature enters the fc1 dot product (see below)
#   dim_key  -- which DEFAULT_NODE_CONFIG entry gives its size (per-node), OR
#   dim      -- a fixed size (scalars only)
#   map      -- (dense_vector_map only) the BPF map holding its per-slot values
#
# Kinds:
#   scalar            -- one value read from the packet in transit (v*w[j,o]).
#   dense_vector_map  -- `size` values read once from a BPF map / node state
#                        (sum_i vec[i]*w[j,o+i]).
#   onehot            -- exactly one active index k in [0,size); a single
#                        switch per feature (NOT per neuron) picks the weight
#                        (w[j,o+k]) -- verifier-safe (prof_Notes.md section 8),
#                        the CFG stays O(size) instead of O(size^n_h1).
#
# The C generation for each kind lives in ebpf_program.py (_gen_feature_*).
# Adding a new feature type = one entry here + its _gen_feature_* fragment
# (+ a userspace seeder for map-backed ones).
# ---------------------------------------------------------------------------
FEATURE_CATALOG = {
    "ttl":             {"kind": "scalar",           "dim": 1},
    "link_state":      {"kind": "dense_vector_map", "map": "link_state", "dim_key": "n_interfaces"},
    "queue_occupancy": {"kind": "dense_vector_map", "map": "queue_state", "dim_key": "n_queues"},
    "ingress_iface":   {"kind": "onehot",           "dim_key": "n_interfaces"},
    "node":            {"kind": "onehot",           "dim_key": "n_nodes"},
}

# Historical fixed feature layout, in the exact order the 65-4-4-7 model was
# trained on. Used when a model declares no explicit "features" list.
_DEFAULT_FEATURE_TYPES = ["link_state", "ingress_iface", "ttl", "node"]


def _meta_path_for(model_path: str) -> str:
    """model_meta.json lives next to the model's weights/.pt file."""
    return os.path.join(os.path.dirname(os.path.abspath(model_path)), "model_meta.json")


def load_model_meta(model_path: str) -> dict:
    """
    Load model_meta.json next to `model_path`. Missing file/fields fall back
    to DEFAULT_META (historical 6/52 default descriptor) so existing models
    keep working unmodified.
    """
    meta = dict(DEFAULT_META)
    path = _meta_path_for(model_path)
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        meta.update(data)
    return meta


def node_config_for(meta: dict) -> dict:
    """Resolve the per-node feature dimensions for a model: DEFAULT_NODE_CONFIG
    overlaid with any "node_config" the model_meta.json provides, plus the
    n_interfaces/n_nodes a legacy default-descriptor model carries directly."""
    cfg = dict(DEFAULT_NODE_CONFIG)
    for k in ("n_interfaces", "n_nodes", "n_queues"):
        if k in meta:
            cfg[k] = meta[k]
    cfg.update(meta.get("node_config", {}))
    return cfg


def feature_size(feature_type: str, node_config: dict) -> int:
    """Size (number of IV slots) of a feature type on a node -- from the node
    config (per-node/per-network), not from the model."""
    entry = FEATURE_CATALOG[feature_type]
    if "dim" in entry:
        return int(entry["dim"])
    return int(node_config[entry["dim_key"]])


def _validate_feature_types(types: list) -> None:
    if not types:
        raise ValueError("model descriptor 'features' must be a non-empty list of feature types")
    seen = set()
    for t in types:
        if t not in FEATURE_CATALOG:
            raise ValueError(f"unknown feature type {t!r}; known: {sorted(FEATURE_CATALOG)}")
        if t in seen:
            # The codegen uses per-type C variable names (_ttl, ls*, w_iface_j,
            # ...), so a type may appear at most once per descriptor.
            raise ValueError(f"feature type {t!r} appears more than once in the descriptor")
        seen.add(t)


def derive_shape(meta: dict) -> dict:
    """
    Resolve a model_meta dict into a concrete shape:
      {"n_in", "n_out", "hidden_dims", "features", "node_config", ...}
    where "features" is the resolved descriptor -- a list of {"type","size"}
    with each size taken from the node config -- which the codegen iterates
    over.

    - explicit "features" list (of type names) -> sizes from the node config,
      n_in = sum(sizes), n_out = meta["n_out"] (required).
    - no "features" list -> historical default descriptor
      [link_state, ingress_iface, ttl, node], n_out = n_interfaces+1.
      Reproduces the original N_IN=65/N_OUT=7 model.
    """
    hidden_dims = meta.get("hidden_dims", [4, 4])
    cfg = node_config_for(meta)

    if meta.get("features"):
        types = list(meta["features"])
        _validate_feature_types(types)
        if "n_out" not in meta:
            raise ValueError("a model with an explicit 'features' list must also declare 'n_out'")
        n_out = int(meta["n_out"])
    else:
        types = list(_DEFAULT_FEATURE_TYPES)
        n_out = cfg["n_interfaces"] + 1

    features = [{"type": t, "size": feature_size(t, cfg)} for t in types]
    n_in = sum(f["size"] for f in features)
    if n_in > MAX_N_IN:
        raise ValueError(f"n_in={n_in} exceeds MAX_N_IN={MAX_N_IN}")
    if n_out <= 0 or n_out > MAX_N_OUT:
        raise ValueError(f"n_out={n_out} outside [1, {MAX_N_OUT}]")

    shape = {
        "n_in": n_in, "n_out": n_out, "hidden_dims": hidden_dims,
        "features": features, "node_config": cfg,
    }
    if not meta.get("features"):
        shape["n_interfaces"] = cfg["n_interfaces"]
        shape["n_nodes"]      = cfg["n_nodes"]
    return shape


def feature_maps(features: list) -> dict:
    """Return {feature_type: map_name} for the map-backed (dense_vector_map)
    features in a resolved descriptor -- the set of BPF maps the control plane
    must seed for this model (e.g. link_state, queue_state). Features read
    directly from the packet/node (scalar, onehot) contribute nothing here."""
    out = {}
    for f in features:
        entry = FEATURE_CATALOG[f["type"]]
        if entry["kind"] == "dense_vector_map":
            out[f["type"]] = entry["map"]
    return out
