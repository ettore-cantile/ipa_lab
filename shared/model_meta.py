"""
model_meta.py — Per-model feature descriptor + per-topology feature dimensions
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

  * PER-TOPOLOGY / PER-NETWORK: the DIMENSION of each feature type.
    A feature's size is a property of the NETWORK TOPOLOGY, shared by every
    node in the same deployment — NOT a property of any individual node and
    NOT a property of the model:
      - link_state  has one slot per egress interface IN THE LARGEST NODE
                    of the network (fixed at training time).
      - node        one-hot has one slot per node IN THE NETWORK.
      - queue_occ   has one slot per queue per interface.
    A node with 3 physical interfaces still builds a link_state feature of
    size n_interfaces (the network maximum) — unused slots are structurally
    zero and their weights are folded away by the compiler.
    All models operating on ANY node of the same topology see the SAME size
    for the same feature type.

    Read from topology_config.json at runtime via load_topology_config().
    Falls back to DEFAULT_TOPOLOGY_CONFIG (historical 6-interface / 52-node
    topology) when the file is absent.

    Any n_interfaces / n_nodes / n_queues keys present in a model's
    model_meta.json are IGNORED when a topology_config is supplied — they
    are properties of the network, not of the model.

  * PER-MODEL: which feature TYPES the model uses (an ordered list, the order
    the model was trained on) and its output width n_out. This is the model
    descriptor: model_meta.json's "features" list.

A model_meta.json therefore looks like:
    {
      "features": ["link_state", "ingress_iface", "ttl", "node"],
      "n_out": 7,
      "hidden_dims": [4, 4]
    }
N_IN = sum of the (topology-derived) sizes of those feature types.

Absence of a "features" list falls back to the historical fixed encoding
[link_state, ingress_iface, ttl, node] with n_out = n_interfaces+1, so a model
with no descriptor (the checked-in 65-4-4-7 model, topology config 6/52)
reproduces the original N_IN=65/N_OUT=7 program.
"""

import json
import os

# ---------------------------------------------------------------------------
# Per-topology / per-network defaults.
# Overridden at runtime by topology_config.json (see load_topology_config()).
# ---------------------------------------------------------------------------
DEFAULT_TOPOLOGY_CONFIG = {
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
#   dim_key  -- which topology_config key gives its size (per-topology), OR
#   dim      -- a fixed size (scalars only)
#   map      -- (dense_vector_map only) the BPF map holding its per-slot values
#
# Kinds:
#   scalar            -- one value read from the packet in transit (v*w[j,o]).
#   dense_vector_map  -- `size` values read once from a BPF map / node state
#                        (sum_i vec[i]*w[j,o+i]).
#   onehot            -- exactly one active index k in [0,size); a single
#                        switch per feature (NOT per neuron) picks the weight
#                        (w[j,o+k]) — verifier-safe (prof_Notes.md section 8),
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


# ---------------------------------------------------------------------------
# topology_config loading  (Problema 1)
# ---------------------------------------------------------------------------

def load_topology_config(path: str = "/etc/ipa/topology_config.json") -> dict:
    """
    Load the per-network topology configuration from *path*.

    This file describes the NETWORK TOPOLOGY shared by all nodes in the
    same deployment — it is NOT a per-node file. It contains the maximum
    feature dimensions that every node must use to build an input vector
    compatible with the trained checkpoint:

      n_interfaces  — number of IV slots for link_state / ingress_iface
                      (= max interfaces across any node in the network)
      n_nodes       — number of IV slots for the node one-hot
                      (= total nodes in the network topology)
      n_queues      — number of IV slots for queue_occupancy
                      (= queues per interface)

    A node with fewer physical interfaces than n_interfaces still builds
    a link_state vector of size n_interfaces — unused slots are zero and
    their weights are folded away at compile time.

    If the file does not exist the function returns DEFAULT_TOPOLOGY_CONFIG
    (historical 6-interface / 52-node topology) so existing setups that
    have no topology_config.json keep working unchanged.
    """
    if os.path.exists(path):
        with open(path) as f:
            cfg = json.load(f)
        print(f"[topology_config] loaded from {path}: {cfg}")
        merged = dict(DEFAULT_TOPOLOGY_CONFIG)
        merged.update(cfg)
        return merged
    else:
        print(
            f"[topology_config] {path} not found — "
            f"using DEFAULT_TOPOLOGY_CONFIG: {DEFAULT_TOPOLOGY_CONFIG}"
        )
        return dict(DEFAULT_TOPOLOGY_CONFIG)


# ---------------------------------------------------------------------------
# model_meta loading
# ---------------------------------------------------------------------------

def _meta_path_for(model_path: str) -> str:
    """model_meta.json lives next to the model's weights/.pt file."""
    return os.path.join(os.path.dirname(os.path.abspath(model_path)), "model_meta.json")


def load_model_meta(model_path: str) -> dict:
    """
    Load model_meta.json next to `model_path`. Missing file/fields fall back
    to DEFAULT_META (historical 6/52 default descriptor) so existing models
    keep working unmodified.

    Note: n_interfaces / n_nodes / n_queues in model_meta.json are retained
    here for backward compatibility but are IGNORED by derive_shape() when
    an explicit topology_config is supplied — they are properties of the
    network topology, not of the model.
    """
    meta = dict(DEFAULT_META)
    path = _meta_path_for(model_path)
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        meta.update(data)
    return meta


def topology_config_for(meta: dict) -> dict:
    """[LEGACY] Resolve per-topology dimensions from a meta dict.

    Kept for backward compatibility with call sites that invoke
    derive_shape(meta) without passing an explicit topology_config.
    New callers should use load_topology_config() and pass the result
    to derive_shape(meta, topology_config=...) directly.

    Priority (lowest to highest):
      DEFAULT_TOPOLOGY_CONFIG
      <- top-level n_interfaces / n_nodes / n_queues keys in meta
      <- meta["topology_config"] sub-dict
    """
    cfg = dict(DEFAULT_TOPOLOGY_CONFIG)
    for k in ("n_interfaces", "n_nodes", "n_queues"):
        if k in meta:
            cfg[k] = meta[k]
    cfg.update(meta.get("topology_config", {}))
    return cfg


def feature_size(feature_type: str, topology_config: dict) -> int:
    """Size (number of IV slots) of a feature type — from the topology
    config (per-network), not from the model."""
    entry = FEATURE_CATALOG[feature_type]
    if "dim" in entry:
        return int(entry["dim"])
    return int(topology_config[entry["dim_key"]])


def _validate_feature_types(types: list) -> None:
    if not types:
        raise ValueError("model descriptor 'features' must be a non-empty list of feature types")
    seen = set()
    for t in types:
        if t not in FEATURE_CATALOG:
            raise ValueError(f"unknown feature type {t!r}; known: {sorted(FEATURE_CATALOG)}")
        if t in seen:
            raise ValueError(f"feature type {t!r} appears more than once in the descriptor")
        seen.add(t)


def derive_shape(meta: dict, topology_config: dict = None,
                 node_config: dict = None) -> dict:
    """
    Resolve a model_meta dict into a concrete shape:
      {"n_in", "n_out", "hidden_dims", "features", "topology_config"}
    where "features" is the resolved descriptor — a list of {"type", "size"}
    with each size taken from the topology config.

    Args:
        meta:            model descriptor loaded by load_model_meta().
        topology_config: per-network dimensions loaded by load_topology_config().
                         AUTHORITATIVE source for n_interfaces, n_nodes,
                         n_queues — any such keys in *meta* (model_meta.json)
                         are ignored.
        node_config:     [DEPRECATED] accepted for backward compatibility only;
                         topology_config takes precedence if both are supplied.

    If neither argument is supplied the function falls back to the legacy
    topology_config_for(meta) behaviour so un-updated callers keep working.
    """
    hidden_dims = meta.get("hidden_dims", [4, 4])

    # Resolution order: topology_config > node_config (deprecated) > legacy fallback
    if topology_config is not None:
        cfg = dict(topology_config)
    elif node_config is not None:
        cfg = dict(node_config)
    else:
        cfg = topology_config_for(meta)

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
        "n_in": n_in,
        "n_out": n_out,
        "hidden_dims": hidden_dims,
        "features": features,
        "topology_config": cfg,
    }
    if not meta.get("features"):
        shape["n_interfaces"] = cfg["n_interfaces"]
        shape["n_nodes"]      = cfg["n_nodes"]
    return shape


# ---------------------------------------------------------------------------
# Checkpoint consistency check  (Problema 2)
# ---------------------------------------------------------------------------

def verify_shape_vs_checkpoint(shape: dict, model_path: str) -> None:
    """
    Verify that the N_IN computed from topology_config + feature types matches
    the actual first-layer input dimension of the PyTorch checkpoint.

    Reads fc1.weight.shape[1] from the state dict and compares it with
    shape['n_in']. If they differ the function raises a clear, blocking
    ValueError — loading the wrong model on a mismatched topology would
    silently produce wrong inference output, which is worse than a hard error.

    Args:
        shape:      output of derive_shape().
        model_path: path to the .pt checkpoint file.

    Raises:
        ValueError   if n_in from topology_config != n_in from checkpoint.
        RuntimeError if torch is not available or the checkpoint cannot be read.
    """
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError(
            "torch is required for checkpoint verification but could not be imported."
        ) from exc

    try:
        state = torch.load(model_path, map_location="cpu")
    except Exception as exc:
        raise RuntimeError(
            f"Could not load PyTorch checkpoint from {model_path!r}: {exc}"
        ) from exc

    if "state_dict" in state and isinstance(state["state_dict"], dict):
        state = state["state_dict"]

    if "fc1.weight" not in state:
        print(
            "[verify] WARNING: 'fc1.weight' not found in checkpoint "
            f"({model_path!r}) — skipping N_IN consistency check."
        )
        return

    n_in_checkpoint = int(state["fc1.weight"].shape[1])
    n_in_topo       = shape["n_in"]

    if n_in_checkpoint != n_in_topo:
        feature_breakdown = ", ".join(
            f"{f['type']}={f['size']}" for f in shape["features"]
        )
        raise ValueError(
            f"\n"
            f"  N_IN MISMATCH — checkpoint incompatible with current topology_config.\n"
            f"\n"
            f"  N_IN expected by the checkpoint   (fc1.weight.shape[1]): {n_in_checkpoint}\n"
            f"  N_IN computed from topology_config + feature types      : {n_in_topo}\n"
            f"\n"
            f"  Feature breakdown: [{feature_breakdown}]\n"
            f"  topology_config used: {shape['topology_config']}\n"
            f"\n"
            f"  The checkpoint in {model_path!r} was trained on a different topology.\n"
            f"  Either use a model trained with n_in={n_in_topo}, or update\n"
            f"  topology_config.json so that it matches the topology the model expects\n"
            f"  (n_in={n_in_checkpoint})."
        )

    print(
        f"[verify] N_IN={n_in_topo} OK — "
        f"checkpoint and topology_config are consistent."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def feature_maps(features: list) -> dict:
    """Return {feature_type: map_name} for the map-backed (dense_vector_map)
    features in a resolved descriptor."""
    out = {}
    for f in features:
        entry = FEATURE_CATALOG[f["type"]]
        if entry["kind"] == "dense_vector_map":
            out[f["type"]] = entry["map"]
    return out
