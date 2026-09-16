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
[link_state, ingress_iface, ttl, node]; n_out comes from the descriptor, so a model
with no descriptor (the checked-in 65-4-4-7 model, topology config 6/52)
reproduces the original N_IN=65/N_OUT=7 program.
"""

import json
import os

# This module's own directory: where weights.json / model_meta.json live.
_SHARED_DIR = os.path.dirname(os.path.abspath(__file__))

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
    # Declared, not left to derive_shape's n_interfaces+1 fallback. The value
    # is the checked-in checkpoint's output width; 6 interfaces is the topology
    # and has nothing to do with it (only 5 of them are ever a label).
    "n_out": 7,
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
# Normalisation divisor for the `ttl` feature.
#
# The training pipeline does NOT feed the raw TTL. IPA_dataset_gen.py builds the
# column as
#     ttl = ttl_value / initial_ttl        with initial_ttl = 30
# so the model was trained on a value in (0, 1] that starts at 1.0 and decreases
# with each hop -- the FRACTION OF THE JOURNEY REMAINING, not a hop count. The
# dataset confirms it: the `ttl` column of dataset_germany50_5.csv ranges over
# [0.3333, 1.0] in steps of 1/30.
#
# The datapath used to pass the raw TTL (30-64). Since link_state enters the
# dot product as 0 or 1, that gave the TTL term 30-64x more leverage per unit of
# weight and buried the failure signal: measured over the trained TTL range, the
# model reacted to a link failure in 0% of cases and redirected onto the DEAD
# link in 16.7%. Dividing the TTL term by this scale restores the trained
# behaviour (reroute on ~48% of failures, dead-link redirects to 0%).
#
# Divide the PRODUCT, never the TTL: `ttl / 30` in integer arithmetic collapses
# the whole 10..30 range onto 0 or 1 and throws the resolution away.
#
# This is a property of the CHECKPOINT (its initial_ttl), not of the topology.
# A model trained with a different initial_ttl needs a different value here; if
# that ever happens it belongs in model_meta.json / the per-model descriptor
# rather than in this constant.
DEFAULT_TTL_SCALE = 30

FEATURE_CATALOG = {
    "ttl":             {"kind": "scalar",           "dim": 1,
                        "scale": DEFAULT_TTL_SCALE},
    "link_state":      {"kind": "dense_vector_map", "map": "link_state", "dim_key": "n_interfaces"},
    "queue_occupancy": {"kind": "dense_vector_map", "map": "queue_state", "dim_key": "n_queues"},
    "ingress_iface":   {"kind": "onehot",           "dim_key": "n_interfaces"},
    "node":            {"kind": "onehot",           "dim_key": "n_nodes"},
}

# Numeric wire/registry code per feature type — single source of truth shared by
# the on-wire IPA header (feat*_code), the descriptor-driven eBPF programs
# (model_desc registry) and their control planes. Matches the historical codes
# in test_ipa.py (link_state=1, ingress_iface=2, ttl=3, node=4); queue_occupancy
# is the added type (5).
FEATURE_CODE = {
    "link_state":      0x01,
    "ingress_iface":   0x02,
    "ttl":             0x03,
    "node":            0x04,
    "queue_occupancy": 0x05,
}

# Historical fixed feature layout, in the exact order the 65-4-4-7 model was
# trained on. Used when a model declares no explicit "features" list.
_DEFAULT_FEATURE_TYPES = ["link_state", "ingress_iface", "ttl", "node"]


def resolve_descriptor(features: list) -> list:
    """Turn a resolved descriptor (list of {"type","size"}) into the flat layout
    the model_desc registry needs: a list of {"code","size","col_off"} where
    col_off is the feature's starting column within the fc1 input row (the
    running sum of preceding feature sizes). Shared by the P2/P3 control planes
    so the runtime IV matches the trained weight layout exactly."""
    out = []
    col = 0
    for f in features:
        out.append({"code": FEATURE_CODE[f["type"]], "size": int(f["size"]),
                    "col_off": col})
        col += int(f["size"])
    return out


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


def feature_scale(feature_type: str) -> int:
    """Divisor applied to a scalar feature's contribution, so the datapath feeds
    the model the same magnitude the training pipeline did. 1 = no scaling.
    See DEFAULT_TTL_SCALE for why `ttl` needs one."""
    return int(FEATURE_CATALOG[feature_type].get("scale", 1))


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
        # n_out is a property of the TRAINED MODEL, not of the topology. The
        # line here used to be `n_out = cfg["n_interfaces"] + 1`, which asserts
        # one class per interface plus exactly one extra, and (everywhere
        # downstream) that the extra one is DROP. The checked-in checkpoint has
        # n_interfaces=6 and n_out=7 -- so the formula happens to give the right
        # WIDTH while being wrong about every class meaning: only 5 classes
        # forward, class 5 drops, class 6 is untrained.
        #
        # Declared n_out wins. The formula survives only as an announced
        # fallback for descriptors written before it was recorded.
        if "n_out" in meta:
            n_out = int(meta["n_out"])
        else:
            n_out = cfg["n_interfaces"] + 1
            print(f"[model_meta] NOTE: descriptor declares no n_out; ASSUMING "
                  f"n_interfaces + 1 = {n_out}. That formula says nothing about "
                  f"what the classes mean -- add \"n_out\" and "
                  f"\"class_semantics\" to model_meta.json.")

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
    except ImportError:
        # Deployment nodes (e.g. Kathara containers) run from the prebuilt
        # weights.json and have no torch/.pt. The checkpoint N_IN cross-check is
        # a dev-machine safety net, not a runtime requirement -- skip it here
        # instead of hard-failing the whole pipeline.
        print("[verify] torch not available — skipping N_IN checkpoint "
              "consistency check (expected on deployment nodes that use the "
              "prebuilt weights.json).")
        return

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


# ---------------------------------------------------------------------------
# Class semantics (see class_semantics.py)
# ---------------------------------------------------------------------------

def load_class_semantics(model_path: str, n_out: int = None):
    """Class semantics for the model whose artefacts sit next to `model_path`.

    Read from model_meta.json's `class_semantics` block. If the descriptor has
    none, a reference layout (FORWARD 0..n_out-2, DROP n_out-1) is built and
    the assumption is PRINTED -- the previous behaviour was the same guess made
    silently, which is how the datapath ended up dropping class 6 while the
    model was trained to drop class 5.
    """
    from class_semantics import ClassSemantics
    meta = load_model_meta(model_path)
    if meta.get("class_semantics"):
        sem = ClassSemantics.from_json(meta)
        if n_out is not None and sem.n_out != n_out:
            raise ValueError(
                f"model_meta.json declares n_out={sem.n_out} but the resolved "
                f"shape has n_out={n_out}. Fix the descriptor rather than "
                f"letting the datapath pick one of the two.")
        return sem
    if n_out is None:
        raise ValueError("no class_semantics in the descriptor and no n_out given")
    print(f"[model_meta] WARNING: no class_semantics in the descriptor; "
          f"assuming FORWARD 0..{n_out - 2} and DROP {n_out - 1}. This is a "
          f"GUESS -- declare class_semantics in model_meta.json. The checked-in "
          f"model's trained DROP class is 5, not {n_out - 1}.")
    return ClassSemantics.forward_then_drop(n_out - 1, drop_class=n_out - 1,
                                            n_out=n_out)


def descriptor_semantics_or_reference(n_out: int, who: str):
    """Semantics for an n_out-wide model: descriptor first, reference second.

    The single fallback used by all three pipelines and the AOT generator, so
    there is one place where "no semantics were supplied" is resolved and one
    wording for it. Order matters:

      1. shared/model_meta.json's class_semantics, if its n_out matches. This
         is a DECLARATION and is used as-is.
      2. FORWARD 0..n_out-2 / DROP n_out-1, printed as an assumption.

    Step 2 is still a guess, and for the checked-in model it is the WRONG one
    (trained DROP is 5, class 6 is untrained). It exists so that a caller who
    forgot to pass semantics gets a loud line in its output rather than a
    silently mis-dropping datapath.
    """
    from class_semantics import ClassSemantics
    try:
        meta = load_model_meta(os.path.join(_SHARED_DIR, "weights.json"))
        if meta.get("class_semantics"):
            sem = ClassSemantics.from_json(meta)
            if sem.n_out == n_out:
                print(f"[{who}] class semantics from model_meta.json "
                      f"(n_out={sem.n_out}, drop_class={sem.drop_class})")
                return sem
            print(f"[{who}] NOTE: model_meta.json declares n_out={sem.n_out}, "
                  f"this model has n_out={n_out}: descriptor not applicable")
    except Exception as e:
        print(f"[{who}] NOTE: model_meta.json unusable ({e})")
    print(f"[{who}] NOTE: no class semantics supplied; ASSUMING the reference "
          f"layout FORWARD 0..{n_out - 2}, DROP {n_out - 1}. This is a guess, "
          f"not a rule -- declare class_semantics in model_meta.json or pass "
          f"`semantics=`.")
    return ClassSemantics.forward_then_drop(n_out - 1, drop_class=n_out - 1,
                                            n_out=n_out)
