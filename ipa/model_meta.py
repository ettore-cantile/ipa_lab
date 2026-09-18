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
    Resolved by load_topology_config(): $IPA_TOPOLOGY_CONFIG, then
    /etc/ipa/topology_config.json, then the model descriptor's `trained_on`
    block. There is deliberately no built-in default.

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
# NO built-in topology numbers.
#
# This used to be `DEFAULT_TOPOLOGY_CONFIG = {"n_interfaces": 6, "n_nodes": 52,
# "n_queues": 4}` -- the Germany50 lab, written into the engine, silently used
# by every caller that did not supply a config. Feature widths are a property
# of the network a model was TRAINED on, so the engine cannot have a default
# for them: any number it picks is a claim about someone else's network.
#
# Resolution order is now explicit, and exhausting it is an error, not a
# fallback. See resolve_topology_config().
# Every topology dimension the feature catalog can ask for. A config needs an
# entry only for the dimensions its model's features actually use: the checked-in
# model has no queue_occupancy feature, so demanding n_queues from it would be
# demanding a number about a network property it never observes. A feature that
# needs a missing key raises at the point of use, naming the key -- see
# feature_size().
TOPOLOGY_KEYS = ("n_interfaces", "n_nodes", "n_queues")
TOPOLOGY_KEYS_REQUIRED = ("n_interfaces", "n_nodes")


class ScenarioError(Exception):
    """No usable topology configuration, or one that contradicts the model."""


DEFAULT_META = {
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
# Compiled ceilings for the dense per-slot features, mirroring IPA_MAX_IFACES /
# IPA_MAX_QUEUES in the P2/P3 C templates. A scenario larger than these needs
# both raised and the programs recompiled; check_topology_fits() says so rather
# than letting the datapath read past the vector.
MAX_N_IFACES = 8
MAX_N_QUEUES = 8


def check_topology_fits(topology_config: dict) -> None:
    """Raise if the scenario exceeds what the datapath was compiled for."""
    for key, ceiling, cdefine in (("n_interfaces", MAX_N_IFACES, "IPA_MAX_IFACES"),
                                  ("n_queues", MAX_N_QUEUES, "IPA_MAX_QUEUES")):
        if key in topology_config and int(topology_config[key]) > ceiling:
            raise ScenarioError(
                f"scenario has {key}={topology_config[key]}, above the compiled "
                f"ceiling {ceiling}. Raise {cdefine} in ebpf_template_arch.py "
                f"and ebpf_modular.py (and MAX_N_{key[2:].upper()} here), then "
                f"recompile. The datapath vectors are sized by that define.")

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
                    "col_off": col, "scale": feature_scale_of(f)})
        col += int(f["size"])
    return out


# ---------------------------------------------------------------------------
# topology_config loading  (Problema 1)
# ---------------------------------------------------------------------------

# Origins already announced, so a resident process says where its topology came
# from once instead of on every resolution. Deliberately not a cache of the
# config itself -- see load_topology_config.
_ANNOUNCED = set()


def _announce_once(msg: str) -> None:
    if msg not in _ANNOUNCED:
        _ANNOUNCED.add(msg)
        print(msg)


def reset_topology_announcements() -> None:
    """Forget what has been announced, so the next resolution prints again.

    For tests that walk several scenarios in one process and want each one
    reported.
    """
    _ANNOUNCED.clear()


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

    Resolution order, highest first:

      1. $IPA_TOPOLOGY_CONFIG           -- an explicit scenario file
      2. `path` (default /etc/ipa/topology_config.json)  -- per-deployment
      3. the model descriptor's `trained_on` block       -- see below
      4. ScenarioError

    A config states the dimensions its model's features need. `n_interfaces`
    and `n_nodes` are required; `n_queues` only when a queue_occupancy feature
    is present, and feature_size() raises if it is asked for and absent.

    Step 3 matters and is not a fallback in disguise. The feature widths are
    fixed by the TRAINING run: a model trained with a 6-slot link_state reads
    6 columns of fc1 whatever network it is later deployed on. So the
    descriptor is a legitimate source for them, and it is the source the
    checked-in model uses (model_meta.json's `trained_on`).

    What is gone is step 0: a `DEFAULT_TOPOLOGY_CONFIG` of {6, 52, 4} baked
    into this module, applied silently whenever nothing else was supplied.
    That made every caller that forgot a config quietly correct for Germany50
    and quietly wrong everywhere else.
    """
    env = os.environ.get("IPA_TOPOLOGY_CONFIG")
    if env:
        with open(env) as f:
            cfg = json.load(f)
        _announce_once(f"[topology_config] loaded from $IPA_TOPOLOGY_CONFIG={env}: {cfg}")
        return _validated_topology(cfg, f"$IPA_TOPOLOGY_CONFIG={env}")
    if os.path.exists(path):
        with open(path) as f:
            cfg = json.load(f)
        _announce_once(f"[topology_config] loaded from {path}: {cfg}")
        return _validated_topology(cfg, path)
    cfg = _topology_from_descriptor()
    if cfg is not None:
        return cfg
    raise ScenarioError(
        "no topology configuration. The engine has no built-in one on "
        "purpose -- feature widths belong to the network a model was trained "
        "on. Supply one of:\n"
        "  $IPA_TOPOLOGY_CONFIG=/path/to/topology_config.json\n"
        f"  {path}\n"
        "  a `trained_on` block in model_meta.json with "
        f"{list(TOPOLOGY_KEYS)}")


def _validated_topology(cfg: dict, origin: str) -> dict:
    missing = [k for k in TOPOLOGY_KEYS_REQUIRED if k not in cfg]
    if missing:
        raise ScenarioError(
            f"{origin}: topology config is missing {missing}. Each of "
            f"{list(TOPOLOGY_KEYS_REQUIRED)} must be stated -- a missing one "
            f"used to be filled from the Germany50 defaults.")
    out = {k: int(cfg[k]) for k in TOPOLOGY_KEYS if k in cfg}
    out["_origin"] = origin
    for k, v in out.items():
        if k != "_origin" and int(v) < 1:
            raise ScenarioError(f"{origin}: {k}={v} must be >= 1")
    return out


def _topology_from_descriptor():
    """Topology dimensions recorded in the model descriptor's `trained_on`."""
    meta_path = os.path.join(_SHARED_DIR, "model_meta.json")
    if not os.path.exists(meta_path):
        return None
    try:
        with open(meta_path) as f:
            meta = json.load(f)
    except Exception as e:
        _announce_once(f"[topology_config] {meta_path} unreadable ({e})")
        return None
    t = meta.get("trained_on") or {}
    if not all(k in t for k in TOPOLOGY_KEYS_REQUIRED):
        present = [k for k in TOPOLOGY_KEYS if k in t]
        if present:
            _announce_once(f"[topology_config] model_meta.json `trained_on` has only "
                  f"{present}; {list(TOPOLOGY_KEYS_REQUIRED)} are required")
        return None
    cfg = _validated_topology(t, f"{meta_path} `trained_on`")
    _announce_once(f"[topology_config] from the model descriptor's `trained_on` "
          f"({meta.get('trained_on', {}).get('topology', 'unnamed')}): {cfg}")
    return cfg


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
      load_topology_config()  -- env / deployment file / descriptor
      <- top-level n_interfaces / n_nodes / n_queues keys in meta
      <- meta["topology_config"] sub-dict

    The base used to be the module's Germany50 constants; it is now whatever
    the scenario resolution finds, so a meta dict that overrides nothing gets
    the scenario's numbers rather than someone else's network's.
    """
    cfg = dict(load_topology_config())
    for k in TOPOLOGY_KEYS:
        if k in meta:
            cfg[k] = int(meta[k])
    cfg.update({k: int(v) for k, v in meta.get("topology_config", {}).items()})
    return cfg


def feature_scale(feature_type: str) -> int:
    """Divisor applied to a scalar feature's contribution, so the datapath feeds
    the model the same magnitude the training pipeline did. 1 = no scaling.
    See DEFAULT_TTL_SCALE for why `ttl` needs one."""
    return int(FEATURE_CATALOG[feature_type].get("scale", 1))


def feature_scale_of(feat: dict) -> int:
    """La scala di QUESTA feature: quella che il modello dichiara se c'e',
    quella del catalogo altrimenti.

    `feature_scale(type)` risponde per TIPO, cioe' uguale per tutti i modelli.
    Ma la scala e' la normalizzazione con cui il modello e' stato ADDESTRATO:
    un modello allenato su `ttl/16` eseguito con `ttl/30` calcola un'altra
    cosa. Finche' l'unico modello in gioco era quello depositato, che usa 30,
    la differenza non si vedeva; i modelli sintetici la rendono visibile e
    misurabile (scenari `small` 16, `large` 64, `ones` 8).
    """
    s = feat.get("scale")
    return int(s) if s is not None else feature_scale(feat["type"])


def feature_size(feature_type: str, topology_config: dict) -> int:
    """Size (number of IV slots) of a feature type — from the topology
    config (per-network), not from the model."""
    entry = FEATURE_CATALOG[feature_type]
    if "dim" in entry:
        return int(entry["dim"])
    key = entry["dim_key"]
    if key not in topology_config:
        raise ScenarioError(
            f"feature {feature_type!r} needs topology dimension {key!r}, which "
            f"the scenario ({topology_config.get('_origin', 'unknown source')}) "
            f"does not declare. Add it there -- it used to be silently filled "
            f"from the Germany50 defaults.")
    return int(topology_config[key])


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

    # La scala per-feature entra nel descrittore risolto. `feature_scales` nel
    # model_meta.json la dichiara per tipo; senza, vale quella del catalogo --
    # quindi i descrittori gia' scritti non cambiano di una virgola.
    _scales = dict(meta.get("feature_scales") or {})
    features = [{"type": t, "size": feature_size(t, cfg),
                 "scale": int(_scales.get(t, feature_scale(t)))}
                for t in types]
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
        # Deployment nodes without torch run from the prebuilt
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


def default_checkpoint() -> str:
    """Path of the .pt this repo is configured for.

    $IPA_CHECKPOINT, then model_meta.json's `checkpoint` key, then the single
    .pt next to the descriptor. The filename used to be the literal
    'frr_germany50_5_model_4x2.pt', repeated in nine places -- a model name is
    data, and one scenario's data at that.
    """
    env = os.environ.get("IPA_CHECKPOINT")
    if env:
        return env
    try:
        with open(os.path.join(_SHARED_DIR, "model_meta.json")) as f:
            ck = json.load(f).get("checkpoint")
        if ck:
            return ck if os.path.isabs(ck) else os.path.join(_SHARED_DIR, ck)
    except Exception:
        pass
    import glob
    pts = sorted(glob.glob(os.path.join(_SHARED_DIR, "*.pt")))
    if len(pts) == 1:
        return pts[0]
    raise ScenarioError(
        f"cannot pick a checkpoint: {len(pts)} .pt files in {_SHARED_DIR}. "
        f"Set $IPA_CHECKPOINT or add a `checkpoint` key to model_meta.json.")
