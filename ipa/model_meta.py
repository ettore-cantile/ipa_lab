"""model_meta.py -- the feature descriptor of a model (which inputs, in which
order, with which encoding) and the feature sizes of a network topology.
"""

import json
import os

_SHARED_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Per-topology / per-network defaults. ---
TOPOLOGY_KEYS = ("n_interfaces", "n_nodes", "n_queues")
TOPOLOGY_KEYS_REQUIRED = ("n_interfaces", "n_nodes")


class ScenarioError(Exception):
    """No usable topology configuration, or one that contradicts the model."""


DEFAULT_META = {
    "hidden_dims": [4, 4],
    "n_out": 7,
}

MAX_N_IN  = 128
MAX_N_OUT = 32
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

# --- Feature catalog: the feature *types* the switch knows how to build locally. ---
DEFAULT_TTL_SCALE = 30

FEATURE_CATALOG = {
    "ttl":             {"kind": "scalar",           "dim": 1,
                        "scale": DEFAULT_TTL_SCALE},
    "link_state":      {"kind": "dense_vector_map", "map": "link_state", "dim_key": "n_interfaces"},
    "queue_occupancy": {"kind": "dense_vector_map", "map": "queue_state", "dim_key": "n_queues"},
    "ingress_iface":   {"kind": "onehot",           "dim_key": "n_interfaces"},
    "node":            {"kind": "onehot",           "dim_key": "n_nodes"},
}

FEATURE_CODE = {
    "link_state":      0x01,
    "ingress_iface":   0x02,
    "ttl":             0x03,
    "node":            0x04,
    "queue_occupancy": 0x05,
}

_DEFAULT_FEATURE_TYPES = ["link_state", "ingress_iface", "ttl", "node"]


def resolve_descriptor(features: list) -> list:
    """Turn a resolved descriptor (list of {"type","size"}) into the flat
    layout the model_desc registry needs."""
    out = []
    col = 0
    for f in features:
        out.append({"code": FEATURE_CODE[f["type"]], "size": int(f["size"]),
                    "col_off": col, "scale": feature_scale_of(f)})
        col += int(f["size"])
    return out


# --- topology_config loading ---

_ANNOUNCED = set()


def _announce_once(msg: str) -> None:
    if msg not in _ANNOUNCED:
        _ANNOUNCED.add(msg)
        print(msg)


def reset_topology_announcements() -> None:
    """Forget what has been announced, so the next resolution prints again."""
    _ANNOUNCED.clear()


def load_topology_config(path: str = "/etc/ipa/topology_config.json") -> dict:
    """Load the per-network topology configuration from *path*."""
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
            f"{list(TOPOLOGY_KEYS_REQUIRED)} must be stated: no default is "
            f"assumed.")
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


# --- model_meta loading ---

def _meta_path_for(model_path: str) -> str:
    """model_meta.json lives next to the model's weights/.pt file."""
    return os.path.join(os.path.dirname(os.path.abspath(model_path)), "model_meta.json")


def load_model_meta(model_path: str) -> dict:
    """Load model_meta.json next to `model_path`."""
    meta = dict(DEFAULT_META)
    path = _meta_path_for(model_path)
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        meta.update(data)
    return meta


def topology_config_for(meta: dict) -> dict:
    """[LEGACY] Resolve per-topology dimensions from a meta dict."""
    cfg = dict(load_topology_config())
    for k in TOPOLOGY_KEYS:
        if k in meta:
            cfg[k] = int(meta[k])
    cfg.update({k: int(v) for k, v in meta.get("topology_config", {}).items()})
    return cfg


def feature_scale(feature_type: str) -> int:
    """Divisor applied to a scalar feature's contribution, so the datapath
    feeds the model the same magnitude the training pipeline did. 1 = no
    scaling."""
    return int(FEATURE_CATALOG[feature_type].get("scale", 1))


def feature_scale_of(feat: dict) -> int:
    """The scale of THIS feature."""
    s = feat.get("scale")
    return int(s) if s is not None else feature_scale(feat["type"])


def feature_size(feature_type: str, topology_config: dict) -> int:
    """Size (number of IV slots) of a feature type — from the topology config
    (per-network), not from the model."""
    entry = FEATURE_CATALOG[feature_type]
    if "dim" in entry:
        return int(entry["dim"])
    key = entry["dim_key"]
    if key not in topology_config:
        raise ScenarioError(
            f"feature {feature_type!r} needs topology dimension {key!r}, which "
            f"the scenario ({topology_config.get('_origin', 'unknown source')}) "
            f"does not declare. Add it there: no default is "
            f"assumed.")
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
    """Resolve a model_meta dict into a concrete shape."""
    hidden_dims = meta.get("hidden_dims", [4, 4])

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
        if "n_out" in meta:
            n_out = int(meta["n_out"])
        else:
            n_out = cfg["n_interfaces"] + 1
            print(f"[model_meta] NOTE: descriptor declares no n_out; ASSUMING "
                  f"n_interfaces + 1 = {n_out}. That formula says nothing about "
                  f"what the classes mean -- add \"n_out\" and "
                  f"\"class_semantics\" to model_meta.json.")

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


# --- checkpoint consistency check ---

def verify_shape_vs_checkpoint(shape: dict, model_path: str) -> None:
    """Verify that the N_IN computed from topology_config + feature types
    matches the actual first-layer input dimension of the PyTorch
    checkpoint."""
    try:
        import torch
    except ImportError:
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


# --- Helpers ---

def feature_maps(features: list) -> dict:
    """Return {feature_type: map_name} for the map-backed features of a
    resolved descriptor."""
    out = {}
    for f in features:
        entry = FEATURE_CATALOG[f["type"]]
        if entry["kind"] == "dense_vector_map":
            out[f["type"]] = entry["map"]
    return out


# --- Class semantics (see class_semantics.py) ---

def load_class_semantics(model_path: str, n_out: int = None):
    """Class semantics for the model whose artefacts sit next to `model_path`."""
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
    """Semantics for an n_out-wide model."""
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
    """Path of the .pt this repo is configured for."""
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
