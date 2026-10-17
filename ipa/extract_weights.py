"""extract_weights.py -- int8 weights of the trained checkpoint.

Run directly it writes weights.json and weights_float.json; imported it gives
extract_weights_int8(). Without torch it reads the existing weights.json.
"""
import json
import os

HIDDEN_DIM   = 4


def _topology():
    import model_meta as _mm
    return _mm.load_topology_config()

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_from_json(json_path: str) -> list:
    """Load precomputed int8 weights from weights.json."""
    with open(json_path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "weights" in data:
        floats  = data["weights"]
        scale   = data.get("scale_factor", 1)
        return [max(-128, min(127, int(round(wf * scale)))) for wf in floats]
    raise ValueError(f"Unrecognized format in {json_path}")


def extract_weights_int8(
    model_path: str = None,
    n_interfaces: int = None,
    n_nodes: int = None,
    hidden_dim: int = None,
) -> list:
    """Return a flat list of int8 weights for the FRR model."""
    _t = _topology() if (n_interfaces is None or n_nodes is None) else {}
    n_interfaces = _t["n_interfaces"] if n_interfaces is None else n_interfaces
    n_nodes      = _t["n_nodes"]      if n_nodes      is None else n_nodes
    hidden_dim   = HIDDEN_DIM if hidden_dim is None else hidden_dim

    if model_path is None:
        import model_meta as _mm
        model_path = _mm.default_checkpoint()
    if not os.path.isabs(model_path):
        candidate = os.path.join(SHARED_DIR, model_path)
        if os.path.exists(candidate):
            model_path = candidate

    try:
        import torch
        from FRR_model import FastRerouteMLP

        m = FastRerouteMLP(
            n_interfaces=n_interfaces,
            n_nodes=n_nodes,
            hidden_dim=hidden_dim
        )
        m.load_state_dict(torch.load(model_path, map_location="cpu"))
        floats  = [w for p in m.parameters() for w in p.data.view(-1).tolist()]
        max_abs = max(abs(w) for w in floats)
        scale   = int(127 / max_abs)
        return [max(-128, min(127, int(round(wf * scale)))) for wf in floats]

    except ImportError:
        pass

    json_path = os.path.join(SHARED_DIR, "weights.json")
    if os.path.exists(json_path):
        import warnings
        warnings.warn(
            "torch not available — loading precomputed weights from weights.json",
            RuntimeWarning,
            stacklevel=2,
        )
        w = _load_from_json(json_path)
        import model_meta as _mm
        n_out = _mm.derive_shape(
            _mm.load_model_meta(json_path),
            topology_config={"n_interfaces": n_interfaces,
                             "n_nodes": n_nodes,
                             "n_queues": 4})["n_out"]
        n_in = n_interfaces + n_interfaces + 1 + n_nodes
        expected = (n_in * hidden_dim + hidden_dim
                    + hidden_dim * hidden_dim + hidden_dim
                    + hidden_dim * n_out + n_out)
        if len(w) != expected:
            raise ValueError(
                f"{json_path} holds {len(w)} weights but the requested shape "
                f"(n_interfaces={n_interfaces}, n_nodes={n_nodes}, "
                f"hidden_dim={hidden_dim}) needs {expected}. weights.json is "
                f"single-shape; regenerate it on a box with torch for this "
                f"topology, or pass the matching shape.")
        return w

    raise ImportError(
        "torch is not installed and weights.json not found in {}. "
        "Either install torch or generate weights.json first with: "
        "python3 extract_weights.py".format(SHARED_DIR)
    )


# --- __main__: produce weights.json and weights_float.json ---
if __name__ == "__main__":
    try:
        import torch
        from FRR_model import FastRerouteMLP
    except ImportError as e:
        print(f"ERROR: {e}")
        print("Run this script on a host where torch is installed.")
        raise SystemExit(1)

    _env = os.environ.get("IPA_CHECKPOINT")
    if _env:
        MODEL_PATH = _env
    else:
        import glob as _glob
        try:
            import model_meta as _mm
            _ck = _mm.load_model_meta(os.path.join(SHARED_DIR, "weights.json")).get("checkpoint")
        except Exception:
            _ck = None
        if _ck:
            MODEL_PATH = _ck if os.path.isabs(_ck) else os.path.join(SHARED_DIR, _ck)
        else:
            _pts = sorted(_glob.glob(os.path.join(SHARED_DIR, "*.pt")))
            if len(_pts) != 1:
                raise SystemExit(
                    f"cannot pick a checkpoint: {len(_pts)} .pt files in "
                    f"{SHARED_DIR}. Set $IPA_CHECKPOINT or add a `checkpoint` "
                    f"key to model_meta.json.")
            MODEL_PATH = _pts[0]
    _TOPO = _topology()
    print(f"Extracting weights from {MODEL_PATH} ...")
    print(f"  topology: n_interfaces={_TOPO['n_interfaces']} n_nodes={_TOPO['n_nodes']}")

    model = FastRerouteMLP(
        n_interfaces=_TOPO["n_interfaces"],
        n_nodes=_TOPO["n_nodes"],
        hidden_dim=HIDDEN_DIM
    )
    model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))

    all_floats   = [w for p in model.parameters() for w in p.data.view(-1).tolist()]
    max_abs      = max(abs(w) for w in all_floats)
    SCALE_FACTOR = int(127 / max_abs)

    print(f"Max |weight| = {max_abs:.6f}")
    print(f"SCALE_FACTOR = {SCALE_FACTOR}")

    integer_weights = []
    for wf in all_floats:
        wi = int(round(wf * SCALE_FACTOR))
        integer_weights.append(max(-128, min(127, wi)))

    clamped = sum(
        1 for w, wf in zip(integer_weights, all_floats)
        if w != int(round(wf * SCALE_FACTOR))
    )
    if clamped:
        print(f"[WARN] {clamped} weights clamped")
    else:
        print("No weights clamped. int8 range respected.")

    with open(os.path.join(SHARED_DIR, "weights.json"), "w") as f:
        json.dump(integer_weights, f)
    with open(os.path.join(SHARED_DIR, "weights_float.json"), "w") as f:
        json.dump({"scale_factor": SCALE_FACTOR, "weights": all_floats}, f)

    _meta_path = os.path.join(SHARED_DIR, "model_meta.json")
    model_meta = {}
    if os.path.exists(_meta_path):
        with open(_meta_path) as f:
            model_meta = json.load(f)
    model_meta.update({
        "n_interfaces": _TOPO["n_interfaces"],
        "n_nodes": _TOPO["n_nodes"],
        "hidden_dims": [HIDDEN_DIM, HIDDEN_DIM],
        "n_out": int(model.out.out_features),
    })
    if not model_meta.get("class_semantics"):
        print("[extract_weights] WARNING: model_meta.json has no "
              "class_semantics. The datapath cannot know which class means "
              "DROP and will fall back to an ANNOUNCED guess "
              f"(DROP = {int(model.out.out_features) - 1}). Declare it with "
              "label_mapping.write_descriptor() using the mapping this model "
              "was trained with.")
    with open(_meta_path, "w") as f:
        json.dump(model_meta, f, indent=2)

    print(f"Saved {len(integer_weights)} int8 weights -> weights.json")
    print(f"int8 range: min={min(integer_weights)}  max={max(integer_weights)}")
    print(f"Saved feature metadata -> model_meta.json: {model_meta}")
