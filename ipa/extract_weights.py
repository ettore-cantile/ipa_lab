"""
extract_weights.py  (design-space-docs branch)
==============================================
Extracts int8-quantized weights from the FRR model checkpoint.

When run directly:  produces weights.json and weights_float.json
When imported:      provides extract_weights_int8(), used by ebpf_program.py
                    (Pipeline 1 codegen), poc_aot/gen_full_c.py (AOT literal
                    generator) and test/verify_prog_run.py.

Architecture fixed to the germany50/5 checkpoint:
  n_interfaces=6, n_nodes=52, hidden_dim=4
  -> 319 total int8 weights  (matches N_WEIGHTS in common.py)

Quantization: PTQ with SCALE_FACTOR = floor(127 / max|w|)

Fallback (no torch):
  If torch is not installed (e.g. inside a stripped container image), and a
  precomputed weights.json exists in the same directory, extract_weights_int8()
  returns its contents directly without loading the .pt file.
"""
import json
import os

# Architecture of the checkpoint being extracted.
#
# N_INTERFACES and N_NODES were literals 6 and 52 here -- the Germany50 lab's
# dimensions, restated in a third place. They are scenario properties, so they
# are read from the scenario; only HIDDEN_DIM stays, because the hidden width
# is a property of the trained model and nothing else knows it.
HIDDEN_DIM   = 4


def _topology():
    import model_meta as _mm
    return _mm.load_topology_config()
# fc1(65*4+4=264) + fc2(4*4+4=20) + out(4*7+7=35) = 319 weights

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_from_json(json_path: str) -> list:
    """Load precomputed int8 weights from weights.json."""
    with open(json_path) as f:
        data = json.load(f)
    # weights.json is a plain list; weights_float.json has {scale_factor, weights}
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "weights" in data:
        # weights_float.json — re-quantize on the fly
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
    """
    Return a flat list of int8 weights for the FRR model.

    n_interfaces/n_nodes/hidden_dim override the module defaults
    (the scenario's n_interfaces/n_nodes + HIDDEN_DIM) -- pass a resolved shape
    (see shared/model_meta.py derive_shape()) to extract weights for a
    topology other than the one checked-in 6/52/4 checkpoint. None means
    "use the module default", so existing callers are unaffected.

    Priority:
      1. If torch is available: load from .pt checkpoint (authoritative).
      2. Else if weights.json exists next to this file: use it (container mode).
      3. Else raise ImportError with a helpful message.

    Returns:
        list of int in [-128, 127], length depends on shape (319 for the
        default 65-4-4-7 topology)
    """
    _t = _topology() if (n_interfaces is None or n_nodes is None) else {}
    n_interfaces = _t["n_interfaces"] if n_interfaces is None else n_interfaces
    n_nodes      = _t["n_nodes"]      if n_nodes      is None else n_nodes
    hidden_dim   = HIDDEN_DIM if hidden_dim is None else hidden_dim

    # model_path=None means "the configured checkpoint" (was the literal
    # frr_germany50_5_model_4x2.pt as a default argument).
    if model_path is None:
        import model_meta as _mm
        model_path = _mm.default_checkpoint()
    # Resolve model path relative to this file if not absolute
    if not os.path.isabs(model_path):
        candidate = os.path.join(SHARED_DIR, model_path)
        if os.path.exists(candidate):
            model_path = candidate

    # --- Path 1: torch available ---
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
        pass  # torch not installed — fall through to JSON fallback

    # --- Path 2: JSON fallback (no torch) ---
    json_path = os.path.join(SHARED_DIR, "weights.json")
    if os.path.exists(json_path):
        import warnings
        warnings.warn(
            "torch not available — loading precomputed weights from weights.json",
            RuntimeWarning,
            stacklevel=2,
        )
        w = _load_from_json(json_path)
        # weights.json holds ONE shape (the checked-in 65-4-4-7 checkpoint). The
        # torch path above honours n_interfaces/n_nodes/hidden_dim; this fallback
        # cannot -- so a caller asking for a different topology would silently get
        # the default-shape weights and generate a program whose literals do not
        # match its declared shape. Fail loudly instead.
        # n_out from the descriptor. It used to read `n_interfaces + 1` here
        # too, so a descriptor declaring a different output width would have
        # been checked against a width nobody declared.
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


# ---------------------------------------------------------------------------
# __main__: produce weights.json and weights_float.json
# Requires torch — intended to run on a host with torch, not on a forwarding node.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        import torch
        from FRR_model import FastRerouteMLP
    except ImportError as e:
        print(f"ERROR: {e}")
        print("Run this script on a host where torch is installed.")
        raise SystemExit(1)

    # Checkpoint path: $IPA_CHECKPOINT, then the descriptor's `checkpoint` key,
    # then the single .pt next to this file. Was the literal filename.
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

    # model_meta.json: the descriptor codegen and the datapath both read.
    #
    # This used to write only {n_interfaces, n_nodes, hidden_dims} and let
    # derive_shape compute n_out = n_interfaces + 1, leaving class MEANINGS
    # recorded nowhere -- which is how the datapath came to drop class 6 while
    # the model was trained to drop class 5. n_out and class_semantics are now
    # written explicitly, and an existing descriptor's semantics are PRESERVED
    # rather than overwritten by a rebuild of the weights.
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
