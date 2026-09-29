"""
model_source.py -- one loader for every model a test or a bench can run.

A model reference is one of:

    checkpoint              the configured, trained checkpoint (the default)
    checkpoint:<file.pt>    another trained checkpoint; its model_meta.json
                            sits next to it and must carry `trained_on`
    synth:<preset>          a synthetic preset of ipa/synth (ipa_like, deep,
                            ...), generated into ipa/synth/scenarios/<preset>
                            the first time it is asked for
    <directory>             a generated synthetic model (model.json) or a
                            descriptor fixture (model_meta.json + weights.json)

and whatever it is, load_model() returns the same Model: int8 weights, the
quantisation scale, the resolved feature descriptor (type, size, scale per
feature), the hidden widths, the class semantics, and -- derived from those,
not declared a second time -- what the model needs from the network it runs
on (`requires`).

Compatibility with a scenario (a network, topologies/<name>/) is
`mismatches(model, topology)`: every feature's width must equal the network's
dimension for it, and the TTL feature's scale must equal the network's
initial TTL, because the model was trained on ttl / initial_ttl.
"""
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
SYNTH_ROOT = os.path.join(SHARED_DIR, "synth", "scenarios")

# Synthetic models name one feature differently from the catalog.
_SYNTH_NAMES = {"queue_occ": "queue_occupancy"}

DIM_NAMES = {"n_nodes": "nodi", "n_interfaces": "interfacce",
             "n_queues": "code", "initial_ttl": "TTL iniziale"}


class ModelError(Exception):
    """A reference that cannot be resolved into a runnable model."""


@dataclass
class Model:
    name: str
    source: str                   # checkpoint | synth | fixture
    path: str                     # the .pt, or the model's directory
    weights: List[int]            # int8, layer by layer: W then b
    scale: int                    # int8 quantisation scale
    features: List[dict]          # [{"type", "size", "scale"}], training order
    hidden: List[int]
    n_out: int
    semantics: object             # class_semantics.ClassSemantics
    reference: bool = False       # the configured checkpoint itself
    ref: str = "checkpoint"       # the reference it was loaded from

    @property
    def n_in(self) -> int:
        return sum(int(f["size"]) for f in self.features)

    @property
    def layer_dims(self):
        sizes = [self.n_in] + list(self.hidden) + [self.n_out]
        return [(sizes[i], sizes[i + 1]) for i in range(len(sizes) - 1)]

    @property
    def shape(self) -> str:
        return "-".join(str(s) for s in
                        [self.n_in] + list(self.hidden) + [self.n_out])

    @property
    def weight_count(self) -> int:
        return sum(a * b + b for a, b in self.layer_dims)

    def feature(self, ftype):
        for f in self.features:
            if f["type"] == ftype:
                return f
        return None

    @property
    def requires(self) -> dict:
        """What the network must provide: one entry per dimension a feature
        reads its width from, plus the initial TTL the ttl feature is scaled
        by. Raises ModelError if two features disagree (link_state 6 wide and
        ingress_iface 3 wide cannot both be n_interfaces)."""
        import model_meta as mm
        req = {}
        for f in self.features:
            cat = mm.FEATURE_CATALOG[f["type"]]
            if "dim_key" in cat:
                key, val = cat["dim_key"], int(f["size"])
            elif f["type"] == "ttl":
                key, val = "initial_ttl", int(f["scale"])
            else:
                continue
            if key in req and req[key] != val:
                raise ModelError(
                    f"{self.name}: le feature chiedono {key}={req[key]} e "
                    f"{key}={val} insieme")
            req[key] = val
        return req

    def describe(self) -> str:
        feats = ", ".join(f"{f['type']} {f['size']}"
                          + (f" /{f['scale']}" if f['type'] == 'ttl' else "")
                          for f in self.features)
        return (f"{self.shape}, {self.weight_count} pesi, scala {self.scale}, "
                f"{len(self.hidden)} strati nascosti, ingressi [{feats}], "
                f"DROP = classe {self.semantics.drop_class}")


# --------------------------------------------------------------------------
# compatibility with a network
# --------------------------------------------------------------------------
def mismatches(model: Model, topology: dict) -> List[str]:
    """Why `model` cannot run on `topology`; empty when it can."""
    try:
        req = model.requires
    except ModelError as e:
        return [str(e)]
    out = []
    for key, val in req.items():
        have = topology.get(key)
        if have is None:
            out.append(f"la rete non dichiara {DIM_NAMES[key]} "
                       f"(il modello ne vuole {val})")
        elif int(have) != int(val):
            out.append(f"{DIM_NAMES[key]}: il modello ne vuole {val}, "
                       f"la rete ne ha {have}")
    return out


# --------------------------------------------------------------------------
# scenarios: the networks under topologies/
# --------------------------------------------------------------------------
TOPOLOGY_ROOT = os.path.join(os.path.dirname(SHARED_DIR), "topologies")
TOPOLOGY_FILE = "topology_config.json"


def topology_path(name_or_path: str) -> str:
    """topologies/<name>/topology_config.json, or the file/dir given."""
    p = name_or_path
    if os.path.isdir(p):
        p = os.path.join(p, TOPOLOGY_FILE)
    elif not os.path.exists(p):
        p = os.path.join(TOPOLOGY_ROOT, name_or_path, TOPOLOGY_FILE)
    if not os.path.exists(p):
        raise ModelError(f"scenario {name_or_path!r} non trovato "
                         f"(cercato {p}); disponibili: "
                         f"{', '.join(list_topologies()) or 'nessuno'}")
    return p


def list_topologies() -> List[str]:
    if not os.path.isdir(TOPOLOGY_ROOT):
        return []
    return sorted(d for d in os.listdir(TOPOLOGY_ROOT)
                  if os.path.exists(os.path.join(TOPOLOGY_ROOT, d,
                                                 TOPOLOGY_FILE)))


def load_topology(name_or_path: str) -> dict:
    """A scenario's dimensions: n_interfaces, n_nodes, n_queues (if
    declared), initial_ttl (if declared), plus `topology` and `_path`.
    Raises ModelError if the network exceeds what the datapath is compiled
    for (model_meta.check_topology_fits)."""
    import model_meta as mm
    p = topology_path(name_or_path)
    with open(p) as f:
        raw = json.load(f)
    try:
        cfg = mm._validated_topology(raw, p)
        mm.check_topology_fits(cfg)
    except mm.ScenarioError as e:
        raise ModelError(str(e))
    cfg.pop("_origin", None)
    if "initial_ttl" in raw:
        cfg["initial_ttl"] = int(raw["initial_ttl"])
    cfg["topology"] = raw.get("topology",
                              os.path.basename(os.path.dirname(p)))
    cfg["_path"] = p
    return cfg


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------
def load_model(ref: Optional[str] = None, topology: Optional[dict] = None,
               quiet: bool = True) -> Model:
    """Resolve a reference (see the module docstring) into a Model.

    `topology` is needed only by descriptor fixtures, whose feature widths
    come from the network instead of being written in the model."""
    ref = (ref or "checkpoint").strip()
    if ref == "checkpoint":
        m = _load_checkpoint(None)
    elif ref.startswith("checkpoint:"):
        m = _load_checkpoint(ref.split(":", 1)[1])
    elif ref.startswith("synth:"):
        m = _load_synth_preset(ref.split(":", 1)[1], quiet=quiet)
    else:
        path = os.path.abspath(ref)
        if os.path.exists(os.path.join(path, "model.json")):
            m = _load_synth_dir(path)
        elif os.path.exists(os.path.join(path, "model_meta.json")):
            m = _load_fixture(path, topology)
        else:
            raise ModelError(
                f"riferimento {ref!r} non riconosciuto: usa checkpoint, "
                f"checkpoint:<file.pt>, synth:<preset> o una cartella con "
                f"model.json o model_meta.json")
    m.ref = ref
    return m


def _semantics_from_meta(meta: dict, n_out: int, who: str):
    from class_semantics import ClassSemantics
    if not meta.get("class_semantics"):
        raise ModelError(f"{who}: il descrittore non dichiara class_semantics")
    sem = ClassSemantics.from_json(meta)
    if sem.n_out != n_out:
        raise ModelError(f"{who}: class_semantics per n_out={sem.n_out}, "
                         f"il modello ne ha {n_out}")
    return sem


def semantics_with_drop(n_out: int, drop_class: int):
    """FORWARD on every class but `drop_class`, ports in class order: the
    layout a synthetic model declares with its drop_class."""
    from class_semantics import ClassSemantics, ClassSpec
    classes, port = {}, 0
    for c in range(n_out):
        if c == drop_class:
            classes[c] = ClassSpec("DROP")
        else:
            classes[c] = ClassSpec("FORWARD", port)
            port += 1
    return ClassSemantics(n_out=n_out, classes=classes, drop_class=drop_class)


def _load_checkpoint(pt_path):
    import model_meta as mm
    default = mm.default_checkpoint()
    pt = os.path.abspath(pt_path) if pt_path else default
    is_ref = os.path.abspath(pt) == os.path.abspath(default)
    if not os.path.exists(pt) and not is_ref:
        raise ModelError(f"checkpoint {pt} non trovato")
    meta = mm.load_model_meta(pt)
    t = meta.get("trained_on") or {}
    if not all(k in t for k in mm.TOPOLOGY_KEYS_REQUIRED):
        raise ModelError(f"{pt}: il model_meta.json accanto non ha `trained_on` "
                         f"con {list(mm.TOPOLOGY_KEYS_REQUIRED)}")
    topo = {k: int(t[k]) for k in mm.TOPOLOGY_KEYS if k in t}
    shape = mm.derive_shape(meta, topology_config=topo)
    ttl_scale = int(meta.get("inputs", {}).get("ttl", {}).get(
        "normalize_by", t.get("initial_ttl", mm.DEFAULT_TTL_SCALE)))
    feats = [dict(f) for f in shape["features"]]
    for f in feats:
        if f["type"] == "ttl":
            f["scale"] = ttl_scale
    hidden = [int(h) for h in shape["hidden_dims"]]
    n_out = int(shape["n_out"])
    if is_ref:
        # The configured checkpoint: the int8 weights and scale the whole
        # repository measures (weights.json / weights_float.json), whether or
        # not torch is importable -- the same pair verify_prog_run loads.
        from extract_weights import extract_weights_int8
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            weights = extract_weights_int8(pt)
        with open(os.path.join(SHARED_DIR, "weights_float.json")) as f:
            scale = int(json.load(f).get("scale_factor", 128))
        name = t.get("topology", "checkpoint")
    else:
        weights, scale = _quantise_checkpoint(pt, topo, hidden, n_out)
        name = os.path.splitext(os.path.basename(pt))[0]
    m = Model(name=name, source="checkpoint", path=pt, weights=list(weights),
              scale=int(scale), features=feats, hidden=hidden, n_out=n_out,
              semantics=_semantics_from_meta(meta, n_out, os.path.basename(pt)),
              reference=is_ref)
    _check_count(m)
    return m


def _quantise_checkpoint(pt, topo, hidden, n_out):
    """int8 weights of a checkpoint other than the configured one. Needs
    torch: weights.json holds the configured model only, and falling back
    to it would measure the wrong network under the right name."""
    if len(hidden) != 2 or hidden[0] != hidden[1]:
        raise ModelError(f"{pt}: FastRerouteMLP ha due strati nascosti uguali, "
                         f"il descrittore dice {hidden}")
    try:
        import torch
        from FRR_model import FastRerouteMLP
    except ImportError:
        raise ModelError(
            f"{pt}: serve torch per leggere un checkpoint diverso da quello "
            f"configurato, e questo interprete non lo vede. Sotto sudo: "
            f"PYTHONPATH=$(python3 -m site --user-site)")
    m = FastRerouteMLP(n_interfaces=topo["n_interfaces"],
                       n_nodes=topo["n_nodes"], hidden_dim=hidden[0],
                       n_classes=n_out)
    m.load_state_dict(torch.load(pt, map_location="cpu"))
    floats = [w for p in m.parameters() for w in p.data.view(-1).tolist()]
    scale = int(127 / max(abs(w) for w in floats))
    return [max(-128, min(127, int(round(w * scale)))) for w in floats], scale


def _load_synth_preset(name, quiet=True):
    from synth.generate import PRESETS
    if name not in PRESETS:
        raise ModelError(f"preset sintetico {name!r} sconosciuto: "
                         f"{', '.join(PRESETS)}")
    d = os.path.join(SYNTH_ROOT, name)
    if not os.path.exists(os.path.join(d, "model.json")):
        import contextlib
        import io
        from synth.generate import generate_scenario, preset
        with (contextlib.redirect_stdout(io.StringIO()) if quiet
              else contextlib.nullcontext()):
            generate_scenario(preset(name), d)
    return _load_synth_dir(d)


def _load_synth_dir(d):
    with open(os.path.join(d, "model.json")) as f:
        mj = json.load(f)
    with open(os.path.join(d, "weights.json")) as f:
        wi = json.load(f)
    wi = wi["weights"] if isinstance(wi, dict) else wi
    feats = [{"type": _SYNTH_NAMES.get(f["name"], f["name"]),
              "size": int(f["size"]),
              "scale": int(f.get("scale", 1) or 1)}
             for f in mj["descriptor"]]
    n_out = int(mj["arch"]["n_out"])
    drop = mj.get("drop_class")
    drop = n_out - 1 if drop is None else int(drop)
    m = Model(name=mj.get("name", os.path.basename(d)), source="synth",
              path=d, weights=list(wi),
              scale=int(mj["quant"]["scale_factor"]), features=feats,
              hidden=[int(h) for h in mj["arch"]["hidden"]], n_out=n_out,
              semantics=semantics_with_drop(n_out, drop))
    _check_count(m)
    return m


def _load_fixture(d, topology):
    """A descriptor fixture (ipa/test/fixtures/...): features named in
    model_meta.json, widths from the network. Without a network the widths
    are unknown, and a guess would be the Germany50 one."""
    import model_meta as mm
    with open(os.path.join(d, "model_meta.json")) as f:
        meta = json.load(f)
    with open(os.path.join(d, "weights.json")) as f:
        wi = json.load(f)
    wi = wi["weights"] if isinstance(wi, dict) else wi
    if topology is None:
        raise ModelError(f"{d}: le larghezze degli ingressi vengono dalla "
                         f"rete; serve lo scenario")
    topo = {k: int(topology[k]) for k in mm.TOPOLOGY_KEYS if k in topology}
    try:
        shape = mm.derive_shape(meta, topology_config=topo)
    except Exception as e:
        raise ModelError(f"{d}: {e}")
    n_out = int(shape["n_out"])
    sem = (_semantics_from_meta(meta, n_out, d) if meta.get("class_semantics")
           else semantics_with_drop(n_out, n_out - 1))
    m = Model(name=os.path.basename(d), source="fixture", path=d,
              weights=list(wi), scale=int(meta.get("scale_factor", 128)),
              features=[dict(f) for f in shape["features"]],
              hidden=[int(h) for h in shape["hidden_dims"]], n_out=n_out,
              semantics=sem)
    _check_count(m)
    return m


def _check_count(m: Model):
    if len(m.weights) != m.weight_count:
        raise ModelError(
            f"{m.name}: {len(m.weights)} pesi, la forma {m.shape} ne vuole "
            f"{m.weight_count}")
