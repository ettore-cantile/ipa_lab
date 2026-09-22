"""
spec.py -- feature semantics and model descriptors for synthetic scenarios.

The point of this package is to make the three eBPF pipelines testable WITHOUT
the professor's checkpoint. Everything here is generated from a declared seed,
so a scenario is reproducible from its descriptor alone.

Feature semantics, not uniform noise
------------------------------------
A feature is not "a slot that holds a number". It has a kind, a value domain, a
width, an encoding and a position in the flat input vector, and a generator that
respects all of them. Sampling every slot from one uniform distribution would
produce input vectors the datapath can never see -- several one-hot slots hot at
once, a TTL of 200 in a model trained on 30 -- and a pipeline that agrees with a
reference on impossible inputs has not been tested on the real ones.

Four kinds are supported:

  real     a value in [lo, hi] that the MODEL was trained on as a float, but
           which the DATAPATH carries as an integer divided by `scale`. This is
           exactly the TTL case: trained on ttl/30 in (0,1], transported as the
           raw hop count with the product divided by 30. `scale` is therefore
           part of the feature's semantics, not an implementation detail.
  integer  a value in [lo, hi] used as-is, scale 1.
  binary   a width-n vector of 0/1, independently sampled, with an optional
           minimum number of ones (link_state: a node with every link down is
           not a scenario worth generating).
  onehot   a width-n vector with exactly one 1. The datapath reads the active
           index and selects a single weight, so generating two hot slots would
           exercise a path that cannot occur.

Layout
------
Features occupy contiguous column ranges in declaration order, which is the
order the model was trained on. `col_off` is the running sum of widths -- the
same convention model_meta.resolve_descriptor uses, so a descriptor produced
here drops straight into the P2/P3 control planes.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Sequence


KINDS = ("real", "integer", "binary", "onehot")


@dataclass
class FeatureSpec:
    """One feature: what it means, how wide it is, how it is sampled."""

    name: str
    kind: str
    size: int = 1
    lo: float = 0.0            # real/integer: inclusive lower bound
    hi: float = 1.0            # real/integer: inclusive upper bound
    scale: int = 1             # real: divisor the datapath applies to the product
    min_ones: int = 0          # binary: minimum number of 1s per sample
    code: int = 0              # on-wire feature code (model_meta.FEATURE_CODE)

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f"{self.name}: unknown kind {self.kind!r}; known: {KINDS}")
        if self.size < 1:
            raise ValueError(f"{self.name}: size must be >= 1, got {self.size}")
        if self.kind in ("real", "integer"):
            if self.size != 1:
                raise ValueError(f"{self.name}: {self.kind} features are scalar (size 1)")
            if self.hi < self.lo:
                raise ValueError(f"{self.name}: hi < lo")
        if self.kind == "integer" and self.scale != 1:
            raise ValueError(f"{self.name}: an integer feature must not be scaled; "
                             f"declare it as 'real' if the model saw it divided")
        if self.kind == "binary" and not (0 <= self.min_ones <= self.size):
            raise ValueError(f"{self.name}: min_ones outside [0, size]")
        if self.kind == "onehot" and self.size < 2:
            raise ValueError(f"{self.name}: a one-hot of width 1 carries no information")
        if self.scale < 1:
            raise ValueError(f"{self.name}: scale must be >= 1")

    # -- what the datapath sees, per column ---------------------------------
    def column_scale(self) -> List[int]:
        """Divisor applied to each of this feature's columns. Only `real`
        features carry one; see the module docstring."""
        return [self.scale] * self.size

    def describe(self) -> str:
        if self.kind == "real":
            return (f"real in [{self.lo:g}, {self.hi:g}] transported as integer "
                    f"with product/{self.scale}")
        if self.kind == "integer":
            return f"integer in [{int(self.lo)}, {int(self.hi)}]"
        if self.kind == "binary":
            return f"binary vector, width {self.size}, at least {self.min_ones} set"
        return f"one-hot, width {self.size}, exactly one set"


@dataclass
class FeatureSet:
    """Ordered feature list = the model's input layout."""

    features: List[FeatureSpec] = field(default_factory=list)

    def __post_init__(self):
        seen = set()
        for f in self.features:
            if f.name in seen:
                raise ValueError(f"duplicate feature name {f.name!r}")
            seen.add(f.name)
        if not self.features:
            raise ValueError("a FeatureSet needs at least one feature")

    @property
    def n_in(self) -> int:
        return sum(f.size for f in self.features)

    def offsets(self) -> List[int]:
        """Starting column of each feature (running sum of widths)."""
        out, col = [], 0
        for f in self.features:
            out.append(col)
            col += f.size
        return out

    def column_scales(self) -> List[int]:
        """Per-column divisors for the whole input vector. Index-aligned with a
        generated vector, so a reference implementation can apply them without
        knowing anything about features."""
        out = []
        for f in self.features:
            out += f.column_scale()
        return out

    def descriptor(self) -> List[dict]:
        """Flat (code, size, col_off) form, the shape the P2/P3 registries want.
        Mirrors model_meta.resolve_descriptor so the two are interchangeable."""
        return [{"code": f.code, "size": f.size, "col_off": off, "name": f.name,
                 "kind": f.kind, "scale": f.scale}
                for f, off in zip(self.features, self.offsets())]

    def to_json(self) -> List[dict]:
        return [dict(name=f.name, kind=f.kind, size=f.size, lo=f.lo, hi=f.hi,
                     scale=f.scale, min_ones=f.min_ones, code=f.code)
                for f in self.features]

    @staticmethod
    def from_json(rows: Sequence[dict]) -> "FeatureSet":
        return FeatureSet([FeatureSpec(**r) for r in rows])

    def summary(self) -> str:
        lines = [f"  n_in = {self.n_in}"]
        for f, off in zip(self.features, self.offsets()):
            span = f"{off}" if f.size == 1 else f"{off}..{off + f.size - 1}"
            lines.append(f"  [{span:>7}] {f.name:<16} {f.describe()}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# The IPA feature set, rebuilt from the declared semantics rather than copied.
# Kept here so a synthetic scenario can be compared against the real layout
# without importing anything that depends on the checkpoint.
# ---------------------------------------------------------------------------
def ipa_feature_set(n_interfaces: int = 6, n_nodes: int = 52,
                    initial_ttl: int = 30) -> FeatureSet:
    """The [link_state, ingress_iface, ttl, node] layout the checked-in model
    was trained on, expressed in this package's vocabulary.

    link_state is `binary` with min_ones=1: a node with every egress down has
    no decision to make, and the trained data never contains that case.
    ttl is `real`, not `integer` -- the model saw ttl/initial_ttl in (0,1].
    """
    return FeatureSet([
        FeatureSpec("link_state", "binary", size=n_interfaces, min_ones=1, code=0x01),
        FeatureSpec("ingress_iface", "onehot", size=n_interfaces, code=0x02),
        FeatureSpec("ttl", "real", lo=1, hi=initial_ttl, scale=initial_ttl, code=0x03),
        FeatureSpec("node", "onehot", size=n_nodes, code=0x04),
    ])


@dataclass
class ModelSpec:
    """A synthetic model: shape, activation, quantisation scheme, seed."""

    name: str
    features: FeatureSet
    n_out: int
    hidden: List[int] = field(default_factory=list)
    activation: str = "relu"
    quant: str = "int8"            # "int8" (symmetric, no zero point) or "float"
    seed: int = 0
    weight_init: str = "uniform"   # "uniform" | "normal" | "sparse" | "ones"
    # Index of the DROP class. None means "let the generator pick the last
    # class", which it then ANNOUNCES -- a generated model is free to choose its
    # own layout, but the choice has to be visible, because "DROP is the last
    # class" silently assumed everywhere is what this work removed.
    drop_class: Optional[int] = None
    max_abs: float = 5.0           # target max|w|; see the note below

    # max_abs exists because the int8 scale is derived from it:
    # scale = int(127 / max|w|), and the scale is the quantisation step.
    # Textbook initialisation (1/sqrt(fan_in)) gives max|w| ~ 0.5 on a 4-wide
    # layer, hence scale ~254: a step ten times finer than the supplied
    # checkpoint's (max|w| = 5.1, scale = 24). Measured on ipa_like, 1000
    # inputs: float/int8 argmax agreement 100.0% at max_abs 0.5, 98.6% at 5.0.
    # The default matches the checkpoint's magnitude, so the pipelines are
    # tested with the quantisation error the real model has; set it
    # explicitly to study the quantisation itself.
    #
    # This comment used to say the opposite -- that a large scale wrecks the
    # model, below 1% agreement. That was the old synth reference, which left
    # the bias of layer l unscaled, a scheme no pipeline runs (see
    # synth/reference.py). Under the datapath's scheme a larger scale only
    # makes the step finer.

    ACTIVATIONS = ("relu",)        # the datapath implements ReLU only
    QUANT = ("int8", "float")
    INITS = ("uniform", "normal", "sparse", "ones")

    def __post_init__(self):
        if self.activation not in self.ACTIVATIONS:
            raise ValueError(
                f"activation {self.activation!r} not supported by the datapath; "
                f"the eBPF programs implement {self.ACTIVATIONS} only -- adding "
                f"another one means adding it to all three pipelines")
        if self.quant not in self.QUANT:
            raise ValueError(f"quant must be one of {self.QUANT}")
        if self.weight_init not in self.INITS:
            raise ValueError(f"weight_init must be one of {self.INITS}")
        if self.n_out < 2:
            raise ValueError("n_out must be >= 2 (at least one egress + DROP)")
        if any(h < 1 for h in self.hidden):
            raise ValueError("hidden widths must be >= 1")
        if self.drop_class is None:
            self.drop_class = self.n_out - 1
            print(f"[synth] ModelSpec: no drop_class given; this synthetic "
                  f"model DECLARES class {self.drop_class} as DROP (the last "
                  f"of {self.n_out}). Pass drop_class= to place it elsewhere -- "
                  f"a non-last DROP is worth testing, since the supplied "
                  f"checkpoint has one.")
        if not (0 <= self.drop_class < self.n_out):
            raise ValueError(f"drop_class {self.drop_class} outside [0, {self.n_out})")
        if self.max_abs <= 0:
            raise ValueError("max_abs must be > 0")

    @property
    def layer_sizes(self) -> List[int]:
        return [self.features.n_in] + list(self.hidden) + [self.n_out]

    @property
    def layer_dims(self) -> List[tuple]:
        """[(n_in, n_out), ...] per layer -- the form load_modular_weights wants."""
        s = self.layer_sizes
        return [(s[i], s[i + 1]) for i in range(len(s) - 1)]

    def weight_count(self) -> int:
        return sum(a * b + b for a, b in self.layer_dims)

    @property
    def shape_str(self) -> str:
        return "-".join(str(s) for s in self.layer_sizes)

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "arch": {"n_in": self.features.n_in, "hidden": list(self.hidden),
                     "n_out": self.n_out, "activation": self.activation,
                     "shape": self.shape_str},
            "features": self.features.to_json(),
            "descriptor": self.features.descriptor(),
            "quant": {"scheme": self.quant, "symmetric": True, "zero_point": 0},
            "drop_class": self.drop_class,
            "seed": self.seed,
            "weight_init": self.weight_init,
            "max_abs": self.max_abs,
            "weight_count": self.weight_count(),
            "provenance": "synthetic -- generated by ipa/synth, "
                          "independent of any trained checkpoint",
        }

    @staticmethod
    def from_json(d: dict) -> "ModelSpec":
        return ModelSpec(
            name=d["name"],
            features=FeatureSet.from_json(d["features"]),
            n_out=d["arch"]["n_out"],
            hidden=list(d["arch"]["hidden"]),
            activation=d["arch"].get("activation", "relu"),
            quant=d["quant"]["scheme"],
            seed=d.get("seed", 0),
            weight_init=d.get("weight_init", "uniform"),
            max_abs=d.get("max_abs", 5.0),
            drop_class=d.get("drop_class"),
        )

    def summary(self) -> str:
        return (f"  name        : {self.name}\n"
                f"  shape       : {self.shape_str}  ({self.weight_count()} weights)\n"
                f"  activation  : {self.activation}\n"
                f"  quant       : {self.quant} (symmetric, zero_point=0)\n"
                f"  drop class  : {self.drop_class} of {self.n_out}\n"
                f"  max|w|      : {self.max_abs:g} (-> int8 scale ~{int(127 / self.max_abs)})\n"
                f"  seed        : {self.seed}\n"
                f"  features:\n{self.features.summary()}")
