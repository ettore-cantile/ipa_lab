"""spec.py -- feature semantics (kind, domain, width, encoding) and model
descriptors for synthetic scenarios.
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
    lo: float = 0.0
    hi: float = 1.0
    scale: int = 1
    min_ones: int = 0
    code: int = 0

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

    def column_scale(self) -> List[int]:
        """Divisor applied to each of this feature's columns."""
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
        """Per-column divisors for the whole input vector."""
        out = []
        for f in self.features:
            out += f.column_scale()
        return out

    def descriptor(self) -> List[dict]:
        """Flat (code, size, col_off) form, the shape the P2/P3 registries
        want."""
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


# --- The IPA feature set, rebuilt from the declared semantics rather than copied. ---
def ipa_feature_set(n_interfaces: int = 6, n_nodes: int = 52,
                    initial_ttl: int = 30) -> FeatureSet:
    """The [link_state, ingress_iface, ttl, node] layout the checked-in model
    was trained on, expressed in this package's vocabulary."""
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
    quant: str = "int8"
    seed: int = 0
    weight_init: str = "uniform"
    drop_class: Optional[int] = None
    max_abs: float = 5.0
    sparsity: float = 0.7

    ACTIVATIONS = ("relu",)
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
        if not (0.0 <= self.sparsity < 1.0):
            raise ValueError("sparsity must be in [0, 1)")

    @property
    def layer_sizes(self) -> List[int]:
        return [self.features.n_in] + list(self.hidden) + [self.n_out]

    @property
    def layer_dims(self) -> List[tuple]:
        """[(n_in, n_out), ...] per layer -- the form load_modular_weights
        wants."""
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
            **({"sparsity": self.sparsity}
               if self.weight_init == "sparse" else {}),
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
            sparsity=d.get("sparsity", 0.7),
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
