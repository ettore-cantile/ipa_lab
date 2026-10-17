"""class_semantics.py -- what each output class of a model means.

A model declares, for every class, an action: FORWARD on a logical port, DROP,
or UNUSED. The pipelines never infer the action from the class index.
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional


MAX_N_OUT = 32
MAX_LOGICAL_PORTS = 32
ACT_INVALID = 0
ACT_FORWARD = 1
ACT_DROP    = 2
ACT_UNUSED  = 3

ACTION_NAMES = {ACT_INVALID: "INVALID", ACT_FORWARD: "FORWARD",
                ACT_DROP: "DROP", ACT_UNUSED: "UNUSED"}
ACTION_CODES = {v: k for k, v in ACTION_NAMES.items()}


class SemanticsError(ValueError):
    """Raised when a descriptor's class semantics are inconsistent."""


@dataclass
class ClassSpec:
    """One output class."""
    action: str
    port: Optional[int] = None

    def __post_init__(self):
        self.action = self.action.upper()
        if self.action not in ACTION_CODES or self.action == "INVALID":
            raise SemanticsError(
                f"unknown action {self.action!r}; use FORWARD, DROP or UNUSED")
        if self.action == "FORWARD":
            if self.port is None:
                raise SemanticsError("a FORWARD class must declare its logical port")
            if not (0 <= int(self.port) < MAX_LOGICAL_PORTS):
                raise SemanticsError(
                    f"logical port {self.port} outside [0, {MAX_LOGICAL_PORTS})")
            self.port = int(self.port)
        elif self.port is not None:
            raise SemanticsError(
                f"a {self.action} class must not declare a port (got {self.port})")

    @property
    def code(self) -> int:
        return ACTION_CODES[self.action]

    def describe(self) -> str:
        return (f"FORWARD -> logical_port {self.port}" if self.action == "FORWARD"
                else self.action)


@dataclass
class ClassSemantics:
    """The full class -> action mapping for one model."""

    n_out: int
    classes: Dict[int, ClassSpec] = field(default_factory=dict)
    drop_class: Optional[int] = None

    def __post_init__(self):
        self.classes = {int(k): v for k, v in self.classes.items()}
        self.validate()

    def validate(self):
        """Every check the descriptor must survive before it can be used."""
        if not isinstance(self.n_out, int) or self.n_out < 1:
            raise SemanticsError(f"n_out must be a positive int, got {self.n_out!r}")
        if self.n_out > MAX_N_OUT:
            raise SemanticsError(
                f"n_out={self.n_out} exceeds the compiled ceiling "
                f"MAX_N_OUT={MAX_N_OUT}. Raise the ceiling in class_semantics.py "
                f"AND the matching #define in the eBPF sources, then reload.")

        for cid in self.classes:
            if not (0 <= cid < self.n_out):
                raise SemanticsError(
                    f"class {cid} outside [0, n_out={self.n_out})")
        missing = sorted(set(range(self.n_out)) - set(self.classes))
        if missing:
            raise SemanticsError(
                f"classes without declared semantics: {missing}. Every class the "
                f"model can emit needs one -- declare it UNUSED if it carries no "
                f"action, rather than leaving it to be inferred.")

        drops = sorted(c for c, s in self.classes.items() if s.action == "DROP")
        if self.drop_class is not None:
            if not (0 <= self.drop_class < self.n_out):
                raise SemanticsError(
                    f"drop_class={self.drop_class} outside [0, {self.n_out})")
            if self.classes[self.drop_class].action != "DROP":
                raise SemanticsError(
                    f"drop_class={self.drop_class} but that class's action is "
                    f"{self.classes[self.drop_class].action}")
        if len(drops) > 1:
            raise SemanticsError(f"more than one DROP class: {drops}")
        if drops and self.drop_class is None:
            raise SemanticsError(
                f"class {drops[0]} has action DROP but drop_class is null; "
                f"declare it so the two cannot drift apart")
        if not drops and self.drop_class is not None:
            raise SemanticsError(
                f"drop_class={self.drop_class} but no class has action DROP")

        ports = [s.port for s in self.classes.values() if s.action == "FORWARD"]
        dup = sorted({p for p in ports if ports.count(p) > 1})
        if dup:
            raise SemanticsError(f"logical port(s) {dup} claimed by more than one class")
        if not ports:
            raise SemanticsError(
                "no class has action FORWARD -- this model can never forward "
                "a packet. If that is intended, the datapath is the wrong "
                "consumer for it.")

    @property
    def forward_classes(self) -> List[int]:
        return sorted(c for c, s in self.classes.items() if s.action == "FORWARD")

    @property
    def unused_classes(self) -> List[int]:
        return sorted(c for c, s in self.classes.items() if s.action == "UNUSED")

    @property
    def logical_ports(self) -> List[int]:
        return sorted(s.port for s in self.classes.values() if s.action == "FORWARD")

    @property
    def n_logical_ports(self) -> int:
        """How many distinct ports the model can select."""
        return len(self.logical_ports)

    def action_of(self, cls: int) -> str:
        if not (0 <= cls < self.n_out) or cls not in self.classes:
            return "INVALID"
        return self.classes[cls].action

    def port_of(self, cls: int) -> Optional[int]:
        s = self.classes.get(cls)
        return s.port if s and s.action == "FORWARD" else None

    def action_table(self) -> List[tuple]:
        """(action_code, port) per class index 0..MAX_N_OUT-1, for the
        class_action BPF map."""
        out = []
        for cid in range(MAX_N_OUT):
            s = self.classes.get(cid)
            if cid >= self.n_out or s is None:
                out.append((ACT_INVALID, 0))
            else:
                out.append((s.code, s.port if s.action == "FORWARD" else 0))
        return out

    def to_json(self) -> dict:
        return {
            "n_out": self.n_out,
            "drop_class": self.drop_class,
            "class_semantics": {
                str(c): ({"action": s.action, "port": s.port}
                         if s.action == "FORWARD" else {"action": s.action})
                for c, s in sorted(self.classes.items())
            },
        }

    @staticmethod
    def from_json(d: dict) -> "ClassSemantics":
        if "n_out" not in d:
            raise SemanticsError("descriptor has no n_out")
        raw = d.get("class_semantics")
        if not raw:
            raise SemanticsError(
                "descriptor has no class_semantics. It is not derived from n_out "
                "on purpose: deriving DROP as n_out-1 is exactly the assumption "
                "this module exists to remove. Use "
                "ClassSemantics.forward_then_drop() to build an explicit one.")
        classes = {int(k): ClassSpec(**v) for k, v in raw.items()}
        return ClassSemantics(n_out=int(d["n_out"]), classes=classes,
                              drop_class=d.get("drop_class"))

    @staticmethod
    def forward_then_drop(n_ports: int, drop_class: Optional[int] = None,
                          n_out: Optional[int] = None,
                          ports: Optional[List[int]] = None) -> "ClassSemantics":
        """Classes 0..n_ports-1 forward to ports (default: identity), then an
        optional DROP class, then UNUSED."""
        ports = list(range(n_ports)) if ports is None else list(ports)
        if len(ports) != n_ports:
            raise SemanticsError(f"ports has {len(ports)} entries, expected {n_ports}")
        if n_out is None:
            n_out = n_ports + (1 if drop_class is not None else 0)
        classes = {}
        for i, p in enumerate(ports):
            classes[i] = ClassSpec("FORWARD", p)
        if drop_class is not None:
            if drop_class in classes:
                raise SemanticsError(
                    f"drop_class={drop_class} collides with a FORWARD class")
            classes[drop_class] = ClassSpec("DROP")
        for c in range(n_out):
            classes.setdefault(c, ClassSpec("UNUSED"))
        return ClassSemantics(n_out=n_out, classes=classes, drop_class=drop_class)

    def summary(self) -> str:
        lines = [f"  n_out = {self.n_out}, "
                 f"drop_class = {self.drop_class if self.drop_class is not None else 'none'}, "
                 f"logical ports = {self.logical_ports}"]
        for c in range(self.n_out):
            lines.append(f"    class {c}: {self.classes[c].describe()}")
        return "\n".join(lines)


def format_decision(cls: int, sem: ClassSemantics, ifindex: Optional[int] = None,
                     iface: Optional[str] = None) -> str:
    """One-line log of a decision, keeping the four levels distinct."""
    act = sem.action_of(cls)
    out = f"class={cls} action={act}"
    if act == "FORWARD":
        out += f" logical_port={sem.port_of(cls)}"
        if ifindex is not None:
            out += f" ifindex={ifindex}"
        if iface is not None:
            out += f" iface={iface}"
    return out

