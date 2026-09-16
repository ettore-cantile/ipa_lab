"""
class_semantics.py -- what each model output class MEANS.

The problem this replaces
------------------------
Until now the meaning of an output class was inferred from its index. Four
mutually inconsistent conventions coexisted in the tree:

  dataset.py      DROP = max(label) + 1        -> 5 for the germany50 dataset
  train.py        DROP = n_interfaces + 1      -> 7, dead code (no -1 survives
                                                  load_dataset), and 7 is not
                                                  even a valid index of a
                                                  7-class output
  the datapath    DROP = n_out - 1             -> 6, and hardcoded as `>= 6`
                                                  in P2/P3
  decode_nexthop  DROP = 0, ports shifted by 1 -> abandoned, still printing

Measured consequence on the checked-in model: 92.3% of the rows the dataset
labels DROP make the model emit class 5, which the datapath then treats as
"forward out logical port 5". The DROP decision was never honoured, and
XDP_DROP was dead code because class 6 never wins the argmax.

The model here
--------------
A class index carries NO meaning by itself. Every valid class gets an explicit
action:

  FORWARD(port)  send the packet out a LOGICAL PORT. Not an ifindex, not an
                 interface name, and not necessarily equal to the class index:
                 ports may be non-consecutive and in any order.
  DROP           discard the packet in the datapath.
  UNUSED         a class the model can emit but that carries no action -- e.g.
                 an output the training data never labelled. Counted, never
                 forwarded. Making this explicit is the point: such a class
                 used to be silently repurposed as DROP.

`drop_class` is OPTIONAL. A model with no DROP class is legitimate, and must
not have one invented for it.

Three separate layers, never conflated:

  L1  compile-time ceilings          MAX_N_OUT, MAX_LOGICAL_PORTS (engine)
  L2  this file + the descriptor     n_out, class semantics       (model)
  L3  node_config.py                 logical port -> ifindex/MAC  (node)
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# --- L1: engine ceilings. NOT the model's n_out. -------------------------
# Compiled into the eBPF programs, which need constant loop bounds and a
# fixed-size class_action map. A model with n_out above the ceiling is refused
# at load time, never silently truncated.
MAX_N_OUT = 32
MAX_LOGICAL_PORTS = 32

# Action codes. These travel to the datapath in the class_action BPF map, so
# the values are part of the kernel/userspace contract -- keep them in sync
# with the ACT_* defines in the eBPF sources.
ACT_INVALID = 0      # class out of range, or no semantics registered
ACT_FORWARD = 1
ACT_DROP    = 2
ACT_UNUSED  = 3

ACTION_NAMES = {ACT_INVALID: "INVALID", ACT_FORWARD: "FORWARD",
                ACT_DROP: "DROP", ACT_UNUSED: "UNUSED"}
ACTION_CODES = {v: k for k, v in ACTION_NAMES.items()}


class SemanticsError(ValueError):
    """Raised when a descriptor's class semantics are inconsistent.

    Always raised, never warned: a model whose class meanings cannot be
    established must not reach a datapath that will then guess.
    """


@dataclass
class ClassSpec:
    """One output class."""
    action: str                      # "FORWARD" | "DROP" | "UNUSED"
    port: Optional[int] = None       # logical port, FORWARD only

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

    # -- validation --------------------------------------------------------
    def validate(self):
        """Every check the descriptor must survive before it can be used."""
        if not isinstance(self.n_out, int) or self.n_out < 1:
            raise SemanticsError(f"n_out must be a positive int, got {self.n_out!r}")
        if self.n_out > MAX_N_OUT:
            raise SemanticsError(
                f"n_out={self.n_out} exceeds the compiled ceiling "
                f"MAX_N_OUT={MAX_N_OUT}. Raise the ceiling in class_semantics.py "
                f"AND the matching #define in the eBPF sources, then reload.")

        # every class in range, none missing, none duplicated. A dict cannot
        # hold duplicates, so the real check is coverage and range.
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

        # drop_class must agree with the map, in both directions
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

        # logical ports: no two FORWARD classes may claim the same port, or the
        # mapping class -> port stops being a function of the packet's decision
        ports = [s.port for s in self.classes.values() if s.action == "FORWARD"]
        dup = sorted({p for p in ports if ports.count(p) > 1})
        if dup:
            raise SemanticsError(f"logical port(s) {dup} claimed by more than one class")
        if not ports:
            # legitimate (a pure classifier), but worth refusing in a forwarding
            # datapath: nothing could ever be forwarded.
            raise SemanticsError(
                "no class has action FORWARD -- this model can never forward "
                "a packet. If that is intended, the datapath is the wrong "
                "consumer for it.")

    # -- queries -----------------------------------------------------------
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
        """How many distinct ports the model can select. NOT n_out, and not the
        node's interface count."""
        return len(self.logical_ports)

    def action_of(self, cls: int) -> str:
        if not (0 <= cls < self.n_out) or cls not in self.classes:
            return "INVALID"
        return self.classes[cls].action

    def port_of(self, cls: int) -> Optional[int]:
        s = self.classes.get(cls)
        return s.port if s and s.action == "FORWARD" else None

    # -- the datapath's view ----------------------------------------------
    def action_table(self) -> List[tuple]:
        """(action_code, port) per class index 0..MAX_N_OUT-1, for the
        class_action BPF map. Classes past n_out are ACT_INVALID, so a datapath
        reading a class it should never see gets an explicit "invalid" rather
        than a stale or zeroed entry that looks like a valid action."""
        out = []
        for cid in range(MAX_N_OUT):
            s = self.classes.get(cid)
            if cid >= self.n_out or s is None:
                out.append((ACT_INVALID, 0))
            else:
                out.append((s.code, s.port if s.action == "FORWARD" else 0))
        return out

    # -- serialisation -----------------------------------------------------
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

    # -- constructors for common shapes -----------------------------------
    @staticmethod
    def forward_then_drop(n_ports: int, drop_class: Optional[int] = None,
                          n_out: Optional[int] = None,
                          ports: Optional[List[int]] = None) -> "ClassSemantics":
        """Classes 0..n_ports-1 forward to ports (default: identity), then an
        optional DROP class, then UNUSED for anything remaining.

        A convenience for the common layout, NOT a default: the caller states
        n_ports and drop_class explicitly. `ports` allows a non-identity and
        non-consecutive class -> port mapping.
        """
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

    # -- human-readable ----------------------------------------------------
    def summary(self) -> str:
        lines = [f"  n_out = {self.n_out}, "
                 f"drop_class = {self.drop_class if self.drop_class is not None else 'none'}, "
                 f"logical ports = {self.logical_ports}"]
        for c in range(self.n_out):
            lines.append(f"    class {c}: {self.classes[c].describe()}")
        return "\n".join(lines)


def format_decision(cls: int, sem: ClassSemantics, ifindex: Optional[int] = None,
                     iface: Optional[str] = None) -> str:
    """One-line log of a decision, keeping the four levels distinct.

    Replaces decode_nexthop, which printed an interface name derived straight
    from the class index -- so class 2 was reported as "eth1" under a
    convention (DROP=0, ports shifted) that no other part of the system used.
    """
    act = sem.action_of(cls)
    out = f"class={cls} action={act}"
    if act == "FORWARD":
        out += f" logical_port={sem.port_of(cls)}"
        if ifindex is not None:
            out += f" ifindex={ifindex}"
        if iface is not None:
            out += f" iface={iface}"
    return out


def load_from_file(path: str) -> ClassSemantics:
    with open(path) as f:
        return ClassSemantics.from_json(json.load(f))
