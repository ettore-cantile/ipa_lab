"""
label_mapping.py -- explicit, recorded dataset label -> class mapping.

Replaces the implicit chain in the training pipeline. The originals are in
Tesi/IPA/ and are NOT modified by this repo: they are the upstream inputs to
this work, not its source. This module is the repo-side equivalent, and it
records what the previous chain left implicit.

What was wrong upstream
-----------------------
  dataset.py:9-11   drop_index = df['label'].max() + 1
                    DROP derived from WHICH LABELS HAPPEN TO APPEAR. On the
                    germany50 dataset labels run 0..4 (never 5: that would be
                    karlsruhe's interface toward h_src, and no path exits
                    there), so drop_index came out 5. Regenerate the dataset
                    with different sampling and DROP silently becomes 6.
  train.py:32-33    y = where(y == -1, n_interfaces + 1, y)
                    Dead code: load_dataset already removed every -1. It also
                    writes 7, which is not a valid index of a 7-class output.
                    The comment above it says "-> 0", a third value.
  train.py:29,144   drop_index is received from load_dataset and never used.
  evaluate.py:109   drop_mask = y_true == (n_interfaces + 1)   # == 7
                    Always empty, and guarded by `if drop_mask.any()`, so DROP
                    accuracy was never computed and never reported missing.

None of those four agreed, and none was recorded anywhere the datapath could
read.

What this module does instead
-----------------------------
The caller states the mapping. Nothing is derived from the data. The mapping is
then VERIFIED against the data and written into the model descriptor, so the
datapath consumes the same semantics the model was trained on.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from class_semantics import ClassSemantics, ClassSpec, SemanticsError


@dataclass
class LabelMapping:
    """Dataset label -> model class, declared explicitly.

    `port_labels` maps a dataset label to the logical port it denotes.
    `drop_label` is the raw label meaning DROP (-1 in this project's datasets),
    and `drop_class` the class index it is mapped onto. Both may be None: a
    dataset with no DROP rows must not get a DROP class invented for it.
    """

    n_out: int
    port_labels: Dict[int, int] = field(default_factory=dict)   # label -> logical port
    label_to_class: Dict[int, int] = field(default_factory=dict)  # label -> class
    drop_label: Optional[int] = None
    drop_class: Optional[int] = None
    unused_classes: List[int] = field(default_factory=list)

    def __post_init__(self):
        if self.drop_label is not None and self.drop_class is None:
            raise SemanticsError(
                "drop_label given without drop_class: state which class index "
                "the DROP rows are mapped onto instead of leaving it to be "
                "derived (that derivation is the bug this module removes)")
        if self.drop_class is not None and self.drop_label is None:
            raise SemanticsError("drop_class given without drop_label")
        for lab, cls in self.label_to_class.items():
            if not (0 <= cls < self.n_out):
                raise SemanticsError(
                    f"label {lab} maps to class {cls}, outside [0, {self.n_out})")
        seen = {}
        for lab, cls in self.label_to_class.items():
            if cls in seen:
                raise SemanticsError(
                    f"classes collide: labels {seen[cls]} and {lab} both map to "
                    f"class {cls}")
            seen[cls] = lab

    # -- the class semantics this mapping implies --------------------------
    def to_class_semantics(self) -> ClassSemantics:
        classes = {}
        for lab, port in self.port_labels.items():
            cls = self.label_to_class[lab]
            classes[cls] = ClassSpec("FORWARD", port)
        if self.drop_class is not None:
            classes[self.drop_class] = ClassSpec("DROP")
        for c in range(self.n_out):
            classes.setdefault(c, ClassSpec("UNUSED"))
        return ClassSemantics(n_out=self.n_out, classes=classes,
                              drop_class=self.drop_class)

    # -- verification against the actual data ------------------------------
    def verify(self, observed_labels, strict: bool = True) -> List[str]:
        """Check the declared mapping against the labels actually present.

        Fails loudly on the four incoherences the old chain could hold
        silently: a label with no mapping, a class outside the output range, a
        declared DROP class with no DROP rows, and DROP rows with no declared
        DROP class.
        """
        obs = set(int(v) for v in observed_labels)
        problems = []

        unmapped = sorted(obs - set(self.label_to_class))
        if unmapped:
            problems.append(
                f"labels present in the data but not in the mapping: {unmapped}")

        declared = set(self.label_to_class) | (
            {self.drop_label} if self.drop_label is not None else set())
        never = sorted(declared - obs)
        if never:
            problems.append(
                f"labels declared but absent from the data: {never} -- their "
                f"classes will never be trained")

        if self.drop_class is not None and self.drop_label not in obs:
            problems.append(
                f"drop_class={self.drop_class} declared but the data has no "
                f"label {self.drop_label}: the DROP class would be untrained")
        if self.drop_class is None and any(v < 0 for v in obs):
            problems.append(
                f"the data contains negative labels {sorted(v for v in obs if v < 0)} "
                f"but no drop_class is declared")

        for cls in self.label_to_class.values():
            if cls in self.unused_classes:
                problems.append(f"class {cls} is declared UNUSED but a label maps to it")

        if strict and problems:
            raise SemanticsError(
                "label mapping does not match the dataset:\n  " + "\n  ".join(problems))
        return problems

    def remap(self, labels):
        """Apply the mapping. Raises on anything undeclared -- a label the
        mapping does not cover must not be silently passed through."""
        out = []
        for v in labels:
            v = int(v)
            if v not in self.label_to_class:
                raise SemanticsError(
                    f"label {v} has no declared class. Extend the mapping "
                    f"rather than letting it through unchanged.")
            out.append(self.label_to_class[v])
        return out

    def to_json(self) -> dict:
        d = self.to_class_semantics().to_json()
        d["label_mapping"] = {
            "n_out": self.n_out,
            "drop_label": self.drop_label,
            "port_labels": {str(k): v for k, v in sorted(self.port_labels.items())},
            "label_to_class": {str(k): v for k, v in sorted(self.label_to_class.items())},
            "provenance": "declared explicitly; NOT derived from max(label)+1",
        }
        return d

    def summary(self) -> str:
        lines = [f"  n_out = {self.n_out}, drop_label = {self.drop_label}, "
                 f"drop_class = {self.drop_class}"]
        for lab in sorted(self.label_to_class):
            cls = self.label_to_class[lab]
            if lab == self.drop_label:
                lines.append(f"    label {lab:>3} -> class {cls} (DROP)")
            else:
                lines.append(f"    label {lab:>3} -> class {cls} "
                             f"-> logical port {self.port_labels[lab]}")
        if self.unused_classes:
            lines.append(f"    UNUSED classes: {self.unused_classes}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
def identity_ports_with_drop(port_labels: List[int], drop_label: Optional[int],
                             drop_class: Optional[int],
                             n_out: Optional[int] = None) -> LabelMapping:
    """Labels denote logical ports directly; class index == label for ports.

    The common case, stated rather than assumed. `n_out` defaults to exactly
    what the mapping needs -- no spare class is created. A spare class is how
    the checked-in model ended up with an untrained class 6 that the datapath
    then used for DROP.
    """
    l2c = {lab: lab for lab in port_labels}
    if drop_label is not None:
        if drop_class is None:
            raise SemanticsError("drop_class must be stated alongside drop_label")
        l2c[drop_label] = drop_class
    need = max(l2c.values()) + 1 if l2c else 0
    if n_out is None:
        n_out = need
    elif n_out < need:
        raise SemanticsError(f"n_out={n_out} too small for the mapping (needs {need})")
    used = set(l2c.values())
    return LabelMapping(n_out=n_out,
                        port_labels={lab: lab for lab in port_labels},
                        label_to_class=l2c,
                        drop_label=drop_label, drop_class=drop_class,
                        unused_classes=sorted(set(range(n_out)) - used))


def observed_labels_from_csv(csv_path: str, label_col: str = "label",
                             limit: Optional[int] = None):
    """Distinct labels in a dataset CSV, for verify(). Streams, so a 13M-row
    file costs nothing but time."""
    import csv as _csv
    seen = set()
    with open(csv_path, newline="") as f:
        r = _csv.reader(f)
        hdr = next(r)
        try:
            i = hdr.index(label_col)
        except ValueError:
            raise SemanticsError(f"{csv_path}: no {label_col!r} column")
        for n, row in enumerate(r):
            seen.add(int(float(row[i])))
            if limit and n + 1 >= limit:
                break
    return sorted(seen)


def write_descriptor(path: str, mapping: LabelMapping, extra: dict = None) -> dict:
    """Merge the mapping's semantics into a model descriptor on disk.

    This is the step the upstream chain was missing: the mapping used at
    training time becomes part of the artefact the datapath loads, instead of
    living only in the preprocessing script.
    """
    doc = {}
    if os.path.exists(path):
        with open(path) as f:
            doc = json.load(f)
    doc.update(mapping.to_json())
    if extra:
        doc.update(extra)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
    return doc
