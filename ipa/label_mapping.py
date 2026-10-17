"""label_mapping.py -- the dataset label -> model class mapping, written down
explicitly (which label is DROP, which classes are unused).
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from class_semantics import ClassSemantics, ClassSpec, SemanticsError


@dataclass
class LabelMapping:
    """Dataset label -> model class, declared explicitly."""

    n_out: int
    port_labels: Dict[int, int] = field(default_factory=dict)
    label_to_class: Dict[int, int] = field(default_factory=dict)
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

    def verify(self, observed_labels, strict: bool = True) -> List[str]:
        """Check the declared mapping against the labels actually present."""
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


def identity_ports_with_drop(port_labels: List[int], drop_label: Optional[int],
                             drop_class: Optional[int],
                             n_out: Optional[int] = None) -> LabelMapping:
    """Labels denote logical ports directly;"""
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

