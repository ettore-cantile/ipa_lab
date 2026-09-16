"""
ipa/synth -- synthetic scenarios for the IPA/eBPF pipelines.

Decouples pipeline evaluation from the supplied checkpoint: models, weights and
input vectors are generated from a declared seed, with feature semantics
(kind, domain, width, encoding, position) declared rather than assumed.

  spec       FeatureSpec / FeatureSet / ModelSpec
  reference  float and int8 forward passes, the latter bit-for-bit with eBPF
  generate   weights, inputs and every artefact a pipeline needs

Entry point: python3 ipa/synth/make_scenario.py --preset ipa_like
"""

from .spec import FeatureSpec, FeatureSet, ModelSpec, ipa_feature_set
from . import reference
from .generate import (generate_scenario, load_scenario, make_weights,
                       make_inputs, check_inputs, preset, PRESETS)

__all__ = [
    "FeatureSpec", "FeatureSet", "ModelSpec", "ipa_feature_set",
    "reference", "generate_scenario", "load_scenario", "make_weights",
    "make_inputs", "check_inputs", "preset", "PRESETS",
]
