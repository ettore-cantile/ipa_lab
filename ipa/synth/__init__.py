"""ipa/synth -- synthetic models, weights and inputs from a declared seed.

    spec       feature and model descriptors
    reference  float and int8 forward passes (int8 = what the datapath computes)
    generate   writes every artefact a pipeline needs
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
