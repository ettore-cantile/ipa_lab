#!/usr/bin/env python3
"""
make_scenario.py -- generate a synthetic scenario's artefacts.

    python3 ipa/synth/make_scenario.py --preset ipa_like
    python3 ipa/synth/make_scenario.py --preset all -n 1000
    python3 ipa/synth/make_scenario.py --n-in-features 6,6,1,52 --n-out 7 \
                                          --hidden 4,4 --seed 42

Writes into ipa/synth/scenarios/<name>/ by default, reusing the repo's
existing artefact names so every loader in the tree consumes them unchanged.
"""

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SHARED = os.path.dirname(_HERE)
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

from synth.spec import FeatureSet, FeatureSpec, ModelSpec        # noqa: E402
from synth.generate import generate_scenario, preset, PRESETS    # noqa: E402
from synth import reference as ref                               # noqa: E402

DEFAULT_ROOT = os.path.join(_HERE, "scenarios")


def _custom_spec(args) -> ModelSpec:
    """Build a ModelSpec from CLI flags.

    --features takes `name:kind:size[:lo:hi:scale]` entries, so feature
    semantics stay explicit on the command line too; there is deliberately no
    "just give me N random features" shortcut, because a feature without a
    declared kind is the thing this package exists to avoid.
    """
    feats = []
    for i, spec in enumerate(args.features.split(",")):
        parts = spec.split(":")
        if len(parts) < 3:
            raise SystemExit(f"--features entry {spec!r}: need name:kind:size[...]")
        name, kind, size = parts[0], parts[1], int(parts[2])
        lo = float(parts[3]) if len(parts) > 3 else 0.0
        hi = float(parts[4]) if len(parts) > 4 else 1.0
        scale = int(parts[5]) if len(parts) > 5 else 1
        feats.append(FeatureSpec(name, kind, size=size, lo=lo, hi=hi,
                                 scale=scale, min_ones=1 if kind == "binary" else 0,
                                 code=0x01 + i))
    hidden = [int(h) for h in args.hidden.split(",")] if args.hidden else []
    return ModelSpec(args.name or "custom", FeatureSet(feats), n_out=args.n_out,
                     hidden=hidden, activation=args.activation, quant=args.quant,
                     seed=args.seed, weight_init=args.weight_init,
                     drop_class=args.drop_class)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--preset", help=f"one of {', '.join(PRESETS)}, or 'all'")
    p.add_argument("--features", help="name:kind:size[:lo:hi:scale] comma-separated")
    p.add_argument("--name")
    p.add_argument("--n-out", type=int, default=7)
    p.add_argument("--hidden", default="4,4", help="comma-separated widths, '' for none")
    p.add_argument("--activation", default="relu")
    p.add_argument("--quant", default="int8", choices=("int8", "float"))
    p.add_argument("--weight-init", default="uniform",
                   choices=("uniform", "normal", "sparse", "ones"))
    p.add_argument("--drop-class", type=int, default=None,
                   help="index of the DROP class; omitted, the generator "
                        "declares the last class and says so")
    p.add_argument("--seed", type=int, default=20260916)
    p.add_argument("-n", "--n-inputs", type=int, default=1000)
    p.add_argument("--input-seed", type=int, default=None)
    p.add_argument("--out", default=DEFAULT_ROOT)
    args = p.parse_args()

    if args.preset:
        names = list(PRESETS) if args.preset == "all" else [args.preset]
        specs = [preset(n, seed=args.seed) for n in names]
    elif args.features:
        specs = [_custom_spec(args)]
    else:
        p.error("give --preset or --features")

    for m in specs:
        outdir = os.path.join(args.out, m.name)
        man = generate_scenario(m, outdir, n_inputs=args.n_inputs,
                                input_seed=args.input_seed)
        print("=" * 68)
        print(m.summary())
        print(f"  weights     : {man['weights']} int8, scale={man['scale_factor']}, "
              f"{man['clamped']} clamped")
        print(f"  inputs      : {man['n_inputs']} vectors, seed={man['input_seed']}")
        print(f"  float/int8 argmax agreement : {100*man['quant_agreement']:.2f}%")
        print(f"  classes float / int8        : {man['classes_float']} / "
              f"{man['classes_int8']}")
        print("  bias scaling under this scheme:")
        for line in ref.bias_scale_report(m.layer_dims):
            print(line)
        print(f"  torch state_dict written    : {man['torch']}")
        print(f"  -> {outdir}")
    print("=" * 68)


if __name__ == "__main__":
    main()
