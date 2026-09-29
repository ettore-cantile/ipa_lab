"""
pipeline_limits.py -- which pipeline can run which model, without loading it.

Every number comes from the module that compiles the program (the P2/P3
ceilings, MAX_N_IN, MAX_N_OUT); nothing is restated here. The loaders enforce
the same limits when they fill the maps, so a model that passes here and is
refused there is a bug in this file, not a second opinion.

    why_not(pipeline, hidden, n_in, n_out) -> None | "reason"

Pipelines: baseline, p1_static (P1), hardcoded (P1.5), template (P2),
modular (P3). rxonly and baseline run no model, so every model "fits".

One limit is not here because it is not a constant: P2's depth is bounded by
the eBPF jump offset (16 bits) of the leaf clang generates, reached around 20
hidden layers at width 4 (diag_verifier.py --depths). A deeper model passes
this check and is refused by the verifier at load time; callers report that
as "not applicable", not as a failure.
"""

PIPELINES = ("baseline", "p1_static", "hardcoded", "template", "modular")
NO_MODEL = ("rxonly", "baseline")


def layer_dims(hidden, n_in, n_out):
    sizes = [int(n_in)] + [int(h) for h in hidden] + [int(n_out)]
    return [(sizes[i], sizes[i + 1]) for i in range(len(sizes) - 1)]


def why_not(pipeline, hidden, n_in, n_out):
    """The reason `pipeline` cannot run a model of this shape, or None."""
    import model_meta as mm
    hidden = [int(h) for h in hidden]
    n_in, n_out = int(n_in), int(n_out)
    if pipeline in NO_MODEL:
        return None
    if n_in > mm.MAX_N_IN:
        return f"n_in={n_in} oltre MAX_N_IN={mm.MAX_N_IN}"
    if not 1 <= n_out <= mm.MAX_N_OUT:
        return f"n_out={n_out} fuori da [1, MAX_N_OUT={mm.MAX_N_OUT}]"
    if pipeline in ("p1_static", "hardcoded"):
        return None
    if pipeline == "template":
        import ebpf_template_arch as A
        if not hidden:
            return "P2 ha bisogno di almeno uno strato nascosto"
        if any(h != hidden[1] for h in hidden[2:]):
            return (f"strati nascosti {hidden}: in P2 quelli oltre il secondo "
                    f"sono n_h2 -> n_h2")
        n_h1 = hidden[0]
        n_h2 = hidden[1] if len(hidden) > 1 else hidden[0]
        if n_h1 > A.T2_MAX_H1 or n_h2 > A.T2_MAX_H2:
            return (f"strati nascosti {hidden} oltre T2_MAX_H1/T2_MAX_H2 "
                    f"({A.T2_MAX_H1}/{A.T2_MAX_H2} neuroni)")
        nw = A.arch_weight_count(n_h1, n_h2, n_in, n_out, n_hidden=len(hidden))
        if nw > A.MAX_WEIGHT_ENTRIES:
            return f"{nw} pesi oltre MAX_WEIGHT_ENTRIES={A.MAX_WEIGHT_ENTRIES}"
        return None
    if pipeline == "modular":
        import ebpf_modular as M
        dims = layer_dims(hidden, n_in, n_out)
        if len(dims) > M.LAYER_CHAIN_SIZE:
            return (f"{len(dims)} strati oltre LAYER_CHAIN_SIZE="
                    f"{M.LAYER_CHAIN_SIZE}")
        if dims[0][1] > M.ML1_MAX_H1 or any(max(a, b) > M.MLH_MAX_H
                                            for a, b in dims[1:]):
            return (f"strati {dims} oltre ML1_MAX_H1/MLH_MAX_H "
                    f"({M.ML1_MAX_H1}/{M.MLH_MAX_H} neuroni)")
        nw = sum(a * b + b for a, b in dims)
        if nw > M.MAX_LAYER_WEIGHT_ENTRIES:
            return (f"{nw} pesi oltre MAX_LAYER_WEIGHT_ENTRIES="
                    f"{M.MAX_LAYER_WEIGHT_ENTRIES}")
        return None
    return f"pipeline sconosciuta: {pipeline!r}"
