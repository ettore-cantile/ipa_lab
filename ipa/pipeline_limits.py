"""pipeline_limits.py -- which pipeline can run which model, without loading it.

    why_not(pipeline, hidden, n_in, n_out) -> None | "reason"
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
        return f"n_in={n_in} above MAX_N_IN={mm.MAX_N_IN}"
    if not 1 <= n_out <= mm.MAX_N_OUT:
        return f"n_out={n_out} outside [1, MAX_N_OUT={mm.MAX_N_OUT}]"
    if pipeline in ("p1_static", "hardcoded"):
        return None
    if pipeline == "template":
        import ebpf_template_arch as A
        if not hidden:
            return "P2 needs at least one hidden layer"
        if any(h != hidden[1] for h in hidden[2:]):
            return (f"hidden layers {hidden}: in P2 those beyond the second "
                    f"are n_h2 -> n_h2")
        n_h1 = hidden[0]
        n_h2 = hidden[1] if len(hidden) > 1 else hidden[0]
        if n_h1 > A.T2_MAX_H1 or n_h2 > A.T2_MAX_H2:
            return (f"hidden layers {hidden} above T2_MAX_H1/T2_MAX_H2 "
                    f"({A.T2_MAX_H1}/{A.T2_MAX_H2} neurons)")
        nw = A.arch_weight_count(n_h1, n_h2, n_in, n_out, n_hidden=len(hidden))
        if nw > A.MAX_WEIGHT_ENTRIES:
            return f"{nw} weights above MAX_WEIGHT_ENTRIES={A.MAX_WEIGHT_ENTRIES}"
        return None
    if pipeline == "modular":
        import ebpf_modular as M
        dims = layer_dims(hidden, n_in, n_out)
        if len(dims) > M.LAYER_CHAIN_SIZE:
            return (f"{len(dims)} layers above LAYER_CHAIN_SIZE="
                    f"{M.LAYER_CHAIN_SIZE}")
        if dims[0][1] > M.ML1_MAX_H1 or any(max(a, b) > M.MLH_MAX_H
                                            for a, b in dims[1:]):
            return (f"layers {dims} above ML1_MAX_H1/MLH_MAX_H "
                    f"({M.ML1_MAX_H1}/{M.MLH_MAX_H} neurons)")
        nw = sum(a * b + b for a, b in dims)
        if nw > M.MAX_LAYER_WEIGHT_ENTRIES:
            return (f"{nw} weights above MAX_LAYER_WEIGHT_ENTRIES="
                    f"{M.MAX_LAYER_WEIGHT_ENTRIES}")
        return None
    return f"unknown pipeline: {pipeline!r}"
