"""
pipeline_setup.py -- load ANY model into any pipeline, the same way for every
test and bench.

The setup_* functions of verify_prog_run build the pipelines for the
configured checkpoint: the 65-4-4-7 shape, its descriptor and its class
semantics are written into them. verify_synth_kernel had its own builders for
the synthetic models. This module is those builders, moved here and fed a
model_source.Model, so a test that is handed another model or another network
loads it through the same code path the three-way comparison already proves.

    setup = build("template", model, node_index=7)
    register_model_id(setup, 190)          # the id pktgen writes
    set_node(setup, 7); set_ingress(setup, ifindex, 1)
    seed_inputs(setup)                     # link_state all up, queues empty
    cls, _ = reference(model, ttl=30, ...)  # what the datapath must decide

The dictionary is the one the verify_prog_run setups return (b, fn, disp,
weights, scale, cls_stats, pkt_stats, pipeline, progs, n_tail), plus "model".

Pipelines: baseline, p1_static (P1, node frozen in the object), hardcoded
(P1.5, node from the node_id map), template (P2), modular (P3).
"""
import ctypes as ct
import os
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pipeline_limits  # noqa: E402

PIPELINE_NUM = {"baseline": 0, "p1_static": 1, "hardcoded": 1,
                "template": 2, "modular": 3}
MAC_NAME = {0: "mac_table", 1: "mac_table", 2: "mac_table_t2",
            3: "mac_table_t3"}
INGRESS_NAME = {1: "ingress_port", 2: "ingress_port_t2",
                3: "ingress_port_t3"}
NODEID_NAME = {1: "node_id", 2: "node_id_t2", 3: "node_id_t3"}


# A map the program does not declare: KeyError from BCC, PinnedMapError (a
# RuntimeError) from the AOT object's pinned maps.
_MISSING_MAP = (KeyError, RuntimeError)


class NotApplicable(Exception):
    """The pipeline refuses this model (a compiled ceiling, or the verifier).
    Not a datapath failure: callers report it apart from the results."""


# --------------------------------------------------------------------------
# where the node and the ingress port sit, for THIS model
# --------------------------------------------------------------------------
def node_index_for(model, preferred=7):
    """A node index inside this model's node one-hot (None if it has none).
    `preferred` is kept when it fits: 7 is what the fabric has always
    claimed, and a network of 4 nodes gets 3."""
    f = model.feature("node")
    if f is None:
        return None
    return min(int(preferred), int(f["size"]) - 1)


def ingress_slot_for(model, preferred=1):
    """A 1-based logical ingress port inside the ingress_iface one-hot, or
    None if the model has no such feature."""
    f = model.feature("ingress_iface")
    if f is None:
        return None
    return max(1, min(int(preferred), int(f["size"])))


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------
def build(pipeline, model, node_index=None, instrument=False):
    """Load `model` into `pipeline`. node_index is frozen into the object for
    p1_static and ignored by the others (they read the node_id map, see
    set_node). instrument=True builds the lookup-counting variant (every
    map lookup wrapped by a per-CPU counter, lookup_ctr) instead of the
    measured program -- the build count_lookups uses."""
    if pipeline not in PIPELINE_NUM:
        raise ValueError(f"pipeline sconosciuta: {pipeline!r}")
    why = pipeline_limits.why_not(pipeline, model.hidden, model.n_in,
                                  model.n_out)
    if why:
        raise NotApplicable(why)
    if pipeline == "baseline":
        setup = _build_baseline(model, instrument)
    elif pipeline in ("p1_static", "hardcoded"):
        if pipeline == "p1_static" and node_index is None:
            node_index = node_index_for(model)
        setup = _build_p1(model, node_index if pipeline == "p1_static"
                          else None, instrument)
    elif pipeline == "template":
        setup = _build_p2(model, instrument)
    else:
        setup = _build_p3(model, instrument)
    setup["model"] = model
    setup["pipeline_name"] = pipeline
    return setup


def _install_mac(b, pl, model):
    from verify_prog_run import _install_mac_table
    _install_mac_table(b, MAC_NAME[pl], semantics=model.semantics)


def _source(raw, instrument):
    """The BCC source as compiled: the lookup-counting rewrite when asked."""
    if not instrument:
        return raw
    from common import instrument_map_lookups
    return "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(raw)


def _build_baseline(model, instrument=False):
    """The floor: parse, TTL, redirect on a fixed class, no model. It reads
    nothing of the model; the model only decides how many ports exist."""
    from bcc import BPF
    import verify_prog_run as V
    b = BPF(text=_source(V.EBPF_BASELINE, instrument))
    fn = b.load_func("xdp_baseline", BPF.XDP)
    _install_mac(b, 0, model)
    return {"b": b, "fn": fn, "disp": fn,
            "weights": model.weights, "scale": model.scale,
            "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"],
            "pipeline": 0, "progs": {"xdp_baseline": fn.fd}, "n_tail": 0}


def _build_p1(model, static_node, instrument):
    import p1_aot
    try:
        setup = p1_aot.load_p1(
            [(0, model.weights, model.scale)], instrument=instrument,
            hidden_dims=tuple(model.hidden), features=model.features,
            n_out=model.n_out, semantics=model.semantics,
            static_node=static_node)
    except ValueError as e:
        raise NotApplicable(f"P1: {e}")
    setup.update(weights=model.weights, scale=model.scale,
                 static_node=static_node)
    setup.setdefault("n_tail", 1)
    _install_mac(setup["b"], 1, model)
    return setup


def _build_p2(model, instrument=False):
    from bcc import BPF
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                    build_arch_leaf)
    b = BPF(text=_source("#define IPA_ARCH_COMBINED 1\n"
                         + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n"
                         + build_arch_leaf(len(model.hidden)), instrument))
    disp = b.load_func("ipa_switch_template", BPF.XDP)
    leaf = b.load_func("arch_generic_2layer", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
    setup = {"b": b, "fn": leaf, "disp": disp,
             "weights": model.weights, "scale": model.scale,
             "cls_stats": b["cls_stats_t2"], "pkt_stats": b["pkt_stats_t2"],
             "pipeline": 2, "n_tail": 1,
             "progs": {"ipa_switch_template": disp.fd,
                       "arch_generic_2layer": leaf.fd}}
    register_model_id(setup, 0, model)
    _install_mac(b, 2, model)
    return setup


def _build_p3(model, instrument=False):
    from bcc import BPF
    from ebpf_modular import EBPF_MODULAR_FULL, LAYER_CHAIN_SIZE
    b = BPF(text=_source(EBPF_MODULAR_FULL, instrument))
    disp = b.load_func("modular_dispatcher", BPF.XDP)
    first = b.load_func("layer_first", BPF.XDP)
    hidden = b.load_func("layer_hidden", BPF.XDP)
    # slot 0 = layer_first (always hop 0), later slots = layer_hidden
    b["layer_chain"][ct.c_int(0)] = ct.c_int(first.fd)
    for i in range(1, LAYER_CHAIN_SIZE):
        b["layer_chain"][ct.c_int(i)] = ct.c_int(hidden.fd)
    n_layers = len(model.layer_dims)
    setup = {"b": b, "fn": hidden, "fn_first": first, "disp": disp,
             "weights": model.weights, "scale": model.scale,
             "cls_stats": b["cls_stats_t3"], "pkt_stats": b["pkt_stats_t3"],
             "pipeline": 3, "last_layer_idx": n_layers - 1,
             # dispatcher -> layer_first -> layer_hidden x (n_layers - 1)
             "n_tail": n_layers,
             "progs": {"modular_dispatcher": disp.fd,
                       "layer_first": first.fd, "layer_hidden": hidden.fd}}
    register_model_id(setup, 0, model)
    _install_mac(b, 3, model)
    return setup


# --------------------------------------------------------------------------
# after the build
# --------------------------------------------------------------------------
def register_model_id(setup, model_id, model=None):
    """Make the model answer to `model_id` as well (pktgen writes 190).
    Same weights, same descriptor, same semantics as model_id 0."""
    model = model or setup["model"]
    b, pl = setup["b"], setup["pipeline"]
    if pl == 0:
        return
    if pl == 1:
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(setup["fn"].fd)
        return
    try:
        if pl == 2:
            from ebpf_template_arch import load_arch_weights
            h = model.hidden
            load_arch_weights(b, model.weights, model_id=model_id,
                              scale=model.scale, n_h1=h[0],
                              n_h2=h[1] if len(h) > 1 else h[0],
                              features=model.features, n_in=model.n_in,
                              semantics=model.semantics, n_hidden=len(h))
        else:
            from ebpf_modular import load_modular_weights
            load_modular_weights(b, model.weights, model_id=model_id,
                                 scale=model.scale,
                                 layer_dims=model.layer_dims,
                                 features=model.features,
                                 semantics=model.semantics)
    except ValueError as e:
        raise NotApplicable(f"P{pl}: {e}")


def set_node(setup, node_index):
    """This node's index, for the pipelines that read it from a map."""
    pl = setup["pipeline"]
    if pl == 0 or node_index is None or setup.get("static_node") is not None:
        return
    setup["b"][NODEID_NAME[pl]][ct.c_uint32(0)] = ct.c_uint32(int(node_index))


def set_ingress(setup, ifindex, slot):
    """Kernel ifindex -> 1-based logical ingress port."""
    pl = setup["pipeline"]
    if pl == 0 or slot is None:
        return
    try:
        tab = setup["b"][INGRESS_NAME[pl]]
    except _MISSING_MAP:
        return          # P1 without an ingress_iface feature has no map
    tab[ct.c_uint32(int(ifindex))] = ct.c_uint32(int(slot))


def seed_inputs(setup, link_state=None, queues=None):
    """Write the node-state features: link_state (default: every link up)
    and queue_state (default: empty), as wide as THIS model reads them."""
    from common import write_vector_map
    model = setup["model"]
    b = setup["b"]
    f = model.feature("link_state")
    if f is not None:
        vals = [1] * f["size"] if link_state is None else list(link_state)
        _write_if_present(write_vector_map, b, "link_state", vals)
    f = model.feature("queue_occupancy")
    if f is not None:
        vals = [0] * f["size"] if queues is None else list(queues)
        _write_if_present(write_vector_map, b, "queue_state", vals)


def _write_if_present(write, b, name, vals):
    try:
        b[name]
    except _MISSING_MAP:
        return
    write(b, name, vals)


def reference(model, ttl, link_state=None, ingress_port=0, node_index=None,
              queues=None):
    """(class, logit) the datapath must produce: verify_prog_run's generic
    reference, which on the checkpoint equals its 65-4-4-7 one exactly."""
    import verify_prog_run as V
    maps = {}
    f = model.feature("link_state")
    if f is not None:
        maps["link_state"] = ([1] * f["size"] if link_state is None
                              else list(link_state))
    f = model.feature("queue_occupancy")
    if f is not None:
        maps["queue_state"] = [0] * f["size"] if queues is None else list(queues)
    return V.ref_infer_sparse(model.weights, model.features, model.hidden,
                              model.n_out, ttl, 0, maps,
                              ingress_port=ingress_port, scale=model.scale,
                              node_index=node_index)
