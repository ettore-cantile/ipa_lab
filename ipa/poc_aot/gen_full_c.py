#!/usr/bin/env python3
"""
gen_full_c.py  --  AOT-literal generator for the recompilation PoC.

Emits the ARCHITECTURE-FAITHFUL, weights-literal libbpf program for Pipeline 1:
a dispatcher + PROG_ARRAY tail-call + a model that re-parses (the double parse),
i.e. byte-for-byte the same topology as the BCC hardcoded path
(ipa_switch_hardcoded -> model_progs.call -> model_<id>). Compiled OFFLINE by
clang into a .o, it is the "models known a priori" alternative to BCC's
clang-at-runtime: the datapath node only does open+load at deploy time (~ms, no
clang), and the weights stay C literals so clang -O2's per-weight strength
reduction is preserved -> the full literal performance, identical to BCC.

DESCRIPTOR-DRIVEN (universal AOT-literal)
-----------------------------------------
The input vector is built feature-by-feature from a per-model *descriptor*
(model_meta.FEATURE_CATALOG), exactly like the BCC generator
(ebpf_program.generate_ebpf_hardcoded) -- the three feature kinds are ported
here to the libbpf dialect:

    scalar            -> ttl = ip->ttl                       (packet in transit)
    dense_vector_map  -> ls0..lsN via ONE bpf_map_lookup_elem (link_state / queue_state)
    onehot            -> a single switch selecting one weight (ingress_iface / node)

so ANY descriptor the BCC path accepts is now also AOT-compilable. With no
descriptor the default [link_state, ingress_iface, ttl, node] / n_out=6+1 is
used -> the checked-in 65-4-4-7 program, byte-identical to before.

The loader (loader_aot.c) populates model_progs, seeds the dense-feature maps it
finds (link_state / queue_state) + mac_table, crafts a UDP/IPA frame and
BPF_PROG_TEST_RUNs the dispatcher.

Run:  python3 gen_full_c.py [--dump-default]  -> nn_aot_arch.bpf.c
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_HERE)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

import model_meta as _model_meta

# The kernel ifindex -> logical port mapping is NOT compiled in. It used to be
# DEFAULT_IFINDEX_TABLE = [2, 3, 4, 5, 6, 7], baked into the generated program
# as a switch, which encodes the assumption eth0 == ifindex 2. Kernel ifindexes
# are assigned by the kernel and are arbitrary -- 205, 217, 229 on a box that
# has created a few veths -- so on real hardware no case matched and the
# trained ingress_iface feature contributed nothing.
#
# An AOT program has even less business guessing them than a BCC one: it is
# compiled on a build machine, possibly months before the node it runs on
# exists. The mapping is the `ingress_port` map, filled at load time by the
# loader (or by the Python control plane) from the node's own interfaces.


def _lit(v) -> str:
    return str(int(v))


# ---------------------------------------------------------------------------
# Per-kind feature generators -- libbpf dialect. Each returns (preamble_lines,
# term_fn): the preamble reads the feature value(s) ONCE; term_fn(j) gives the
# C expression of that feature's contribution to hidden neuron j. Mirrors
# ebpf_program._gen_feature_* (BCC dialect) one-to-one; the only differences are
# map access (bpf_map_lookup_elem vs map.lookup) and the u32 map key.
# ---------------------------------------------------------------------------
_SCALAR_SOURCE = {
    "ttl": ("_ttl", "((__u32)ip->ttl) & 0xff"),
}


def _feat_scalar(feat, offset, n_in, fc1_w, n_h1):
    """Scalar feature term, divided by the feature's training scale.

    Mirrors ebpf_program._gen_feature_scalar exactly -- the AOT object must
    compute the same thing as the BCC build or the two Pipeline 1 backends
    disagree. The division applies to the PRODUCT (dividing the TTL itself
    would collapse 10..30 onto 0 or 1); see model_meta.DEFAULT_TTL_SCALE.
    """
    var, expr = _SCALAR_SOURCE[feat["type"]]
    # The scale the descriptor declares for THIS feature, not the catalogue's
    # default for its type -- the same rule as ebpf_program's generator. This
    # read feature_scale(type) after the BCC path had been fixed, so the AOT
    # object -- P1's only deploy path -- ran a ttl/16 model with ttl/30.
    scale = _model_meta.feature_scale_of(feat)
    pre = [f"    __u32 {var} = {expr};   /* feature '{feat['type']}' (scalar) */"]
    def term(j):
        prod = f"(__s64){var} * {_lit(fc1_w[j * n_in + offset])}LL"
        return prod if scale == 1 else f"(({prod}) / {scale}LL)"
    return pre, term


def _feat_dense_vector(feat, offset, n_in, fc1_w, n_h1, static_ports=None):
    """Dense vector read from its map with ONE lookup. With static_ports only
    the columns of ports that exist on the node are generated -- the rule and
    its conditions are ebpf_program._live_slots, imported rather than copied,
    so the two P1 backends cannot disagree on which columns are dead."""
    from ebpf_program import _live_slots
    map_name = _model_meta.FEATURE_CATALOG[feat["type"]]["map"]
    prefix = "ls" if map_name == "link_state" else "qs"
    size = feat["size"]
    live = _live_slots(feat, size, static_ports)
    if len(live) == size:
        head = (f"    /* feature '{feat['type']}': {size} values read with ONE "
                f"lookup from {map_name} */")
    else:
        dead = [i for i in range(size) if i not in live]
        head = (f"    /* feature '{feat['type']}': {len(live)} of {size} slots "
                f"exist on this node ({live}); slots {dead} have no interface "
                f"behind them, are structurally 0, and are not generated. */")
    lines = [
        head,
        "    long long " + ", ".join(f"{prefix}{i}=0LL" for i in live) + ";",
        f"    {{ __u32 _z=0; struct {map_name}_vec *_p = bpf_map_lookup_elem(&{map_name}, &_z);",
        "      if (_p) {",
    ]
    for i in live:
        lines.append(f"        {prefix}{i}=(long long)_p->v[{i}];")
    lines.append("      } }")
    def term(j):
        return " + ".join(
            f"{prefix}{i} * {_lit(fc1_w[j * n_in + offset + i])}LL" for i in live)
    return lines, term


def _feat_onehot_iface(feat, offset, n_in, fc1_w, n_h1):
    size = feat["size"]
    lines = ["    /* feature 'ingress_iface' (one-hot): kernel ifindex -> logical",
             "     * 1..size through the ingress_port map -- a node fact, resolved at",
             "     * load time, not a constant compiled into the program. The WEIGHT",
             "     * switch below stays literal: that is what this generator is for. */",
             "    __u32 _iface = 0U;",
             "    { __u32 _kif = ctx->ingress_ifindex;",
             "      __u32 *_lp = bpf_map_lookup_elem(&ingress_port, &_kif);",
             f"      if (_lp && *_lp >= 1U && *_lp <= {size}U) _iface = *_lp; }}"]
    for j in range(n_h1):
        lines.append(f"    long long w_iface_{j} = 0LL;")
    lines.append("    switch (_iface) {")
    for k in range(1, size + 1):
        assigns = " ".join(
            f"w_iface_{j} = {_lit(fc1_w[j * n_in + offset + (k - 1)])}LL;" for j in range(n_h1))
        lines.append(f"        case {k}: {assigns} break;")
    lines.append("        default: break;")
    lines.append("    }")
    def term(j):
        return f"w_iface_{j}"
    return lines, term


def _feat_onehot_node(feat, offset, n_in, fc1_w, n_h1, static_index=None):
    """Node one-hot. static_index=None: read from the node_id map (P1.5, one
    object for the whole network). static_index=k: frozen at build time (P1,
    one object per node) -- the switch collapses to n_h1 constants that clang
    folds. Same two modes, same refusal, as ebpf_program's generator."""
    size = feat["size"]
    if static_index is not None:
        if not (0 <= static_index < size):
            raise ValueError(
                f"static_node={static_index} outside [0, {size}) for a node "
                f"one-hot of width {size}. Refused rather than silently "
                f"emitting an all-zero column, which would look like a "
                f"working program for a node that is not in the topology.")
        lines = [f"    /* feature 'node' (one-hot) FROZEN at index "
                 f"{static_index} of {size}: no node_id read, no switch. */"]
        for j in range(n_h1):
            lines.append(f"    long long w_node_{j} = "
                         f"{_lit(fc1_w[j * n_in + offset + static_index])}LL;")
        return lines, (lambda j: f"w_node_{j}")
    lines = ["    /* feature 'node' (one-hot): this NODE's index, from the node_id",
             "     * map -- not ipa->model_id, which identifies the MODEL.",
             "     * Bounded to a byte so the verifier reasons about the switch",
             "     * below cheaply; 256 is the unknown sentinel and falls through",
             "     * to the default, setting no weight. */",
             "    __u32 _node = 0x100U;",
             "    { __u32 _nz = 0; __u32 *_nid = bpf_map_lookup_elem(&node_id, &_nz);",
             "      if (_nid && *_nid <= 0xffU) _node = *_nid; }"]
    for j in range(n_h1):
        lines.append(f"    long long w_node_{j} = 0LL;")
    lines.append("    switch (_node) {")
    for k in range(size):
        assigns = " ".join(
            f"w_node_{j} = {_lit(fc1_w[j * n_in + offset + k])}LL;" for j in range(n_h1))
        lines.append(f"        case {k}: {assigns} break;")
    lines.append("        default: break;")
    lines.append("    }")
    def term(j):
        return f"w_node_{j}"
    return lines, term


def _gen_feature(feat, offset, n_in, fc1_w, n_h1, static_node=None,
                 static_ports=None):
    t = feat["type"]
    kind = _model_meta.FEATURE_CATALOG[t]["kind"]
    if kind == "scalar":
        return _feat_scalar(feat, offset, n_in, fc1_w, n_h1)
    if kind == "dense_vector_map":
        return _feat_dense_vector(feat, offset, n_in, fc1_w, n_h1,
                                  static_ports=static_ports)
    if kind == "onehot":
        if t == "ingress_iface":
            return _feat_onehot_iface(feat, offset, n_in, fc1_w, n_h1)
        if t == "node":
            return _feat_onehot_node(feat, offset, n_in, fc1_w, n_h1,
                                     static_index=static_node)
    raise ValueError(f"no C generator for feature type {t!r} (kind {kind!r})")


# ---------------------------------------------------------------------------
# Weight slicing (identical formula to ebpf_program.generate_ebpf_hardcoded).
# ---------------------------------------------------------------------------
def _layer_sizes(shape):
    """[n_in, h1, ..., hk, n_out] -- hidden depth is whatever hidden_dims holds."""
    return ([shape["n_in"]] + [int(d) for d in shape["hidden_dims"]]
            + [shape["n_out"]])


def _weight_count(layer_sizes):
    return sum(layer_sizes[i-1]*layer_sizes[i] + layer_sizes[i]
               for i in range(1, len(layer_sizes)))


def _slices(w, layer_sizes):
    """[(W, B)] per layer. Generic per-layer layout (n_prev*n_cur weights then
    n_cur biases), which reduces to the historical 2-hidden-layer layout."""
    layers = []
    off = 0
    for i in range(1, len(layer_sizes)):
        n_prev, n_cur = layer_sizes[i-1], layer_sizes[i]
        layers.append((w[off:off+n_prev*n_cur],
                       w[off+n_prev*n_cur:off+n_prev*n_cur+n_cur]))
        off += n_prev*n_cur + n_cur
    return layers


_PARSE = """    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    __u8 ip_proto = *((__u8 *)ip + 9);
    if (ip_proto != 17) return XDP_PASS;
    __u32 ihl = (((__u8 *)ip)[0] & 0x0f) << 2;
    if (ihl < 20) return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)((void *)ip + ihl);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;"""


def _emit_model_body(shape, w, scale: int = 1, semantics=None,
                     static_node=None, static_ports=None) -> list:
    """IV + MLP + argmax + action body of the tail-called model program (weights
    as literals). ctx/data/eth/ip/udp/ipa are already parsed by the caller-emitted
    _PARSE block (the SECOND parse the dispatcher+tail-call architecture forces)."""
    features = shape["features"]
    n_out = shape["n_out"]
    n_in = shape["n_in"]
    sizes = _layer_sizes(shape)
    if len(w) != _weight_count(sizes):
        raise ValueError(f"expected {_weight_count(sizes)} weights for "
                         f"{'-'.join(map(str, sizes))}, got {len(w)}")
    if static_ports is not None and static_node is None:
        raise ValueError(
            "static_ports requires static_node: freezing WHICH ports exist is "
            "part of specialising P1 to one node (the same rule as the BCC "
            "generator); P1.5 keeps the model's full feature width.")
    layers = _slices(w, sizes)
    n_hidden = len(sizes) - 2

    L = []; A = L.append
    # Same opening comment as ebpf_program's model function: test/p1_c_eval
    # finds the inference section of either backend by it.
    A("    /* Input vector built locally, features: "
      + ", ".join(f"{f['type']}[{f['size']}]" for f in features) + " */")

    # --- fc1: build the IV feature by feature, in descriptor order ---
    fc1_w, fc1_b = layers[0]
    n_h1 = sizes[1]
    term_fns = []
    offset = 0
    for feat in features:
        pre, term = _gen_feature(feat, offset, n_in, fc1_w, n_h1,
                                 static_node=static_node,
                                 static_ports=static_ports)
        L.extend(pre)
        term_fns.append(term)
        offset += feat["size"]

    # Zero hidden layers -> the first layer already IS the output layer (no ReLU).
    first = "h1" if n_hidden else "o"
    for j in range(n_h1):
        terms = " + ".join(tf(j) for tf in term_fns)
        A(f"    long long a1_{j} = {terms} + {_lit(fc1_b[j])}LL;")
        A(f"    long long {first}_{j} = "
          + (f"a1_{j} > 0 ? a1_{j} : 0;" if n_hidden else f"a1_{j};"))

    # --- remaining layers: hidden ones with ReLU, output layer without ---
    prev = [f"{first}_{j}" for j in range(n_h1)]
    for li in range(1, len(layers)):
        W, B = layers[li]
        n_prev, n_cur = sizes[li], sizes[li + 1]
        is_out = (li == len(layers) - 1)
        pfx = "o" if is_out else f"h{li + 1}"
        for j in range(n_cur):
            terms = " + ".join(f"{prev[i]} * {_lit(W[j*n_prev+i])}LL"
                               for i in range(n_prev))
            # Bias scaled into the accumulator's units: the weights are
            # round(w_float * scale), so this layer's products carry
            # scale**(li+1) while a bias stored the same way carries scale**1.
            # Multiplying by scale**li puts them in the same scale. Computed
            # here, so the object pays nothing at runtime. Mirrors
            # ebpf_program._gen_dense_layer -- the two Pipeline 1 backends must
            # compute the same thing.
            bmul = scale ** li
            if is_out:
                A(f"    long long {pfx}_{j} = {terms} + {_lit(int(B[j]) * bmul)}LL;")
            else:
                A(f"    long long a{li+1}_{j} = {terms} + {_lit(int(B[j]) * bmul)}LL;")
                A(f"    long long {pfx}_{j} = a{li+1}_{j} > 0 ? a{li+1}_{j} : 0;")
        prev = [f"{pfx}_{j}" for j in range(n_cur)]

    A("    long long best_val = o_0; int best_cls = 0;")
    for k in range(1, n_out):
        A(f"    if (o_{k} > best_val) {{ best_val = o_{k}; best_cls = {k}; }}")
    # class -> action -> logical port, GENERATED from the descriptor. Mirrors
    # ebpf_program._gen_class_dispatch: the two Pipeline 1 backends must emit
    # the same semantics, or the AOT object and the BCC build disagree.
    # The previous `best_cls >= n_out - 1` hardcoded both that DROP is the last
    # class and that a class index is a port index. Neither holds.
    A("    /* --- class -> action -> logical port (from the model descriptor) --- */")
    A("    __u32 _port = 0xffffffffU;")
    A("    switch (best_cls) {")
    for cid in range(n_out):
        spec = semantics.classes[cid]
        if spec.action == "FORWARD":
            A(f"    case {cid}: _port = {spec.port}U; break;"
              f"   /* FORWARD -> logical port {spec.port} */")
        elif spec.action == "DROP":
            # The class was decided: record it, as the BCC build does, so a
            # DROP is distinguishable from a program that never reached argmax
            # and the two P1 backends report the same counters.
            A(f"    case {cid}: {{   /* DROP (declared) */")
            A("        __u32 di = 2; __u64 *dv = bpf_map_lookup_elem(&pkt_stats, &di);")
            A("        if (dv) __sync_fetch_and_add(dv, 1);")
            A(f"        __u32 dc = {cid}U;")
            A("        __u64 *dcv = bpf_map_lookup_elem(&cls_stats, &dc);")
            A("        if (dcv) __sync_fetch_and_add(dcv, 1);")
            A("        return XDP_DROP;")
            A("    }")
        else:
            A(f"    case {cid}: {{   /* UNUSED */")
            A("        __u32 ui = 1; __u64 *uv = bpf_map_lookup_elem(&pkt_stats, &ui);")
            A("        if (uv) __sync_fetch_and_add(uv, 1);")
            A(f"        __u32 uc = {cid}U;")
            A("        __u64 *ucv = bpf_map_lookup_elem(&cls_stats, &uc);")
            A("        if (ucv) __sync_fetch_and_add(ucv, 1);")
            A("        return XDP_PASS;")
            A("    }")
    A("    default: {   /* argmax outside [0, n_out) */")
    A("        __u32 xi = 1; __u64 *xv = bpf_map_lookup_elem(&pkt_stats, &xi);")
    A("        if (xv) __sync_fetch_and_add(xv, 1);")
    A("        return XDP_PASS;")
    A("    }")
    A("    }")
    A("    if (_port == 0xffffffffU) {")
    A("        __u32 xi = 1; __u64 *xv = bpf_map_lookup_elem(&pkt_stats, &xi);")
    A("        if (xv) __sync_fetch_and_add(xv, 1);")
    A("        return XDP_PASS;")
    A("    }")
    A("    /* mac_table is keyed by LOGICAL PORT, not by class. */")
    A("    /* mac_table is keyed by LOGICAL PORT, cls_stats by CLASS. */")
    A("    struct fwd_action *act = bpf_map_lookup_elem(&mac_table, &_port);")
    A("    if (act && act->ifindex != 0) {   /* ARRAY: never NULL; ifindex==0 => unprovisioned */")
    A("        /* A hop must not forward a packet whose TTL would reach 0.")
    A("         * Counted as MISS and handed to the kernel, which emits the")
    A("         * ICMP Time Exceeded. Mirrors the BCC pipelines exactly. */")
    A("        if (ip->ttl <= 1) {")
    A("            __u32 ti = 1; __u64 *tv = bpf_map_lookup_elem(&pkt_stats, &ti);")
    A("            if (tv) __sync_fetch_and_add(tv, 1);")
    A("            return XDP_PASS;")
    A("        }")
    A("        ipa_ttl_dec(ip);")
    A("        __u32 hi = 0; __u64 *hv = bpf_map_lookup_elem(&pkt_stats, &hi);")
    A("        if (hv) __sync_fetch_and_add(hv, 1);")
    A("        __u32 _cs_key = (__u32)best_cls;")
    A("        __u64 *cv = bpf_map_lookup_elem(&cls_stats, &_cs_key);")
    A("        if (cv) __sync_fetch_and_add(cv, 1);")
    A("        __builtin_memcpy(eth->h_source, act->src_mac, 6);")
    A("        __builtin_memcpy(eth->h_dest,   act->dst_mac, 6);")
    A("        return bpf_redirect(act->ifindex, 0);")
    A("    }")
    A("    __u32 mi = 1; __u64 *mv = bpf_map_lookup_elem(&pkt_stats, &mi);")
    A("    if (mv) __sync_fetch_and_add(mv, 1);")
    A("    return XDP_PASS;")
    return L


def _emit_maps(shape) -> list:
    """Map + struct declarations (libbpf dialect). Dense-feature maps are emitted
    only for the dense_vector_map features present in the descriptor, sized from
    the topology; the always-on maps (pkt_stats/cls_stats/mac_table/model_progs)
    are unconditional."""
    n_out = shape["n_out"]
    L = []; A = L.append
    for f in shape["features"]:
        entry = _model_meta.FEATURE_CATALOG[f["type"]]
        if entry["kind"] == "dense_vector_map":
            m = entry["map"]
            A("struct %s_vec { __u32 v[%d]; };" % (m, f["size"]))
            A("struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);")
            A("         __type(key, __u32); __type(value, struct %s_vec); } %s SEC(\".maps\");" % (m, m))
    A("struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 3);")
    A("         __type(key, __u32); __type(value, __u64); } pkt_stats SEC(\".maps\");")
    A("struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, %d);" % n_out)
    A("         __type(key, __u32); __type(value, __u64); } cls_stats SEC(\".maps\");")
    A("struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 16);")
    A("         __type(key, __u32); __type(value, struct fwd_action); } mac_table SEC(\".maps\");")
    A("struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 256);")
    A("         __type(key, __u32); __type(value, __u32); } model_progs SEC(\".maps\");")
    A("/* kernel ingress ifindex -> LOGICAL PORT (1-based; absent contributes")
    A(" * nothing). The ingress-side mirror of mac_table: which interface")
    A(" * realises which port is a node fact, and an AOT program is compiled")
    A(" * before the node exists. */")
    A("struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);")
    A("         __type(key, __u32); __type(value, __u32); } ingress_port SEC(\".maps\");")
    A("/* This node's index in the node one-hot, written by the loader at")
    A(" * attach time. It used to come from ipa->model_id -- the packet's")
    A(" * MODEL id, which is not a node identity: the same packet carries it")
    A(" * along its whole path, so every node fired the same slot and 52 of")
    A(" * the 65 inputs carried nothing.")
    A(" *")
    A(" * A HASH, not an ARRAY: an array is pre-allocated and zero-filled, so")
    A(" * a lookup always succeeds and \"not installed\" reads back as node 0.")
    A(" */")
    A("struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1);")
    A("         __type(key, __u32); __type(value, __u32); } node_id SEC(\".maps\");")
    return L


def _emit_arch(shape, w, scale: int = 1, semantics=None, static_node=None,
               static_ports=None, models=None) -> str:
    """FULL-PATH, ARCHITECTURE-FAITHFUL literal program: dispatcher +
    PROG_ARRAY tail-call + model that RE-parses (double parse) -- same topology
    as the BCC hardcoded path, so BPF_PROG_TEST_RUN on the dispatcher measures
    the identical per-packet work test_suite --kernel measures.

    One model: `xdp_model`, wired by loader_aot at model_progs[0].
    models=[(model_id, weights, scale), ...]: one `xdp_model_<id>` each, all
    sharing descriptor, shape and semantics (as build_combined_hardcoded_source
    requires for BCC); loader_aot wires each at model_progs[<id>].
    static_node / static_ports: P1 specialised to one node, see
    _feat_onehot_node and _feat_dense_vector."""
    if models is None:
        models = [(None, w, scale)]
    feats_str = ", ".join(f"{f['type']}[{f['size']}]" for f in shape["features"])
    shape_str = "-".join(str(s) for s in _layer_sizes(shape))
    L = []; A = L.append
    A("// AUTO-GENERATED by gen_full_c.py (arch-faithful, descriptor-driven) -- do not edit by hand.")
    A("// dispatcher + tail-call + double-parse == BCC hardcoded architecture.")
    A(f"// descriptor: [{feats_str}] -> {shape_str}")
    A("#include <linux/bpf.h>")
    A("#include <linux/if_ether.h>")
    A("#include <linux/ip.h>")
    A("#include <linux/udp.h>")
    A("#include <linux/in.h>")
    A("#include <bpf/bpf_helpers.h>")
    A("#include <bpf/bpf_endian.h>")
    A("")
    A("struct ipa_hdr {")
    A("    __u8 model_id; __u8 model_type; __u8 param_size; __be16 scale_factor;")
    A("    __u8 input_size; __u8 output_size; __u8 hidden_layers; __u8 neurons_per_layer;")
    A("    __u8 n_feature_types;")
    A("    __u8 f0c,f0n,f1c,f1n,f2c,f2n,f3c,f3n; __u8 n_output_types; __u8 o0c,o0n;")
    A("} __attribute__((packed));")
    A("struct fwd_action { __u32 ifindex; __u8 src_mac[6]; __u8 dst_mac[6]; } __attribute__((packed));")
    A("")
    A("/* TTL decrement for a forwarding hop, with the RFC 1624 incremental")
    A(" * checksum fix -- same helper as the BCC pipelines (see ebpf_program.py).")
    A(" * A redirecting node is a router hop: without this a forwarding loop")
    A(" * never expires. */")
    A("static __always_inline void ipa_ttl_dec(struct iphdr *iph) {")
    A("    __u32 _c = (__u32)iph->check;")
    A("    _c += (__u32)bpf_htons(0x0100);")
    A("    iph->check = (__u16)(_c + (_c >= 0xFFFF));")
    A("    iph->ttl--;")
    A("}")
    A("")
    L.extend(_emit_maps(shape))
    A("")
    # --- model program(s) (tail-call targets): re-parse, then infer ---
    for mid, mw, mscale in models:
        A("SEC(\"xdp\")")
        A("int xdp_model(struct xdp_md *ctx) {" if mid is None
          else f"int xdp_model_{int(mid)}(struct xdp_md *ctx) {{")
        A(_PARSE)
        L.extend(_emit_model_body(shape, mw, mscale, semantics,
                                  static_node=static_node,
                                  static_ports=static_ports))
        A("}")
        A("")
    # --- dispatcher (entry): parses, tail-calls model_progs[model_id] ---
    A("SEC(\"xdp\")")
    A("int xdp_dispatch(struct xdp_md *ctx) {")
    A(_PARSE)
    A("    __u32 mid = (__u32)ipa->model_id;")
    A("    bpf_tail_call(ctx, &model_progs, mid);")
    A("    return XDP_PASS;   // only if model_id has no registered program")
    A("}")
    A("")
    A("char _license[] SEC(\"license\") = \"GPL\";")
    return "\n".join(L) + "\n"


def _resolve_shape(model_path=None, meta=None, topology_config=None):
    """Resolve the shape from a model descriptor + topology, using
    the SAME model_meta logic as the BCC path. With no meta the default
    descriptor [link_state, ingress_iface, ttl, node], n_out from it, is
    used -> the historical 65-4-4-7 shape."""
    if meta is None:
        meta = dict(_model_meta.DEFAULT_META)
        if model_path:
            meta = _model_meta.load_model_meta(model_path)
    if topology_config is None:
        topology_config = _model_meta.load_topology_config()
    shape = _model_meta.derive_shape(meta, topology_config=topology_config)

    return shape


def generate_arch_literal_c(model_path: str = None, meta: dict = None,
                            topology_config: dict = None, semantics=None) -> str:
    """Importable: the ARCHITECTURE-FAITHFUL literal program (dispatcher +
    tail-call + double-parse), descriptor-driven. Real int8 weights from
    model_path; the descriptor is resolved from `meta`/`topology_config`
    (defaults reproduce the 65-4-4-7 program byte-for-byte)."""
    shape = _resolve_shape(model_path, meta, topology_config)
    sizes = _layer_sizes(shape)
    n_weights = _weight_count(sizes)
    # Weights AND scale from the same function the BCC build uses
    # (ebpf_program.load_and_generate), so the two P1 backends cannot compile
    # different numbers. The scale used to be read from ipa/weights_float.json
    # whatever the checkpoint: right for the checked-in model, which lives
    # there, and wrong for any other -- load_and_generate reads the file next
    # to the checkpoint, or derives it from the .pt.
    from ebpf_program import load_and_generate
    _meta = meta if meta is not None else (
        _model_meta.load_model_meta(model_path) if model_path
        else dict(_model_meta.DEFAULT_META))
    _, w, scale = load_and_generate(
        model_path or _model_meta.default_checkpoint(), meta=_meta,
        topology_config=shape["topology_config"])
    if len(w) != n_weights:
        raise SystemExit(f"expected {n_weights} weights for "
                         f"{'-'.join(map(str, sizes))}, got {len(w)}")
    # Class semantics: declared, not inferred. With no argument the shared
    # resolver reads the descriptor and announces any fallback, so the AOT
    # object and the BCC build resolve it identically.
    if semantics is None:
        from model_meta import descriptor_semantics_or_reference
        semantics = descriptor_semantics_or_reference(sizes[-1], "AOT")
    semantics.validate()
    if semantics.n_out != sizes[-1]:
        raise SystemExit(f"class semantics declare n_out={semantics.n_out} but "
                         f"the model outputs {sizes[-1]}")
    return _emit_arch(shape, w, scale, semantics)


def generate_meta_header(semantics=None) -> str:
    """Emit nn_aot_meta.h: the class semantics the loader must seed against.

    loader_aot.c is C with no JSON parser, so it used to seed mac_table for
    classes 0..n_out-2 -- re-deriving "DROP is the last class" and "class k is
    a forwarding class" in a third language. It now seeds exactly the LOGICAL
    PORTS this model can select, generated from the same ClassSemantics object
    the datapath switch is generated from.
    """
    if semantics is None:
        shape = _resolve_shape()
        from model_meta import descriptor_semantics_or_reference
        semantics = descriptor_semantics_or_reference(_layer_sizes(shape)[-1],
                                                      "AOT/meta")
    ports = semantics.logical_ports
    L = ["/* GENERATED by gen_full_c.py -- do not edit. */",
         "#ifndef NN_AOT_META_H",
         "#define NN_AOT_META_H",
         "",
         f"#define AOT_N_OUT      {semantics.n_out}",
         f"#define AOT_N_PORTS    {len(ports)}",
         ("#define AOT_LOGICAL_PORTS { "
          + ", ".join(str(p) for p in ports) + " }") if ports else
         "#define AOT_LOGICAL_PORTS { 0 }   /* no forwarding class */",
         ""]
    for cid in range(semantics.n_out):
        L.append(f"/* class {cid}: {semantics.classes[cid].describe()} */")
    L += ["", "#endif", ""]
    return "\n".join(L)


def main():
    with open(os.path.join(_HERE, "nn_aot_arch.bpf.c"), "w") as f:
        f.write(generate_arch_literal_c())
    with open(os.path.join(_HERE, "nn_aot_meta.h"), "w") as f:
        f.write(generate_meta_header())
    shape = _resolve_shape()
    print(f"wrote nn_aot_arch.bpf.c + nn_aot_meta.h (arch-faithful literal, "
          f"{'-'.join(map(str, _layer_sizes(shape)))}) in {_HERE}")


if __name__ == "__main__":
    main()
