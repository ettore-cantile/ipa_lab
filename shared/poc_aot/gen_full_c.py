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

# kernel ifindex -> logical port 1..n_interfaces (loader sets ctx->ingress_ifindex = 2)
DEFAULT_IFINDEX_TABLE = [2, 3, 4, 5, 6, 7]


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
    var, expr = _SCALAR_SOURCE[feat["type"]]
    pre = [f"    __u32 {var} = {expr};   /* feature '{feat['type']}' (scalar) */"]
    def term(j):
        return f"(__s64){var} * {_lit(fc1_w[j * n_in + offset])}LL"
    return pre, term


def _feat_dense_vector(feat, offset, n_in, fc1_w, n_h1):
    map_name = _model_meta.FEATURE_CATALOG[feat["type"]]["map"]
    prefix = "ls" if map_name == "link_state" else "qs"
    size = feat["size"]
    lines = [
        f"    /* feature '{feat['type']}': {size} values read with ONE lookup from {map_name} */",
        "    long long " + ", ".join(f"{prefix}{i}=0LL" for i in range(size)) + ";",
        f"    {{ __u32 _z=0; struct {map_name}_vec *_p = bpf_map_lookup_elem(&{map_name}, &_z);",
        "      if (_p) {",
    ]
    for i in range(size):
        lines.append(f"        {prefix}{i}=(long long)_p->v[{i}];")
    lines.append("      } }")
    def term(j):
        return " + ".join(
            f"{prefix}{i} * {_lit(fc1_w[j * n_in + offset + i])}LL" for i in range(size))
    return lines, term


def _feat_onehot_iface(feat, offset, n_in, fc1_w, n_h1, ifindex_table):
    size = feat["size"]
    lines = ["    /* feature 'ingress_iface' (one-hot): raw ifindex -> logical 1..size */",
             "    __u32 _iface = 0U;",
             "    switch (ctx->ingress_ifindex) {"]
    seen = set()
    for logical_idx, kern in enumerate(ifindex_table[:size], start=1):
        ki = int(kern)
        if ki in seen:
            continue
        seen.add(ki)
        lines.append(f"        case {ki}U: _iface = {logical_idx}U; break;")
    lines.append("        default: break;")
    lines.append("    }")
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


def _feat_onehot_node(feat, offset, n_in, fc1_w, n_h1):
    size = feat["size"]
    lines = ["    /* feature 'node' (one-hot): active index = model_id */",
             "    __u32 _node = (__u32)ipa->model_id;  /* switch default zeroes out-of-range */"]
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


def _gen_feature(feat, offset, n_in, fc1_w, n_h1, ifindex_table):
    t = feat["type"]
    kind = _model_meta.FEATURE_CATALOG[t]["kind"]
    if kind == "scalar":
        return _feat_scalar(feat, offset, n_in, fc1_w, n_h1)
    if kind == "dense_vector_map":
        return _feat_dense_vector(feat, offset, n_in, fc1_w, n_h1)
    if kind == "onehot":
        if t == "ingress_iface":
            return _feat_onehot_iface(feat, offset, n_in, fc1_w, n_h1, ifindex_table)
        if t == "node":
            return _feat_onehot_node(feat, offset, n_in, fc1_w, n_h1)
    raise ValueError(f"no C generator for feature type {t!r} (kind {kind!r})")


# ---------------------------------------------------------------------------
# Weight slicing (identical formula to ebpf_program.generate_ebpf_hardcoded).
# ---------------------------------------------------------------------------
def _slices(w, n_in, n_h1, n_h2, n_out):
    fc1_w = w[0:n_in*n_h1]
    fc1_b = w[n_in*n_h1:n_in*n_h1+n_h1]
    b2 = n_in*n_h1+n_h1
    fc2_w = w[b2:b2+n_h1*n_h2]
    fc2_b = w[b2+n_h1*n_h2:b2+n_h1*n_h2+n_h2]
    b3 = b2+n_h1*n_h2+n_h2
    out_w = w[b3:b3+n_h2*n_out]
    out_b = w[b3+n_h2*n_out:b3+n_h2*n_out+n_out]
    return fc1_w, fc1_b, fc2_w, fc2_b, out_w, out_b


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


def _emit_model_body(shape, w, ifindex_table) -> list:
    """IV + MLP + argmax + action body of the tail-called model program (weights
    as literals). ctx/data/eth/ip/udp/ipa are already parsed by the caller-emitted
    _PARSE block (the SECOND parse the dispatcher+tail-call architecture forces)."""
    features = shape["features"]
    n_out = shape["n_out"]
    n_h1, n_h2 = shape["hidden_dims"]
    n_in = shape["n_in"]
    fc1_w, fc1_b, fc2_w, fc2_b, out_w, out_b = _slices(w, n_in, n_h1, n_h2, n_out)

    L = []; A = L.append

    # --- fc1: build the IV feature by feature, in descriptor order ---
    term_fns = []
    offset = 0
    for feat in features:
        pre, term = _gen_feature(feat, offset, n_in, fc1_w, n_h1, ifindex_table)
        L.extend(pre)
        term_fns.append(term)
        offset += feat["size"]

    for j in range(n_h1):
        terms = " + ".join(tf(j) for tf in term_fns)
        A(f"    long long a1_{j} = {terms} + {_lit(fc1_b[j])}LL;")
        A(f"    long long h1_{j} = a1_{j} > 0 ? a1_{j} : 0;")

    for j in range(n_h2):
        terms = " + ".join(f"h1_{i} * {_lit(fc2_w[j*n_h1+i])}LL" for i in range(n_h1))
        A(f"    long long a2_{j} = {terms} + {_lit(fc2_b[j])}LL;")
        A(f"    long long h2_{j} = a2_{j} > 0 ? a2_{j} : 0;")

    for j in range(n_out):
        terms = " + ".join(f"h2_{i} * {_lit(out_w[j*n_h2+i])}LL" for i in range(n_h2))
        A(f"    long long o_{j} = {terms} + {_lit(out_b[j])}LL;")

    A("    long long best_val = o_0; int best_cls = 0;")
    for k in range(1, n_out):
        A(f"    if (o_{k} > best_val) {{ best_val = o_{k}; best_cls = {k}; }}")
    A(f"    if (best_cls >= {n_out - 1}) {{")
    A("        __u32 di = 2; __u64 *dv = bpf_map_lookup_elem(&pkt_stats, &di);")
    A("        if (dv) __sync_fetch_and_add(dv, 1);")
    A("        return XDP_DROP;")
    A("    }")
    A("    __u32 _cls = (__u32)best_cls;")
    A("    struct fwd_action *act = bpf_map_lookup_elem(&mac_table, &_cls);")
    A("    if (act) {")
    A("        __u32 hi = 0; __u64 *hv = bpf_map_lookup_elem(&pkt_stats, &hi);")
    A("        if (hv) __sync_fetch_and_add(hv, 1);")
    A("        __u64 *cv = bpf_map_lookup_elem(&cls_stats, &_cls);")
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
    A("struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16);")
    A("         __type(key, __u32); __type(value, struct fwd_action); } mac_table SEC(\".maps\");")
    A("struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 256);")
    A("         __type(key, __u32); __type(value, __u32); } model_progs SEC(\".maps\");")
    return L


def _emit_arch(shape, w, ifindex_table) -> str:
    """FULL-PATH, ARCHITECTURE-FAITHFUL literal program: dispatcher +
    PROG_ARRAY tail-call + model that RE-parses (double parse) -- same topology
    as the BCC hardcoded path, so BPF_PROG_TEST_RUN on the dispatcher measures
    the identical per-packet work test_suite --kernel measures."""
    feats_str = ", ".join(f"{f['type']}[{f['size']}]" for f in shape["features"])
    n_h1, n_h2 = shape["hidden_dims"]
    L = []; A = L.append
    A("// AUTO-GENERATED by gen_full_c.py (arch-faithful, descriptor-driven) -- do not edit by hand.")
    A("// dispatcher + tail-call + double-parse == BCC hardcoded architecture.")
    A(f"// descriptor: [{feats_str}] -> {shape['n_in']}-{n_h1}-{n_h2}-{shape['n_out']}")
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
    L.extend(_emit_maps(shape))
    A("")
    # --- model program (tail-call target): re-parses, then infers ---
    A("SEC(\"xdp\")")
    A("int xdp_model(struct xdp_md *ctx) {")
    A(_PARSE)
    L.extend(_emit_model_body(shape, w, ifindex_table))
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
    """Resolve (shape, ifindex_table) from a model descriptor + topology, using
    the SAME model_meta logic as the BCC path. With no meta the default
    descriptor [link_state, ingress_iface, ttl, node] / n_out=n_interfaces+1 is
    used -> the historical 65-4-4-7 shape."""
    if meta is None:
        meta = dict(_model_meta.DEFAULT_META)
        if model_path:
            meta = _model_meta.load_model_meta(model_path)
    if topology_config is None:
        topology_config = dict(_model_meta.DEFAULT_TOPOLOGY_CONFIG)
    shape = _model_meta.derive_shape(meta, topology_config=topology_config)

    iface_size = next((f["size"] for f in shape["features"] if f["type"] == "ingress_iface"), 0)
    ifindex_table = list(DEFAULT_IFINDEX_TABLE[:max(iface_size, 1)])
    while len(ifindex_table) < iface_size:
        ifindex_table.append(2)
    return shape, ifindex_table


def generate_arch_literal_c(model_path: str = None, meta: dict = None,
                            topology_config: dict = None) -> str:
    """Importable: the ARCHITECTURE-FAITHFUL literal program (dispatcher +
    tail-call + double-parse), descriptor-driven. Real int8 weights from
    model_path; the descriptor is resolved from `meta`/`topology_config`
    (defaults reproduce the 65-4-4-7 program byte-for-byte)."""
    from extract_weights import extract_weights_int8
    shape, ifindex_table = _resolve_shape(model_path, meta, topology_config)
    n_h1, n_h2 = shape["hidden_dims"]
    n_in, n_out = shape["n_in"], shape["n_out"]
    n_weights = n_in*n_h1 + n_h1 + n_h1*n_h2 + n_h2 + n_h2*n_out + n_out
    w = extract_weights_int8(model_path) if model_path else extract_weights_int8()
    if len(w) != n_weights:
        raise SystemExit(f"expected {n_weights} weights for {n_in}-{n_h1}-{n_h2}-{n_out}, got {len(w)}")
    return _emit_arch(shape, w, ifindex_table)


def main():
    with open(os.path.join(_HERE, "nn_aot_arch.bpf.c"), "w") as f:
        f.write(generate_arch_literal_c())
    shape, _ = _resolve_shape()
    n_h1, n_h2 = shape["hidden_dims"]
    print(f"wrote nn_aot_arch.bpf.c (arch-faithful literal, "
          f"{shape['n_in']}-{n_h1}-{n_h2}-{shape['n_out']}) in {_HERE}")


if __name__ == "__main__":
    main()
