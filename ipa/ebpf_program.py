"""ebpf_program.py -- Pipeline 1 (P1): the model compiled into the program.

Generates the C source of a program whose weights are literals, fully
unrolled: no map lookup for the weights. The node loads the object compiled
offline (p1_aot.py, poc_aot/).
"""

import os
import model_meta as _model_meta

def reference_shape():
    """{n_in, n_out, hidden_dims, n_weights} of the configured model."""
    import model_meta as _mm
    sh = _mm.derive_shape(
        _mm.load_model_meta(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "weights.json")),
        topology_config=_mm.load_topology_config())
    dims = list(sh["hidden_dims"])
    sizes = [sh["n_in"]] + dims + [sh["n_out"]]
    n_w = sum(sizes[i] * sizes[i + 1] + sizes[i + 1] for i in range(len(sizes) - 1))
    return {"n_in": sh["n_in"], "n_out": sh["n_out"],
            "hidden_dims": dims, "n_weights": n_w}

_COMMON_STRUCTS = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct ipa_hdr {
    __u8   model_id;
    __u8   model_type;
    __u8   param_size;
    __be16 scale_factor;
    __u8   input_size;
    __u8   output_size;
    __u8   hidden_layers;
    __u8   neurons_per_layer;
    __u8   n_feature_types;
    __u8   feat0_code;  __u8 feat0_count;
    __u8   feat1_code;  __u8 feat1_count;
    __u8   feat2_code;  __u8 feat2_count;
    __u8   feat3_code;  __u8 feat3_count;
    __u8   n_output_types;
    __u8   out0_code;   __u8 out0_count;
} __attribute__((packed));

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

/* ---- TTL handling for a forwarding hop -----------------------------------
 * A node that redirects a packet IS a router hop and must decrement the TTL,
 * or a forwarding loop never dies. Until this existed the datapath read
 * ip->ttl as a model feature and never wrote it: a redirected packet kept its
 * TTL forever, which on this topology produced a permanent loop between two
 * adjacent nodes instead of the packet eventually expiring.
 *
 * Incremental checksum fix per RFC 1624, in the canonical form used by the
 * kernel's own samples/bpf/xdp_fwd_kern.c. TTL is the high byte of the
 * {ttl,protocol} 16-bit word, so decrementing it subtracts 0x0100 from that
 * word; the one's-complement checksum is corrected by adding htons(0x0100)
 * and folding the carry back in.
 *
 * Called ONLY on the forwarding path, AFTER inference: the model must see the
 * TTL as received, which is what the Python reference replicates. */
static inline __attribute__((always_inline))
void ipa_ttl_dec(struct iphdr *iph) {
    __u32 _c = (__u32)iph->check;
    _c += (__u32)bpf_htons(0x0100);
    iph->check = (__u16)(_c + (_c >= 0xFFFF));
    iph->ttl--;
}

#ifdef IPA_COUNT_LOOKUPS
BPF_PERCPU_ARRAY(lookup_ctr, __u64, 1);
static inline __attribute__((always_inline)) void ctr_inc(void) {
    int _lci = 0;
    __u64 *_lcv = lookup_ctr.lookup(&_lci);
    if (_lcv) *_lcv += 1;   /* per-CPU: no atomic needed */
}
#define CTR_INC() ctr_inc()
#else
#define CTR_INC() do {} while (0)
#endif

static __always_inline long long ipa_relu(long long x) {
    long long m = x >> 63;
    asm volatile("" : "+r"(m));
    return x & ~m;
}
#define RELU_LL(x)    ipa_relu(x)
"""

EBPF_HARDCODED_DISPATCHER = r"""
int ipa_switch_hardcoded(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr  *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr   *ip  = (struct iphdr *)(eth + 1);
    if ((void *)(ip  + 1) > data_end) return XDP_PASS;

    __u8 ip_proto = *((__u8 *)ip + 9);
    if (ip_proto != IPPROTO_UDP) return XDP_PASS;

    __u32 _ip_hlen = (((__u8 *)ip)[0] & 0x0fU) << 2U;
    if (_ip_hlen < 20U) return XDP_PASS;
    struct udphdr  *udp = (struct udphdr *)((void *)ip + _ip_hlen);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;

    __u32 mid = (__u32)ipa->model_id;
    model_progs.call(ctx, mid);
    return XDP_PASS;   /* reached only if model_id has no registered program */
}
"""


def _build_header(dense_vector_maps: dict, n_out: int,
                  semantics=None) -> str:
    """Build the map/struct declarations for a combined hardcoded source."""
    map_decls = ""
    for map_name, size in sorted(dense_vector_maps.items()):
        map_decls += (
            f"/* {map_name}: {size} per-slot values for a dense_vector feature, held in\n"
            f" * ONE struct-valued entry (key 0) so the datapath reads the whole vector\n"
            f" * with a SINGLE bpf_map_lookup_elem instead of {size}. Written by the\n"
            f" * userspace seeder ({map_name}_monitor.py). INPUT feature, not a weight. */\n"
            f"struct {map_name}_vec {{ __u32 v[{size}]; }};\n"
            f"BPF_ARRAY({map_name}, struct {map_name}_vec, 1);\n"
        )
    if semantics is not None:
        _ports = semantics.logical_ports
        mac_capacity = max(8, (max(_ports) + 1) if _ports else 0)
    else:
        mac_capacity = max(8, n_out)
    return _COMMON_STRUCTS + f"""
{map_decls}BPF_PERCPU_ARRAY(pkt_stats,        __u64, 3);   /* [0]=hit [1]=miss(no mac_table entry) [2]=drop */
BPF_PERCPU_ARRAY(cls_stats,        __u64, {n_out});   /* per-class redirect counter */

/* mac_table: LOGICAL PORT (what the class semantics map the argmax output
 * onto) -> {{ifindex, src/dst MAC}}.
 * Same struct/role as P2/P3's mac_table_t2/t3 -- the NN decides the port,
 * this only resolves the L2 next-hop and rewrites the Ethernet header
 * before bpf_redirect(). A BPF_ARRAY (not a hash): the key is the dense
 * logical port index, so a direct O(1) array index is both correct and
 * cheaper than hashing. Unlike a hash, an ARRAY lookup NEVER returns NULL
 * (every slot exists, zero-initialised), so "class not provisioned" is
 * detected by ifindex==0 (never a valid egress ifindex) instead of NULL. */
BPF_ARRAY(mac_table, struct fwd_action, {mac_capacity});

/* Kernel ingress ifindex -> LOGICAL PORT (1-based; absent contributes nothing).
 *
 * This replaces a compile-time `ifindex_table`, baked into the generated
 * switch as `case 2: _iface = 1; case 3: _iface = 2; ...`. That table encoded
 * the assumption eth0 == ifindex 2, which holds on a freshly booted machine
 * and nowhere else: on a box that has created a few veths the ingress arrives
 * with ifindex 207, no case matches, and the trained ingress_iface feature
 * silently contributes nothing. Which interface realises which logical port is
 * a NODE fact, resolved at runtime -- the same reason mac_table is a map. */
BPF_HASH(ingress_port, __u32, __u32, 64);
/* This node's index in the node one-hot, written by the control plane at
 * deploy time (a node fact, like mac_table and ingress_port).
 *
 * A HASH and not an ARRAY, deliberately: a BPF_ARRAY is pre-allocated and
 * zero-filled, so a lookup always succeeds and "nothing installed" reads back
 * as node 0 -- indistinguishable from a real node 0, which is the very defect
 * this map exists to remove. With a hash, absent means absent.
 */
BPF_HASH(node_id, __u32, __u32, 1);

/* model_progs: dispatcher -> model_<id>, indexed directly by ipa->model_id.
 * A single tail call, matching the design-space spec's hardcoded pipeline
 * ("packet -> dispatcher -> tail call -> model_<id> -> action"). */
BPF_PROG_ARRAY(model_progs, 256);
"""


def _lit(v) -> str:
    return str(int(v))


def _gen_dense_layer(prev_terms: list, n_cur: int, w: list, b: list,
                     out_prefix: str, relu: bool, bias_mul: int = 1) -> list:
    """Emit `n_cur` neurons of a fully-connected layer as single-expression C
    statements."""
    n_prev = len(prev_terms)
    lines = []
    for j in range(n_cur):
        terms = " + ".join(
            f"{prev_terms[i]} * {_lit(w[j * n_prev + i])}LL" for i in range(n_prev)
        )
        bias = _lit(int(b[j]) * bias_mul)
        expr = f"{terms} + {bias}LL"
        if relu:
            lines.append(f"    long long {out_prefix}_{j} = RELU_LL({expr});")
        else:
            lines.append(f"    long long {out_prefix}_{j} = {expr};")
    return lines


def _gen_argmax(n_out: int, out_prefix: str = "out") -> list:
    lines = [f"    long long best_val = {out_prefix}_0;", "    int best_cls = 0;"]
    for k in range(1, n_out):
        lines.append(
            f"    if ({out_prefix}_{k} > best_val) {{ best_val = {out_prefix}_{k}; best_cls = {k}; }}"
        )
    return lines


def _gen_class_dispatch(semantics) -> str:
    """Emit the class -> action -> logical port dispatch for Pipeline 1."""
    lines = ["    /* --- class -> action -> logical port (generated from the",
             "     *     model descriptor; see class_semantics.py) --- */",
             "    __u32 _port = 0xffffffffU;   /* sentinel: no port selected */",
             "    switch (best_cls) {"]
    for cid in range(semantics.n_out):
        spec = semantics.classes[cid]
        if spec.action == "FORWARD":
            lines.append(f"    case {cid}: _port = {spec.port}U; break;"
                         f"   /* FORWARD -> logical port {spec.port} */")
        elif spec.action == "DROP":
            lines.append(f"    case {cid}: {{"
                         f"   /* DROP (declared, not inferred) */")
            lines.append("        int _di = 2; __u64 *_dv = pkt_stats.lookup(&_di);")
            lines.append("        if (_dv) *_dv += 1;")
            lines.append(f"        __u32 _dc = {cid}U;")
            lines.append("        __u64 *_dcv = cls_stats.lookup(&_dc);")
            lines.append("        if (_dcv) *_dcv += 1;")
            lines.append("        return XDP_DROP;")
            lines.append("    }")
        else:
            lines.append(f"    case {cid}: {{"
                         f"   /* UNUSED: countable, never forwarded */")
            lines.append("        int _ui = 1; __u64 *_uv = pkt_stats.lookup(&_ui);")
            lines.append("        if (_uv) *_uv += 1;")
            lines.append(f"        __u32 _uc = {cid}U;")
            lines.append("        __u64 *_ucv = cls_stats.lookup(&_uc);")
            lines.append("        if (_ucv) *_ucv += 1;")
            lines.append("        return XDP_PASS;")
            lines.append("    }")
    lines += [
        "    default: {   /* argmax outside [0, n_out): must not happen */",
        "        int _xi = 1; __u64 *_xv = pkt_stats.lookup(&_xi);",
        "        if (_xv) *_xv += 1;",
        "        return XDP_PASS;",
        "    }",
        "    }",
        "    if (_port == 0xffffffffU) {",
        "        int _xi = 1; __u64 *_xv = pkt_stats.lookup(&_xi);",
        "        if (_xv) *_xv += 1;",
        "        return XDP_PASS;",
        "    }",
    ]
    return "\n".join(lines)


def _gen_action_epilogue(semantics) -> str:
    """Post-argmax epilogue."""
    return f"""
{_gen_class_dispatch(semantics)}

    /* Two different keys, and they must not be conflated:
     *   mac_table  is keyed by LOGICAL PORT (what the node provisioned)
     *   cls_stats  is keyed by CLASS       (what the model emitted)
     * They used to share one `_cls = _port` variable. For the reference model
     * class k forwards on port k, so the two agreed by accident; a model whose
     * forwarding classes sit on non-consecutive ports would have had its
     * per-class counter written at a port index. */
    struct fwd_action *_action = mac_table.lookup(&_port);
    if (_action != NULL && _action->ifindex != 0) {{
        /* A hop must not forward a packet whose TTL would reach 0. Counted as
         * MISS -- the existing "we did not forward this" bucket, which already
         * returns XDP_PASS -- and handed to the kernel, which is what emits the
         * ICMP Time Exceeded and makes traceroute work. */
        if (ip->ttl <= 1) {{
            int _ti = 1; __u64 *_tv = pkt_stats.lookup(&_ti);
            if (_tv) *_tv += 1;
            return XDP_PASS;
        }}
        ipa_ttl_dec(ip);
        int _hi = 0; __u64 *_hv = pkt_stats.lookup(&_hi);
        if (_hv) *_hv += 1;
        __u32 _cs_key = (__u32)best_cls;
        __u64 *_cv = cls_stats.lookup(&_cs_key);
        if (_cv) *_cv += 1;
        __builtin_memcpy(eth->h_source, _action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   _action->dst_mac, 6);
        return bpf_redirect(_action->ifindex, 0);
    }}
    /* no mac_table entry for that logical port (the node did not provision
     * it, or its link is down) */
    int _mi = 1; __u64 *_mv = pkt_stats.lookup(&_mi);
    if (_mv) *_mv += 1;
    return XDP_PASS;
"""


_PACKET_PROLOGUE = r"""
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr  *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr   *ip  = (struct iphdr *)(eth + 1);
    if ((void *)(ip  + 1) > data_end) return XDP_PASS;

    /* FIX(#4): read protocol via absolute RFC 791 byte offset (byte 9) */
    __u8 ip_proto = *((__u8 *)ip + 9);
    if (ip_proto != 17U) return XDP_PASS;

    /* FIX(#4): compute UDP header pointer from actual ihl*4 */
    __u32 _ip_hlen = (((__u8 *)ip)[0] & 0x0fU) << 2U;
    if (_ip_hlen < 20U) return XDP_PASS;
    struct udphdr  *udp = (struct udphdr *)((void *)ip + _ip_hlen);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;
"""


# --- Per-feature C generators (the "catalog" of how each feature type in ---
_SCALAR_SOURCE = {
    "ttl": ("_ttl", "((__u32)ip->ttl) & 0xff"),
}
_DENSEVEC_SOURCE = {
    "link_state":      ("ls", "link_state"),
    "queue_occupancy": ("qs", "queue_state"),
}


def _gen_feature_scalar(feat, offset, n_in, fc1_w, n_h1):
    """Scalar feature term, divided by the feature's training scale."""
    from model_meta import feature_scale_of
    var, expr = _SCALAR_SOURCE[feat["type"]]
    scale = feature_scale_of(feat)
    preamble = [f"    __u32 {var} = {expr};   /* feature '{feat['type']}' (scalar) */"]
    def term(j):
        prod = f"(__s64){var} * {_lit(fc1_w[j * n_in + offset])}LL"
        return prod if scale == 1 else f"(({prod}) / {scale}LL)"
    return preamble, term


def _live_slots(feat, size, static_ports):
    """The columns this node can actually see as non-zero."""
    if static_ports is None:
        return list(range(size))
    if _model_meta.FEATURE_CATALOG[feat["type"]].get("dim_key") != "n_interfaces":
        return list(range(size))
    live = sorted(i for i in static_ports if 0 <= i < size)
    if not live:
        raise ValueError(
            f"static_ports={sorted(static_ports)} leaves feature "
            f"{feat['type']!r} (width {size}) with no live column. A node with "
            f"no interface at all cannot forward, and a program whose whole "
            f"link_state contributes nothing should be refused here rather "
            f"than compiled and deployed looking healthy.")
    return live


def _gen_feature_dense_vector(feat, offset, n_in, fc1_w, n_h1,
                              static_ports=None):
    """Dense vector read from a map, optionally restricted to the ports
    present."""
    prefix, map_name = _DENSEVEC_SOURCE[feat["type"]]
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
        f"    {{ int _z=0; struct {map_name}_vec *_p = {map_name}.lookup(&_z);",
        "      if (_p) {",
    ]
    for i in live:
        lines.append(f"        {prefix}{i}=(long long)_p->v[{i}];")
    lines.append("      } }")
    def term(j):
        return " + ".join(
            f"{prefix}{i} * {_lit(fc1_w[j * n_in + offset + i])}LL" for i in live)
    return lines, term


def _gen_feature_onehot_iface(feat, offset, n_in, fc1_w, n_h1):
    """ingress-iface one-hot."""
    size = feat["size"]
    lines = ["    /* feature 'ingress_iface' (one-hot): kernel ifindex -> logical 1..size,",
             "     * resolved through the ingress_port map (a node fact, not a model fact) */",
             "    __u32 _iface = 0U;",
             "    { __u32 _kif = ctx->ingress_ifindex;",
             "      __u32 *_lp = ingress_port.lookup(&_kif);",
             "      if (_lp && *_lp >= 1U && *_lp <= " + str(size) + "U) _iface = *_lp; }"]
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


def _gen_feature_onehot_node(feat, offset, n_in, fc1_w, n_h1,
                             static_index=None):
    """node one-hot: the weight switch selects fc1_w[j, offset + node]."""
    size = feat["size"]
    if static_index is not None:
        if not (0 <= static_index < size):
            raise ValueError(
                f"static_node={static_index} outside [0, {size}) for a node "
                f"one-hot of width {size}. Refused rather than silently "
                f"emitting an all-zero column, which would look like a "
                f"working program for a node that is not in the topology.")
        lines = [f"    /* feature 'node' (one-hot) FROZEN at index "
                 f"{static_index} of {size}.",
                 "     * No node_id map read and no switch: this binary is "
                 "valid on that",
                 "     * node alone. The weights below are constants, so clang "
                 "folds them",
                 "     * into the accumulator -- zeros disappear, powers of two "
                 "become",
                 "     * shifts. See _gen_feature_onehot_node. */"]
        for j in range(n_h1):
            w = fc1_w[j * n_in + offset + static_index]
            lines.append(f"    long long w_node_{j} = {_lit(w)}LL;")

        def term_static(j):
            return f"w_node_{j}"
        return lines, term_static

    lines = ["    /* feature 'node' (one-hot): index read from the node_id map */",
             "    /* Bounded to a byte: the verifier reasons about the",
             "     * switch below far more cheaply with a tight range, and",
             "     * the node id is a byte. 256 = unknown, which",
             "     * falls through to the default and sets no weight. */",
             "    __u32 _node = 0x100U;",
             "    { __u32 _nz = 0; __u32 *_nid = node_id.lookup(&_nz);",
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
    """Dispatch to the right per-kind generator for one descriptor entry."""
    t = feat["type"]
    kind = _model_meta.FEATURE_CATALOG[t]["kind"]
    if kind == "scalar":
        return _gen_feature_scalar(feat, offset, n_in, fc1_w, n_h1)
    if kind == "dense_vector_map":
        return _gen_feature_dense_vector(feat, offset, n_in, fc1_w, n_h1,
                                         static_ports=static_ports)
    if kind == "onehot":
        if t == "ingress_iface":
            return _gen_feature_onehot_iface(feat, offset, n_in, fc1_w, n_h1)
        if t == "node":
            return _gen_feature_onehot_node(feat, offset, n_in, fc1_w, n_h1,
                                            static_index=static_node)
    raise ValueError(f"no C generator for feature type {t!r} (kind {kind!r})")


# --- Sparse route: builds the input vector locally on the node, feature by ---
def generate_ebpf_hardcoded(
    weights_int8: list,
    scale: int,
    model_id: int = 0,
    include_header: bool = True,
    n_interfaces: int = None,
    n_nodes: int = None,
    hidden_dims: tuple = (4, 4),
    features: list = None,
    n_out: int = None,
    semantics=None,
    static_node: int = None,
    static_ports=None,
) -> str:
    """Generate an eBPF XDP program, function name `model_<model_id>`, for
    model `model_id`."""
    dims = [int(d) for d in hidden_dims]

    if features is None:
        _meta = dict(_model_meta.load_model_meta(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "weights.json")))
        if n_interfaces is not None:
            _meta["n_interfaces"] = n_interfaces
        if n_nodes is not None:
            _meta["n_nodes"] = n_nodes
        _shape = _model_meta.derive_shape(
            _meta, topology_config=_model_meta.topology_config_for(_meta))
        features = _shape["features"]
        n_out = _shape["n_out"]
    if n_out is None:
        raise ValueError("generate_ebpf_hardcoded: n_out is required when 'features' is given")
    _model_meta._validate_feature_types([f["type"] for f in features])

    n_in = sum(f["size"] for f in features)

    layer_sizes = [n_in] + dims + [n_out]
    n_weights = sum(layer_sizes[i - 1] * layer_sizes[i] + layer_sizes[i]
                    for i in range(1, len(layer_sizes)))
    if len(weights_int8) != n_weights:
        raise ValueError(
            f"Expected {n_weights} weights for shape "
            f"{'-'.join(map(str, layer_sizes))}, got {len(weights_int8)}")

    w = weights_int8
    if static_ports is not None and static_node is None:
        raise ValueError(
            "static_ports requires static_node: freezing WHICH ports exist is "
            "part of specialising P1 to one node, and it is the node that "
            "makes that knowledge legitimate. P1.5 (static_node=None) serves "
            "the whole network from one binary and keeps the model's full "
            "feature width.")

    layers = []
    off = 0
    for i in range(1, len(layer_sizes)):
        n_prev, n_cur = layer_sizes[i - 1], layer_sizes[i]
        layers.append((w[off : off + n_prev * n_cur],
                       w[off + n_prev * n_cur : off + n_prev * n_cur + n_cur]))
        off += n_prev * n_cur + n_cur

    fc1_w, fc1_b = layers[0]
    n_h1 = layer_sizes[1]
    first_prefix = "h1" if dims else "out"
    fc1_lines = []
    term_fns  = []
    offset = 0
    for feat in features:
        pre, term = _gen_feature(feat, offset, n_in, fc1_w, n_h1,
                                 static_node=static_node,
                                 static_ports=static_ports)
        fc1_lines.extend(pre)
        term_fns.append(term)
        offset += feat["size"]

    for j in range(n_h1):
        terms = " + ".join(tf(j) for tf in term_fns)
        expr = f"{terms} + {_lit(fc1_b[j])}LL"
        fc1_lines.append(
            f"    long long {first_prefix}_{j} = "
            + (f"RELU_LL({expr});" if dims else f"{expr};"))

    rest_lines = []
    prev_names = [f"{first_prefix}_{j}" for j in range(n_h1)]
    for li in range(1, len(layers)):
        W, B = layers[li]
        n_cur = layer_sizes[li + 1]
        is_out = (li == len(layers) - 1)
        prefix = "out" if is_out else f"h{li + 1}"
        rest_lines.extend(_gen_dense_layer(prev_names, n_cur, W, B, prefix,
                                           relu=not is_out,
                                           bias_mul=scale ** li))
        prev_names = [f"{prefix}_{j}" for j in range(n_cur)]

    argmax_lines = _gen_argmax(n_out)

    fc1_src    = "\n".join(fc1_lines)
    rest_src   = "\n".join(rest_lines)
    argmax_src = "\n".join(argmax_lines)
    if semantics is None:
        from model_meta import descriptor_semantics_or_reference
        semantics = descriptor_semantics_or_reference(n_out, "Pipeline1")
    semantics.validate()
    if semantics.n_out != n_out:
        raise ValueError(f"class semantics declare n_out={semantics.n_out} "
                         f"but the model outputs {n_out}")
    epilogue   = _gen_action_epilogue(semantics)

    shape_str = ("-".join(str(f["size"]) for f in features)
                 + " -> " + "-".join(str(s) for s in layer_sizes))
    feats_str = ", ".join(f"{f['type']}[{f['size']}]" for f in features)

    fn_name = f"model_{model_id}"
    body = f"""
int {fn_name}(struct xdp_md *ctx) {{
{_PACKET_PROLOGUE}
    /* Pure hardcoded: weights are C literals below, no weight map.
     * Always run inference. */
    __u16 scale = {scale}U;
    if (scale == 0) return XDP_PASS;

    /* Input vector built locally, features: {feats_str} */
{fc1_src}

{rest_src}

{argmax_src}
{epilogue}}}
"""
    src = body if not include_header else (
        f"/* Pipeline 1 (sparse) — model_id={model_id}, scale={scale}, "
        f"features=[{feats_str}], shape={shape_str} */\n" + body
    )
    return src


def _dense_vector_maps_for(features: list) -> dict:
    """{map_name: size} for the map-backed feature types in a descriptor -- the
    BPF maps _build_header must declare and the control plane must seed."""
    dvmaps = {}
    for f in features:
        entry = _model_meta.FEATURE_CATALOG[f["type"]]
        if entry["kind"] == "dense_vector_map":
            dvmaps[entry["map"]] = f["size"]
    return dvmaps


def build_combined_hardcoded_source(
    models: list,
    n_interfaces: int = None,
    n_nodes: int = None,
    hidden_dims: tuple = (4, 4),
    features: list = None,
    n_out: int = None,
    semantics=None,
    static_node: int = None,
    static_ports=None,
) -> str:
    """models: list of (model_id, weights_int8, scale) tuples, all sharing the
    same feature descriptor / n_out / hidden_dims (the map sizes and cls
    range are shared by the whole compiled object; register differently-
    shaped models as separate objects)."""
    if features is None:
        _meta = dict(_model_meta.load_model_meta(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "weights.json")))
        if n_interfaces is not None:
            _meta["n_interfaces"] = n_interfaces
        if n_nodes is not None:
            _meta["n_nodes"] = n_nodes
        _shape = _model_meta.derive_shape(
            _meta, topology_config=_model_meta.topology_config_for(_meta))
        features = _shape["features"]
        n_out = _shape["n_out"]
    if n_out is None:
        raise ValueError("build_combined_hardcoded_source: n_out required when 'features' is given")

    dvmaps = _dense_vector_maps_for(features)
    if semantics is None:
        from model_meta import descriptor_semantics_or_reference
        semantics = descriptor_semantics_or_reference(n_out, "Pipeline1")
    src = (_build_header(dvmaps, n_out, semantics=semantics) + "\n"
           + EBPF_HARDCODED_DISPATCHER)
    for entry in models:
        if len(entry) == 4:
            model_id, weights_int8, scale, _stale = entry
            if _stale is not None:
                raise ValueError(
                    "build_combined_hardcoded_source does not take a "
                    "compile-time ifindex_table: the kernel ifindex -> logical "
                    "port mapping is the runtime `ingress_port` map, filled by "
                    "common.install_ingress_port_table() from the node's own "
                    "interfaces. Pass (model_id, weights, scale).")
        else:
            model_id, weights_int8, scale = entry
        src += "\n" + generate_ebpf_hardcoded(
            weights_int8, scale, model_id, include_header=False,
            hidden_dims=hidden_dims, features=features, n_out=n_out,
            semantics=semantics, static_node=static_node,
            static_ports=static_ports)
    return src


# --- Loader: resolves a model's descriptor (ipa/model_meta.py) and generates ---
def load_and_generate(
    model_path: str = None,
    model_id: int = 0,
    meta: dict = None,
    topology_config: dict = None,
) -> tuple:
    """Returns (ebpf_src, weights_int8, scale) -- a standalone combined source
    (header + dispatcher + one model_<model_id> function) ready to compile
    and attach EBPF_HARDCODED_DISPATCHER's "ipa_switch_hardcoded" as the XDP
    entry point."""
    import json, os

    if meta is None:
        meta = _model_meta.load_model_meta(model_path)
    shape = _model_meta.derive_shape(meta, topology_config=topology_config)
    model_dir = os.path.dirname(model_path) or "."
    weights_float_path = os.path.join(model_dir, "weights_float.json")
    weights_plain_path = os.path.join(model_dir, "weights.json")

    def _load_weights_from_json():
        from extract_weights import _load_from_json
        if os.path.exists(weights_float_path):
            with open(weights_float_path) as f:
                sc = int(json.load(f).get("scale_factor", meta.get("scale_factor", 128)))
            return _load_from_json(weights_float_path), sc
        if os.path.exists(weights_plain_path):
            return _load_from_json(weights_plain_path), int(meta.get("scale_factor", 128))
        raise FileNotFoundError(
            f"synthetic-shape model needs weights.json or weights_float.json in {model_dir}")

    if meta.get("features"):
        weights_int8, scale = _load_weights_from_json()
    else:
        from extract_weights import extract_weights_int8
        if os.path.exists(weights_float_path):
            with open(weights_float_path) as f:
                scale = int(json.load(f)["scale_factor"])
        else:
            try:
                import torch
                from FRR_model import FastRerouteMLP
                m = FastRerouteMLP(n_interfaces=shape["n_interfaces"], n_nodes=shape["n_nodes"],
                                   hidden_dim=shape["hidden_dims"][0])
                m.load_state_dict(torch.load(model_path))
                floats  = [w for p in m.parameters() for w in p.data.view(-1).tolist()]
                max_abs = max(abs(w) for w in floats)
                scale   = int(127 / max_abs)
            except ImportError:
                _, scale = _load_weights_from_json()
                print(f"[load_and_generate] torch not available — using scale={scale} "
                      f"from json (deployment node).")
        weights_int8 = extract_weights_int8(
            model_path,
            n_interfaces=shape["n_interfaces"],
            n_nodes=shape["n_nodes"],
            hidden_dim=shape["hidden_dims"][0],
        )

    ebpf_src = build_combined_hardcoded_source(
        [(model_id, weights_int8, scale)],
        features=shape["features"], n_out=shape["n_out"],
        hidden_dims=tuple(shape["hidden_dims"]))
    return ebpf_src, weights_int8, scale


def __getattr__(name):
    """Lazy `EBPF_PROGRAM`."""
    if name == "EBPF_PROGRAM":
        return build_combined_hardcoded_source(
            [(0, [0] * reference_shape()["n_weights"], 128, None)])
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    import sys
    model_path = (sys.argv[1] if len(sys.argv) > 1
                  else _model_meta.default_checkpoint())
    src, w, s = load_and_generate(model_path)
    print(src)
