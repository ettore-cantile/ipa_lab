"""
ebpf_program.py  —  Pipeline 1: Hardcoded Model (design-space baseline).

Design space position:
  - Maximum performance, minimum flexibility
  - Each model -> a dedicated eBPF program
  - Weights hardcoded as literals in the C source
  - A single tail call, NO map lookup for the weights (pure hardcoded).
  - Action: best_cls -> mac_table[best_cls] -> MAC rewrite -> bpf_redirect
    (cls 0..n_interfaces-1 = redirect on the resolved iface with real
    src/dst MAC, cls n_interfaces = XDP_DROP). Same mac_table pattern as
    P2/P3 -- the NN decides the port, mac_table only resolves the L2
    next-hop -- so the packet's Ethernet header is rewritten before
    leaving, not just its egress iface.

Generic input vector (see shared/model_meta.py), zero-weight-lookup and
fully unrolled -- costs nothing vs. the original fixed 65-4-4-7 program
when the default descriptor is used:

  generate_ebpf_hardcoded / build_combined_hardcoded_source:
    The input vector is built ON THE NODE from a per-model descriptor: an
    ordered list of feature TYPES (from model_meta.FEATURE_CATALOG), each
    read from its local source (packet TTL, link_state / queue_state maps,
    ingress iface, node). A feature's SIZE is a per-node/per-network
    property (model_meta node config), NOT a model parameter: link_state
    has one slot per egress interface of the node, node one-hot one slot
    per node in the network, etc. N_IN = sum of the sizes; N_OUT is the
    number of output classes (last class = DROP). Different models may use
    different feature-type SETS; each program builds only its own subset.
    The default descriptor [link_state, ingress_iface, ttl, node] with node
    config 6/52 reproduces the historical 65-4-4-7 program.

Stack budget (why the input vector is read sparsely instead of
materializing a dense feature array):
  iv[65] as int array  -> 260B (too much)
  iv0..iv64 long long  -> 520B (exceeds 512B alone)

  Solution: the feature vector has only a handful of live entries at
  runtime (link_state[0..n_interfaces-1], ttl, one iface one-hot bit, one
  node one-hot bit); all other positions are structurally zero, so their
  weight*0 terms are never even generated. See generate_ebpf_hardcoded().

Verifier constraints (why the sparse route's codegen is shaped this way):
  1) switch(_iface){...}; switch(_node){...} REPEATED per hidden neuron
     (once per j in 0..N_H1-1): each neuron's pair of switches multiplies
     the number of CFG paths the verifier must explore, so the total
     explodes as O((n_interfaces*n_nodes)^N_H1) -- for the historical
     7*52 with N_H1=4 that is ~1.75e10 -> "Permission denied" (verifier
     gives up after the 1,000,000-instruction budget).
  2) Replacing per-neuron switches with per-neuron `static const __s64`
     lookup arrays (W_IFACEj[N], W_NODEj[M]) avoided the path explosion,
     but `static const` arrays declared inside a BCC-compiled function are
     placed in a global/.rodata symbol that BCC's legacy (non-CO-RE)
     compilation pipeline cannot relocate for XDP programs: the emitted
     LD_IMM64 address collapses to a literal 0, and the verifier rejects
     the subsequent load ("R1 invalid mem access 'scalar'").
  Fix: emit ONE switch(_iface) and ONE switch(_node) TOTAL (not per
  neuron), each case assigning the per-neuron contribution for ALL
  N_H1 neurons at once. This keeps the branch total O(n_interfaces +
  n_nodes) regardless of N_H1 (no combinatorial blow-up) and only ever
  touches plain scalar stack locals -- no globals, no maps.

  3) The SAME broken-global-array pattern also existed in the post-argmax
     action code as `static const __u32 IFINDEX_TABLE[...]` indexed by
     `best_cls`. Same symptom ("R7 invalid mem access 'scalar'"), same fix
     at the time: a `switch (best_cls) {...}` (no loop -> no explosion
     risk). That switch has since been replaced again, this time by a
     real mac_table BPF_HASH lookup (matching P2/P3's action pattern) --
     a plain BPF_HASH lookup is verifier-safe here (unlike the broken
     static const array) because it goes through the normal map helper,
     not a relocated global symbol.

  4) ip->protocol bitfield ambiguity on BCC/Kathara (DBG_NOT_UDP=100%):
     struct iphdr declares ihl:4,version:4 as a bitfield at byte 0.
     On BCC with minimal kernel headers inside Kathara containers,
     Clang's packing of this bitfield can cause ip->protocol (byte 9)
     to be read at the wrong offset, making ALL UDP packets fail the
     IPPROTO_UDP check even though tcpdump confirms proto=17.
     Fix: read protocol via *((__u8 *)ip + 9) -- absolute RFC 791 offset,
     independent of any struct packing or bitfield layout.
     Additionally, the UDP header pointer now uses ip->ihl*4 (the actual
     IP header length) instead of sizeof(struct iphdr)=20, which is
     correct when IP Options are present (ihl > 5).

  5) Feature vector iface one-hot always zero (chosen_port=DROP, 100%):
     _iface = ctx->ingress_ifindex & 0x7 produced e.g. 655 & 7 = 7,
     which never matched any switch(_iface) case, so w_iface_j = 0 for
     all neurons. Fix: emit a preliminary switch(ctx->ingress_ifindex)
     that maps each hardcoded kernel ifindex (from ifindex_table,
     resolved at pipeline startup via socket.if_nametoindex) to the
     logical index 1..n_interfaces used by the training feature encoding,
     stored in _iface before the existing switch(_iface).
"""

import model_meta as _model_meta

# Historical/default shape constants -- kept as documented fallback
# defaults for callers that don't pass a scenario shape explicitly, so
# every existing call site (tests, verify_prog_run.py, bench scripts)
# keeps producing byte-identical output to before this module was
# generalized. See model_meta.py for how a model's real shape is derived.
N_IN   = 65
N_H1   =  4
N_H2   =  4
N_OUT  =  7
N_WEIGHTS = N_IN*N_H1 + N_H1 + N_H1*N_H2 + N_H2 + N_H2*N_OUT + N_OUT  # 319

_COMMON_STRUCTS = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

/* Fallback: in some Kathara/minimal-header environments IPPROTO_UDP may
 * not be defined via the includes above. Hardcode the RFC 791 value. */
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

/* CTR_INC(): real per-packet map-lookup counter, active only when
 * IPA_COUNT_LOOKUPS is #defined before this source (measurement builds --
 * see common.py instrument_map_lookups() / verify_prog_run.count_lookups()).
 * A no-op otherwise, so production/performance builds are unaffected. */
#ifdef IPA_COUNT_LOOKUPS
BPF_ARRAY(lookup_ctr, __u64, 1);
static inline __attribute__((always_inline)) void ctr_inc(void) {
    int _lci = 0;
    __u64 *_lcv = lookup_ctr.lookup(&_lci);
    if (_lcv) __sync_fetch_and_add(_lcv, 1);
}
#define CTR_INC() ctr_inc()
#else
#define CTR_INC() do {} while (0)
#endif

#define RELU_LL(x)    ((x) > 0LL ? (x) : 0LL)
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

    /* Single tail call, no map lookup for weights, no intermediate state --
     * model_progs is indexed directly by the protocol's model_id byte.
     * Descriptor-agnostic: works the same for any registered model, whatever
     * feature set its input vector is built from. */
    __u32 mid = (__u32)ipa->model_id;
    model_progs.call(ctx, mid);
    return XDP_PASS;   /* reached only if model_id has no registered program */
}
"""


def _build_header(dense_vector_maps: dict, n_out: int) -> str:
    """
    Build the map/struct declarations for a combined hardcoded source.

    dense_vector_maps: {map_name: size} for the map-backed feature types the
    model(s) use (e.g. {"link_state": 6} for the default model, plus
    "queue_state" for a model using queue_occupancy). Each becomes a
    BPF_ARRAY the control plane seeds. A model that uses no map-backed
    features passes {} (its whole input vector comes from the packet TTL
    and one-hot indices).
    n_out sizes cls_stats and the mac_table capacity -- generalizes what
    used to be fixed at 7/8 respectively.
    """
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
    mac_capacity = max(8, n_out)
    return _COMMON_STRUCTS + f"""
{map_decls}BPF_ARRAY(pkt_stats,        __u64, 3);   /* [0]=hit [1]=miss(no mac_table entry) [2]=drop */
BPF_ARRAY(cls_stats,        __u64, {n_out});   /* per-class redirect counter */

/* mac_table: egress class (the argmax output) -> {{ifindex, src/dst MAC}}.
 * Same struct/role as P2/P3's mac_table_t2/t3 -- the NN decides the port,
 * this only resolves the L2 next-hop and rewrites the Ethernet header
 * before bpf_redirect(). */
BPF_HASH(mac_table, __u32, struct fwd_action, {mac_capacity});

/* model_progs: dispatcher -> model_<id>, indexed directly by ipa->model_id.
 * A single tail call, matching the design-space spec's hardcoded pipeline
 * ("packet -> dispatcher -> tail call -> model_<id> -> action"). */
BPF_PROG_ARRAY(model_progs, 256);
"""


def _lit(v) -> str:
    return str(int(v))


def _gen_dense_layer(prev_terms: list, n_cur: int, w: list, b: list,
                     out_prefix: str, relu: bool) -> list:
    """
    Emit `n_cur` neurons of a fully-connected layer as single-expression C
    statements: out_prefix_j = RELU_LL(sum_i(prev_terms[i] * w[j,i]) + b[j]).
    `prev_terms` are pre-rendered C expressions for the previous layer's
    activations (the `h*_i` locals) -- shared by the fc2 and output stages,
    which are identical once the previous layer's values are in hand.
    """
    n_prev = len(prev_terms)
    lines = []
    for j in range(n_cur):
        terms = " + ".join(
            f"{prev_terms[i]} * {_lit(w[j * n_prev + i])}LL" for i in range(n_prev)
        )
        bias = _lit(b[j])
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


def _gen_action_epilogue(drop_cls_expr: str) -> str:
    """
    Shared post-argmax epilogue: class -> mac_table[class] -> MAC rewrite
    -> bpf_redirect (or DROP if best_cls indicates the drop class). Never
    assumes anything about the feature encoding, only about `best_cls`.
    """
    return f"""
    /* --- Action: class -> mac_table[class] -> MAC rewrite -> bpf_redirect --- */
    if ({drop_cls_expr}) {{
        int _di = 2; __u64 *_dv = pkt_stats.lookup(&_di);
        if (_dv) __sync_fetch_and_add(_dv, 1);
        return XDP_DROP;
    }}

    __u32 _cls = (__u32)best_cls;
    struct fwd_action *_action = mac_table.lookup(&_cls);
    if (_action != NULL) {{
        int _hi = 0; __u64 *_hv = pkt_stats.lookup(&_hi);
        if (_hv) __sync_fetch_and_add(_hv, 1);
        __u64 *_cv = cls_stats.lookup(&_cls);
        if (_cv) __sync_fetch_and_add(_cv, 1);
        __builtin_memcpy(eth->h_source, _action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   _action->dst_mac, 6);
        return bpf_redirect(_action->ifindex, 0);
    }}
    /* no mac_table entry for that class (not provisioned) */
    int _mi = 1; __u64 *_mv = pkt_stats.lookup(&_mi);
    if (_mv) __sync_fetch_and_add(_mv, 1);
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


# ---------------------------------------------------------------------------
# Per-feature C generators (the "catalog" of how each feature type in
# model_meta.FEATURE_CATALOG is read locally and enters the fc1 dot product).
# Each returns (preamble_lines, term_fn): `preamble_lines` are emitted once
# (declarations / map reads / the single one-hot switch), `term_fn(j)` gives
# the C expression for that feature's contribution to hidden neuron j.
#
# Weight layout: for hidden neuron j, feature f's weights occupy
# fc1_w[j*n_in + offset .. offset+size-1], where `offset` is the running sum
# of the sizes of the features before it in the descriptor (so the flat
# weight order matches the descriptor order the model was trained on).
#
# A feature type appears at most once per descriptor (enforced in
# model_meta._validate_descriptor), so these per-type variable names
# (_ttl, _iface, _node, ls*, qs*, w_iface_j, w_node_j) never collide.
# ---------------------------------------------------------------------------
_SCALAR_SOURCE = {
    # type -> (C var name, C expression reading it from the packet in transit)
    "ttl": ("_ttl", "((__u32)ip->ttl) & 0xff"),
}
_DENSEVEC_SOURCE = {
    # type -> (C var prefix, BPF map name holding the per-slot values)
    "link_state":      ("ls", "link_state"),
    "queue_occupancy": ("qs", "queue_state"),
}


def _gen_feature_scalar(feat, offset, n_in, fc1_w, n_h1):
    var, expr = _SCALAR_SOURCE[feat["type"]]
    preamble = [f"    __u32 {var} = {expr};   /* feature '{feat['type']}' (scalar) */"]
    def term(j):
        return f"(__s64){var} * {_lit(fc1_w[j * n_in + offset])}LL"
    return preamble, term


def _gen_feature_dense_vector(feat, offset, n_in, fc1_w, n_h1):
    prefix, map_name = _DENSEVEC_SOURCE[feat["type"]]
    size = feat["size"]
    lines = [
        f"    /* feature '{feat['type']}': {size} values read with ONE lookup from {map_name} */",
        "    long long " + ", ".join(f"{prefix}{i}=0LL" for i in range(size)) + ";",
        f"    {{ int _z=0; struct {map_name}_vec *_p = {map_name}.lookup(&_z);",
        "      if (_p) {",
    ]
    for i in range(size):
        lines.append(f"        {prefix}{i}=(long long)_p->v[{i}];")
    lines.append("      } }")
    def term(j):
        return " + ".join(
            f"{prefix}{i} * {_lit(fc1_w[j * n_in + offset + i])}LL" for i in range(size))
    return lines, term


def _gen_feature_onehot_iface(feat, offset, n_in, fc1_w, n_h1, ifindex_table):
    """ingress-iface one-hot: exactly one active logical port (1..size), the
    weight switch selects fc1_w[j, offset + (port-1)]. One switch total (not
    per neuron) -- verifier-safe (see module docstring / prof_Notes.md #8)."""
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


def _gen_feature_onehot_node(feat, offset, n_in, fc1_w, n_h1):
    """node one-hot: active index = model_id (0..size-1), weight switch selects
    fc1_w[j, offset + node]. One switch total, verifier-safe."""
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
    """Dispatch to the right per-kind generator for one descriptor entry."""
    t = feat["type"]
    kind = _model_meta.FEATURE_CATALOG[t]["kind"]
    if kind == "scalar":
        return _gen_feature_scalar(feat, offset, n_in, fc1_w, n_h1)
    if kind == "dense_vector_map":
        return _gen_feature_dense_vector(feat, offset, n_in, fc1_w, n_h1)
    if kind == "onehot":
        if t == "ingress_iface":
            return _gen_feature_onehot_iface(feat, offset, n_in, fc1_w, n_h1, ifindex_table)
        if t == "node":
            return _gen_feature_onehot_node(feat, offset, n_in, fc1_w, n_h1)
    raise ValueError(f"no C generator for feature type {t!r} (kind {kind!r})")


# ---------------------------------------------------------------------------
# Sparse route: builds the input vector locally on the node, feature by
# feature, from a per-model descriptor (model_meta.FEATURE_CATALOG).
# ---------------------------------------------------------------------------
def generate_ebpf_hardcoded(
    weights_int8: list,
    scale: int,
    model_id: int = 0,
    ifindex_table: list = None,
    include_header: bool = True,
    n_interfaces: int = 6,
    n_nodes: int = 52,
    hidden_dims: tuple = (4, 4),
    features: list = None,
    n_out: int = None,
) -> str:
    """
    Generate an eBPF XDP program, function name `model_<model_id>`, for
    model `model_id`. Reachable only via a tail call from
    EBPF_HARDCODED_DISPATCHER's `model_progs[model_id]`.

    The input vector is built locally on the node from a per-model
    *descriptor* (`features`): an ordered list of {"type","size"} entries,
    each a feature type from model_meta.FEATURE_CATALOG read from its local
    source (packet TTL, link_state / queue_state maps, ingress iface, node).
    N_IN = sum of the sizes; N_OUT is the number of output classes (last
    class = DROP). hidden_dims = (n_h1, n_h2).

    Backward compatibility: if `features` is None, a default descriptor is
    built from n_interfaces/n_nodes in the historical order
    [link_state, ingress_iface, ttl, node] with n_out = n_interfaces+1, so
    the checked-in 65-4-4-7 model still generates a functionally identical
    program. (`n_out` is required when `features` is given explicitly.)

    After argmax the program:
      - resolves the action via mac_table[best_cls] -> {ifindex, src_mac, dst_mac}
      - cls < n_out-1: rewrites eth->h_source/h_dest, bpf_redirect(ifindex, 0)
                 -> pkt_stats[0]++, cls_stats[cls]++
      - cls < n_out-1 but mac_table has no entry: pkt_stats[1]++, XDP_PASS
      - cls == n_out-1:  XDP_DROP    -> pkt_stats[2]++
      - inference always runs (pure hardcoded, no cache gate)
      - mac_table itself is populated by the CALLER (method4_hardcoded.py)

    ifindex_table: kernel ifindex -> logical port mapping for the
                   ingress_iface one-hot feature (if present in the
                   descriptor). Defaults to [2, 3, ...].
    """
    n_h1, n_h2 = hidden_dims

    if features is None:
        _shape = _model_meta.derive_shape({"n_interfaces": n_interfaces, "n_nodes": n_nodes})
        features = _shape["features"]
        n_out = _shape["n_out"]
    if n_out is None:
        raise ValueError("generate_ebpf_hardcoded: n_out is required when 'features' is given")
    _model_meta._validate_feature_types([f["type"] for f in features])

    n_in = sum(f["size"] for f in features)
    n_weights = n_in * n_h1 + n_h1 + n_h1 * n_h2 + n_h2 + n_h2 * n_out + n_out
    if len(weights_int8) != n_weights:
        raise ValueError(f"Expected {n_weights} weights, got {len(weights_int8)}")

    # ifindex_table sized to the ingress_iface feature (if any); default
    # [2,3,...]. For a descriptor without ingress_iface it is unused.
    iface_size = next((f["size"] for f in features if f["type"] == "ingress_iface"), 0)
    if ifindex_table is None:
        ifindex_table = list(range(2, 2 + max(iface_size, 1)))
    ifindex_table = list(ifindex_table[:max(iface_size, 1)])
    while len(ifindex_table) < iface_size:
        ifindex_table.append(2)

    w = weights_int8
    fc1_w = w[0             : n_in*n_h1]
    fc1_b = w[n_in*n_h1     : n_in*n_h1 + n_h1]
    base2 = n_in*n_h1 + n_h1
    fc2_w = w[base2         : base2 + n_h1*n_h2]
    fc2_b = w[base2+n_h1*n_h2 : base2+n_h1*n_h2+n_h2]
    base3 = base2 + n_h1*n_h2 + n_h2
    out_w = w[base3         : base3 + n_h2*n_out]
    out_b = w[base3+n_h2*n_out : base3+n_h2*n_out+n_out]

    # --- fc1: build the IV feature by feature, in descriptor order ---
    # Running weight offset per feature; each feature emits its preamble
    # (declarations / map reads / the single one-hot switch) and a term_fn(j)
    # for its contribution to hidden neuron j.
    fc1_lines = []
    term_fns  = []
    offset = 0
    for feat in features:
        pre, term = _gen_feature(feat, offset, n_in, fc1_w, n_h1, ifindex_table)
        fc1_lines.extend(pre)
        term_fns.append(term)
        offset += feat["size"]

    for j in range(n_h1):
        terms = " + ".join(tf(j) for tf in term_fns)
        fc1_lines.append(
            f"    long long h1_{j} = RELU_LL({terms} + {_lit(fc1_b[j])}LL);")

    h1_names = [f"h1_{j}" for j in range(n_h1)]
    fc2_lines  = _gen_dense_layer(h1_names, n_h2, fc2_w, fc2_b, "h2", relu=True)
    h2_names = [f"h2_{j}" for j in range(n_h2)]
    out_lines  = _gen_dense_layer(h2_names, n_out, out_w, out_b, "out", relu=False)
    argmax_lines = _gen_argmax(n_out)

    fc1_src    = "\n".join(fc1_lines)
    fc2_src    = "\n".join(fc2_lines)
    out_src    = "\n".join(out_lines)
    argmax_src = "\n".join(argmax_lines)
    epilogue   = _gen_action_epilogue(f"best_cls >= {n_out - 1}")

    shape_str = "-".join(str(f["size"]) for f in features) + f" -> {n_in}-{n_h1}-{n_h2}-{n_out}"
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

{fc2_src}

{out_src}

{argmax_src}
{epilogue}}}
"""
    src = body if not include_header else (
        f"/* Pipeline 1 (sparse) — model_id={model_id}, scale={scale}, "
        f"features=[{feats_str}], shape={shape_str} */\n" + body
    )
    return src


def _dense_vector_maps_for(features: list) -> dict:
    """{map_name: size} for the map-backed feature types in a descriptor --
    the BPF maps _build_header must declare and the control plane must seed."""
    dvmaps = {}
    for f in features:
        entry = _model_meta.FEATURE_CATALOG[f["type"]]
        if entry["kind"] == "dense_vector_map":
            dvmaps[entry["map"]] = f["size"]
    return dvmaps


def build_combined_hardcoded_source(
    models: list,
    n_interfaces: int = 6,
    n_nodes: int = 52,
    hidden_dims: tuple = (4, 4),
    features: list = None,
    n_out: int = None,
) -> str:
    """
    models: list of (model_id, weights_int8, scale, ifindex_table) tuples,
    all sharing the same feature descriptor / n_out / hidden_dims (the map
    sizes and cls range are shared by the whole compiled object; register
    differently-shaped models via separate method4_hardcoded.py runs).

    Feature descriptor: pass `features` (+ `n_out`) for a heterogeneous
    feature set, or leave them None to build the historical default
    descriptor from n_interfaces/n_nodes (n_out = n_interfaces+1) -- keeps
    every existing caller (tests, benches) working unchanged.

    Returns one compilation unit: header (incl. the dense_vector maps the
    descriptor needs + model_progs) + dispatcher + one model_<id> function
    per entry in `models`.
    """
    if features is None:
        _shape = _model_meta.derive_shape({"n_interfaces": n_interfaces, "n_nodes": n_nodes})
        features = _shape["features"]
        n_out = _shape["n_out"]
    if n_out is None:
        raise ValueError("build_combined_hardcoded_source: n_out required when 'features' is given")

    dvmaps = _dense_vector_maps_for(features)
    src = _build_header(dvmaps, n_out) + "\n" + EBPF_HARDCODED_DISPATCHER
    for model_id, weights_int8, scale, ifindex_table in models:
        src += "\n" + generate_ebpf_hardcoded(
            weights_int8, scale, model_id, ifindex_table, include_header=False,
            hidden_dims=hidden_dims, features=features, n_out=n_out)
    return src


# ---------------------------------------------------------------------------
# Loader: resolves a model's descriptor (shared/model_meta.py) and generates
# the combined hardcoded source.
# ---------------------------------------------------------------------------
def load_and_generate(
    model_path: str = "shared/frr_germany50_5_model_4x2.pt",
    model_id: int = 0,
    ifindex_table: list = None,
    meta: dict = None,
) -> tuple:
    """
    Returns (ebpf_src, weights_int8, scale) -- a standalone combined source
    (header + dispatcher + one model_<model_id> function) ready to compile
    and attach EBPF_HARDCODED_DISPATCHER's "ipa_switch_hardcoded" as the XDP
    entry point.

    meta: optional model_meta dict (see model_meta.py); if None, loaded
    from model_meta.json next to model_path, defaulting to the historical
    6/52 default descriptor when absent -- so existing callers that never
    heard of model_meta.json keep getting exactly today's behavior.

    Weights come from torch/extract_weights ONLY for the default-descriptor
    model (the trained 65-4-4-7 checkpoint). A model with an explicit
    heterogeneous "features" descriptor has no trained checkpoint, so it
    loads a flat int8 weight list straight from weights.json/weights_float.json
    next to model_path (synthetic weights), never touching torch.
    """
    import json, os

    if meta is None:
        meta = _model_meta.load_model_meta(model_path)
    shape = _model_meta.derive_shape(meta)
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

    # A custom heterogeneous descriptor has no trained checkpoint -> synthetic
    # weights from json; the default descriptor is the real trained 65-4-4-7
    # model -> torch/extract_weights.
    if meta.get("features"):
        weights_int8, scale = _load_weights_from_json()
    else:
        from extract_weights import extract_weights_int8
        if os.path.exists(weights_float_path):
            with open(weights_float_path) as f:
                scale = int(json.load(f)["scale_factor"])
        else:
            import torch
            from FRR_model import FastRerouteMLP
            m = FastRerouteMLP(n_interfaces=shape["n_interfaces"], n_nodes=shape["n_nodes"],
                               hidden_dim=shape["hidden_dims"][0])
            m.load_state_dict(torch.load(model_path))
            floats  = [w for p in m.parameters() for w in p.data.view(-1).tolist()]
            max_abs = max(abs(w) for w in floats)
            scale   = int(127 / max_abs)
        weights_int8 = extract_weights_int8(
            model_path,
            n_interfaces=shape["n_interfaces"],
            n_nodes=shape["n_nodes"],
            hidden_dim=shape["hidden_dims"][0],
        )

    ebpf_src = build_combined_hardcoded_source(
        [(model_id, weights_int8, scale, ifindex_table)],
        features=shape["features"], n_out=shape["n_out"],
        hidden_dims=tuple(shape["hidden_dims"]))
    return ebpf_src, weights_int8, scale


EBPF_PROGRAM = build_combined_hardcoded_source([(0, [0]*N_WEIGHTS, 128, None)])

if __name__ == "__main__":
    import sys
    model_path = sys.argv[1] if len(sys.argv) > 1 else "shared/frr_germany50_5_model_4x2.pt"
    src, w, s = load_and_generate(model_path)
    print(src)
