"""
ebpf_program.py  —  Pipeline 1: Hardcoded Model (design-space baseline).

Design space position:
  - Maximum performance, minimum flexibility
  - Each model -> a dedicated eBPF program
  - Weights hardcoded as literals in the C source
  - A single tail call, NO map lookup for the weights (pure hardcoded).
  - Action: best_cls -> (class semantics) -> logical port ->
    mac_table[port] -> MAC rewrite -> bpf_redirect
    (the class semantics say which classes forward, on which logical port,
    and which one drops -- no class index implies an action). Same mac_table
    pattern as
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

  4) ip->protocol bitfield ambiguity on BCC with minimal headers
     (DBG_NOT_UDP=100%):
     struct iphdr declares ihl:4,version:4 as a bitfield at byte 0.
     On BCC with minimal kernel headers inside a stripped container image,
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
     all neurons. The fix went through two stages: first a switch over
     kernel ifindexes compiled in from a table, which only moved the
     assumption (it hardcoded eth0 == ifindex 2 and matched nothing on a
     real box); then the `ingress_port` map, read at runtime, which maps
     the kernel ifindex to the logical index 1..n_interfaces the training
     feature encoding uses,
     stored in _iface before the existing switch(_iface).
"""

import os
import model_meta as _model_meta

# Historical/default shape constants -- kept as documented fallback
# defaults for callers that don't pass a scenario shape explicitly, so
# every existing call site (tests, verify_prog_run.py, bench scripts)
# keeps producing byte-identical output to before this module was
# generalized. See model_meta.py for how a model's real shape is derived.
# Were N_IN=65 / N_H1=4 / N_H2=4 / N_OUT=7 / N_WEIGHTS=319 -- the Germany50
# checkpoint's shape, written here as if it were the module's shape. Nothing in
# the generator reads them any more (every entry point takes `features`,
# `n_out` and `hidden_dims`), so they are resolved lazily and only for the one
# caller that wants "the configured model's shape".
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

/* Fallback: in some minimal-header environments IPPROTO_UDP may
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

/* CTR_INC(): real per-packet map-lookup counter, active only when
 * IPA_COUNT_LOOKUPS is #defined before this source (measurement builds --
 * see common.py instrument_map_lookups() / verify_prog_run.count_lookups()).
 * A no-op otherwise, so production/performance builds are unaffected. */
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


def _build_header(dense_vector_maps: dict, n_out: int,
                  semantics=None) -> str:
    """
    Build the map/struct declarations for a combined hardcoded source.

    dense_vector_maps: {map_name: size} for the map-backed feature types the
    model(s) use (e.g. {"link_state": 6} for the default model, plus
    "queue_state" for a model using queue_occupancy). Each becomes a
    BPF_ARRAY the control plane seeds. A model that uses no map-backed
    features passes {} (its whole input vector comes from the packet TTL
    and one-hot indices).
    n_out sizes cls_stats (one counter per CLASS). mac_table is sized by the
    LOGICAL PORT space instead, from `semantics`: the two are different index
    spaces and `max(8, n_out)` only covered the port space because the
    reference model happens to number its ports 0..n_out-2. Without semantics
    the old bound is kept, and that is safe only because it is >= n_out.
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
    if semantics is not None:
        _ports = semantics.logical_ports
        mac_capacity = max(8, (max(_ports) + 1) if _ports else 0)
    else:
        mac_capacity = max(8, n_out)
    return _COMMON_STRUCTS + f"""
{map_decls}BPF_ARRAY(pkt_stats,        __u64, 3);   /* [0]=hit [1]=miss(no mac_table entry) [2]=drop */
BPF_ARRAY(cls_stats,        __u64, {n_out});   /* per-class redirect counter */

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
 * the assumption eth0 == ifindex 2, which holds in a freshly booted container
 * and nowhere else: on a box that has created a few veths the ingress arrives
 * with ifindex 207, no case matches, and the trained ingress_iface feature
 * silently contributes nothing. Which interface realises which logical port is
 * a NODE fact, resolved at runtime -- the same reason mac_table is a map. */
BPF_HASH(ingress_port, __u32, __u32, 64);

/* model_progs: dispatcher -> model_<id>, indexed directly by ipa->model_id.
 * A single tail call, matching the design-space spec's hardcoded pipeline
 * ("packet -> dispatcher -> tail call -> model_<id> -> action"). */
BPF_PROG_ARRAY(model_progs, 256);
"""


def _lit(v) -> str:
    return str(int(v))


def _gen_dense_layer(prev_terms: list, n_cur: int, w: list, b: list,
                     out_prefix: str, relu: bool, bias_mul: int = 1) -> list:
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
        # Bias scaled into the accumulator's units. The weights are stored as
        # round(w_float * scale), so after L layers of products the accumulator
        # carries scale**L while a bias stored the same way carries only
        # scale**1. Multiplying by scale**(L-1) puts the two in the same scale.
        # Computed here in Python, so P1 pays nothing at runtime and cannot
        # overflow: the literal is exact. See _gen_dense_layer's callers for
        # where bias_mul comes from, and docs for the measured effect
        # (float/int8 argmax agreement 72% -> 96%).
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
    """Emit the class -> action -> logical port dispatch for Pipeline 1.

    P1 is code generation, so the semantics are resolved HERE and become a
    switch over literal class indices: no map lookup and no index arithmetic at
    runtime. The switch is generated FROM THE DESCRIPTOR, so a model with a
    different DROP class or non-consecutive ports produces different code
    rather than being silently misinterpreted.

    The previous version emitted `if (best_cls >= n_out - 1) return XDP_DROP;`
    -- which hardcoded both that DROP is the last class and that every other
    class maps onto a port of the same index. Neither holds: the checked-in
    model's trained DROP class is 5, not 6.
    """
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
            lines.append("        if (_dv) __sync_fetch_and_add(_dv, 1);")
            # The class was decided; record it, so a DROP is distinguishable
            # from a program that never reached argmax.
            lines.append(f"        __u32 _dc = {cid}U;")
            lines.append("        __u64 *_dcv = cls_stats.lookup(&_dc);")
            lines.append("        if (_dcv) __sync_fetch_and_add(_dcv, 1);")
            lines.append("        return XDP_DROP;")
            lines.append("    }")
        else:
            lines.append(f"    case {cid}: {{"
                         f"   /* UNUSED: countable, never forwarded */")
            lines.append("        int _ui = 1; __u64 *_uv = pkt_stats.lookup(&_ui);")
            lines.append("        if (_uv) __sync_fetch_and_add(_uv, 1);")
            lines.append(f"        __u32 _uc = {cid}U;")
            lines.append("        __u64 *_ucv = cls_stats.lookup(&_uc);")
            lines.append("        if (_ucv) __sync_fetch_and_add(_ucv, 1);")
            lines.append("        return XDP_PASS;")
            lines.append("    }")
    lines += [
        "    default: {   /* argmax outside [0, n_out): must not happen */",
        "        int _xi = 1; __u64 *_xv = pkt_stats.lookup(&_xi);",
        "        if (_xv) __sync_fetch_and_add(_xv, 1);",
        "        return XDP_PASS;",
        "    }",
        "    }",
        "    if (_port == 0xffffffffU) {",
        "        int _xi = 1; __u64 *_xv = pkt_stats.lookup(&_xi);",
        "        if (_xv) __sync_fetch_and_add(_xv, 1);",
        "        return XDP_PASS;",
        "    }",
    ]
    return "\n".join(lines)


def _gen_action_epilogue(semantics) -> str:
    """
    Post-argmax epilogue: class -> action -> logical port -> mac_table[port]
    -> MAC rewrite -> bpf_redirect. mac_table is keyed by LOGICAL PORT, so the
    node decides which interface realises the port the model selected.
    """
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
            if (_tv) __sync_fetch_and_add(_tv, 1);
            return XDP_PASS;
        }}
        ipa_ttl_dec(ip);
        int _hi = 0; __u64 *_hv = pkt_stats.lookup(&_hi);
        if (_hv) __sync_fetch_and_add(_hv, 1);
        __u32 _cs_key = (__u32)best_cls;
        __u64 *_cv = cls_stats.lookup(&_cs_key);
        if (_cv) __sync_fetch_and_add(_cv, 1);
        __builtin_memcpy(eth->h_source, _action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   _action->dst_mac, 6);
        return bpf_redirect(_action->ifindex, 0);
    }}
    /* no mac_table entry for that logical port (the node did not provision
     * it, or its link is down) */
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
    """Scalar feature term, divided by the feature's training scale.

    The division is applied to the PRODUCT, not to the feature: `ttl / 30` in
    integer arithmetic collapses the whole 10..30 range onto 0 or 1. Signed
    integer division in C truncates toward zero, and the Python reference must
    use int(a/b) (not //) to match on negative weights.
    See model_meta.DEFAULT_TTL_SCALE for why `ttl` is scaled at all.
    """
    from model_meta import feature_scale
    var, expr = _SCALAR_SOURCE[feat["type"]]
    scale = feature_scale(feat["type"])
    preamble = [f"    __u32 {var} = {expr};   /* feature '{feat['type']}' (scalar) */"]
    def term(j):
        prod = f"(__s64){var} * {_lit(fc1_w[j * n_in + offset])}LL"
        return prod if scale == 1 else f"(({prod}) / {scale}LL)"
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


def _gen_feature_onehot_iface(feat, offset, n_in, fc1_w, n_h1):
    """ingress-iface one-hot: exactly one active logical port (1..size), the
    weight switch selects fc1_w[j, offset + (port-1)]. One switch total (not
    per neuron) -- verifier-safe (see module docstring / prof_Notes.md #8).

    The logical port comes from the ingress_port map, not from a switch over
    hardcoded kernel ifindexes: see that map's declaration for why. The WEIGHT
    switch below stays literal -- that is what Pipeline 1 is."""
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


def _gen_feature(feat, offset, n_in, fc1_w, n_h1):
    """Dispatch to the right per-kind generator for one descriptor entry."""
    t = feat["type"]
    kind = _model_meta.FEATURE_CATALOG[t]["kind"]
    if kind == "scalar":
        return _gen_feature_scalar(feat, offset, n_in, fc1_w, n_h1)
    if kind == "dense_vector_map":
        return _gen_feature_dense_vector(feat, offset, n_in, fc1_w, n_h1)
    if kind == "onehot":
        if t == "ingress_iface":
            return _gen_feature_onehot_iface(feat, offset, n_in, fc1_w, n_h1)
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
    include_header: bool = True,
    n_interfaces: int = None,
    n_nodes: int = None,
    hidden_dims: tuple = (4, 4),
    features: list = None,
    n_out: int = None,
    semantics=None,
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
    class = DROP). hidden_dims = any-length sequence of hidden widths
    (e.g. (4, 4), (8,), (4, 4, 4, 4), () for a pure linear model): DEPTH is
    variable, not fixed at 2.

    Backward compatibility: if `features` is None, a default descriptor is
    built from n_interfaces/n_nodes in the historical order
    [link_state, ingress_iface, ttl, node], with n_out from the descriptor, so
    the checked-in 65-4-4-7 model still generates a functionally identical
    program. (`n_out` is required when `features` is given explicitly.)

    After argmax the program:
      - resolves the action via mac_table[best_cls] -> {ifindex, src_mac, dst_mac}
      - class whose declared action is FORWARD: rewrites eth->h_source/h_dest
        and bpf_redirect(ifindex, 0) on the interface bound to its logical port
                 -> pkt_stats[0]++, cls_stats[cls]++
      - FORWARD but mac_table has no entry for that port: pkt_stats[1]++,
        XDP_PASS
      - class whose declared action is DROP:   XDP_DROP -> pkt_stats[2]++
      - class declared UNUSED: cls_stats[cls]++, XDP_PASS (countable, never
        forwarded -- the model was not trained to emit it)
    Which class is which comes from the ClassSemantics passed in, never from
    the index.
      - inference always runs (pure hardcoded, no cache gate)
      - mac_table itself is populated by the CALLER (method4_hardcoded.py)

    The ingress_iface one-hot no longer takes an `ifindex_table` argument.
    It used to default to [2, 3, ...] and be compiled into a switch, which
    encoded "eth0 is ifindex 2" into the program. The mapping is now the
    ingress_port map, filled by the control plane from the node's own
    interfaces -- see common.install_ingress_port_table.
    """
    dims = [int(d) for d in hidden_dims]

    if features is None:
        # n_interfaces/n_nodes default to the SCENARIO, not to 6/52. Those
        # literals in the signature meant a caller who passed neither got
        # the Germany50 widths for whatever model it was generating.
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

    # Layer sizes: [n_in, h1, h2, ..., hk, n_out]. `hidden_dims` may hold ANY
    # number of hidden layers (0 = pure linear model). Weight layout is the
    # generic per-layer one — n_prev*n_cur weights then n_cur biases, layer by
    # layer — which reduces exactly to the historical 2-hidden-layer layout
    # when hidden_dims == (n_h1, n_h2), so existing checkpoints are unchanged.
    layer_sizes = [n_in] + dims + [n_out]
    n_weights = sum(layer_sizes[i - 1] * layer_sizes[i] + layer_sizes[i]
                    for i in range(1, len(layer_sizes)))
    if len(weights_int8) != n_weights:
        raise ValueError(
            f"Expected {n_weights} weights for shape "
            f"{'-'.join(map(str, layer_sizes))}, got {len(weights_int8)}")

    w = weights_int8
    layers = []            # [(W, B)] one entry per layer, input -> output
    off = 0
    for i in range(1, len(layer_sizes)):
        n_prev, n_cur = layer_sizes[i - 1], layer_sizes[i]
        layers.append((w[off : off + n_prev * n_cur],
                       w[off + n_prev * n_cur : off + n_prev * n_cur + n_cur]))
        off += n_prev * n_cur + n_cur

    # --- fc1: build the IV feature by feature, in descriptor order ---
    # Running weight offset per feature; each feature emits its preamble
    # (declarations / map reads / the single one-hot switch) and a term_fn(j)
    # for its contribution to first-layer neuron j.
    fc1_w, fc1_b = layers[0]
    n_h1 = layer_sizes[1]
    # With zero hidden layers the first layer IS the output layer: no ReLU and
    # the "out_" prefix argmax reads directly.
    first_prefix = "h1" if dims else "out"
    fc1_lines = []
    term_fns  = []
    offset = 0
    for feat in features:
        pre, term = _gen_feature(feat, offset, n_in, fc1_w, n_h1)
        fc1_lines.extend(pre)
        term_fns.append(term)
        offset += feat["size"]

    for j in range(n_h1):
        terms = " + ".join(tf(j) for tf in term_fns)
        expr = f"{terms} + {_lit(fc1_b[j])}LL"
        fc1_lines.append(
            f"    long long {first_prefix}_{j} = "
            + (f"RELU_LL({expr});" if dims else f"{expr};"))

    # --- remaining layers: h2..hk (ReLU), then the output layer (no ReLU) ---
    rest_lines = []
    prev_names = [f"{first_prefix}_{j}" for j in range(n_h1)]
    for li in range(1, len(layers)):
        W, B = layers[li]
        n_cur = layer_sizes[li + 1]
        is_out = (li == len(layers) - 1)
        prefix = "out" if is_out else f"h{li + 1}"
        # Layer li (0-based) needs its bias multiplied by scale**li: layer 0
        # is already consistent (both bias and products carry scale**1), every
        # later layer accumulates one more factor of scale in its products.
        rest_lines.extend(_gen_dense_layer(prev_names, n_cur, W, B, prefix,
                                           relu=not is_out,
                                           bias_mul=scale ** li))
        prev_names = [f"{prefix}_{j}" for j in range(n_cur)]

    argmax_lines = _gen_argmax(n_out)

    fc1_src    = "\n".join(fc1_lines)
    rest_src   = "\n".join(rest_lines)
    argmax_src = "\n".join(argmax_lines)
    # Class semantics come from the descriptor. Never inferred here: when the
    # caller passes none, one shared helper resolves it (model_meta.json first,
    # an announced reference layout second) so every pipeline reports the same
    # thing the same way.
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
    n_interfaces: int = None,
    n_nodes: int = None,
    hidden_dims: tuple = (4, 4),
    features: list = None,
    n_out: int = None,
    semantics=None,
) -> str:
    """
    models: list of (model_id, weights_int8, scale) tuples,
    all sharing the same feature descriptor / n_out / hidden_dims (the map
    sizes and cls range are shared by the whole compiled object; register
    differently-shaped models via separate method4_hardcoded.py runs).

    Feature descriptor: pass `features` (+ `n_out`) for a heterogeneous
    feature set, or leave them None to build the historical default
    descriptor from the scenario's n_interfaces/n_nodes (n_out from the model
    descriptor). Pass n_interfaces/n_nodes only to override the scenario.

    Returns one compilation unit: header (incl. the dense_vector maps the
    descriptor needs + model_progs) + dispatcher + one model_<id> function
    per entry in `models`.
    """
    if features is None:
        # n_interfaces/n_nodes default to the SCENARIO, not to 6/52. Those
        # literals in the signature meant a caller who passed neither got
        # the Germany50 widths for whatever model it was generating.
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
    # Resolve the semantics ONCE here, so the header's mac_table capacity and
    # every model_<id> dispatch switch come from the same object. Left to the
    # per-model default, the header would size mac_table from one resolution
    # while the switch used another.
    if semantics is None:
        from model_meta import descriptor_semantics_or_reference
        semantics = descriptor_semantics_or_reference(n_out, "Pipeline1")
    src = (_build_header(dvmaps, n_out, semantics=semantics) + "\n"
           + EBPF_HARDCODED_DISPATCHER)
    for entry in models:
        # (model_id, weights, scale), or the old 4-tuple whose last element was
        # a compile-time ifindex_table. A None there is the shape every caller
        # already used and is simply dropped; anything else is refused rather
        # than ignored, because ignoring it would silently discard a mapping
        # the caller believed was in effect.
        if len(entry) == 4:
            model_id, weights_int8, scale, _stale = entry
            if _stale is not None:
                raise ValueError(
                    "build_combined_hardcoded_source no longer takes a "
                    "compile-time ifindex_table: the kernel ifindex -> logical "
                    "port mapping is the runtime `ingress_port` map, filled by "
                    "common.install_ingress_port_table() from the node's own "
                    "interfaces. Pass (model_id, weights, scale).")
        else:
            model_id, weights_int8, scale = entry
        src += "\n" + generate_ebpf_hardcoded(
            weights_int8, scale, model_id, include_header=False,
            hidden_dims=hidden_dims, features=features, n_out=n_out,
            semantics=semantics)
    return src


# ---------------------------------------------------------------------------
# Loader: resolves a model's descriptor (shared/model_meta.py) and generates
# the combined hardcoded source.
# ---------------------------------------------------------------------------
def load_and_generate(
    model_path: str = None,
    model_id: int = 0,
    meta: dict = None,
    topology_config: dict = None,
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
    # topology_config (per-network dimensions) is authoritative for feature
    # sizes; when omitted, derive_shape falls back to the legacy meta-derived
    # config so un-updated callers keep working.
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
            # Deriving scale from the .pt needs torch; deployment nodes
            # have no torch and run from the prebuilt json instead. Fall back to
            # the json/meta scale rather than hard-failing.
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
    """Lazy `EBPF_PROGRAM`: the historical all-zero-weights sample program.

    It used to be built eagerly at import time, so EVERY importer of this
    module (the whole test suite, and every subprocess-isolated sweep cell in
    bench_depth_vs_width.py) paid a full 65-4-4-7 codegen -- including the
    52-case node switch -- for a constant nothing in the repo reads. Building
    it on first attribute access keeps the name working for any external
    caller while costing importers nothing."""
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
