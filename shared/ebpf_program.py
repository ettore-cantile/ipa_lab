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

Two scenario "kinds" (see shared/model_meta.py), both zero-weight-lookup
and fully unrolled -- neither costs anything vs. the original fixed
65-4-4-7 program when the default shape is used:

  "sparse" (generate_ebpf_hardcoded / build_combined_hardcoded_source):
    generalizes the ORIGINAL encoding. The feature vector is still derived
    from packet metadata (link_state map + ingress ifindex + ttl +
    model_id), but n_interfaces/n_nodes (previously fixed at 6/52) are now
    parameters:
      N_IN  = 2*n_interfaces + 1 + n_nodes
              (link_state[n_interfaces] + iface one-hot[n_interfaces]
               + ttl[1] + node one-hot[n_nodes])
      N_OUT = n_interfaces + 1        (n_interfaces egress classes + drop)
    Defaults (n_interfaces=6, n_nodes=52) reproduce the historical
    65-4-4-7 program byte-for-byte.

  "dense" (generate_ebpf_hardcoded_dense / build_combined_hardcoded_dense_source):
    no FRR-specific semantics assumed. n_in/n_out are declared directly by
    the model (bounded by MAX_N_IN/MAX_N_OUT in model_meta.py). The actual
    per-packet feature vector (already quantized to int8) is read straight
    from the IPA packet PAYLOAD -- the same bytes that, in the sparse
    route (and in P2/P3), carry an unused weight blob; the datapath never
    reads that payload today, so repurposing it costs nothing. One bounds
    check (`(void*)(ipa+1) + n_in > data_end`), then a fully-unrolled dot
    product against hardcoded weights -- no map lookup at all (cheaper
    than the sparse route's link_state reads).

Stack budget (why the sparse route reads packet metadata sparsely instead
of materializing a dense feature array):
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
     * Shape-agnostic: works the same for any registered model, sparse or
     * dense. */
    __u32 mid = (__u32)ipa->model_id;
    model_progs.call(ctx, mid);
    return XDP_PASS;   /* reached only if model_id has no registered program */
}
"""


def _build_header(n_interfaces: int, n_out: int, need_link_state: bool) -> str:
    """
    Build the map/struct declarations for a combined hardcoded source.

    n_interfaces sizes link_state (sparse route only -- dense passes
    need_link_state=False and this map is omitted entirely, since dense
    inputs come from the packet payload, not from network-state maps).
    n_out sizes cls_stats and the mac_table capacity -- generalizes what
    used to be fixed at 7/8 respectively.
    """
    if need_link_state:
        link_state_decl = (
            "/* link_state[i] = operational up/down of egress iface i (feature slots\n"
            " * 0..n_interfaces-1). Written by the userspace carrier monitor\n"
            " * (link_state_monitor.py); read here into the first n_interfaces\n"
            " * feature-vector entries. 1 = link up, 0 = link down. This is the ONLY\n"
            " * map read in the sparse-route inference path -- it is an INPUT feature,\n"
            " * not a weight (weights remain C literals in both routes). */\n"
            f"BPF_ARRAY(link_state, __u32, {n_interfaces});\n"
        )
    else:
        link_state_decl = ""  # dense route: no network-state map, inputs come from the payload
    mac_capacity = max(8, n_out)
    return _COMMON_STRUCTS + f"""
{link_state_decl}BPF_ARRAY(pkt_stats,        __u64, 3);   /* [0]=hit [1]=miss(no mac_table entry) [2]=drop */
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
    activations (either `h*_i` locals or, for the dense route's first
    layer, direct payload-byte reads) -- shared between the sparse route's
    fc2/out stages and the dense route's fc1/fc2/out stages, since those
    stages are identical once the previous layer's values are in hand.
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
    -> bpf_redirect (or DROP if best_cls indicates the drop class).
    Identical for the sparse and dense routes -- the action never assumed
    anything about the feature encoding, only about `best_cls`.
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
# Sparse route: generalizes the original FRR feature encoding.
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
) -> str:
    """
    Generate an eBPF XDP program, function name `model_<model_id>`, for
    model `model_id`. Reachable only via a tail call from
    EBPF_HARDCODED_DISPATCHER's `model_progs[model_id]`.

    n_interfaces/n_nodes replace the historical fixed 6/52 -- the feature
    vector is N_IN = 2*n_interfaces + 1 + n_nodes wide (link_state +
    iface one-hot + ttl + node one-hot), N_OUT = n_interfaces + 1 (egress
    classes + drop). Defaults reproduce the original 65-4-4-7 shape
    byte-for-byte. hidden_dims = (n_h1, n_h2).

    After argmax the program:
      - resolves the action via mac_table[best_cls] -> {ifindex, src_mac, dst_mac}
      - cls < n_interfaces: rewrites eth->h_source/h_dest, bpf_redirect(ifindex, 0)
                 -> pkt_stats[0]++, cls_stats[cls]++
      - cls < n_interfaces but mac_table has no entry: pkt_stats[1]++, XDP_PASS
      - cls == n_interfaces:  XDP_DROP    -> pkt_stats[2]++
      - inference always runs (pure hardcoded, no cache gate)
      - mac_table itself is populated by the CALLER (method4_hardcoded.py)

    ifindex_table: list of up to n_interfaces integers mapping cls
                   0..n_interfaces-1 to kernel ifindex, used for the INPUT
                   ingress-iface one-hot feature. Defaults to
                   [2, 3, ..., n_interfaces+1].

    include_header: True returns header+body (a standalone compilable
      source). False returns only the function body, for concatenating
      several models + EBPF_HARDCODED_DISPATCHER into one compilation unit
      (see build_combined_hardcoded_source).
    """
    n_h1, n_h2 = hidden_dims
    n_in  = 2 * n_interfaces + 1 + n_nodes
    n_out = n_interfaces + 1
    n_weights = n_in * n_h1 + n_h1 + n_h1 * n_h2 + n_h2 + n_h2 * n_out + n_out

    if len(weights_int8) != n_weights:
        raise ValueError(f"Expected {n_weights} weights, got {len(weights_int8)}")

    if ifindex_table is None:
        ifindex_table = list(range(2, 2 + n_interfaces))
    ifindex_table = list(ifindex_table[:n_interfaces])
    if len(ifindex_table) < n_interfaces:
        ifindex_table += [2] * (n_interfaces - len(ifindex_table))

    w = weights_int8
    fc1_w = w[0             : n_in*n_h1]
    fc1_b = w[n_in*n_h1     : n_in*n_h1 + n_h1]
    base2 = n_in*n_h1 + n_h1
    fc2_w = w[base2         : base2 + n_h1*n_h2]
    fc2_b = w[base2+n_h1*n_h2 : base2+n_h1*n_h2+n_h2]
    base3 = base2 + n_h1*n_h2 + n_h2
    out_w = w[base3         : base3 + n_h2*n_out]
    out_b = w[base3+n_h2*n_out : base3+n_h2*n_out+n_out]

    fc1_lines = []
    fc1_lines.append("    /* fc1: only 3 live features -- ttl, iface one-hot, node one-hot */")
    fc1_lines.append("    __u32 _ttl  = ((__u32)ip->ttl) & 0xff;")
    fc1_lines.append("    __u32 _node = (__u32)ipa->model_id;  /* switch default zeroes anything outside 0..n_nodes-1 */")

    fc1_lines.append("    /* FIX(#5): map raw kernel ifindex -> logical 1..n_interfaces for one-hot */")
    fc1_lines.append("    __u32 _iface = 0U;")
    fc1_lines.append("    switch (ctx->ingress_ifindex) {")
    _seen_ifindex = set()
    for logical_idx, kern_ifindex in enumerate(ifindex_table, start=1):
        ki = int(kern_ifindex)
        if ki in _seen_ifindex:
            continue
        _seen_ifindex.add(ki)
        fc1_lines.append(f"        case {ki}U: _iface = {logical_idx}U; break;")
    fc1_lines.append("        default: break;")
    fc1_lines.append("    }")

    for j in range(n_h1):
        fc1_lines.append(f"    long long w_iface_{j} = 0LL, w_node_{j} = 0LL;")

    fc1_lines.append("    switch (_iface) {")
    for iface in range(1, n_interfaces + 1):
        assigns = " ".join(
            f"w_iface_{j} = {_lit(fc1_w[j * n_in + n_interfaces - 1 + iface])}LL;"
            for j in range(n_h1)
        )
        fc1_lines.append(f"        case {iface}: {assigns} break;")
    fc1_lines.append("        default: break;")
    fc1_lines.append("    }")

    fc1_lines.append("    switch (_node) {")
    for node in range(n_nodes):
        assigns = " ".join(
            f"w_node_{j} = {_lit(fc1_w[j * n_in + 2*n_interfaces + 1 + node])}LL"
            for j in range(n_h1)
        )
        fc1_lines.append(f"        case {node}: {assigns} break;")
    fc1_lines.append("        default: break;")
    fc1_lines.append("    }")

    for j in range(n_h1):
        w_ttl = int(fc1_w[j * n_in + 2 * n_interfaces])
        b_j   = int(fc1_b[j])
        ls_terms = " + ".join(
            f"ls{i} * {_lit(fc1_w[j * n_in + i])}LL" for i in range(n_interfaces)
        )
        fc1_lines.append(
            f"    long long h1_{j} = RELU_LL("
            f"(__s64)_ttl * {_lit(w_ttl)}LL"
            f" + w_iface_{j}"
            f" + w_node_{j}"
            f" + {ls_terms}"
            f" + {_lit(b_j)}LL);"
        )

    h1_names = [f"h1_{j}" for j in range(n_h1)]
    fc2_lines  = _gen_dense_layer(h1_names, n_h2, fc2_w, fc2_b, "h2", relu=True)
    h2_names = [f"h2_{j}" for j in range(n_h2)]
    out_lines  = _gen_dense_layer(h2_names, n_out, out_w, out_b, "out", relu=False)
    argmax_lines = _gen_argmax(n_out)

    ls_read_lines = ["    long long " + ", ".join(f"ls{i}=0LL" for i in range(n_interfaces)) + ";"]
    ls_read_lines.append("    { int _lk; __u32 *_lp;")
    for i in range(n_interfaces):
        ls_read_lines.append(
            f"       _lk={i}; _lp=link_state.lookup(&_lk); if (_lp) ls{i}=(long long)(*_lp);"
        )
    ls_read_lines.append("    }")

    fc1_src    = "\n".join(fc1_lines)
    fc2_src    = "\n".join(fc2_lines)
    out_src    = "\n".join(out_lines)
    argmax_src = "\n".join(argmax_lines)
    ls_src     = "\n".join(ls_read_lines)
    epilogue   = _gen_action_epilogue(f"best_cls >= {n_interfaces}")

    fn_name = f"model_{model_id}"
    body = f"""
int {fn_name}(struct xdp_md *ctx) {{
{_PACKET_PROLOGUE}
    /* Pure hardcoded: weights are C literals below, no weight map.
     * Always run inference. */
    __u16 scale = {scale}U;
    if (scale == 0) return XDP_PASS;

    /* link_state[0..{n_interfaces-1}]: egress up/down read from map into feature slots. */
{ls_src}

{fc1_src}

{fc2_src}

{out_src}

{argmax_src}
{epilogue}}}
"""
    src = body if not include_header else (
        f"/* Pipeline 1 (sparse) — model_id={model_id}, scale={scale}, "
        f"shape={n_in}-{n_h1}-{n_h2}-{n_out} */\n" + body
    )
    return src


def build_combined_hardcoded_source(
    models: list,
    n_interfaces: int = 6,
    n_nodes: int = 52,
    hidden_dims: tuple = (4, 4),
) -> str:
    """
    models: list of (model_id, weights_int8, scale, ifindex_table) tuples,
    all sharing the same (n_interfaces, n_nodes, hidden_dims) shape (mixing
    shapes in one compiled object isn't meaningful -- each shape needs its
    own map sizes; register differently-shaped models via separate BPF
    objects/method4_hardcoded.py runs instead).

    Returns one compilation unit: header (incl. model_progs) + dispatcher +
    one model_<id> function per entry in `models`. Caller loads
    "ipa_switch_hardcoded" as the XDP entry point, loads each "model_<id>",
    and wires model_progs[model_id] = model_<id>.fd.
    """
    n_out = n_interfaces + 1
    src = _build_header(n_interfaces, n_out, need_link_state=True) + "\n" + EBPF_HARDCODED_DISPATCHER
    for model_id, weights_int8, scale, ifindex_table in models:
        src += "\n" + generate_ebpf_hardcoded(
            weights_int8, scale, model_id, ifindex_table, include_header=False,
            n_interfaces=n_interfaces, n_nodes=n_nodes, hidden_dims=hidden_dims)
    return src


# ---------------------------------------------------------------------------
# Dense route: no FRR-specific semantics -- feature vector read straight
# from the IPA packet payload, n_in/n_out declared by the model.
# ---------------------------------------------------------------------------
def generate_ebpf_hardcoded_dense(
    weights_int8: list,
    scale: int,
    model_id: int = 0,
    n_in: int = 10,
    n_out: int = 4,
    hidden_dims: tuple = (4, 4),
    include_header: bool = True,
) -> str:
    """
    Generate an eBPF XDP program, function name `model_<model_id>`, for a
    "dense-generic" scenario model: the per-packet feature vector (int8,
    length n_in) is read directly from the IPA payload -- no link_state
    map, no ttl/ingress-iface/model_id feature derivation. n_out is a
    plain argmax width (no implicit "classes + drop" meaning is assumed
    by the datapath itself; by convention the last class, n_out-1, is
    still treated as DROP so the action epilogue matches the sparse
    route/mac_table semantics -- see _gen_action_epilogue()).

    Bounds check: one comparison against data_end covers the whole n_in-byte
    read (same idiom already used for struct ipa_hdr itself), then each
    feat[i] access is a plain constant-offset byte read -- no per-byte
    re-check needed, and no map lookup at all (cheaper than the sparse
    route's link_state reads).
    """
    n_h1, n_h2 = hidden_dims
    n_weights = n_in * n_h1 + n_h1 + n_h1 * n_h2 + n_h2 + n_h2 * n_out + n_out
    if len(weights_int8) != n_weights:
        raise ValueError(f"Expected {n_weights} weights, got {len(weights_int8)}")

    w = weights_int8
    fc1_w = w[0             : n_in*n_h1]
    fc1_b = w[n_in*n_h1     : n_in*n_h1 + n_h1]
    base2 = n_in*n_h1 + n_h1
    fc2_w = w[base2         : base2 + n_h1*n_h2]
    fc2_b = w[base2+n_h1*n_h2 : base2+n_h1*n_h2+n_h2]
    base3 = base2 + n_h1*n_h2 + n_h2
    out_w = w[base3         : base3 + n_h2*n_out]
    out_b = w[base3+n_h2*n_out : base3+n_h2*n_out+n_out]

    feat_terms = [f"(long long)(__s8)_feat[{i}]" for i in range(n_in)]
    fc1_lines  = _gen_dense_layer(feat_terms, n_h1, fc1_w, fc1_b, "h1", relu=True)
    h1_names   = [f"h1_{j}" for j in range(n_h1)]
    fc2_lines  = _gen_dense_layer(h1_names, n_h2, fc2_w, fc2_b, "h2", relu=True)
    h2_names   = [f"h2_{j}" for j in range(n_h2)]
    out_lines  = _gen_dense_layer(h2_names, n_out, out_w, out_b, "out", relu=False)
    argmax_lines = _gen_argmax(n_out)

    fc1_src    = "\n".join(fc1_lines)
    fc2_src    = "\n".join(fc2_lines)
    out_src    = "\n".join(out_lines)
    argmax_src = "\n".join(argmax_lines)
    epilogue   = _gen_action_epilogue(f"best_cls >= {n_out - 1}")

    fn_name = f"model_{model_id}"
    body = f"""
int {fn_name}(struct xdp_md *ctx) {{
{_PACKET_PROLOGUE}
    __u16 scale = {scale}U;
    if (scale == 0) return XDP_PASS;

    /* Dense-generic: feature vector is the payload itself, n_in={n_in}
     * quantized int8 values, one bounds check covers all of them. */
    __u8 *_feat = (__u8 *)(ipa + 1);
    if ((void *)(_feat + {n_in}) > data_end) return XDP_PASS;

{fc1_src}

{fc2_src}

{out_src}

{argmax_src}
{epilogue}}}
"""
    src = body if not include_header else (
        f"/* Pipeline 1 (dense) — model_id={model_id}, scale={scale}, "
        f"shape={n_in}-{n_h1}-{n_h2}-{n_out} */\n" + body
    )
    return src


def build_combined_hardcoded_dense_source(models: list, n_out: int, hidden_dims: tuple = (4, 4)) -> str:
    """
    models: list of (model_id, weights_int8, scale, n_in) tuples, all
    sharing the same n_out/hidden_dims (cls_stats/mac_table are sized by
    n_out; different n_in per model is fine since each model_<id> function
    declares its own bounds check independently).
    """
    src = _build_header(n_interfaces=0, n_out=n_out, need_link_state=False) + "\n" + EBPF_HARDCODED_DISPATCHER
    for model_id, weights_int8, scale, n_in in models:
        src += "\n" + generate_ebpf_hardcoded_dense(
            weights_int8, scale, model_id, n_in=n_in, n_out=n_out,
            hidden_dims=hidden_dims, include_header=False)
    return src


# ---------------------------------------------------------------------------
# Loader: resolves a model's scenario metadata (shared/model_meta.py) and
# dispatches to the sparse or dense generator.
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
    sparse/6/52/[4,4] shape when absent -- so existing callers that never
    heard of model_meta.json keep getting exactly today's behavior.

    scenario == "dense" never touches FastRerouteMLP/torch (there is no
    trained dense checkpoint format in this repo yet) -- it loads a flat
    int8 weight list straight from weights.json/weights_float.json next to
    model_path, matching whatever shape model_meta.json declares.
    """
    import json, os

    if meta is None:
        meta = _model_meta.load_model_meta(model_path)
    shape = _model_meta.derive_shape(meta)
    model_dir = os.path.dirname(model_path) or "."
    weights_float_path = os.path.join(model_dir, "weights_float.json")
    weights_plain_path = os.path.join(model_dir, "weights.json")

    if meta.get("scenario", "sparse") == "dense":
        from extract_weights import _load_from_json
        if os.path.exists(weights_float_path):
            with open(weights_float_path) as f:
                scale = int(json.load(f).get("scale_factor", meta.get("scale_factor", 128)))
            weights_int8 = _load_from_json(weights_float_path)
        elif os.path.exists(weights_plain_path):
            scale = int(meta.get("scale_factor", 128))
            weights_int8 = _load_from_json(weights_plain_path)
        else:
            raise FileNotFoundError(
                f"dense scenario needs weights.json or weights_float.json in {model_dir}")
        ebpf_src = build_combined_hardcoded_dense_source(
            [(model_id, weights_int8, scale, shape["n_in"])],
            n_out=shape["n_out"], hidden_dims=tuple(shape["hidden_dims"]))
        return ebpf_src, weights_int8, scale

    # scenario == "sparse" (default, backward compatible)
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
        n_interfaces=shape["n_interfaces"], n_nodes=shape["n_nodes"],
        hidden_dims=tuple(shape["hidden_dims"]))
    return ebpf_src, weights_int8, scale


EBPF_PROGRAM = build_combined_hardcoded_source([(0, [0]*N_WEIGHTS, 128, None)])

if __name__ == "__main__":
    import sys
    model_path = sys.argv[1] if len(sys.argv) > 1 else "shared/frr_germany50_5_model_4x2.pt"
    src, w, s = load_and_generate(model_path)
    print(src)
