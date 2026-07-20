"""
ebpf_modular.py  —  Pipeline 3: Modular Neural Pipeline.

Design space position:
  - Neural inference is decomposed into a tail-call chain of TWO generic
    layer programs (not one per layer, not one per model):
      layer_first  : always hop 0. Input is the protocol-fixed 65-feature
                      IPA vector, read SPARSELY straight from scratch_meta +
                      link_state (same trick as Pipeline 2's arch_generic_2layer
                      -- only ~9 of 65 inputs are ever non-zero per packet).
                      Output width n_out is dynamic, up to ML1_MAX_H1.
      layer_hidden  : hop 1..n_layers-1. Dense n_in -> n_out (both dynamic,
                      up to MLH_MAX_H), reading/writing scratch_acts.
  - Whichever hop is the model's LAST layer (decided at runtime, not by
    which program is wired at that slot -- see below) argmaxes and forwards
    instead of chaining further
  - Maximum flexibility: changing model architecture (depth AND width) =
    change the registered (n_in, n_out) list + weights for that model_id;
    no eBPF recompilation, for any depth/width combination within the
    compiled ceilings below

Why two programs, not one "fully generic" block:
  An earlier version of this file used ONE block generic over n_in up to 80
  (to also cover the 65-wide first layer) with a DENSE map-lookup loop over
  every input position. That blew the kernel's BPF_COMPLEXITY_LIMIT_INSNS
  (4096 instructions on this lab's kernel -- the historic pre-5.2 hard cap,
  not the newer 1M-instruction limit): looping densely over 65 mostly-zero
  inputs for every hidden neuron is enormously wasteful, since real IPA
  packets only ever have ~9 non-zero features (link_state bits, one ingress-
  iface bit, ttl, one node bit). Splitting the first hop into its own
  program that reads those ~9 positions directly (mirroring Pipeline 2's
  sparse fc1) cuts its cost by roughly 7x and keeps hidden-to-hidden hops
  small (dense, but bounded to a small MLH_MAX_H, not the 65-wide input).
  Two small compiled programs fit the 4096-instruction cap; one large one
  did not.

Compile-time ceilings (verifier needs a compile-time trip count; wider/
deeper models need these raised and the program reloaded once -- raising
them grows layer_first/layer_hidden's own instruction count, watch the
4096-instruction cap on kernels that still enforce it):
  PROTO_N_IN   = 65  (fixed: the IPA feature vector is always this wide;
                       not a ceiling, the exact, protocol-mandated width)
  ML1_MAX_H1   = 8   (first layer's output width ceiling)
  MLH_MAX_H    = 8   (every later layer's input AND output width ceiling,
                       including the model's last layer, e.g. the
                       protocol-fixed 7-class output)
  layer_chain size = 16 (max depth; Linux tail-call limit is ~33 anyway)
A layer whose shape exceeds these is rejected at load time by
load_modular_weights() with a clear error, not silently corrupted.

Why the two programs never conflict across concurrently-registered models
of different depths:
  layer_chain[0] is ALWAYS layer_first.fd and layer_chain[i>=1] is ALWAYS
  layer_hidden.fd, for every model, regardless of that model's own depth --
  because layer 0 is always "the first layer" and layer i>=1 is always "a
  later layer", true for any model. Whether a given hop is ALSO "the last
  layer" (argmax+redirect instead of ReLU+continue) is decided INSIDE the
  program from data (layer_idx+1 == n_layers, both read from per-model
  registries), never by which program sits at that tail-call slot. So
  model A (3 layers) and model B (2 layers) can share layer_chain[1]
  perfectly fine: for A it continues to layer_chain[2], for B it argmaxes,
  and both facts are resolved from A/B's own registry entry, not from the
  slot itself.

Maps:
  scratch_acts     : BPF_PERCPU_ARRAY  index -> long long  (hidden activations,
                      NOT used for the first layer -- that reads scratch_meta
                      + link_state directly, see layer_first)
  scratch_meta      : BPF_PERCPU_ARRAY  0 -> {model_id, scale, layer_idx, ingress_if, ttl}
  layer_weights     : BPF_ARRAY  (flat index) -> __u8  (unsigned byte storage;
                      eBPF C code casts to __s8 for signed arithmetic via WEIGHT() macro;
                      Python side stores int8 as c_uint8(v & 0xFF) two's complement)
  layer_chain       : BPF_PROG_ARRAY  0 -> layer_first.fd, 1..15 -> layer_hidden.fd
  layer_registry    : model_id -> {scale_factor, n_layers}
  layer_shapes      : {model_id, layer_idx} -> {n_in, n_out, weight_offset}
  mac_table_t3      : u32 class (argmax output) -> fwd_action {ifindex, src/dst MAC}
  cls_stats_t3      : per-class redirect counter
  pkt_stats_t3      : [0]=HIT [1]=MISS [2]=DROP

Action: the last layer runs argmax -> class, then a single mac_table_t3[class]
lookup resolves the L2 next-hop and bpf_redirect()s (cls 6 = DROP). No output
key, no per-TTL validation -- the NN decides, the table only maps class->port.

Feature encoding (protocol-fixed, independent of hidden depth/width):
  link_state[0..5] + ingress-iface one-hot [6..11] + ttl [12] + node one-hot
  [13..64] -- always the first layer's n_in=65 input; the last layer's
  n_out is always 7 (6 egress classes + drop), matching the mac_table/argmax
  action above. layer_first reads these straight from scratch_meta/link_state
  (no dense 65-slot scratch_acts array is ever built for it).

Weight storage:
  layer_weights uses an unsigned-byte leaf (__u8). The libbcc build in the
  Kathara container cannot resolve a signed-byte leaf type, so signedness is
  handled explicitly: the eBPF C code casts each byte to __s8 via WEIGHT()
  before arithmetic, and load_modular_weights() stores each int8 as
  c_uint8(v & 0xFF) (identical two's-complement bits), bypassing the BCC leaf
  encoder for the map write.
"""

# Scratch map layout constants
SCRATCH_ACT_SIZE   = 128   # max activations at any layer boundary
SCRATCH_META_SLOTS = 16    # metadata slots

# Metadata indices in scratch_meta
META_MODEL_ID     = 0
META_SCALE        = 1
META_LAYER_IDX    = 2
META_INGRESS_IF   = 3
META_TTL          = 4

# Compile-time layer-shape ceilings (see module docstring)
PROTO_N_IN   = 65   # protocol-fixed IPA feature vector width, not a ceiling
ML1_MAX_H1   = 8    # first layer's output width ceiling
MLH_MAX_H    = 8    # later layers' input/output width ceiling
LAYER_CHAIN_SIZE = 16

EBPF_MODULAR_COMMON_HEADER = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

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

/* Scratch maps: PERCPU to avoid contention */
#define SCRATCH_ACT_SIZE   128
#define SCRATCH_META_SLOTS  16
BPF_PERCPU_ARRAY(scratch_acts, long long, SCRATCH_ACT_SIZE);
BPF_PERCPU_ARRAY(scratch_meta, long long, SCRATCH_META_SLOTS);

/* Weight map: __u8 leaf (unsigned byte storage).
 * Using __u8 instead of __s8 avoids KeyError: 'signed char' in BCC
 * str2ctype on older libbcc versions (< 0.20) present in the Kathara
 * container.  __s8 expands to 'signed char' which is absent from
 * str2ctype; __u8 expands to 'unsigned char' which IS present.
 * Sign semantics are preserved: eBPF C code casts each retrieved byte
 * to (__s8) via the WEIGHT() macro before any multiply-accumulate. */
#define MAX_LAYER_WEIGHT_ENTRIES 2048
BPF_ARRAY(layer_weights, __u8, MAX_LAYER_WEIGHT_ENTRIES);

/* link_state: 6 egress up/down slots (feature [0..5]), held in ONE struct-valued
 * entry (key 0) so layer_first reads the whole vector with a SINGLE lookup
 * instead of 6. Written by the userspace carrier monitor. 1=up, 0=down. */
struct ls_vec { __u32 v[6]; };
BPF_ARRAY(link_state, struct ls_vec, 1);

/* queue_occupancy feature: n_queues occupancy slots in one struct-valued entry
 * (key 0), seeded by queue_state_monitor.py. Present so a descriptor can use the
 * queue_occupancy feature type; unused if the model's descriptor omits it. */
struct qs_vec { __u32 v[4]; };
BPF_ARRAY(queue_state, struct qs_vec, 1);

/* Per-model feature descriptor (model_desc registry): which feature types the
 * first-hop input uses, their size and starting column in the layer-0 input
 * row. Populated by the control plane from model_meta.resolve_descriptor(); read
 * at runtime by layer_first to build the IV generically instead of the old
 * hardcoded 65-feature layout. */
#define ML_MAX_FEAT 4
struct feat_ent { __u8 code; __u8 size; __u8 col_off; __u8 _pad; };
struct model_desc { __u8 n_feat; __u8 n_in; __u8 _p0; __u8 _p1; struct feat_ent feats[ML_MAX_FEAT]; };
BPF_HASH(model_desc, __u8, struct model_desc, 256);

/* Layer chain tail-call map: slot 0 = layer_first.fd, slots 1..15 =
 * layer_hidden.fd -- see module docstring for why this never conflicts
 * across concurrently-registered models of different depths. */
BPF_PROG_ARRAY(layer_chain, 16);

/* mac_table: egress class (0..5, the argmax output) -> {ifindex, src/dst MAC}.
 * The NN decides the port; this only resolves the L2 next-hop. */
BPF_HASH(mac_table_t3, __u32, struct fwd_action, 8);
BPF_ARRAY(pkt_stats_t3, __u64, 3);   /* [0]=HIT [1]=MISS [2]=DROP */
BPF_ARRAY(cls_stats_t3, __u64, 7);   /* per-class redirect counter */

/* CTR_INC(): real per-packet map-lookup counter, active only when
 * IPA_COUNT_LOOKUPS is #defined before this source (measurement builds --
 * see common.py instrument_map_lookups()). No-op otherwise. */
#ifdef IPA_COUNT_LOOKUPS
BPF_ARRAY(lookup_ctr, __u64, 1);
/* BCC's rewriter refuses table.lookup() calls that appear textually inside
 * a macro expansion -- must be a real function (static inline, like
 * ml_argmax_forward below), not a #define body. */
static inline __attribute__((always_inline)) void ctr_inc(void) {
    int _lci = 0;
    __u64 *_lcv = lookup_ctr.lookup(&_lci);
    if (_lcv) __sync_fetch_and_add(_lcv, 1);
}
#define CTR_INC() ctr_inc()
#else
#define CTR_INC() do {} while (0)
#endif

/* Explicit signed cast so arithmetic is correct after __u8 storage */
#define WEIGHT(p) ((__s8)(*p))
#define RELU(x)  ((x) > 0 ? (x) : 0)

/* Metadata slot indices */
#define META_MODEL_ID    0
#define META_SCALE       1
#define META_LAYER_IDX   2
#define META_INGRESS_IF  3
#define META_TTL         4

/* Per-model metadata: model_id -> {scale_factor, n_layers}. n_layers tells
 * each hop when it has reached the last layer (layer_idx+1==n_layers). */
struct layer_model_entry {
    __u16 scale_factor;
    __u8  n_layers;
} __attribute__((packed));
BPF_HASH(layer_registry, __u8, struct layer_model_entry, 256);

/* Per-(model_id, layer_idx) shape: which n_in/n_out this hop computes and
 * where its weights start in the flat layer_weights array. This is what
 * makes the layer chain architecture-agnostic -- it never assumes a fixed
 * width or depth, it just looks up what THIS model's THIS layer needs.
 * (layer 0's n_in is always PROTO_N_IN=65 by protocol, so only its n_out
 * is actually consulted -- see layer_first.) */
struct layer_shape_key {
    __u8 model_id;
    __u8 layer_idx;
} __attribute__((packed));
struct layer_shape_entry {
    __u16 n_in;
    __u16 n_out;
    __u32 weight_offset;
} __attribute__((packed));
BPF_HASH(layer_shapes, struct layer_shape_key, struct layer_shape_entry, 512);

/* Shared argmax + mac_table + redirect epilogue, used by both layer_first
 * (1-layer models) and layer_hidden whenever they are the model's last
 * layer. A plain C helper, not a macro, so both callers get one copy of
 * the logic without the macro-argument foot-guns of the previous 3-block
 * design (see git history: struct padding bugs from more implicit magic). */
static inline __attribute__((always_inline))
int ml_argmax_forward(struct xdp_md *ctx, void *data, void *data_end, int best_cls) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (best_cls >= 6) {
        int di = 2; __u64 *dv = pkt_stats_t3.lookup(&di);
        if (dv) __sync_fetch_and_add(dv, 1);
        return XDP_DROP;
    }

    __u32 cls = (__u32)best_cls;
    struct fwd_action *action = mac_table_t3.lookup(&cls);
    if (action != NULL) {
        int si = 0; __u64 *v = pkt_stats_t3.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        __u64 *cv = cls_stats_t3.lookup(&cls);
        if (cv) __sync_fetch_and_add(cv, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    /* no mac_table entry for that class (e.g. link down / not provisioned) */
    int si = 1; __u64 *v = pkt_stats_t3.lookup(&si);
    if (v) __sync_fetch_and_add(v, 1);
    return XDP_PASS;
}
"""

# -----------------------------------------------------------------
# Dispatcher: parse packet, stash metadata, tail call layer_chain[0].
# No scratch_acts writes here -- layer_first reads scratch_meta/link_state
# directly (sparse), it never needs a dense 65-slot feature array.
# -----------------------------------------------------------------
EBPF_MODULAR_DISPATCHER = EBPF_MODULAR_COMMON_HEADER + r"""

int modular_dispatcher(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)  return XDP_PASS;
    /* Read protocol via absolute RFC 791 byte offset (byte 9), not ip->protocol,
     * to avoid bitfield packing ambiguity -- see ebpf_program.py FIX(#4). */
    __u8 ip_proto = *((__u8 *)ip + 9);
    if (ip_proto != IPPROTO_UDP)   return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)  return XDP_PASS;
    if (udp->dest != bpf_htons(9999))  return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end)  return XDP_PASS;

    __u8 model_id = ipa->model_id;
    struct layer_model_entry *lentry = layer_registry.lookup(&model_id);
    if (!lentry) return XDP_PASS;

    int idx;
    idx = META_MODEL_ID;   { long long v = model_id;               scratch_meta.update(&idx, &v); }
    idx = META_SCALE;      { long long v = lentry->scale_factor;   scratch_meta.update(&idx, &v); }
    idx = META_LAYER_IDX;  { long long v = 0LL;                    scratch_meta.update(&idx, &v); }
    idx = META_INGRESS_IF; { long long v = ctx->ingress_ifindex;   scratch_meta.update(&idx, &v); }
    idx = META_TTL;        { long long v = ip->ttl;                scratch_meta.update(&idx, &v); }

    /* Tail call to layer_chain[0] = layer_first. It reads model_id/scale/
     * ttl/ingress_if straight back out of scratch_meta and link_state --
     * the protocol-fixed 65-feature vector is never materialized densely. */
    layer_chain.call(ctx, 0);
    return XDP_PASS;
}
"""

# -----------------------------------------------------------------
# layer_first: always hop 0. Sparse read of the protocol-fixed 65-feature
# IPA vector (mirrors Pipeline 2's arch_generic_2layer fc1 loop) -> n_out
# up to ML1_MAX_H1. Argmax+forward directly if this is also the last layer
# (a 1-layer model), otherwise ReLU + write scratch_acts + chain to hop 1.
# -----------------------------------------------------------------
EBPF_LAYER_FIRST = EBPF_MODULAR_COMMON_HEADER + r"""
#define PROTO_N_IN  65
#define ML1_MAX_H1   8
#define ML_N_QUEUES  4
#define ML_MAX_N_IN  128
#define FEAT_LINK_STATE  0x01
#define FEAT_INGRESS_IF  0x02
#define FEAT_TTL         0x03
#define FEAT_NODE_ID     0x04
#define FEAT_QUEUE_OCC   0x05

int layer_first(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int mi_model = META_MODEL_ID;
    long long *mp = scratch_meta.lookup(&mi_model);
    if (!mp) return XDP_PASS;
    __u8 model_id = (__u8)(*mp);

    int ms = META_SCALE;
    long long *sp = scratch_meta.lookup(&ms);
    if (!sp || *sp == 0) return XDP_PASS;

    struct layer_model_entry *lentry = layer_registry.lookup(&model_id);
    if (!lentry) return XDP_PASS;
    __u8 n_layers = lentry->n_layers;
    if (n_layers == 0) return XDP_PASS;
    __u8 is_last = (n_layers == 1) ? 1 : 0;

    struct layer_shape_key key = {};
    key.model_id  = model_id;
    key.layer_idx = 0;
    struct layer_shape_entry *shape = layer_shapes.lookup(&key);
    if (!shape) return XDP_PASS;

    __u32 n_out = shape->n_out;
    __u32 woff  = shape->weight_offset;
    if (n_out == 0 || n_out > ML1_MAX_H1) return XDP_PASS;

    /* Per-model feature descriptor: n_in (= sum of feature sizes) + feature
     * layout, read at runtime -> the first-hop IV is built GENERICALLY instead
     * of the old hardcoded 65-feature layout. Populated by the CP via
     * model_meta.resolve_descriptor(). */
    struct model_desc *desc = model_desc.lookup(&model_id);
    if (!desc) return XDP_PASS;
    __u32 n_in = desc->n_in;
    if (n_in == 0 || n_in > ML_MAX_N_IN) return XDP_PASS;
    __u32 bias_off = n_in * n_out;

    int mtl = META_TTL;
    long long *ttlp = scratch_meta.lookup(&mtl);
    __u32 _ttl = ttlp ? (__u32)(*ttlp) & 0xff : 0;

    int mif = META_INGRESS_IF;
    long long *ifp = scratch_meta.lookup(&mif);
    __u32 _raw_iface = ifp ? (__u32)(*ifp) : 0;

    __u32 _node = (__u32)model_id;

    /* dense feature vectors, each read once (single lookup), reused per neuron.
     * Sized to the topology; the descriptor's per-feature size gates the slots. */
    long long ls[6];
    { int lsz = 0; struct ls_vec *lsp = link_state.lookup(&lsz);
      #pragma unroll
      for (int i = 0; i < 6; i++) ls[i] = lsp ? (long long)(lsp->v[i]) : 0LL; }
    long long qs[ML_N_QUEUES];
    { int qsz = 0; struct qs_vec *qsp = queue_state.lookup(&qsz);
      #pragma unroll
      for (int i = 0; i < ML_N_QUEUES; i++) qs[i] = qsp ? (long long)(qsp->v[i]) : 0LL; }

    long long out[ML1_MAX_H1];
    long long best_val = -9999999LL;
    int best_cls = 0;

    #pragma unroll
    for (int j = 0; j < ML1_MAX_H1; j++) {
        if (j >= n_out) { out[j] = 0LL; continue; }

        int bidx = woff + bias_off + j;
        __u8 *bp = layer_weights.lookup(&bidx);
        long long acc = bp ? (long long)WEIGHT(bp) : 0LL;

        /* Descriptor-driven IV: each declared feature contributes at its runtime
         * column offset (layer-0 row = j*n_in + col_off). Unrolled to
         * ML_MAX_FEAT; slots past n_feat skipped. Dense features gate on feat
         * size; one-hot (iface/node) is a single runtime-indexed weight. */
        #pragma unroll
        for (int f = 0; f < ML_MAX_FEAT; f++) {
            if (f < desc->n_feat) {
                __u8  code = desc->feats[f].code;
                __u32 sz   = desc->feats[f].size;
                __u32 base = woff + j * n_in + desc->feats[f].col_off;
                if (code == FEAT_TTL) {
                    int idx = base;
                    __u8 *wp = layer_weights.lookup(&idx);
                    if (wp) acc += (long long)_ttl * (long long)WEIGHT(wp);
                } else if (code == FEAT_LINK_STATE) {
                    #pragma unroll
                    for (int i = 0; i < 6; i++) {
                        if ((__u32)i < sz) {
                            int idx = base + i;
                            __u8 *wp = layer_weights.lookup(&idx);
                            if (wp) acc += ls[i] * (long long)WEIGHT(wp);
                        }
                    }
                } else if (code == FEAT_QUEUE_OCC) {
                    #pragma unroll
                    for (int i = 0; i < ML_N_QUEUES; i++) {
                        if ((__u32)i < sz) {
                            int idx = base + i;
                            __u8 *wp = layer_weights.lookup(&idx);
                            if (wp) acc += qs[i] * (long long)WEIGHT(wp);
                        }
                    }
                } else if (code == FEAT_INGRESS_IF) {
                    if (_raw_iface >= 1 && _raw_iface <= sz) {
                        int idx = base + (_raw_iface - 1);
                        __u8 *wp = layer_weights.lookup(&idx);
                        if (wp) acc += (long long)WEIGHT(wp);
                    }
                } else if (code == FEAT_NODE_ID) {
                    if (_node < sz) {
                        int idx = base + _node;
                        __u8 *wp = layer_weights.lookup(&idx);
                        if (wp) acc += (long long)WEIGHT(wp);
                    }
                }
            }
        }

        if (is_last) {
            if (acc > best_val) { best_val = acc; best_cls = j; }
        } else {
            out[j] = RELU(acc);
        }
    }

    if (!is_last) {
        #pragma unroll
        for (int j = 0; j < ML1_MAX_H1; j++) {
            int ki = j;
            scratch_acts.update(&ki, &out[j]);
        }
        int li = META_LAYER_IDX;
        long long nv = 1LL;
        scratch_meta.update(&li, &nv);
        layer_chain.call(ctx, 1);
        return XDP_PASS;
    }

    return ml_argmax_forward(ctx, data, data_end, best_cls);
}
"""

# -----------------------------------------------------------------
# layer_hidden: hop 1..n_layers-1. Dense n_in -> n_out (+ ReLU, unless this
# is the model's last layer, in which case argmax+forward instead).
# -----------------------------------------------------------------
EBPF_LAYER_HIDDEN = EBPF_MODULAR_COMMON_HEADER + r"""
#define MLH_MAX_H  8

int layer_hidden(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int mi_model = META_MODEL_ID;
    long long *mp = scratch_meta.lookup(&mi_model);
    if (!mp) return XDP_PASS;
    __u8 model_id = (__u8)(*mp);

    int mi_layer = META_LAYER_IDX;
    long long *lp = scratch_meta.lookup(&mi_layer);
    if (!lp) return XDP_PASS;
    __u8 layer_idx = (__u8)(*lp);

    struct layer_model_entry *lentry = layer_registry.lookup(&model_id);
    if (!lentry) return XDP_PASS;
    __u8 n_layers = lentry->n_layers;
    if (n_layers == 0 || layer_idx >= n_layers) return XDP_PASS;
    __u8 is_last = (layer_idx + 1 == n_layers) ? 1 : 0;

    struct layer_shape_key key = {};
    key.model_id  = model_id;
    key.layer_idx = layer_idx;
    struct layer_shape_entry *shape = layer_shapes.lookup(&key);
    if (!shape) return XDP_PASS;

    __u32 n_in  = shape->n_in;
    __u32 n_out = shape->n_out;
    __u32 woff  = shape->weight_offset;
    if (n_in == 0 || n_in > MLH_MAX_H || n_out == 0 || n_out > MLH_MAX_H) return XDP_PASS;
    __u32 bias_off = n_in * n_out;

    long long out[MLH_MAX_H];
    long long best_val = -9999999LL;
    int best_cls = 0;

    #pragma unroll
    for (int j = 0; j < MLH_MAX_H; j++) {
        if (j >= n_out) { out[j] = 0LL; continue; }
        int bidx = woff + bias_off + j;
        __u8 *bp = layer_weights.lookup(&bidx);
        long long acc = bp ? (long long)WEIGHT(bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < MLH_MAX_H; i++) {
            if (i >= n_in) continue;
            int fi = i;
            long long *xp = scratch_acts.lookup(&fi);
            long long x = xp ? *xp : 0LL;
            int widx = woff + j * n_in + i;
            __u8 *wp = layer_weights.lookup(&widx);
            if (wp) acc += x * (long long)WEIGHT(wp);
        }
        if (is_last) {
            if (acc > best_val) { best_val = acc; best_cls = j; }
        } else {
            out[j] = RELU(acc);
        }
    }

    if (!is_last) {
        #pragma unroll
        for (int j = 0; j < MLH_MAX_H; j++) {
            int ki = j;
            scratch_acts.update(&ki, &out[j]);
        }
        int li = META_LAYER_IDX;
        long long nv = (long long)(layer_idx + 1);
        scratch_meta.update(&li, &nv);
        layer_chain.call(ctx, layer_idx + 1);
        return XDP_PASS;
    }

    return ml_argmax_forward(ctx, data, data_end, best_cls);
}
"""

# Full combined source for single-program compilation
EBPF_MODULAR_FULL = (
    EBPF_MODULAR_DISPATCHER
    + "\n" + EBPF_LAYER_FIRST.replace(EBPF_MODULAR_COMMON_HEADER, "")
    + "\n" + EBPF_LAYER_HIDDEN.replace(EBPF_MODULAR_COMMON_HEADER, "")
)


def load_modular_weights(
    bpf_obj,
    weights_int8: list,
    model_id: int = 0,
    scale: int = 128,
    layer_dims: list = None,
    base_offset: int = 0,
    features: list = None,
) -> int:
    """
    Populate layer_registry, layer_shapes and layer_weights for Pipeline 3.

    layer_dims: ordered list of (n_in, n_out) tuples, one per layer, e.g.
      [(65, 4), (4, 4), (4, 7)] for today's 65-4-4-7 model (the default,
      used when layer_dims is None -- backward compatible with the one
      trained model checked into the repo). Any depth/width combination
      works as long as:
        - the first layer's n_in is exactly PROTO_N_IN=65 (protocol
          feature vector -- layer_first reads it sparsely, not generically)
          and its n_out is <= ML1_MAX_H1
        - every later layer's n_in and n_out are both <= MLH_MAX_H
      This is what makes Pipeline 3 genuinely architecture-agnostic: no
      eBPF recompilation for a different depth or different hidden widths,
      just a different layer_dims + weights. By protocol, the last layer's
      n_out should be 7 (6 egress classes + drop) -- not enforced here, but
      a mismatch will desync the mac_table class range from what the
      network expects.

    base_offset: lets the caller stack several models' weights in the same
      layer_weights array without overlap (like Pipeline 2's weight_offset).
      Returns the total weight count this model consumed, so the caller can
      compute the next model's base_offset as a running sum -- models may
      have different total sizes (different depth/width), unlike Pipeline 2
      where every model shares the same 2-hidden-layer topology.

    Weight layout in the flat array (relative to base_offset): each layer's
    weights back-to-back, each as [n_in*n_out weights][n_out biases] --
    identical to the flat layout already used by weights.json for the
    3-layer case, so the checked-in weights.json needs no migration.

    NOTE: layer_weights map uses __u8 in C (to avoid BCC str2ctype
    KeyError: 'signed char' on older libbcc).  We store the int8 value
    as its unsigned two's-complement bit pattern (c_uint8).  The eBPF C
    code re-casts each byte to (__s8) before accumulation, so arithmetic
    is correct.
    """
    from ctypes import c_uint8, c_uint16, c_uint32, Structure

    if layer_dims is None:
        layer_dims = [(65, 4), (4, 4), (4, 7)]

    n_layers = len(layer_dims)
    if n_layers == 0 or n_layers > LAYER_CHAIN_SIZE:
        raise ValueError(f"n_layers={n_layers} must be in [1, {LAYER_CHAIN_SIZE}] (layer_chain size)")

    for i, (n_in, n_out) in enumerate(layer_dims):
        if i == 0:
            # First-layer n_in = the descriptor's N_IN (sum of feature sizes),
            # no longer fixed to 65: layer_first now builds the IV generically
            # from model_desc. Must match the model_desc seeded for this model_id
            # (see load_model_desc) and stay within the compiled ceiling.
            if n_in <= 0 or n_in > 128:  # MAX_N_IN / ML_MAX_N_IN in the eBPF source
                raise ValueError(
                    f"first layer n_in={n_in} outside [1, 128] (ML_MAX_N_IN)")
            if n_out <= 0 or n_out > ML1_MAX_H1:
                raise ValueError(
                    f"first layer n_out={n_out} exceeds the compiled ceiling "
                    f"ML1_MAX_H1={ML1_MAX_H1} -- raise it in ebpf_modular.py and reload")
        else:
            if n_in <= 0 or n_in > MLH_MAX_H or n_out <= 0 or n_out > MLH_MAX_H:
                raise ValueError(
                    f"layer {i} shape ({n_in},{n_out}) exceeds the compiled ceiling "
                    f"MLH_MAX_H={MLH_MAX_H} -- raise it in ebpf_modular.py and reload")

    total_weights = sum(n_in * n_out + n_out for (n_in, n_out) in layer_dims)
    if base_offset + total_weights > 2048:  # MAX_LAYER_WEIGHT_ENTRIES in the eBPF source
        raise ValueError(
            f"base_offset={base_offset} + total_weights={total_weights} "
            f"exceeds MAX_LAYER_WEIGHT_ENTRIES=2048 -- too many concurrent model_id's")
    if len(weights_int8) < total_weights:
        raise ValueError(
            f"layer_dims={layer_dims} needs {total_weights} weights, "
            f"got only {len(weights_int8)}")

    # Flat per-layer offsets (relative to base_offset)
    layer_offsets = []
    offset = base_offset
    for (n_in, n_out) in layer_dims:
        layer_offsets.append(offset)
        offset += n_in * n_out + n_out

    for idx, w in enumerate(weights_int8[:total_weights]):
        key = c_uint32(base_offset + idx)
        val = c_uint8(int(w) & 0xFF)
        bpf_obj["layer_weights"][key] = val

    class LayerShapeKey(Structure):
        _pack_ = 1
        _fields_ = [("model_id", c_uint8), ("layer_idx", c_uint8)]

    class LayerShapeEntry(Structure):
        _pack_ = 1
        _fields_ = [("n_in", c_uint16), ("n_out", c_uint16), ("weight_offset", c_uint32)]

    shapes_table = bpf_obj["layer_shapes"]
    for layer_idx, ((n_in, n_out), woff) in enumerate(zip(layer_dims, layer_offsets)):
        shapes_table[LayerShapeKey(model_id=model_id, layer_idx=layer_idx)] = \
            LayerShapeEntry(n_in=n_in, n_out=n_out, weight_offset=woff)

    class LayerModelEntry(Structure):
        _pack_ = 1
        _fields_ = [("scale_factor", c_uint16), ("n_layers", c_uint8)]

    bpf_obj["layer_registry"][c_uint8(model_id)] = \
        LayerModelEntry(scale_factor=scale, n_layers=n_layers)

    shape_str = "-".join(str(d[0]) for d in layer_dims) + f"-{layer_dims[-1][1]}"
    print(f"[Pipeline3] model_id={model_id} registered: scale={scale}, "
          f"shape={shape_str}, n_layers={n_layers}, "
          f"base_offset={base_offset}, total_weights={total_weights}")

    # Seed the first-hop feature descriptor (default 65-feature layout unless a
    # custom one is passed) so layer_first builds its IV generically. Folded in
    # here so every existing caller (methods + test harnesses) registers
    # model_desc without a separate call. n_in must equal the first layer's n_in.
    if features is None:
        from model_meta import derive_shape, DEFAULT_META, DEFAULT_TOPOLOGY_CONFIG
        features = derive_shape(dict(DEFAULT_META),
                                topology_config=dict(DEFAULT_TOPOLOGY_CONFIG))["features"]
    load_model_desc(bpf_obj, features, n_in=layer_dims[0][0], model_id=model_id)
    return total_weights


# Max features per descriptor -- must match ML_MAX_FEAT in the eBPF source.
ML_MAX_FEAT = 4


def load_model_desc(bpf_obj, features: list, n_in: int, model_id: int = 0) -> None:
    """
    Populate model_desc[model_id] so layer_first builds the first-hop input
    vector GENERICALLY from a per-model descriptor (instead of the old hardcoded
    65-feature layout). Call once per registered model_id, alongside
    load_modular_weights(); n_in must equal layer_dims[0][0].

    features: resolved descriptor (list of {"type","size"}, from
              model_meta.derive_shape) in the order the model was trained on;
              its flat (code,size,col_off) form comes from
              model_meta.resolve_descriptor(). Default [link_state,
              ingress_iface, ttl, node] / n_in=65 reproduces the historical
              layer-0 layout byte-for-byte.
    """
    from ctypes import c_uint8, Structure
    from model_meta import resolve_descriptor

    ents = resolve_descriptor(features)
    if len(ents) > ML_MAX_FEAT:
        raise ValueError(
            f"descriptor has {len(ents)} features, exceeds ML_MAX_FEAT={ML_MAX_FEAT} "
            f"(raise ML_MAX_FEAT in ebpf_modular.py and reload to support it)")
    if n_in > 128:  # ML_MAX_N_IN in the eBPF source
        raise ValueError(f"n_in={n_in} exceeds ML_MAX_N_IN=128")

    class FeatEnt(Structure):
        _pack_ = 1
        _fields_ = [("code", c_uint8), ("size", c_uint8),
                    ("col_off", c_uint8), ("_pad", c_uint8)]

    class ModelDesc(Structure):
        _pack_ = 1
        _fields_ = [("n_feat", c_uint8), ("n_in", c_uint8),
                    ("_p0", c_uint8), ("_p1", c_uint8),
                    ("feats", FeatEnt * ML_MAX_FEAT)]

    d = ModelDesc(n_feat=len(ents), n_in=n_in)
    for i, e in enumerate(ents):
        d.feats[i] = FeatEnt(code=e["code"], size=e["size"], col_off=e["col_off"])
    bpf_obj["model_desc"][c_uint8(model_id)] = d
    print(f"[Pipeline3] model_desc[{model_id}] = n_feat={len(ents)} n_in={n_in} "
          f"feats={[(e['code'], e['size'], e['col_off']) for e in ents]}")
