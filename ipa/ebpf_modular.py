"""ebpf_modular.py -- Pipeline 3 (P3): the modular pipeline.

The network runs as a chain of tail calls through two generic layer programs
(layer_first, layer_hidden). Shapes and weights live in maps, so any depth and
width up to the compiled ceilings runs without recompiling.
"""
import os

SCRATCH_ACT_SIZE   = 128
SCRATCH_META_SLOTS = 16
META_MODEL_ID     = 0
META_SCALE        = 1
META_LAYER_IDX    = 2
META_NODE_CTX     = 3
META_TTL          = 4

ML1_MAX_H1   = 8
P3_MAX_QUEUES = 8
MLH_MAX_H    = 8
LAYER_CHAIN_SIZE = 16
MAX_LAYER_WEIGHT_ENTRIES = 2048
EBPF_MODULAR_COMMON_HEADER = r"""
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

#define ACT_INVALID 0
#define ACT_FORWARD 1
#define ACT_DROP    2
#define ACT_UNUSED  3
#define MAX_N_OUT   32
struct class_act { __u8 action; __u8 port; __u8 _p0; __u8 _p1; };

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

#define SCRATCH_ACT_SIZE   128
#define SCRATCH_META_SLOTS  16
struct act_vec { long long v[SCRATCH_ACT_SIZE]; };
#define barrier_var(x) asm volatile("" : "=r"(x) : "0"(x))

BPF_PERCPU_ARRAY(scratch_acts, struct act_vec, 1);
BPF_PERCPU_ARRAY(scratch_meta, long long, SCRATCH_META_SLOTS);

#define MAX_LAYER_WEIGHT_ENTRIES 2048
struct lw_blk { __u8 w[MAX_LAYER_WEIGHT_ENTRIES]; };
BPF_ARRAY(layer_weights, struct lw_blk, 1);

#define LW_W(blk, i) ((long long)(__s8)((blk)->w[(__u32)(i) & (MAX_LAYER_WEIGHT_ENTRIES - 1)]))

#define IPA_MAX_IFACES  8
#define IPA_MAX_QUEUES  8
struct ls_vec { __u32 v[IPA_MAX_IFACES]; };
BPF_ARRAY(link_state, struct ls_vec, 1);

struct qs_vec { __u32 v[IPA_MAX_QUEUES]; };
BPF_ARRAY(queue_state, struct qs_vec, 1);

#define ML_MAX_FEAT 4
#define ML_MAX_DEPTH 16
struct feat_ent { __u8 code; __u8 size; __u8 col_off; __u8 scale; };
struct model_desc { __u8 n_feat; __u8 n_in; __u8 _p0; __u8 _p1; struct feat_ent feats[ML_MAX_FEAT]; };

static __always_inline long long ipa_div_trunc(long long num, __u64 den)
{
    if (den == 0) den = 1;
    if (num < 0)
        return -(long long)(((__u64)(-num)) / den);
    return (long long)(((__u64)num) / den);
}

BPF_HASH(model_desc, __u8, struct model_desc, 256);

BPF_PROG_ARRAY(layer_chain, 16);

/* mac_table_t3: LOGICAL PORT (from class_action_t3) -> {ifindex, src/dst MAC}.
 * The NN decides the port; this only resolves the L2 next-hop. */
/* mac_table_t3 is keyed by LOGICAL PORT, not by class. */
BPF_ARRAY(mac_table_t3, struct fwd_action, MAX_N_OUT);
BPF_HASH(ingress_port_t3, __u32, __u32, 64);

BPF_HASH(node_id_t3, __u32, __u32, 1);

/* class_action_t3: (model_id, bank, class) -> {action, logical port}, as
 * class_action_t2 in ebpf_template_arch.py. */
#define CLASS_ACT_BANKS   2
#define CLASS_ACT_MODELS  256   /* model_id is a __u8 */
#define CLASS_ACT_KEY(mid, bank, cls) \
    (((((__u32)(mid) & 0xffU) * CLASS_ACT_BANKS + ((__u32)(bank) & 1U)) \
      * MAX_N_OUT) + (__u32)(cls))
BPF_ARRAY(class_action_t3, struct class_act,
          CLASS_ACT_MODELS * CLASS_ACT_BANKS * MAX_N_OUT);
BPF_PERCPU_ARRAY(pkt_stats_t3, __u64, 3);   /* [0]=HIT [1]=MISS [2]=DROP */
BPF_PERCPU_ARRAY(cls_stats_t3, __u64, MAX_N_OUT);   /* per-class redirect counter */

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

/* Explicit signed cast so arithmetic is correct after __u8 storage */
#define WEIGHT(p) ((__s8)(*p))
static __always_inline long long ipa_relu(long long x) {
    long long m = x >> 63;
    asm volatile("" : "+r"(m));
    return x & ~m;
}

/* Metadata slot indices */
#define META_MODEL_ID    0
#define META_SCALE       1
#define META_LAYER_IDX   2
#define META_NODE_CTX    3
#define META_TTL         4

/* Per-model metadata: model_id -> {scale_factor, n_layers, sem_bank}.
 * n_layers tells each hop when it has reached the last layer
 * (layer_idx+1==n_layers). sem_bank selects which of this model's two
 * class_action_t3 banks is live -- see CLASS_ACT_KEY; it is committed in this
 * entry, which the control plane writes LAST. */
struct layer_model_entry {
    __u16 scale_factor;
    __u8  n_layers;
    __u8  sem_bank;
} __attribute__((packed));
BPF_HASH(layer_registry, __u8, struct layer_model_entry, 256);

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

static inline __attribute__((always_inline))
int ml_argmax_forward(struct xdp_md *ctx, void *data, void *data_end,
                      int best_cls, __u32 n_out, __u32 sem_key0) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (best_cls < 0 || (__u32)best_cls >= n_out) {
        int mi = 1; __u64 *mv = pkt_stats_t3.lookup(&mi);
        if (mv) *mv += 1;
        return XDP_PASS;
    }
    __u32 _ci = (__u32)best_cls;
    __u32 _sk = sem_key0 + _ci;
    struct class_act *ca = class_action_t3.lookup(&_sk);
    if (!ca || ca->action == ACT_INVALID) {
        int mi = 1; __u64 *mv = pkt_stats_t3.lookup(&mi);
        if (mv) *mv += 1;
        return XDP_PASS;
    }
    if (ca->action == ACT_DROP) {
        int di = 2; __u64 *dv = pkt_stats_t3.lookup(&di);
        if (dv) *dv += 1;
        __u64 *dcv = cls_stats_t3.lookup(&_ci);
        if (dcv) *dcv += 1;
        return XDP_DROP;
    }
    if (ca->action != ACT_FORWARD) {           /* ACT_UNUSED */
        __u64 *ucv = cls_stats_t3.lookup(&_ci);
        if (ucv) *ucv += 1;
        int mi = 1; __u64 *mv = pkt_stats_t3.lookup(&mi);
        if (mv) *mv += 1;
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 port = (__u32)ca->port;
    struct fwd_action *action = mac_table_t3.lookup(&port);
    if (action != NULL && action->ifindex != 0) {
        if (ip->ttl <= 1) {
            int ti = 1; __u64 *tv = pkt_stats_t3.lookup(&ti);
            if (tv) *tv += 1;
            return XDP_PASS;
        }
        ipa_ttl_dec(ip);
        int si = 0; __u64 *v = pkt_stats_t3.lookup(&si);
        if (v) *v += 1;
        __u64 *cv = cls_stats_t3.lookup(&_ci);   /* keyed by CLASS */
        if (cv) *cv += 1;
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    int si = 1; __u64 *v = pkt_stats_t3.lookup(&si);
    if (v) *v += 1;
    return XDP_PASS;
}
"""

# --- Dispatcher: parse packet, stash metadata, tail call layer_chain[0]. ---
EBPF_MODULAR_DISPATCHER = EBPF_MODULAR_COMMON_HEADER + r"""

int modular_dispatcher(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)  return XDP_PASS;
    __u8 ip_proto = *((__u8 *)ip + 9);
    if (ip_proto != IPPROTO_UDP)   return XDP_PASS;
    __u32 _ip_hlen = (((__u8 *)ip)[0] & 0x0fU) << 2U;
    if (_ip_hlen < 20U) return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)((void *)ip + _ip_hlen);
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
    idx = META_NODE_CTX;
    { __u32 _kif = ctx->ingress_ifindex;
      __u32 *_lp = ingress_port_t3.lookup(&_kif);
      __u32 _port = _lp ? (*_lp & 0xffffU) : 0U;
      __u32 _nz = 0;
      __u32 *_nid = node_id_t3.lookup(&_nz);
      /* 0xff = unknown, so a node index is 0..254. */
      __u32 _nd = (_nid && *_nid < 0xffU) ? *_nid : 0xffU;
      long long v = (long long)((_nd << 16) | _port);
      scratch_meta.update(&idx, &v); }
    idx = META_TTL;        { long long v = ip->ttl;                scratch_meta.update(&idx, &v); }

    layer_chain.call(ctx, 0);
    return XDP_PASS;
}
"""

# --- layer_first: always hop 0. Sparse read of the protocol-fixed 65-feature ---
EBPF_LAYER_FIRST = EBPF_MODULAR_COMMON_HEADER + r"""

#define ML1_MAX_H1   8

#define ML_TTL_SCALE 30
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
    __u32 last_key = (n_layers == 1)
        ? (0x80000000U | CLASS_ACT_KEY(model_id, lentry->sem_bank, 0)) : 0U;

    struct layer_shape_key key = {};
    key.model_id  = model_id;
    key.layer_idx = 0;
    struct layer_shape_entry *shape = layer_shapes.lookup(&key);
    if (!shape) return XDP_PASS;

    __u32 n_out = shape->n_out;
    __u32 woff  = shape->weight_offset;
    if (n_out == 0 || n_out > ML1_MAX_H1) return XDP_PASS;
    barrier_var(n_out);
    n_out &= 0xfU;               /* ML1_MAX_H1 = 8, so 4 bits suffice */

    struct model_desc *desc = model_desc.lookup(&model_id);
    if (!desc) return XDP_PASS;
    __u32 n_in = desc->n_in;
    if (n_in == 0 || n_in > ML_MAX_N_IN) return XDP_PASS;
    barrier_var(n_in);
    n_in &= 0xffU;               /* ML_MAX_N_IN = 128 */
    __u32 bias_off = n_in * n_out;

    int mtl = META_TTL;
    long long *ttlp = scratch_meta.lookup(&mtl);
    __u32 _ttl = ttlp ? (__u32)(*ttlp) & 0xff : 0;

    int mctx = META_NODE_CTX;
    long long *cxp = scratch_meta.lookup(&mctx);
    __u32 _ctx = cxp ? (__u32)(*cxp) : 0xff0000U;
    __u32 _raw_iface = _ctx & 0xffffU;
    __u32 _node      = (_ctx >> 16) & 0xffU;

    long long ls[IPA_MAX_IFACES];
    { int lsz = 0; struct ls_vec *lsp = link_state.lookup(&lsz);
      #pragma unroll
      for (int i = 0; i < IPA_MAX_IFACES; i++)
          ls[i] = lsp ? (long long)(lsp->v[i]) : 0LL; }
    long long qs[IPA_MAX_QUEUES];
    #pragma unroll
    for (int i = 0; i < IPA_MAX_QUEUES; i++) qs[i] = 0LL;
    __u8 _need_qs = 0;
    #pragma unroll
    for (int f = 0; f < ML_MAX_FEAT; f++)
        if (f < desc->n_feat && desc->feats[f].code == FEAT_QUEUE_OCC) _need_qs = 1;
    if (_need_qs) {
      int qsz = 0; struct qs_vec *qsp = queue_state.lookup(&qsz);
      if (qsp) {
        #pragma unroll
        for (int i = 0; i < IPA_MAX_QUEUES; i++) qs[i] = (long long)(qsp->v[i]);
      }
    }

    int _lwz = 0;
    struct lw_blk *LW = layer_weights.lookup(&_lwz);
    if (!LW) return XDP_PASS;

    long long out[ML1_MAX_H1];

    #pragma unroll
    for (int j = 0; j < ML1_MAX_H1; j++)
        out[j] = LW_W(LW, woff + bias_off + j);

    #pragma unroll
    for (int f = 0; f < ML_MAX_FEAT; f++) {
        if (f >= desc->n_feat) continue;
        __u8  code = desc->feats[f].code;
        __u32 sz   = desc->feats[f].size;
        __u32 coff = desc->feats[f].col_off;
        if (code == FEAT_TTL) {
            __u64 _sc = desc->feats[f].scale ? desc->feats[f].scale
                                             : ML_TTL_SCALE;
            #pragma unroll
            for (int j = 0; j < ML1_MAX_H1; j++)
                out[j] += ipa_div_trunc((long long)_ttl
                           * LW_W(LW, woff + j * n_in + coff), _sc);
        } else if (code == FEAT_LINK_STATE) {
            #pragma unroll
            for (int i = 0; i < IPA_MAX_IFACES; i++) {
                if ((__u32)i >= sz) continue;
                long long x = ls[i];
                #pragma unroll
                for (int j = 0; j < ML1_MAX_H1; j++)
                    out[j] += x * LW_W(LW, woff + j * n_in + coff + i);
            }
        } else if (code == FEAT_QUEUE_OCC) {
            #pragma unroll
            for (int i = 0; i < IPA_MAX_QUEUES; i++) {
                if ((__u32)i >= sz) continue;
                long long x = qs[i];
                #pragma unroll
                for (int j = 0; j < ML1_MAX_H1; j++)
                    out[j] += x * LW_W(LW, woff + j * n_in + coff + i);
            }
        } else if (code == FEAT_INGRESS_IF) {
            if (_raw_iface >= 1 && _raw_iface <= sz) {
                __u32 c = coff + (_raw_iface - 1);
                #pragma unroll
                for (int j = 0; j < ML1_MAX_H1; j++)
                    out[j] += LW_W(LW, woff + j * n_in + c);
            }
        } else if (code == FEAT_NODE_ID) {
            if (_node < sz) {
                __u32 c = coff + _node;
                #pragma unroll
                for (int j = 0; j < ML1_MAX_H1; j++)
                    out[j] += LW_W(LW, woff + j * n_in + c);
            }
        }
    }

    long long best_val = -9223372036854775807LL - 1LL;
    int best_cls = 0;

    #pragma unroll
    for (int j = 0; j < ML1_MAX_H1; j++) {
        if (j >= n_out) { out[j] = 0LL; continue; }
        if (last_key) {
            if (out[j] > best_val) { best_val = out[j]; best_cls = j; }
        } else {
            out[j] = ipa_relu(out[j]);
        }
    }

    if (!last_key) {
        int _az = 0;
        struct act_vec *ACT = scratch_acts.lookup(&_az);
        if (!ACT) return XDP_PASS;
        #pragma unroll
        for (int j = 0; j < ML1_MAX_H1; j++) ACT->v[j] = out[j];
        int li = META_LAYER_IDX;
        long long nv = 1LL;
        scratch_meta.update(&li, &nv);
        layer_chain.call(ctx, 1);
        return XDP_PASS;
    }

    return ml_argmax_forward(ctx, data, data_end, best_cls, n_out,
                             last_key & 0x7fffffffU);
}
"""

# --- layer_hidden: hop 1..n_layers-1. Dense n_in -> n_out (+ ReLU, unless this ---
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
    /* Same reason as in layer_first. */
    barrier_var(n_in);
    barrier_var(n_out);
    n_in  &= 0xfU;
    n_out &= 0xfU;
    /* Bias multiplier: the weights are stored as round(w_float * scale), so
     * this layer's products carry scale**(layer_idx+1) while a bias stored the
     * same way carries only scale**1. Multiplying the bias by scale**layer_idx
     * puts the two in the same units. Without it the biases are progressively
     * under-weighted with depth and the datapath disagrees with the trained
     * model on 28% of decisions (measured: argmax agreement 72% -> 96%).
     *
     * Unrolled to ML_MAX_DEPTH because the verifier needs a constant trip
     * count; layer_idx < n_layers <= LAYER_CHAIN_SIZE, so every reachable
     * depth is covered. A model deep enough for scale**layer_idx to overflow
     * int64 would already have overflowed its accumulators. */
    long long bias_mul = 1LL;
    #pragma unroll
    for (int _bp = 0; _bp < ML_MAX_DEPTH; _bp++) {
        if (_bp < layer_idx) bias_mul *= (long long)lentry->scale_factor;
    }

    __u32 bias_off = n_in * n_out;

    int _lwz = 0;
    struct lw_blk *LW = layer_weights.lookup(&_lwz);
    if (!LW) return XDP_PASS;
    int _az = 0;
    struct act_vec *ACT = scratch_acts.lookup(&_az);
    if (!ACT) return XDP_PASS;

    long long out[MLH_MAX_H];
    /* LLONG_MIN sentinel -- see layer_first / ebpf_template_arch.py. */
    long long best_val = -9223372036854775807LL - 1LL;
    int best_cls = 0;

    #pragma unroll
    for (int j = 0; j < MLH_MAX_H; j++) {
        if (j >= n_out) { out[j] = 0LL; continue; }
        long long acc = LW_W(LW, woff + bias_off + j) * bias_mul;
        #pragma unroll
        for (int i = 0; i < MLH_MAX_H; i++) {
            if (i >= n_in) continue;
            acc += ACT->v[i] * LW_W(LW, woff + j * n_in + i);
        }
        if (is_last) {
            if (acc > best_val) { best_val = acc; best_cls = j; }
        } else {
            out[j] = ipa_relu(acc);
        }
    }

    if (!is_last) {
        #pragma unroll
        for (int j = 0; j < MLH_MAX_H; j++) ACT->v[j] = out[j];
        int li = META_LAYER_IDX;
        long long nv = (long long)(layer_idx + 1);
        scratch_meta.update(&li, &nv);
        layer_chain.call(ctx, layer_idx + 1);
        return XDP_PASS;
    }

    return ml_argmax_forward(ctx, data, data_end, best_cls, n_out,
                             CLASS_ACT_KEY(model_id, lentry->sem_bank, 0));
}
"""

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
    semantics=None,
) -> int:
    """Populate layer_registry, layer_shapes and layer_weights for Pipeline 3."""
    if features:
        for _f in features:
            if _f.get("type") == "queue_occupancy" and int(_f.get("size", 0)) > P3_MAX_QUEUES:
                raise ValueError(
                    f"Pipeline 3 compiles a queue_occupancy vector of "
                    f"{P3_MAX_QUEUES} slot(s); this descriptor asks for "
                    f"{_f['size']}. Raise IPA_MAX_QUEUES in the eBPF source and "
                    f"RE-MEASURE whether layer_first still loads -- it sits at "
                    f"the verifier's complexity limit, and that ceiling is what "
                    f"currently buys the room for the node index.")

    from ctypes import c_uint8, c_uint16, c_uint32, Structure

    if layer_dims is None:
        layer_dims = [(65, 4), (4, 4), (4, 7)]

    if semantics is None:
        from model_meta import descriptor_semantics_or_reference
        semantics = descriptor_semantics_or_reference(layer_dims[-1][1],
                                                      "Pipeline3")
    semantics.validate()
    if semantics.n_out != layer_dims[-1][1]:
        raise ValueError(
            f"class semantics declare n_out={semantics.n_out} but the last "
            f"layer outputs {layer_dims[-1][1]}. Descriptor and model must "
            f"agree before either reaches the datapath.")

    n_layers = len(layer_dims)
    if n_layers == 0 or n_layers > LAYER_CHAIN_SIZE:
        raise ValueError(f"n_layers={n_layers} must be in [1, {LAYER_CHAIN_SIZE}] (layer_chain size)")

    for i, (n_in, n_out) in enumerate(layer_dims):
        if i == 0:
            if n_in <= 0 or n_in > 128:
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
    if base_offset + total_weights > MAX_LAYER_WEIGHT_ENTRIES:
        raise ValueError(
            f"base_offset={base_offset} + total_weights={total_weights} "
            f"exceeds MAX_LAYER_WEIGHT_ENTRIES={MAX_LAYER_WEIGHT_ENTRIES} -- too "
            f"many concurrent model_id's. Raise it here AND the matching #define "
            f"in the eBPF source (keep it a power of two).")
    if len(weights_int8) < total_weights:
        raise ValueError(
            f"layer_dims={layer_dims} needs {total_weights} weights, "
            f"got only {len(weights_int8)}")

    layer_offsets = []
    offset = base_offset
    for (n_in, n_out) in layer_dims:
        layer_offsets.append(offset)
        offset += n_in * n_out + n_out

    lw_tbl = bpf_obj["layer_weights"]
    blk = lw_tbl[c_uint32(0)]
    for idx, w in enumerate(weights_int8[:total_weights]):
        blk.w[base_offset + idx] = int(w) & 0xFF
    lw_tbl[c_uint32(0)] = blk

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

    if features is None:
        from model_meta import derive_shape, DEFAULT_META, load_topology_config
        features = derive_shape(dict(DEFAULT_META),
                                topology_config=load_topology_config())["features"]
    load_model_desc(bpf_obj, features, n_in=layer_dims[0][0], model_id=model_id)

    from ebpf_template_arch import load_class_action
    bank = load_class_action(bpf_obj, "class_action_t3", "layer_registry",
                             model_id, semantics)

    class LayerModelEntry(Structure):
        _pack_ = 1
        _fields_ = [("scale_factor", c_uint16), ("n_layers", c_uint8),
                    ("sem_bank", c_uint8)]

    bpf_obj["layer_registry"][c_uint8(model_id)] = \
        LayerModelEntry(scale_factor=scale, n_layers=n_layers, sem_bank=bank)

    shape_str = "-".join(str(d[0]) for d in layer_dims) + f"-{layer_dims[-1][1]}"
    print(f"[P3] model {model_id} registered: shape {shape_str}, "
          f"{n_layers} layers, {total_weights} weights from {base_offset}, "
          f"scale {scale}")

    return total_weights


ML_MAX_FEAT = 4


def load_model_desc(bpf_obj, features: list, n_in: int, model_id: int = 0) -> None:
    """Populate model_desc[model_id] so layer_first builds the first-hop input
    vector GENERICALLY from a per-model descriptor (instead of the old
    hardcoded 65-feature layout)."""
    from ctypes import c_uint8, Structure
    from model_meta import resolve_descriptor

    ents = resolve_descriptor(features)
    if len(ents) > ML_MAX_FEAT:
        raise ValueError(
            f"descriptor has {len(ents)} features, exceeds ML_MAX_FEAT={ML_MAX_FEAT} "
            f"(raise ML_MAX_FEAT in ebpf_modular.py and reload to support it)")
    if n_in > 128:
        raise ValueError(f"n_in={n_in} exceeds ML_MAX_N_IN=128")

    class FeatEnt(Structure):
        _pack_ = 1
        _fields_ = [("code", c_uint8), ("size", c_uint8),
                    ("col_off", c_uint8), ("scale", c_uint8)]

    class ModelDesc(Structure):
        _pack_ = 1
        _fields_ = [("n_feat", c_uint8), ("n_in", c_uint8),
                    ("_p0", c_uint8), ("_p1", c_uint8),
                    ("feats", FeatEnt * ML_MAX_FEAT)]

    for e in ents:
        sc = int(e.get("scale", 0) or 0)
        if not 0 <= sc <= 255:
            raise ValueError(
                f"feature code {e['code']}: scale {sc} does not fit "
                f"feat_ent.scale (one byte, 0..255). Refused rather than "
                f"truncated: the datapath would divide by another number.")

    d = ModelDesc(n_feat=len(ents), n_in=n_in)
    for i, e in enumerate(ents):
        d.feats[i] = FeatEnt(code=e["code"], size=e["size"],
                             col_off=e["col_off"],
                             scale=int(e.get("scale", 0) or 0))
    bpf_obj["model_desc"][c_uint8(model_id)] = d
