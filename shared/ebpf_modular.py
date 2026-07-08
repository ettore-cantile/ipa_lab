"""
ebpf_modular.py  —  Pipeline 3: Modular Neural Pipeline.

Design space position:
  - Neural inference is decomposed into reusable eBPF layer-block programs
  - Each block implements one linear transformation N_in -> N_out + ReLU
  - Intermediate activations transit via BPF_PERCPU_ARRAY scratch map
  - Layer chain: dispatcher -> layer_block_1 -> ... -> layer_block_N -> argmax
  - Maximum flexibility: changing model architecture = change layer sequence + weights

Layer blocks implemented:
  layer_65_4  : fc1  (65 inputs  -> 4 hidden, with ReLU)
  layer_4_4   : fc2  (4  hidden  -> 4 hidden, with ReLU)
  layer_4_7   : out  (4  hidden  -> 7 outputs, argmax + forward)

Maps:
  scratch_acts     : BPF_PERCPU_ARRAY  index -> long long  (intermediate activations)
  scratch_meta     : BPF_PERCPU_ARRAY  0 -> {model_id, weight_offset, scale, layer_idx}
  layer_weights    : BPF_HASH  (layer_id, neuron_idx) -> int8
  layer_chain      : BPF_PROG_ARRAY  layer_idx -> BPF prog fd
  layer_registry   : model_id -> {n_layers, layer_ids[8], weight_offsets[8], scale}
  fwd_table_t3     : u64 -> fwd_action
  valid_keys_t3    : u8  -> u64
  pkt_stats_t3     : [0]=HIT [1]=MISS [2]=FAKE
  miss_events_t3   : perf buffer

eBPF verifier notes:
  - scratch_acts is PERCPU -> no spinlock needed
  - all layer dimensions are compile-time constants per program
  - tail call limit: 33 consecutive (Linux). For 3-layer net: 3 tail calls OK.
  - weight map key encodes (layer_id * MAX_NEURONS_SQ + flat_index)
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

struct miss_event_t3 {
    __u8  model_id;
    __u8  ttl;
    __u32 ingress_ifindex;
    __u8  layer_idx;
    __u64 key;
};

/* Scratch maps: PERCPU to avoid contention */
#define SCRATCH_ACT_SIZE   128
#define SCRATCH_META_SLOTS  16
BPF_PERCPU_ARRAY(scratch_acts, long long, SCRATCH_ACT_SIZE);
BPF_PERCPU_ARRAY(scratch_meta, long long, SCRATCH_META_SLOTS);

/* Weight map: flat int8, keyed by absolute index */
#define MAX_LAYER_WEIGHT_ENTRIES 2048
BPF_ARRAY(layer_weights, __s8, MAX_LAYER_WEIGHT_ENTRIES);

/* Layer chain tail-call map: layer_idx -> BPF prog fd */
BPF_PROG_ARRAY(layer_chain, 16);

/* Forwarding maps */
BPF_HASH(fwd_table_t3, __u64, struct fwd_action, 256);
BPF_HASH(valid_keys_t3, __u8, __u64, 256);
BPF_ARRAY(pkt_stats_t3, __u64, 3);
BPF_PERF_OUTPUT(miss_events_t3);

#define OUTPUT_OFFSET 100000ULL
#define RELU(x)  ((x) > 0 ? (x) : 0)

/* Metadata slot indices */
#define META_MODEL_ID    0
#define META_SCALE       1
#define META_LAYER_IDX   2
#define META_INGRESS_IF  3
#define META_TTL         4
"""

# -----------------------------------------------------------------
# Dispatcher: feature extraction + write to scratch + tail call layer_chain[0]
# -----------------------------------------------------------------
EBPF_MODULAR_DISPATCHER = EBPF_MODULAR_COMMON_HEADER + r"""

/* Layer registry: model_id -> {scale_factor, w_off_fc1, w_off_fc2, w_off_out} */
struct layer_model_entry {
    __u16 scale_factor;
    __u32 w_off_fc1;   /* weight offset for layer fc1 (65->4) */
    __u32 w_off_fc2;   /* weight offset for layer fc2 (4->4)  */
    __u32 w_off_out;   /* weight offset for output layer (4->7) */
};
BPF_HASH(layer_registry, __u8, struct layer_model_entry, 256);

int modular_dispatcher(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)  return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)   return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)  return XDP_PASS;
    if (udp->dest != bpf_htons(9999))  return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end)  return XDP_PASS;

    __u8 model_id = ipa->model_id;
    struct layer_model_entry *lentry = layer_registry.lookup(&model_id);
    if (!lentry) return XDP_PASS;

    /* Write metadata to scratch_meta */
    int idx;
    idx = META_MODEL_ID;   { long long v = model_id;               scratch_meta.update(&idx, &v); }
    idx = META_SCALE;      { long long v = lentry->scale_factor;   scratch_meta.update(&idx, &v); }
    idx = META_LAYER_IDX;  { long long v = 0LL;                    scratch_meta.update(&idx, &v); }
    idx = META_INGRESS_IF; { long long v = ctx->ingress_ifindex;   scratch_meta.update(&idx, &v); }
    idx = META_TTL;        { long long v = ip->ttl;                scratch_meta.update(&idx, &v); }

    /* Feature extraction -> write to scratch_acts[0..N_IN-1]
     * (4-feature stub matching Pipeline 1 for fair comparison) */
    long long fv;
    int fi;
    fi = 0; fv = ipa->model_id;           scratch_acts.update(&fi, &fv);
    fi = 1; fv = ip->ttl;                  scratch_acts.update(&fi, &fv);
    fi = 2; fv = ctx->ingress_ifindex;    scratch_acts.update(&fi, &fv);
    fi = 3; fv = ipa->input_size;         scratch_acts.update(&fi, &fv);
    /* Remaining 61 features set to 0 */
    fv = 0;
    #pragma unroll
    for (int i = 4; i < 65; i++) { int ki = i; scratch_acts.update(&ki, &fv); }

    /* Store weight offsets in meta slots 5,6,7 */
    idx = 5; { long long v = lentry->w_off_fc1; scratch_meta.update(&idx, &v); }
    idx = 6; { long long v = lentry->w_off_fc2; scratch_meta.update(&idx, &v); }
    idx = 7; { long long v = lentry->w_off_out; scratch_meta.update(&idx, &v); }

    /* Tail call to layer_chain[0] = layer_65_4 */
    layer_chain.call(ctx, 0);
    return XDP_PASS;
}
"""

# -----------------------------------------------------------------
# Layer block 0: fc1  65 -> 4  (ReLU)
# Reads input from scratch_acts[0..64]
# Writes output to scratch_acts[0..3]
# Tail-calls layer_chain[1]
# -----------------------------------------------------------------
EBPF_LAYER_65_4 = EBPF_MODULAR_COMMON_HEADER + r"""
#define L0_N_IN   65
#define L0_N_OUT   4
/* fc1 weight layout: w[j*L0_N_IN + i], bias at w[L0_N_IN*L0_N_OUT + j] */
#define L0_W_SIZE  (L0_N_IN * L0_N_OUT + L0_N_OUT)  /* 260 + 4 = 264 */

int layer_65_4(struct xdp_md *ctx) {
    /* Read weight offset from meta slot 5 */
    int mi = 5;
    long long *woff_p = scratch_meta.lookup(&mi);
    if (!woff_p) return XDP_PASS;
    __u32 woff = (__u32)(*woff_p);

    /* Compute fc1 */
    long long out[L0_N_OUT];
    #pragma unroll
    for (int j = 0; j < L0_N_OUT; j++) {
        int bidx = woff + L0_N_IN * L0_N_OUT + j;
        if (bidx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
        __s8 *bp = layer_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < L0_N_IN; i++) {
            int fi = i;
            long long *xp = scratch_acts.lookup(&fi);
            long long x = xp ? *xp : 0LL;
            int widx = woff + j * L0_N_IN + i;
            if (widx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
            __s8 *wp = layer_weights.lookup(&widx);
            if (wp) acc += x * (long long)(*wp);
        }
        out[j] = RELU(acc);
    }

    /* Write output activations to scratch_acts[0..L0_N_OUT-1] */
    #pragma unroll
    for (int j = 0; j < L0_N_OUT; j++) {
        int ki = j;
        scratch_acts.update(&ki, &out[j]);
    }

    /* Advance layer index */
    int li = META_LAYER_IDX;
    long long *lp = scratch_meta.lookup(&li);
    if (lp) { long long nv = *lp + 1; scratch_meta.update(&li, &nv); }

    /* Tail call to layer_chain[1] = layer_4_4 */
    layer_chain.call(ctx, 1);
    return XDP_PASS;
}
"""

# -----------------------------------------------------------------
# Layer block 1: fc2  4 -> 4  (ReLU)
# -----------------------------------------------------------------
EBPF_LAYER_4_4 = EBPF_MODULAR_COMMON_HEADER + r"""
#define L1_N_IN   4
#define L1_N_OUT  4
#define L1_W_BASE_META_SLOT  6

int layer_4_4(struct xdp_md *ctx) {
    int mi = L1_W_BASE_META_SLOT;
    long long *woff_p = scratch_meta.lookup(&mi);
    if (!woff_p) return XDP_PASS;
    __u32 woff = (__u32)(*woff_p);

    long long out[L1_N_OUT];
    #pragma unroll
    for (int j = 0; j < L1_N_OUT; j++) {
        int bidx = woff + L1_N_IN * L1_N_OUT + j;
        if (bidx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
        __s8 *bp = layer_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < L1_N_IN; i++) {
            int fi = i;
            long long *xp = scratch_acts.lookup(&fi);
            long long x = xp ? *xp : 0LL;
            int widx = woff + j * L1_N_IN + i;
            if (widx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
            __s8 *wp = layer_weights.lookup(&widx);
            if (wp) acc += x * (long long)(*wp);
        }
        out[j] = RELU(acc);
    }

    #pragma unroll
    for (int j = 0; j < L1_N_OUT; j++) {
        int ki = j; scratch_acts.update(&ki, &out[j]);
    }

    int li = META_LAYER_IDX;
    long long *lp = scratch_meta.lookup(&li);
    if (lp) { long long nv = *lp + 1; scratch_meta.update(&li, &nv); }

    layer_chain.call(ctx, 2);
    return XDP_PASS;
}
"""

# -----------------------------------------------------------------
# Layer block 2: output  4 -> 7  (argmax + forward)
# -----------------------------------------------------------------
EBPF_LAYER_4_7_ARGMAX = EBPF_MODULAR_COMMON_HEADER + r"""
#define L2_N_IN   4
#define L2_N_OUT  7
#define L2_W_BASE_META_SLOT  7

int layer_4_7_argmax(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Retrieve metadata */
    int ms = META_SCALE;
    long long *sp = scratch_meta.lookup(&ms);
    if (!sp || *sp == 0) return XDP_PASS;
    __u16 scale = (__u16)(*sp);

    int mi = L2_W_BASE_META_SLOT;
    long long *woff_p = scratch_meta.lookup(&mi);
    if (!woff_p) return XDP_PASS;
    __u32 woff = (__u32)(*woff_p);

    /* Argmax over output layer */
    long long best_val = -9999999LL;
    int best_cls = 0;
    #pragma unroll
    for (int k = 0; k < L2_N_OUT; k++) {
        int bidx = woff + L2_N_IN * L2_N_OUT + k;
        if (bidx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
        __s8 *bp = layer_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < L2_N_IN; i++) {
            int fi = i;
            long long *xp = scratch_acts.lookup(&fi);
            long long x = xp ? *xp : 0LL;
            int widx = woff + k * L2_N_IN + i;
            if (widx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
            __s8 *wp = layer_weights.lookup(&widx);
            if (wp) acc += x * (long long)(*wp);
        }
        if (acc > best_val) { best_val = acc; best_cls = k; }
    }

    __u64 key = (__u64)((best_val + (long long)(OUTPUT_OFFSET * scale)) / (__u64)scale);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)  return XDP_PASS;

    struct fwd_action *action = fwd_table_t3.lookup(&key);
    __u64 *correct_key        = valid_keys_t3.lookup(&ip->ttl);

    if (action != NULL && correct_key && *correct_key == key) {
        int si = 0; __u64 *v = pkt_stats_t3.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    } else if (action != NULL) {
        int si = 2; __u64 *v = pkt_stats_t3.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
    } else {
        int si = 1; __u64 *v = pkt_stats_t3.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);

        int mid_slot = META_MODEL_ID;
        long long *mid_p = scratch_meta.lookup(&mid_slot);
        int li_slot = META_LAYER_IDX;
        long long *lip = scratch_meta.lookup(&li_slot);
        int ttl_slot = META_TTL;
        long long *ttlp = scratch_meta.lookup(&ttl_slot);
        int if_slot = META_INGRESS_IF;
        long long *ifp = scratch_meta.lookup(&if_slot);

        struct miss_event_t3 ev = {};
        ev.model_id        = mid_p ? (__u8)(*mid_p) : 0;
        ev.ttl             = ttlp  ? (__u8)(*ttlp)  : ip->ttl;
        ev.ingress_ifindex = ifp   ? (__u32)(*ifp)  : ctx->ingress_ifindex;
        ev.layer_idx       = lip   ? (__u8)(*lip)   : 2;
        ev.key             = key;
        miss_events_t3.perf_submit(ctx, &ev, sizeof(ev));
    }
    return XDP_PASS;
}
"""

# Full combined source for single-program compilation (BCC can load all functions)
EBPF_MODULAR_FULL = (
    EBPF_MODULAR_DISPATCHER
    + "\n" + EBPF_LAYER_65_4.replace(EBPF_MODULAR_COMMON_HEADER, "")
    + "\n" + EBPF_LAYER_4_4.replace(EBPF_MODULAR_COMMON_HEADER, "")
    + "\n" + EBPF_LAYER_4_7_ARGMAX.replace(EBPF_MODULAR_COMMON_HEADER, "")
)


def load_modular_weights(
    bpf_obj,
    weights_int8: list,
    model_id: int = 0,
    scale: int = 128,
    n_in: int = 65, n_h1: int = 4, n_h2: int = 4, n_out: int = 7
) -> None:
    """
    Populate layer_registry and layer_weights for Pipeline 3.

    Weight layout in flat array:
      [0 .. n_in*n_h1-1]            fc1 weights
      [n_in*n_h1 .. +n_h1-1]        fc1 biases
      [.. .. +n_h1*n_h2-1]           fc2 weights
      [.. .. +n_h2-1]                fc2 biases
      [.. .. +n_h2*n_out-1]          out weights
      [.. .. +n_out-1]               out biases
    """
    from ctypes import c_int8, c_uint32, c_uint16, c_uint8, Structure

    fc1_size = n_in * n_h1 + n_h1    # 264
    fc2_size = n_h1 * n_h2 + n_h2    # 20
    out_size = n_h2 * n_out + n_out   # 35

    w_off_fc1 = 0
    w_off_fc2 = fc1_size
    w_off_out = fc1_size + fc2_size

    for idx, w in enumerate(weights_int8[:fc1_size + fc2_size + out_size]):
        key = c_uint32(idx)
        val = c_int8(int(w))
        bpf_obj["layer_weights"][key] = val

    class LayerModelEntry(Structure):
        _fields_ = [("scale_factor", c_uint16),
                    ("w_off_fc1",    c_uint32),
                    ("w_off_fc2",    c_uint32),
                    ("w_off_out",    c_uint32)]

    entry = LayerModelEntry(
        scale_factor=scale,
        w_off_fc1=w_off_fc1,
        w_off_fc2=w_off_fc2,
        w_off_out=w_off_out
    )
    bpf_obj["layer_registry"][c_uint8(model_id)] = entry

    print(f"[Pipeline3] model_id={model_id} registered: "
          f"scale={scale}, w_off_fc1={w_off_fc1}, "
          f"w_off_fc2={w_off_fc2}, w_off_out={w_off_out}, "
          f"total_weights={fc1_size + fc2_size + out_size}")
