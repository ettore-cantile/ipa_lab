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
  layer_weights    : BPF_ARRAY  (flat index) -> __u8  (unsigned byte storage;
                     eBPF C code casts to __s8 for signed arithmetic via WEIGHT() macro;
                     Python side stores int8 as c_uint8(v & 0xFF) two's complement)
  layer_chain      : BPF_PROG_ARRAY  layer_idx -> BPF prog fd
  layer_registry   : model_id -> {n_layers, layer_ids[8], weight_offsets[8], scale}
  mac_table_t3     : u32 class (argmax output) -> fwd_action {ifindex, src/dst MAC}
  cls_stats_t3     : per-class redirect counter
  pkt_stats_t3     : [0]=HIT [1]=MISS [2]=DROP

Action: the last layer runs argmax -> class, then a single mac_table_t3[class]
lookup resolves the L2 next-hop and bpf_redirect()s (cls 6 = DROP). No output
key, no per-TTL validation -- the NN decides, the table only maps class->port.

eBPF verifier notes:
  - scratch_acts is PERCPU -> no spinlock needed
  - all layer dimensions are compile-time constants per program
  - tail call limit: 33 consecutive (Linux). For 3-layer net: 3 tail calls OK.
  - weight map key encodes (layer_id * MAX_NEURONS_SQ + flat_index)

Feature encoding:
  The dispatcher writes the same sparse one-hot layout used by Pipeline 1 into
  scratch_acts before the first tail call: 6 link_state (unused) + 6 ingress
  iface one-hot [6..11] + 1 ttl [12] + 52 node one-hot [13..64]. This keeps
  inference comparable across the three pipelines on the same model. Each layer
  block reads scratch_acts[i] one element at a time.

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

/* link_state[i] = egress iface i up/down (feature [0..5]); written by the
 * userspace carrier monitor, read by the dispatcher into scratch_acts[0..5].
 * 1 = up, 0 = down. */
BPF_ARRAY(link_state, __u32, 6);

/* Layer chain tail-call map: layer_idx -> BPF prog fd */
BPF_PROG_ARRAY(layer_chain, 16);

/* mac_table: egress class (0..5, the argmax output) -> {ifindex, src/dst MAC}.
 * The NN decides the port; this only resolves the L2 next-hop. */
BPF_HASH(mac_table_t3, __u32, struct fwd_action, 8);
BPF_ARRAY(pkt_stats_t3, __u64, 3);   /* [0]=HIT [1]=MISS [2]=DROP */
BPF_ARRAY(cls_stats_t3, __u64, 7);   /* per-class redirect counter */

/* Explicit signed cast so arithmetic is correct after __u8 storage */
#define WEIGHT(p) ((__s8)(*p))
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

    /* Write metadata to scratch_meta */
    int idx;
    idx = META_MODEL_ID;   { long long v = model_id;               scratch_meta.update(&idx, &v); }
    idx = META_SCALE;      { long long v = lentry->scale_factor;   scratch_meta.update(&idx, &v); }
    idx = META_LAYER_IDX;  { long long v = 0LL;                    scratch_meta.update(&idx, &v); }
    idx = META_INGRESS_IF; { long long v = ctx->ingress_ifindex;   scratch_meta.update(&idx, &v); }
    idx = META_TTL;        { long long v = ip->ttl;                scratch_meta.update(&idx, &v); }

    /* Feature extraction -> write to scratch_acts[0..64].
     * Encoding MUST match Pipeline 1 / the trained model (FRR_model.py):
     *   [0..5]   egress link_state (up/down), read from the link_state map
     *   [6..11]  ingress-iface one-hot (index = 5 + ifindex, ifindex 1..6)
     *   [12]     ttl (raw scalar)
     *   [13..64] node one-hot (index = 13 + model_id, model_id 0..51)
     * Zero all 65 slots first (scratch_acts is PERCPU and may hold stale
     * values from a previous packet on this CPU), then set only the live
     * ones -- mirrors ebpf_program.py's sparse encoding exactly. */
    long long zero = 0LL;
    int fi;
    #pragma unroll
    for (int i = 0; i < 65; i++) { fi = i; scratch_acts.update(&fi, &zero); }

    /* Feature [0..5] = egress link_state (up/down) from the link_state map. */
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        int lsk = i;
        __u32 *lsp = link_state.lookup(&lsk);
        long long lsv = lsp ? (long long)(*lsp) : 0LL;
        fi = i; scratch_acts.update(&fi, &lsv);
    }

    __u32 _ttl   = ((__u32)ip->ttl) & 0xff;
    __u32 _iface = ((__u32)ctx->ingress_ifindex) & 0x7;   /* valid 1..6 */
    __u32 _node  = ((__u32)ipa->model_id) & 0x3f;         /* valid 0..51 */

    long long ttlv = _ttl;
    fi = 12; scratch_acts.update(&fi, &ttlv);

    long long one = 1LL;
    if (_iface >= 1 && _iface <= 6) {
        fi = 5 + _iface;
        scratch_acts.update(&fi, &one);
    }
    if (_node <= 51) {
        fi = 13 + _node;
        scratch_acts.update(&fi, &one);
    }

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
        __u8 *bp = layer_weights.lookup(&bidx);
        long long acc = bp ? (long long)((__s8)(*bp)) : 0LL;
        #pragma unroll
        for (int i = 0; i < L0_N_IN; i++) {
            int fi = i;
            long long *xp = scratch_acts.lookup(&fi);
            long long x = xp ? *xp : 0LL;
            int widx = woff + j * L0_N_IN + i;
            if (widx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
            __u8 *wp = layer_weights.lookup(&widx);
            if (wp) acc += x * (long long)((__s8)(*wp));
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
        __u8 *bp = layer_weights.lookup(&bidx);
        long long acc = bp ? (long long)((__s8)(*bp)) : 0LL;
        #pragma unroll
        for (int i = 0; i < L1_N_IN; i++) {
            int fi = i;
            long long *xp = scratch_acts.lookup(&fi);
            long long x = xp ? *xp : 0LL;
            int widx = woff + j * L1_N_IN + i;
            if (widx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
            __u8 *wp = layer_weights.lookup(&widx);
            if (wp) acc += x * (long long)((__s8)(*wp));
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
        __u8 *bp = layer_weights.lookup(&bidx);
        long long acc = bp ? (long long)((__s8)(*bp)) : 0LL;
        #pragma unroll
        for (int i = 0; i < L2_N_IN; i++) {
            int fi = i;
            long long *xp = scratch_acts.lookup(&fi);
            long long x = xp ? *xp : 0LL;
            int widx = woff + k * L2_N_IN + i;
            if (widx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
            __u8 *wp = layer_weights.lookup(&widx);
            if (wp) acc += x * (long long)((__s8)(*wp));
        }
        if (acc > best_val) { best_val = acc; best_cls = k; }
    }

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* The NN decided the egress class (argmax). cls 6 = DROP. */
    if (best_cls >= 6) {
        int di = 2; __u64 *dv = pkt_stats_t3.lookup(&di);
        if (dv) __sync_fetch_and_add(dv, 1);
        return XDP_DROP;
    }

    /* mac_table: class -> {ifindex, src/dst MAC}. Single lookup, no key math,
     * no output validation -- resolve the L2 next-hop and redirect. */
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

    NOTE: layer_weights map uses __u8 in C (to avoid BCC str2ctype
    KeyError: 'signed char' on older libbcc).  We store the int8 value
    as its unsigned two's-complement bit pattern (c_uint8).  The eBPF C
    code re-casts each byte to (__s8) before accumulation, so arithmetic
    is correct.
    """
    from ctypes import c_uint8, c_uint32, c_uint16, Structure

    fc1_size = n_in * n_h1 + n_h1    # 264
    fc2_size = n_h1 * n_h2 + n_h2    # 20
    out_size = n_h2 * n_out + n_out   # 35

    w_off_fc1 = 0
    w_off_fc2 = fc1_size
    w_off_out = fc1_size + fc2_size

    for idx, w in enumerate(weights_int8[:fc1_size + fc2_size + out_size]):
        key = c_uint32(idx)
        # Store as unsigned bit pattern — C side casts back to __s8 for math
        val = c_uint8(int(w) & 0xFF)
        bpf_obj["layer_weights"][key] = val

    class LayerModelEntry(Structure):
        _pack_ = 1
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
