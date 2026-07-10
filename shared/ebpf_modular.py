"""
ebpf_modular.py  —  Pipeline 3: Modular Neural Pipeline.

Design space position:
  - Neural inference is decomposed into reusable eBPF layer-block programs
  - ONE generic layer block (layer_generic) implements any linear
    transformation n_in -> n_out (+ ReLU unless it's the model's last layer)
  - Intermediate activations transit via BPF_PERCPU_ARRAY scratch map
  - Layer chain: dispatcher -> layer_generic -> layer_generic -> ... (as
    many hops as the model has layers) -> argmax + forward on the last hop
  - Maximum flexibility: changing model architecture (depth AND width) =
    change the (n_in, n_out) list registered for that model_id + weights;
    no recompilation, same compiled program for every architecture that
    fits the ceilings below

Compile-time ceilings (verifier needs a compile-time trip count; wider/
deeper models need these raised and the program reloaded once):
  ML_MAX_IN   = 80   (covers the protocol-fixed 65-feature input vector
                       plus headroom for hidden widths feeding forward)
  ML_MAX_OUT  = 16   (covers hidden widths and the protocol-fixed 7-class
                       output layer)
  layer_chain size = 16 (max depth; Linux tail-call limit is ~33 anyway)
A layer whose shape exceeds these is rejected at load time by
load_modular_weights() with a clear error, not silently corrupted.

Why one generic block instead of one program per layer:
  Whether a given hop is "the last layer" (ReLU vs argmax+redirect) is
  decided INSIDE the program from data (layer_idx+1 == n_layers, both read
  from per-model registries), not by which program is wired at that
  layer_chain slot. This means layer_chain[i] = the SAME layer_generic.fd
  for every i, for every model, regardless of how deep any individual
  model is -- so several models with DIFFERENT depths can be registered
  concurrently without their layer_chain slots conflicting (a model-per-
  slot design would break the moment two concurrent models disagreed on
  which slot is "last").

Maps:
  scratch_acts    : BPF_PERCPU_ARRAY  index -> long long  (intermediate activations)
  scratch_meta     : BPF_PERCPU_ARRAY  0 -> {model_id, scale, layer_idx, ingress_if, ttl}
  layer_weights    : BPF_ARRAY  (flat index) -> __u8  (unsigned byte storage;
                     eBPF C code casts to __s8 for signed arithmetic via WEIGHT() macro;
                     Python side stores int8 as c_uint8(v & 0xFF) two's complement)
  layer_chain      : BPF_PROG_ARRAY  layer_idx -> layer_generic's own fd (every slot)
  layer_registry   : model_id -> {scale_factor, n_layers}
  layer_shapes     : {model_id, layer_idx} -> {n_in, n_out, weight_offset}
  mac_table_t3     : u32 class (argmax output) -> fwd_action {ifindex, src/dst MAC}
  cls_stats_t3     : per-class redirect counter
  pkt_stats_t3     : [0]=HIT [1]=MISS [2]=DROP

Action: the last layer runs argmax -> class, then a single mac_table_t3[class]
lookup resolves the L2 next-hop and bpf_redirect()s (cls 6 = DROP). No output
key, no per-TTL validation -- the NN decides, the table only maps class->port.

Feature encoding (protocol-fixed, independent of hidden depth/width):
  The dispatcher writes the same sparse one-hot layout used by Pipeline 1/2
  into scratch_acts before the first tail call: 6 link_state + 6 ingress
  iface one-hot [6..11] + 1 ttl [12] + 52 node one-hot [13..64]. This keeps
  inference comparable across the three pipelines on the same model. It is
  always the first layer's n_in=65 input; the last layer's n_out is always
  7 (6 egress classes + drop), matching the mac_table/argmax action below.

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
ML_MAX_IN  = 80
ML_MAX_OUT = 16
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

/* link_state[i] = egress iface i up/down (feature [0..5]); written by the
 * userspace carrier monitor, read by the dispatcher into scratch_acts[0..5].
 * 1 = up, 0 = down. */
BPF_ARRAY(link_state, __u32, 6);

/* Layer chain tail-call map: every slot holds layer_generic's own fd --
 * see module docstring for why one program serves every hop/every model. */
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

/* Per-model metadata: model_id -> {scale_factor, n_layers}. n_layers tells
 * layer_generic when it has reached the last hop (layer_idx+1==n_layers). */
struct layer_model_entry {
    __u16 scale_factor;
    __u8  n_layers;
} __attribute__((packed));
BPF_HASH(layer_registry, __u8, struct layer_model_entry, 256);

/* Per-(model_id, layer_idx) shape: which n_in/n_out this hop computes and
 * where its weights start in the flat layer_weights array. This is what
 * makes layer_generic architecture-agnostic -- it never assumes a fixed
 * width or depth, it just looks up what THIS model's THIS layer needs. */
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
"""

# -----------------------------------------------------------------
# Dispatcher: feature extraction + write to scratch + tail call layer_chain[0]
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

    /* Write metadata to scratch_meta */
    int idx;
    idx = META_MODEL_ID;   { long long v = model_id;               scratch_meta.update(&idx, &v); }
    idx = META_SCALE;      { long long v = lentry->scale_factor;   scratch_meta.update(&idx, &v); }
    idx = META_LAYER_IDX;  { long long v = 0LL;                    scratch_meta.update(&idx, &v); }
    idx = META_INGRESS_IF; { long long v = ctx->ingress_ifindex;   scratch_meta.update(&idx, &v); }
    idx = META_TTL;        { long long v = ip->ttl;                scratch_meta.update(&idx, &v); }

    /* Feature extraction -> write to scratch_acts[0..64].
     * Encoding MUST match Pipeline 1/2 / the trained model (FRR_model.py):
     *   [0..5]   egress link_state (up/down), read from the link_state map
     *   [6..11]  ingress-iface one-hot (index = 5 + ifindex, ifindex 1..6)
     *   [12]     ttl (raw scalar)
     *   [13..64] node one-hot (index = 13 + model_id, model_id 0..51)
     * This is the model's first layer's input (n_in=65), fixed by the IPA
     * packet format regardless of the model's hidden depth/width.
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

    /* Tail call to layer_chain[0] -- layer_generic looks up model_id/layer_idx
     * itself from scratch_meta, no per-model wiring needed here. */
    layer_chain.call(ctx, 0);
    return XDP_PASS;
}
"""

# -----------------------------------------------------------------
# Generic layer block: n_in -> n_out (+ ReLU, unless it's the model's last
# layer, in which case it argmaxes and forwards instead of chaining further)
# -----------------------------------------------------------------
EBPF_LAYER_GENERIC = EBPF_MODULAR_COMMON_HEADER + r"""
#define ML_MAX_IN   80
#define ML_MAX_OUT  16

int layer_generic(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int mi_model = META_MODEL_ID;
    long long *mp = scratch_meta.lookup(&mi_model);
    if (!mp) return XDP_PASS;
    __u8 model_id = (__u8)(*mp);

    int ms = META_SCALE;
    long long *sp = scratch_meta.lookup(&ms);
    if (!sp || *sp == 0) return XDP_PASS;

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
    if (n_in == 0 || n_in > ML_MAX_IN || n_out == 0 || n_out > ML_MAX_OUT) return XDP_PASS;

    /* Flat per-layer weight layout: [n_in*n_out weights][n_out bias],
     * relative to woff -- identical to the single-layer case in Pipeline 2. */
    __u32 bias_off = n_in * n_out;

    long long out[ML_MAX_OUT];
    long long best_val = -9999999LL;
    int best_cls = 0;

    #pragma unroll
    for (int j = 0; j < ML_MAX_OUT; j++) {
        if (j >= n_out) { out[j] = 0LL; continue; }

        int bidx = woff + bias_off + j;
        if (bidx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
        __u8 *bp = layer_weights.lookup(&bidx);
        long long acc = bp ? (long long)WEIGHT(bp) : 0LL;

        #pragma unroll
        for (int i = 0; i < ML_MAX_IN; i++) {
            if (i >= n_in) continue;
            int fi = i;
            long long *xp = scratch_acts.lookup(&fi);
            long long x = xp ? *xp : 0LL;
            int widx = woff + j * n_in + i;
            if (widx >= MAX_LAYER_WEIGHT_ENTRIES) return XDP_PASS;
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
        /* Not the last layer: publish activations for the next hop, advance
         * layer_idx, keep chaining -- layer_chain[layer_idx+1] is this same
         * program, it will look up the next layer's own shape itself. */
        #pragma unroll
        for (int j = 0; j < ML_MAX_OUT; j++) {
            int ki = j;
            scratch_acts.update(&ki, &out[j]);
        }
        int li = META_LAYER_IDX;
        long long nv = (long long)(layer_idx + 1);
        scratch_meta.update(&li, &nv);

        layer_chain.call(ctx, layer_idx + 1);
        return XDP_PASS;
    }

    /* Last layer: best_cls is the argmax decided above -- act on it. */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* The NN decided the egress class (argmax). cls 6 = DROP. */
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

# Full combined source for single-program compilation
EBPF_MODULAR_FULL = (
    EBPF_MODULAR_DISPATCHER
    + "\n" + EBPF_LAYER_GENERIC.replace(EBPF_MODULAR_COMMON_HEADER, "")
)


def load_modular_weights(
    bpf_obj,
    weights_int8: list,
    model_id: int = 0,
    scale: int = 128,
    layer_dims: list = None,
    base_offset: int = 0,
) -> int:
    """
    Populate layer_registry, layer_shapes and layer_weights for Pipeline 3.

    layer_dims: ordered list of (n_in, n_out) tuples, one per layer, e.g.
      [(65, 4), (4, 4), (4, 7)] for today's 65-4-4-7 model (the default,
      used when layer_dims is None -- backward compatible with the one
      trained model checked into the repo). Any depth/width combination
      works as long as each (n_in, n_out) fits under ML_MAX_IN=80/
      ML_MAX_OUT=16 -- this is what makes Pipeline 3 genuinely
      architecture-agnostic: no eBPF recompilation for a different depth
      or different hidden widths, just a different layer_dims + weights.
      By protocol, the first layer's n_in should be 65 (IPA feature vector)
      and the last layer's n_out should be 7 (6 egress classes + drop) --
      not enforced here, but a mismatch will desync the dispatcher's
      feature vector / mac_table class range from what the network expects.

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
    if n_layers == 0 or n_layers > 16:  # layer_chain BPF_PROG_ARRAY size
        raise ValueError(f"n_layers={n_layers} must be in [1, 16] (layer_chain size)")
    for shape in layer_dims:
        n_in, n_out = shape
        if n_in <= 0 or n_in > 80 or n_out <= 0 or n_out > 16:  # ML_MAX_IN/ML_MAX_OUT
            raise ValueError(
                f"layer shape {shape} outside the compiled ceiling "
                f"ML_MAX_IN=80/ML_MAX_OUT=16 -- raise the ceiling in "
                f"ebpf_modular.py and reload to support it")

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
    return total_weights
