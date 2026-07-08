"""
ebpf_template_arch.py  —  Pipeline 2: Pre-built Architectural Template.

Design space position:
  - One eBPF program per architecture shape (e.g. arch_65_4_4_7)
  - Multiple models sharing the same shape reuse the same program
  - Weights are stored in BPF_ARRAY maps, loaded at runtime by the CP
  - No recompilation needed to change weights; only a BPF map update
  - One tail call: dispatcher -> model_registry -> arch_<shape>

Architecture supported here: 65-4-4-7 (matching the existing model).
  fc1  : 65 inputs  -> 4 hidden   (260 weights + 4 bias = 264)
  fc2  : 4  hidden  -> 4 hidden   (16  weights + 4 bias = 20)
  out  : 4  hidden  -> 7 outputs  (28  weights + 7 bias = 35)
  Total: 319 int8 values  (same N_WEIGHTS as Pipeline 1)

Maps introduced:
  arch_registry   : model_id  -> {arch_id, weight_offset, scale_factor}
  arch_weights    : index     -> int8  (flat weight array, all models concatenated)
  fwd_table_t2    : u64 key   -> fwd_action   (same as Pipeline 1)
  valid_keys_t2   : u8  ttl   -> u64 key      (same)
  pkt_stats_t2    : [0]=HIT [1]=MISS [2]=FAKE (same semantics)
  miss_events_t2  : perf buffer

Tail-call map:
  arch_progs      : arch_id -> BPF program fd
  (the dispatcher in ipa_switch_template tail-calls arch_progs[arch_id])

eBPF verifier notes:
  - All layer dimensions are compile-time #defines -> verifier sees static bounds
  - Weight accesses use (weight_offset + computed_index) with explicit bound check
  - Intermediate activations are kept in local stack arrays (no map needed)
  - Single tail call: dispatcher -> arch program

Combined compilation note (pipeline_benchmark.py):
  EBPF_ARCH_65_4_4_7 uses an #ifndef IPA_ARCH_COMBINED guard around all
  shared declarations (structs, maps, #includes).  When pipeline_benchmark
  prepends '#define IPA_ARCH_COMBINED 1' and concatenates the two sources
  into one BCC text, only the arch-specific #defines and the function body
  are compiled, eliminating duplicate-symbol errors.
"""

# Architecture constants (65-4-4-7 model)
N_IN   = 65
N_H1   = 4
N_H2   = 4
N_OUT  = 7
N_WEIGHTS_T2 = (N_IN * N_H1 + N_H1) + (N_H1 * N_H2 + N_H2) + (N_H2 * N_OUT + N_OUT)
# = 264 + 20 + 35 = 319

EBPF_TEMPLATE_ARCH_DISPATCHER = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

/* IPA header — identical to Pipeline 1 */
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

/* Model registry entry: maps model_id -> arch_id + weight_offset + scale
 * MUST be packed: arch_id (__u8) would otherwise get 3 bytes of implicit
 * padding before weight_offset (__u32), breaking the Python ctypes mapping. */
struct arch_entry {
    __u8  arch_id;        /* index into arch_progs tail-call map        */
    __u32 weight_offset;  /* byte offset into arch_weights flat array   */
    __u16 scale_factor;   /* same semantics as model_cache.scale_factor */
} __attribute__((packed));

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

struct miss_event_t2 {
    __u8  model_id;
    __u8  ttl;
    __u32 ingress_ifindex;
    __u8  arch_id;
    __u64 key;
};

/* Weight flat array: index 0..319*MAX_MODELS-1, int8 values */
#define MAX_WEIGHT_ENTRIES 1024
BPF_ARRAY(arch_weights, __s8, MAX_WEIGHT_ENTRIES);

/* Model registry: model_id -> arch_entry */
BPF_HASH(arch_registry, __u8, struct arch_entry, 256);

/* Tail-call map: arch_id -> arch program fd */
BPF_PROG_ARRAY(arch_progs, 8);

/* Forwarding maps (same as Pipeline 1) */
BPF_HASH(fwd_table_t2, __u64, struct fwd_action, 256);
BPF_HASH(valid_keys_t2, __u8, __u64, 256);
BPF_ARRAY(pkt_stats_t2, __u64, 3);
BPF_PERF_OUTPUT(miss_events_t2);

int ipa_switch_template(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)  return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999))  return XDP_PASS;

    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end)  return XDP_PASS;

    __u8 model_id = ipa->model_id;
    struct arch_entry *entry = arch_registry.lookup(&model_id);
    if (!entry) return XDP_PASS;  /* model not registered */

    /* The arch program re-looks up arch_registry[model_id] to retrieve
     * weight_offset and scale_factor after the tail call.  This is the
     * simplest verifier-safe approach; no XDP metadata scratch is needed. */
    arch_progs.call(ctx, entry->arch_id);
    return XDP_PASS;  /* tail call failed */
}
"""

# -----------------------------------------------------------------
# Arch program: 65-4-4-7  (compiled once, shared by all models
# with this shape).  Reads weights from arch_weights[offset..]
#
# IPA_ARCH_COMBINED guard:
#   When this source is concatenated with EBPF_TEMPLATE_ARCH_DISPATCHER
#   in pipeline_benchmark.py, the caller prepends:
#       '#define IPA_ARCH_COMBINED 1\n'
#   so that the shared declarations (structs, maps, #includes) are skipped
#   and only the arch-specific #defines + int arch_65_4_4_7() are compiled.
#   When compiled standalone (method5_template.py) the guard is absent and
#   the full self-contained source is used as before.
# -----------------------------------------------------------------
EBPF_ARCH_65_4_4_7 = r"""
/* Architecture compile-time constants (always needed) */
#define T2_N_IN    65
#define T2_N_H1     4
#define T2_N_H2     4
#define T2_N_OUT    7
#define T2_FC1_W_OFF  0
#define T2_FC1_B_OFF  260
#define T2_FC2_W_OFF  264
#define T2_FC2_B_OFF  280
#define T2_OUT_W_OFF  284
#define T2_OUT_B_OFF  312
#define T2_N_WEIGHTS  319
#define OUTPUT_OFFSET 100000ULL
#define RELU(x)  ((x) > 0 ? (x) : 0)

#ifndef IPA_ARCH_COMBINED
/* ---- standalone includes and declarations (skipped when combined) ---- */
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

struct arch_entry {
    __u8  arch_id;
    __u32 weight_offset;
    __u16 scale_factor;
} __attribute__((packed));

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

struct miss_event_t2 {
    __u8  model_id;
    __u8  ttl;
    __u32 ingress_ifindex;
    __u8  arch_id;
    __u64 key;
};

#define MAX_WEIGHT_ENTRIES 1024
BPF_ARRAY(arch_weights, __s8, MAX_WEIGHT_ENTRIES);
BPF_HASH(arch_registry, __u8, struct arch_entry, 256);
BPF_HASH(fwd_table_t2, __u64, struct fwd_action, 256);
BPF_HASH(valid_keys_t2, __u8, __u64, 256);
BPF_ARRAY(pkt_stats_t2, __u64, 3);
BPF_PERF_OUTPUT(miss_events_t2);
#endif /* IPA_ARCH_COMBINED */

int arch_65_4_4_7(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)  return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)   return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)  return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end)  return XDP_PASS;

    __u8 model_id = ipa->model_id;
    struct arch_entry *entry = arch_registry.lookup(&model_id);
    if (!entry) return XDP_PASS;

    __u32 woff  = entry->weight_offset;
    __u16 scale = entry->scale_factor;
    if (scale == 0) return XDP_PASS;

    /* Feature extraction (4 features used; remaining 61 zeroed) */
    long long iv[T2_N_IN];
    __builtin_memset(iv, 0, sizeof(iv));
    iv[0] = ipa->model_id;
    iv[1] = ip->ttl;
    iv[2] = ctx->ingress_ifindex;
    iv[3] = ipa->input_size;

    /* fc1: T2_N_IN -> T2_N_H1 */
    long long h1[T2_N_H1];
    #pragma unroll
    for (int j = 0; j < T2_N_H1; j++) {
        int bidx = woff + T2_FC1_B_OFF + j;
        if (bidx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        __s8 *bp = arch_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < T2_N_IN; i++) {
            int widx = woff + T2_FC1_W_OFF + j * T2_N_IN + i;
            if (widx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            __s8 *wp = arch_weights.lookup(&widx);
            if (wp) acc += iv[i] * (long long)(*wp);
        }
        h1[j] = RELU(acc);
    }

    /* fc2: T2_N_H1 -> T2_N_H2 */
    long long h2[T2_N_H2];
    #pragma unroll
    for (int j = 0; j < T2_N_H2; j++) {
        int bidx = woff + T2_FC2_B_OFF + j;
        if (bidx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        __s8 *bp = arch_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < T2_N_H1; i++) {
            int widx = woff + T2_FC2_W_OFF + j * T2_N_H1 + i;
            if (widx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            __s8 *wp = arch_weights.lookup(&widx);
            if (wp) acc += h1[i] * (long long)(*wp);
        }
        h2[j] = RELU(acc);
    }

    /* output layer: T2_N_H2 -> T2_N_OUT, argmax */
    long long best_val = -9999999LL;
    int best_cls = 0;
    #pragma unroll
    for (int k = 0; k < T2_N_OUT; k++) {
        int bidx = woff + T2_OUT_B_OFF + k;
        if (bidx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        __s8 *bp = arch_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < T2_N_H2; i++) {
            int widx = woff + T2_OUT_W_OFF + k * T2_N_H2 + i;
            if (widx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            __s8 *wp = arch_weights.lookup(&widx);
            if (wp) acc += h2[i] * (long long)(*wp);
        }
        if (acc > best_val) { best_val = acc; best_cls = k; }
    }

    __u64 key = (__u64)((best_val + (long long)(OUTPUT_OFFSET * scale)) / (__u64)scale);

    struct fwd_action *action = fwd_table_t2.lookup(&key);
    __u64 *correct_key        = valid_keys_t2.lookup(&ip->ttl);

    if (action != NULL && correct_key && *correct_key == key) {
        int si = 0; __u64 *v = pkt_stats_t2.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    } else {
        /* Both MISS (no action) and FAKE HIT (wrong TTL) go to perf buffer */
        int fake = (action != NULL) ? 1 : 0;
        int si   = fake ? 2 : 1;
        __u64 *v = pkt_stats_t2.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        struct miss_event_t2 ev = {};
        ev.model_id = model_id; ev.ttl = ip->ttl;
        ev.ingress_ifindex = ctx->ingress_ifindex;
        ev.arch_id = entry->arch_id; ev.key = key;
        miss_events_t2.perf_submit(ctx, &ev, sizeof(ev));
    }
    return XDP_PASS;
}
"""


def load_arch_weights(bpf_obj, weights_int8: list, model_id: int = 0, scale: int = 128) -> None:
    """
    Populate the arch_registry and arch_weights maps for Pipeline 2.

    Args:
        bpf_obj     : loaded BCC BPF object
        weights_int8: flat list of 319 int8 values (same order as Pipeline 1)
        model_id    : model identifier (u8)
        scale       : quantization scale factor
    """
    from ctypes import c_int8, c_uint32, c_uint16, c_uint8, Structure

    weight_offset = 0  # first model starts at index 0
    arch_id = 0        # arch index 0 = 65_4_4_7

    # Populate arch_weights flat array
    for idx, w in enumerate(weights_int8[:N_WEIGHTS_T2]):
        key = c_uint32(weight_offset + idx)
        val = c_int8(int(w))
        bpf_obj["arch_weights"][key] = val

    # _pack_ = 1 ensures the Python struct layout matches the C __attribute__((packed))
    # definition: no padding between arch_id (1 byte) and weight_offset (4 bytes).
    class ArchEntry(Structure):
        _pack_ = 1
        _fields_ = [("arch_id",       c_uint8),
                    ("weight_offset",  c_uint32),
                    ("scale_factor",   c_uint16)]

    entry = ArchEntry(arch_id=arch_id, weight_offset=weight_offset, scale_factor=scale)
    bpf_obj["arch_registry"][c_uint8(model_id)] = entry

    print(f"[Pipeline2] model_id={model_id} registered: arch={arch_id}, "
          f"offset={weight_offset}, scale={scale}, weights={len(weights_int8[:N_WEIGHTS_T2])}")
