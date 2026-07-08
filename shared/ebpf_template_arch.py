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
  arch_weights    : index     -> char  (signed, flat weight array)
  fwd_table_t2    : u64 key   -> fwd_action
  valid_keys_t2   : u8  ttl   -> u64 key
  pkt_stats_t2    : [0]=HIT [1]=MISS [2]=FAKE
  miss_events_t2  : perf buffer

BCC leaf-type note:
  BPF_ARRAY uses 'char' (not '__s8') as the leaf type.  BCC legacy
  str2ctype maps 'char' -> c_char but the Python side uses c_int8 via
  direct fd-level ctypes write, bypassing BCC's leaf decoder entirely.
  'char' is signed on x86/x86_64 so the semantics are identical to __s8.

Combined compilation note (pipeline_benchmark.py):
  EBPF_ARCH_65_4_4_7 wraps shared declarations in
  #ifndef IPA_ARCH_COMBINED / #endif.  pipeline_benchmark prepends
  '#define IPA_ARCH_COMBINED 1' before concatenating the two sources.

Fixed bugs (2026-07-08):
  1) Stack overflow: `long long iv[T2_N_IN]` (65 * 8B = 520B) alone
     exceeded the 512B BPF stack limit, before even counting h1[4],
     h2[4] and the various pointers -- this would have failed to load
     with the same class of error fixed in Pipeline 1 (ebpf_program.py).
  2) Feature-encoding mismatch: the input vector was populated as
     iv[0]=model_id, iv[1]=ttl, iv[2]=ingress_ifindex, iv[3]=input_size,
     which does NOT match how the model was actually trained (see
     FRR_model.py: 6 link_state (unused, always 0) + 6 ingress-iface
     one-hot [6..11] + 1 ttl [12] + 52 node one-hot [13..64], identical
     to Pipeline 1's encoding). Inference run through the old encoding
     was not comparable to Pipeline 1/3 on the same model.
  Fix: drop the `iv[]` array entirely and compute each hidden neuron's
  dot product directly from the 3 live scalars (_ttl, _iface, _node)
  via arithmetic BPF_ARRAY indices (woff + j*T2_N_IN + {12, 5+iface,
  13+node}). This is safe for arbitrary runtime indices -- unlike the
  `static const` globals that broke Pipeline 1's verifier load, a
  BPF_ARRAY lookup with a computed key is exactly what maps are for --
  and is mathematically identical to summing over all 65 positions
  (every other position is always 0), while removing the stack array
  and cutting fc1 from 65*4 to 3*4 map lookups.
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

/* 'char' leaf type: BCC legacy str2ctype knows 'char'; '__s8' expands to
 * 'signed char' which is NOT in str2ctype -> KeyError at map access.
 * char is signed on x86/x86_64 so semantics are identical to __s8. */
#define MAX_WEIGHT_ENTRIES 1024
BPF_ARRAY(arch_weights, char, MAX_WEIGHT_ENTRIES);

BPF_HASH(arch_registry, __u8, struct arch_entry, 256);
BPF_PROG_ARRAY(arch_progs, 8);
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
    if (!entry) return XDP_PASS;

    arch_progs.call(ctx, entry->arch_id);
    return XDP_PASS;
}
"""

EBPF_ARCH_65_4_4_7 = r"""
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
BPF_ARRAY(arch_weights, char, MAX_WEIGHT_ENTRIES);
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

    /* Feature encoding (must match Pipeline 1 / the trained model exactly,
     * see FRR_model.py: 6 link_state (always 0, unused) + 6 ingress-iface
     * one-hot [6..11] + 1 ttl [12] + 52 node one-hot [13..64]).
     * Only 3 features are ever non-zero per packet, so instead of
     * materializing a `long long iv[65]` on the stack (520B -- already
     * overflows the 512B BPF stack limit on its own) we compute each
     * hidden neuron's dot product directly from the 3 live scalars via
     * arithmetic BPF_ARRAY indices. This is safe (map lookups accept any
     * computed index, unlike the `static const` globals fixed in Pipeline 1 --
     * see ebpf_program.py's "Verifier history") and mathematically identical
     * to summing over all 65 positions, since every other position is 0. */
    __u32 _ttl   = ((__u32)ip->ttl) & 0xff;
    __u32 _iface = ((__u32)ctx->ingress_ifindex) & 0x7;   /* valid 1..6 */
    __u32 _node  = ((__u32)ipa->model_id) & 0x3f;         /* valid 0..51 */

    /* fc1: T2_N_IN -> T2_N_H1
     * Note: arch_weights stores 'char' (signed) but lookup returns char*;
     * cast to (signed char) to preserve sign for the multiply-accumulate. */
    long long h1[T2_N_H1];
    #pragma unroll
    for (int j = 0; j < T2_N_H1; j++) {
        int bidx = woff + T2_FC1_B_OFF + j;
        if (bidx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        char *bp = arch_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*(signed char *)bp) : 0LL;

        int ttl_idx = woff + T2_FC1_W_OFF + j * T2_N_IN + 12;
        if (ttl_idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        char *ttl_wp = arch_weights.lookup(&ttl_idx);
        if (ttl_wp) acc += (long long)_ttl * (long long)(*(signed char *)ttl_wp);

        if (_iface >= 1 && _iface <= 6) {
            int iface_idx = woff + T2_FC1_W_OFF + j * T2_N_IN + 5 + _iface;
            if (iface_idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            char *iface_wp = arch_weights.lookup(&iface_idx);
            if (iface_wp) acc += (long long)(*(signed char *)iface_wp);
        }

        if (_node <= 51) {
            int node_idx = woff + T2_FC1_W_OFF + j * T2_N_IN + 13 + _node;
            if (node_idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            char *node_wp = arch_weights.lookup(&node_idx);
            if (node_wp) acc += (long long)(*(signed char *)node_wp);
        }

        h1[j] = RELU(acc);
    }

    /* fc2: T2_N_H1 -> T2_N_H2 */
    long long h2[T2_N_H2];
    #pragma unroll
    for (int j = 0; j < T2_N_H2; j++) {
        int bidx = woff + T2_FC2_B_OFF + j;
        if (bidx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        char *bp = arch_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*(signed char *)bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < T2_N_H1; i++) {
            int widx = woff + T2_FC2_W_OFF + j * T2_N_H1 + i;
            if (widx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            char *wp = arch_weights.lookup(&widx);
            if (wp) acc += h1[i] * (long long)(*(signed char *)wp);
        }
        h2[j] = RELU(acc);
    }

    /* output: T2_N_H2 -> T2_N_OUT, argmax */
    long long best_val = -9999999LL;
    int best_cls = 0;
    #pragma unroll
    for (int k = 0; k < T2_N_OUT; k++) {
        int bidx = woff + T2_OUT_B_OFF + k;
        if (bidx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        char *bp = arch_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*(signed char *)bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < T2_N_H2; i++) {
            int widx = woff + T2_OUT_W_OFF + k * T2_N_H2 + i;
            if (widx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            char *wp = arch_weights.lookup(&widx);
            if (wp) acc += h2[i] * (long long)(*(signed char *)wp);
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
    Populate arch_registry and arch_weights for Pipeline 2.

    BCC leaf-type workaround: instead of bpf_obj["arch_weights"][key] = val
    (which goes through str2ctype and fails for 'signed char'), we write
    directly via the map's fd using ctypes, bypassing BCC's type decoder.
    """
    import ctypes as ct
    from ctypes import c_int8, c_uint32, c_uint16, c_uint8, Structure

    weight_offset = 0
    arch_id       = 0

    # Direct fd-level write: get the table object but use .items() iteration
    # only for the key type; write the leaf as a raw c_int8 via the map fd.
    tbl = bpf_obj["arch_weights"]
    for idx, w in enumerate(weights_int8[:N_WEIGHTS_T2]):
        k = c_uint32(weight_offset + idx)
        v = c_int8(int(w))
        # BCC Table.__setitem__ calls leaf_sprintf which also uses str2ctype.
        # Use the underlying bpf_update_elem syscall directly via the fd.
        ret = ct.CDLL("libbcc.so.0", use_errno=True).bpf_update_elem(
            tbl.map_fd, ct.byref(k), ct.byref(v), 0)
        if ret != 0:
            import errno, os
            raise OSError(errno.errorcode.get(ct.get_errno(), "?"),
                          f"bpf_update_elem arch_weights[{idx}] failed")

    class ArchEntry(Structure):
        _pack_ = 1
        _fields_ = [("arch_id",       c_uint8),
                    ("weight_offset",  c_uint32),
                    ("scale_factor",   c_uint16)]

    entry = ArchEntry(arch_id=arch_id, weight_offset=weight_offset,
                      scale_factor=scale)
    bpf_obj["arch_registry"][c_uint8(model_id)] = entry

    print(f"[Pipeline2] model_id={model_id} registered: arch={arch_id}, "
          f"offset={weight_offset}, scale={scale}, "
          f"weights={len(weights_int8[:N_WEIGHTS_T2])}")
