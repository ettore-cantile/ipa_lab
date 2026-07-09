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
  str2ctype maps 'char' -> c_char but the Python side writes via the
  raw bpf(2) syscall (BPF_MAP_UPDATE_ELEM), bypassing BCC's type
  decoder entirely.  The kernel BPF_ARRAY always stores 4-byte aligned
  slots on x86_64, so the value is passed as c_int32 (sign-extended
  from the int8 weight).  'char' is signed on x86/x86_64 so the
  semantics in the eBPF program are identical to __s8.

Why NOT libbcc.so.0.bpf_update_elem:
  bpf_update_elem is an internal libbcc symbol, not part of the public
  ABI.  On Kathara/Debian containers it either does not resolve or
  returns -1 silently, leaving arch_weights empty.  The raw syscall is
  the correct, stable approach (same used by prog_test_run elsewhere).

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

Fixed bugs (2026-07-09 v5):
  3) KEY DIVISION OVERFLOW (reverted): the sdiv-based formula
       long long key_ll = (best_val + OUTPUT_OFFSET*(long long)scale)
                          / (long long)scale;
     was correct mathematically but the BPF LLVM backend refuses to
     compile `sdiv i64` -- it is not a native BPF instruction and LLVM
     emits: "Unsupport signed division for DAG: i64 = sdiv".
     Fix (v6): use unsigned division.  The numerator is ALWAYS >= 0
     because OUTPUT_OFFSET*scale (>= 100000) >> |best_val| (< 5e6 only
     for pathological int8 models, but for our 319-weight model the
     empirical range is << 1e5 per unit scale).  So:
       __u64 num = (__u64)(best_val + OUTPUT_OFFSET*(long long)scale);
       __u64 key = num / (__u64)scale;
     compiles to BPF udiv64 which is supported, and gives bit-identical
     results to sdiv for all reachable values (positive numerator means
     floor == truncation-toward-zero == Python // for positive args).
  4) INGRESS_IFINDEX SANDBOX CLAMPING: ctx->ingress_ifindex == 65536 in
     BPF_PROG_TEST_RUN (kernel assigns a junk ifindex not in [1..6]).
     The old code `& 0x7` happened to give 0 for 65536 by coincidence;
     replaced with an explicit clamp `(<= 6) ? x : 0` so behaviour is
     documented and robust for any sandbox ifindex value.

Fixed bugs (2026-07-09 v8):
  5) ARCH_WEIGHTS WRITE VIA libbcc.so.0 FAILS SILENTLY: bpf_update_elem
     is not a public libbcc ABI symbol; on Kathara/Debian the CDLL lookup
     resolves to NULL or returns -1 without raising an exception, so ALL
     writes to arch_weights are no-ops and the map stays zeroed.
     Consequence: every arch_weights.lookup() in the eBPF program returns
     a pointer to a zero byte, so acc = 0 for all neurons, best_val = 0,
     key = OUTPUT_OFFSET = 100000, never matching the correct key
     -> pkt_stats[HIT]=0 always, all TTL FAIL.
     Fix: use the raw bpf(2) syscall (NR=321, BPF_MAP_UPDATE_ELEM=2)
     directly via libc.syscall(), same mechanism as prog_test_run().
     The BPF_ARRAY slot is 4-byte aligned, so the value is c_int32
     (sign-extended from int8) to match the kernel copy size exactly.
"""

import ctypes as ct
import os

# Architecture constants (65-4-4-7 model)
N_IN   = 65
N_H1   = 4
N_H2   = 4
N_OUT  = 7
N_WEIGHTS_T2 = (N_IN * N_H1 + N_H1) + (N_H1 * N_H2 + N_H2) + (N_H2 * N_OUT + N_OUT)
# = 264 + 20 + 35 = 319

# ---------------------------------------------------------------------------
# Raw bpf(2) syscall helper for BPF_MAP_UPDATE_ELEM
# ---------------------------------------------------------------------------

_libc = ct.CDLL("libc.so.6", use_errno=True)
_BPF_SYSCALL_NR      = 321   # x86_64
_BPF_MAP_UPDATE_ELEM = 2
_BPF_ANY             = 0

class _BpfAttrMapElem(ct.Structure):
    """union bpf_attr for BPF_MAP_UPDATE_ELEM / BPF_MAP_LOOKUP_ELEM."""
    _fields_ = [
        ("map_fd",  ct.c_uint32),
        ("key",     ct.c_uint64),
        ("value",   ct.c_uint64),
        ("flags",   ct.c_uint64),
    ]

def _bpf_map_update(map_fd: int, key_obj, val_obj) -> None:
    """
    Write a single entry to a BPF map via the raw bpf(2) syscall.

    key_obj and val_obj must be ctypes instances (their address is passed
    to the kernel).  Raises OSError on failure.

    Why not libbcc bpf_update_elem:
      bpf_update_elem is an internal libbcc symbol not in its public ABI.
      On Kathara/Debian containers it either does not resolve or returns
      -1 silently, leaving the map empty.  The raw syscall is the correct
      stable mechanism (same used by prog_test_run in verify_prog_run.py).
    """
    attr = _BpfAttrMapElem(
        map_fd = map_fd,
        key    = ct.cast(ct.byref(key_obj), ct.c_void_p).value,
        value  = ct.cast(ct.byref(val_obj), ct.c_void_p).value,
        flags  = _BPF_ANY,
    )
    ret = _libc.syscall(_BPF_SYSCALL_NR, _BPF_MAP_UPDATE_ELEM,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        e = ct.get_errno()
        raise OSError(e, os.strerror(e))


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
 * char is signed on x86/x86_64 so semantics are identical to __s8.
 * NOTE: BPF_ARRAY aligns each slot to 4 bytes on x86_64; the Python
 * writer uses c_int32 (sign-extended from int8) to match the slot size. */
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
#define OUTPUT_OFFSET 100000LL
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
     * to summing over all 65 positions, since every other position is 0.
     *
     * SANDBOX NOTE: ctx->ingress_ifindex == 65536 in BPF_PROG_TEST_RUN.
     * Clamp explicitly to [0,6]: any value > 6 means "no valid iface" (0),
     * which is consistent with Python ref_infer(ifindex=0). */
    __u32 _ttl   = ((__u32)ip->ttl) & 0xff;
    __u32 _raw_iface = ctx->ingress_ifindex;
    __u32 _iface = (_raw_iface >= 1 && _raw_iface <= 6) ? _raw_iface : 0;
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

    /* KEY FORMULA — unsigned division (BPF does not support sdiv i64).
     *
     * BPF LLVM backend error if using signed division (sdiv i64):
     *   "Unsupport signed division for DAG" / "Please convert to unsigned"
     *
     * Safe to use udiv because the numerator is always positive:
     *   OUTPUT_OFFSET * scale >= 100000 * 1 = 100000
     *   |best_val| < OUTPUT_OFFSET * scale for all reachable int8 models
     * so (best_val + OUTPUT_OFFSET*(long long)scale) > 0 always.
     *
     * For positive numerator: udiv == sdiv == Python // (all truncate to 0).
     * Matches Python exactly: (ref_val + OUTPUT_OFFSET * scale) // scale */
    long long _num_signed = best_val + OUTPUT_OFFSET * (long long)scale;
    if (_num_signed < 0) return XDP_PASS;  /* safety guard, should never fire */
    __u64 num = (__u64)_num_signed;
    __u64 key = num / (__u64)scale;        /* udiv i64: supported by BPF */

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

    Uses the raw bpf(2) syscall (BPF_MAP_UPDATE_ELEM) instead of
    libbcc's bpf_update_elem, which is an internal symbol not in the
    public libbcc ABI and silently fails on Kathara/Debian containers.

    BPF_ARRAY slot alignment note:
      On x86_64 the kernel aligns each BPF_ARRAY element to 8 bytes for
      u64 maps, but for 'char' (1-byte declared type) BCC/kernel uses
      max(sizeof(char), 8) = 8 bytes per slot in some versions, or
      exactly sizeof(char)=1 with 4-byte alignment in others.  To be
      safe we pass c_int32 (4 bytes, sign-extended from int8) which
      covers the most common alignment without overwriting adjacent slots.
    """
    from ctypes import c_uint8, c_uint32, c_uint16, c_int32, Structure

    weight_offset = 0
    arch_id       = 0
    map_fd        = bpf_obj["arch_weights"].map_fd

    for idx, w in enumerate(weights_int8[:N_WEIGHTS_T2]):
        k = c_uint32(weight_offset + idx)
        # c_int32: sign-extend the int8 value into a 4-byte slot so the
        # kernel copy covers the full BPF_ARRAY element width.
        v = c_int32(ct.c_int8(int(w)).value)
        _bpf_map_update(map_fd, k, v)

    class ArchEntry(Structure):
        _pack_ = 1
        _fields_ = [("arch_id",       c_uint8),
                    ("weight_offset",  c_uint32),
                    ("scale_factor",   c_uint16)]

    entry = ArchEntry(arch_id=arch_id, weight_offset=weight_offset,
                      scale_factor=scale)
    bpf_obj["arch_registry"][c_uint8(model_id)] = entry

    print(f"[Pipeline2] model_id={model_id} registered: arch_id={arch_id}, "
          f"w_off={weight_offset}, scale={scale}, "
          f"weights={len(weights_int8[:N_WEIGHTS_T2])}")
