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

BCC leaf-type / BPF_ARRAY slot-size note:
  BPF_ARRAY with 'char' leaf declared in BCC allocates value_size=8 bytes
  per slot on x86_64 (kernel rounds up to nearest power-of-two >= 8).
  The Python writer detects the real value_size via BPF_OBJ_GET_INFO_BY_FD
  and allocates a properly-sized zeroed buffer for each write, placing
  the int8 value at byte 0 (LSB on little-endian).  The eBPF program
  reads *(signed char *)bp which is bp[0] -- correct on LE.

Why NOT libbcc.so.0.bpf_update_elem:
  bpf_update_elem is an internal libbcc symbol, not part of the public
  ABI.  On Kathara/Debian containers it either does not resolve or
  returns -1 silently, leaving arch_weights empty.  The raw bpf(2)
  syscall is the correct stable mechanism.

Combined compilation note (pipeline_benchmark.py):
  EBPF_ARCH_65_4_4_7 wraps shared declarations in
  #ifndef IPA_ARCH_COMBINED / #endif.  pipeline_benchmark prepends
  '#define IPA_ARCH_COMBINED 1' before concatenating the two sources.

Fixed bugs (2026-07-08):
  1) Stack overflow: `long long iv[T2_N_IN]` (65 * 8B = 520B).
  2) Feature-encoding mismatch (old iv[0]=model_id encoding).
  Fix: sparse dot-product via BPF_ARRAY index arithmetic.

Fixed bugs (2026-07-09 v5-v6):
  3) sdiv i64 not supported by BPF LLVM -> use udiv.
  4) ingress_ifindex=65536 in sandbox -> explicit clamp to [0,6].

Fixed bugs (2026-07-09 v8):
  5) libbcc bpf_update_elem not public ABI -> raw bpf(2) syscall.

Fixed bugs (2026-07-09 v9):
  6) value_size mismatch: BPF_ARRAY 'char' slot is 8 bytes on kernel;
     passing c_int32 (4 bytes) caused EINVAL or partial writes.
     Fix: detect real value_size via BPF_OBJ_GET_INFO_BY_FD, allocate
     a zeroed buffer of that size, write int8 at byte 0.
"""

import ctypes as ct
import os
import struct

# Architecture constants (65-4-4-7 model)
N_IN   = 65
N_H1   = 4
N_H2   = 4
N_OUT  = 7
N_WEIGHTS_T2 = (N_IN * N_H1 + N_H1) + (N_H1 * N_H2 + N_H2) + (N_H2 * N_OUT + N_OUT)
# = 264 + 20 + 35 = 319

# ---------------------------------------------------------------------------
# Raw bpf(2) syscall helpers
# ---------------------------------------------------------------------------

_libc = ct.CDLL("libc.so.6", use_errno=True)
_BPF_SYSCALL_NR          = 321   # x86_64
_BPF_MAP_UPDATE_ELEM     = 2
_BPF_OBJ_GET_INFO_BY_FD  = 15
_BPF_ANY                 = 0


class _BpfAttrMapElem(ct.Structure):
    """
    Mirrors the kernel union bpf_attr for BPF_MAP_UPDATE/LOOKUP_ELEM.

    Kernel layout (from include/uapi/linux/bpf.h):
      struct {          /* used by BPF_MAP_*_ELEM commands */
        __u32  map_fd;  /* offset  0, size 4 */
        /* 4-byte implicit pad to align __aligned_u64 */
        __aligned_u64  key;    /* offset  8, size 8 */
        __aligned_u64  value;  /* offset 16, size 8 */
        __u64          flags;  /* offset 24, size 8 */
      };
    Total: 32 bytes.  ctypes with natural alignment produces the same
    layout (c_uint32 + 4-byte pad + c_uint64 + c_uint64 + c_uint64).
    """
    _fields_ = [
        ("map_fd",  ct.c_uint32),
        ("_pad",    ct.c_uint32),   # explicit pad to match __aligned_u64
        ("key",     ct.c_uint64),
        ("value",   ct.c_uint64),
        ("flags",   ct.c_uint64),
    ]


class _BpfMapInfo(ct.Structure):
    """
    First fields of struct bpf_map_info (bpf.h).  We only need
    value_size (offset 12) so we declare enough to reach it.
    """
    _fields_ = [
        ("map_type",    ct.c_uint32),   # offset  0
        ("id",          ct.c_uint32),   # offset  4
        ("key_size",    ct.c_uint32),   # offset  8
        ("value_size",  ct.c_uint32),   # offset 12
        ("max_entries", ct.c_uint32),   # offset 16
    ]


class _BpfAttrObjInfo(ct.Structure):
    """
    union bpf_attr for BPF_OBJ_GET_INFO_BY_FD:
      __u32  bpf_fd
      __u32  info_len
      __aligned_u64 info  (pointer)
    """
    _fields_ = [
        ("bpf_fd",   ct.c_uint32),
        ("info_len", ct.c_uint32),
        ("info",     ct.c_uint64),
    ]


def _get_map_value_size(map_fd: int) -> int:
    """
    Return the kernel-reported value_size for a BPF map fd.
    Falls back to 8 if the syscall is not available.
    """
    info = _BpfMapInfo()
    attr = _BpfAttrObjInfo(
        bpf_fd   = map_fd,
        info_len = ct.sizeof(info),
        info     = ct.cast(ct.byref(info), ct.c_void_p).value,
    )
    ret = _libc.syscall(_BPF_SYSCALL_NR, _BPF_OBJ_GET_INFO_BY_FD,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        return 8   # safe fallback: BPF_ARRAY 'char' slot >= 8 bytes
    return max(1, int(info.value_size))


def _bpf_map_update_char(map_fd: int, value_size: int,
                         index: int, int8_val: int) -> None:
    """
    Write int8_val into arch_weights[index] via BPF_MAP_UPDATE_ELEM.

    Allocates a zeroed buffer of `value_size` bytes, places the int8
    value at byte 0 (little-endian, matching *(signed char *)ptr in eBPF),
    then calls the raw bpf(2) syscall.  Raises OSError on failure.
    """
    key_buf = ct.c_uint32(index)
    # Zeroed value buffer sized to the map's actual slot size.
    val_buf = (ct.c_uint8 * value_size)()
    # Write sign-preserved byte at position 0.
    val_buf[0] = ct.c_uint8(ct.c_int8(int8_val).value & 0xFF).value

    attr = _BpfAttrMapElem(
        map_fd = map_fd,
        _pad   = 0,
        key    = ct.cast(ct.byref(key_buf), ct.c_void_p).value,
        value  = ct.cast(val_buf, ct.c_void_p).value,
        flags  = _BPF_ANY,
    )
    ret = _libc.syscall(_BPF_SYSCALL_NR, _BPF_MAP_UPDATE_ELEM,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        e = ct.get_errno()
        raise OSError(e, f"BPF_MAP_UPDATE_ELEM arch_weights[{index}] "
                         f"(value_size={value_size}): {os.strerror(e)}")


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

/* 'char' leaf type: BCC str2ctype knows 'char'; '__s8'/'signed char'
 * are NOT in str2ctype -> KeyError.  char is signed on x86/x86_64.
 * Slot size in kernel BPF_ARRAY is roundup(sizeof(char), 8) = 8 bytes;
 * Python writer detects this via BPF_OBJ_GET_INFO_BY_FD and uses a
 * zeroed 8-byte buffer with the int8 value at byte 0. */
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

    /* Feature encoding: matches Pipeline 1 / FRR_model.py exactly.
     * Sparse dot-product: only 3 positions are non-zero per packet.
     * SANDBOX: ctx->ingress_ifindex=65536 -> clamp to 0. */
    __u32 _ttl   = ((__u32)ip->ttl) & 0xff;
    __u32 _raw_iface = ctx->ingress_ifindex;
    __u32 _iface = (_raw_iface >= 1 && _raw_iface <= 6) ? _raw_iface : 0;
    __u32 _node  = ((__u32)ipa->model_id) & 0x3f;

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

    long long _num_signed = best_val + OUTPUT_OFFSET * (long long)scale;
    if (_num_signed < 0) return XDP_PASS;
    __u64 num = (__u64)_num_signed;
    __u64 key = num / (__u64)scale;

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


def load_arch_weights(bpf_obj, weights_int8: list,
                      model_id: int = 0, scale: int = 128) -> None:
    """
    Populate arch_registry and arch_weights for Pipeline 2.

    Detects the kernel BPF_ARRAY slot size via BPF_OBJ_GET_INFO_BY_FD
    and writes each int8 weight into a properly-sized zeroed buffer at
    byte 0, using the raw bpf(2) BPF_MAP_UPDATE_ELEM syscall.
    """
    from ctypes import c_uint8, c_uint32, c_uint16, Structure

    weight_offset = 0
    arch_id       = 0
    map_fd        = bpf_obj["arch_weights"].map_fd

    # Detect actual slot size (usually 8 for BPF_ARRAY 'char' on x86_64).
    value_size = _get_map_value_size(map_fd)
    print(f"[Pipeline2] arch_weights value_size={value_size} bytes/slot")

    for idx, w in enumerate(weights_int8[:N_WEIGHTS_T2]):
        _bpf_map_update_char(map_fd, value_size,
                             index=weight_offset + idx,
                             int8_val=int(w))

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
