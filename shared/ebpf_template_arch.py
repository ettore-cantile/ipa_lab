"""
ebpf_template_arch.py  —  Pipeline 2: Pre-built Architectural Template.

Design space position:
  - One eBPF program per architecture shape (e.g. arch_65_4_4_7)
  - Multiple models sharing the same shape reuse the same program
  - Weights are stored in BPF_ARRAY maps, loaded at runtime by the CP
  - One tail call: dispatcher -> arch_progs[arch_id] -> arch_65_4_4_7

Architecture supported here: 65-4-4-7 (matching the existing model).
  fc1  : 65 inputs  -> 4 hidden   (260 weights + 4 bias = 264)
  fc2  : 4  hidden  -> 4 hidden   (16  weights + 4 bias = 20)
  out  : 4  hidden  -> 7 outputs  (28  weights + 7 bias = 35)
  Total: 319 int8 values

Control-plane split of responsibilities
  load_arch_weights() populates:
    - arch_weights    (319 int8 values via raw bpf(2) syscall)
    - arch_registry   (arch_id, weight_offset, scale_factor)
  The CALLER must separately wire the tail-call array BEFORE or AFTER:
    leaf_fn = b.load_func("arch_65_4_4_7", BPF.XDP)
    b["arch_progs"][ct.c_int(arch_id)] = ct.c_int(leaf_fn.fd)
  This is done in verify_prog_run.py setup_template() already.
  load_arch_weights does NOT touch arch_progs -- BCC does not expose
  loaded XDP programs via bpf_obj[name] (only maps), so the fd must be
  obtained from the .load_func() return value in the caller.

Implementation notes:
  - Inference uses a sparse dot-product over the one-hot feature vector via
    BPF_ARRAY index arithmetic, avoiding a large on-stack activation array.
  - The output key division uses unsigned division (BPF LLVM has no signed
    64-bit divide), with an OUTPUT_OFFSET bias to keep the numerator positive.
  - ingress_ifindex is clamped to [0,6]; under BPF_PROG_TEST_RUN it is a
    sandbox value outside that range and is treated as "no ingress iface".
  - Weights are written through the raw bpf(2) syscall (libbcc does not export
    a stable bpf_update_elem); the real map slot size is detected via
    BPF_OBJ_GET_INFO_BY_FD before writing.
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
# Raw bpf(2) syscall helpers
# ---------------------------------------------------------------------------

_libc = ct.CDLL("libc.so.6", use_errno=True)
_BPF_SYSCALL_NR          = 321   # x86_64
_BPF_MAP_UPDATE_ELEM     = 2
_BPF_MAP_LOOKUP_ELEM     = 1
_BPF_OBJ_GET_INFO_BY_FD  = 15
_BPF_ANY                 = 0


class _BpfAttrMapElem(ct.Structure):
    """
    union bpf_attr for BPF_MAP_UPDATE/LOOKUP_ELEM.
    Kernel layout: u32 map_fd + 4-byte pad + u64 key + u64 value + u64 flags.
    """
    _fields_ = [
        ("map_fd",  ct.c_uint32),
        ("_pad",    ct.c_uint32),
        ("key",     ct.c_uint64),
        ("value",   ct.c_uint64),
        ("flags",   ct.c_uint64),
    ]


class _BpfMapInfo(ct.Structure):
    _fields_ = [
        ("map_type",    ct.c_uint32),
        ("id",          ct.c_uint32),
        ("key_size",    ct.c_uint32),
        ("value_size",  ct.c_uint32),
        ("max_entries", ct.c_uint32),
    ]


class _BpfAttrObjInfo(ct.Structure):
    _fields_ = [
        ("bpf_fd",   ct.c_uint32),
        ("info_len", ct.c_uint32),
        ("info",     ct.c_uint64),
    ]


def _get_map_value_size(map_fd: int) -> int:
    """Return kernel-reported value_size for a BPF map fd; fallback 8."""
    info = _BpfMapInfo()
    attr = _BpfAttrObjInfo(
        bpf_fd   = map_fd,
        info_len = ct.sizeof(info),
        info     = ct.cast(ct.byref(info), ct.c_void_p).value,
    )
    ret = _libc.syscall(_BPF_SYSCALL_NR, _BPF_OBJ_GET_INFO_BY_FD,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        print(f"[Pipeline2] BPF_OBJ_GET_INFO_BY_FD errno={ct.get_errno()}, fallback value_size=8")
        return 8
    return max(1, int(info.value_size))


def _bpf_map_update_char(map_fd: int, value_size: int,
                         index: int, int8_val: int) -> None:
    """
    Write int8_val into a BPF_ARRAY[index] via raw BPF_MAP_UPDATE_ELEM.
    Allocates a zeroed buffer of value_size bytes; places int8 at byte 0.
    """
    key_buf = ct.c_uint32(index)
    val_buf = (ct.c_uint8 * value_size)()
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
        raise OSError(e, f"BPF_MAP_UPDATE_ELEM arch_weights[{index}]="
                         f"{int8_val} (value_size={value_size}): {os.strerror(e)}")


def _bpf_map_lookup_char(map_fd: int, value_size: int, index: int) -> int:
    """Read arch_weights[index]; return as signed int8 (for post-load verification)."""
    key_buf = ct.c_uint32(index)
    val_buf = (ct.c_uint8 * value_size)()
    attr = _BpfAttrMapElem(
        map_fd = map_fd,
        _pad   = 0,
        key    = ct.cast(ct.byref(key_buf), ct.c_void_p).value,
        value  = ct.cast(val_buf, ct.c_void_p).value,
        flags  = 0,
    )
    ret = _libc.syscall(_BPF_SYSCALL_NR, _BPF_MAP_LOOKUP_ELEM,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        return None
    return ct.c_int8(val_buf[0]).value


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
} __attribute__((packed));

/* 'char' leaf: BCC str2ctype knows 'char'; '__s8'/'signed char' are not. */
#define MAX_WEIGHT_ENTRIES 1024
BPF_ARRAY(arch_weights, char, MAX_WEIGHT_ENTRIES);

/* link_state[i] = egress iface i up/down (feature [0..5]); written by the
 * userspace carrier monitor, read by the leaf arch program. 1=up, 0=down. */
BPF_ARRAY(link_state, __u32, 6);

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
} __attribute__((packed));

#define MAX_WEIGHT_ENTRIES 1024
BPF_ARRAY(arch_weights, char, MAX_WEIGHT_ENTRIES);
BPF_ARRAY(link_state, __u32, 6);
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

    __u32 _ttl       = ((__u32)ip->ttl) & 0xff;
    __u32 _raw_iface = ctx->ingress_ifindex;
    __u32 _iface     = (_raw_iface >= 1 && _raw_iface <= 6) ? _raw_iface : 0;
    __u32 _node      = ((__u32)ipa->model_id) & 0x3f;

    /* Read link_state[0..5] ONCE (feature [0..5]); reused across all neurons.
     * (Previously read inside the neuron loop = 6*N_H1 redundant lookups.) */
    long long ls[6];
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        int lsk = i;
        __u32 *lsp = link_state.lookup(&lsk);
        ls[i] = lsp ? (long long)(*lsp) : 0LL;
    }

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

        /* link_state features [0..5]: acc += ls[i] * w[j, i] */
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            if (ls[i]) {
                int ls_idx = woff + T2_FC1_W_OFF + j * T2_N_IN + i;
                if (ls_idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
                char *ls_wp = arch_weights.lookup(&ls_idx);
                if (ls_wp) acc += ls[i] * (long long)(*(signed char *)ls_wp);
            }
        }

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
    Populate arch_weights and arch_registry for Pipeline 2.

    DOES NOT touch arch_progs.  The caller (setup_template in
    verify_prog_run.py) is responsible for wiring the tail-call array:
        leaf_fn = b.load_func("arch_65_4_4_7", BPF.XDP)
        b["arch_progs"][ct.c_int(arch_id)] = ct.c_int(leaf_fn.fd)
    BCC does not expose loaded programs via bpf_obj[name] -- only maps
    are accessible that way -- so the fd must come from .load_func().
    """
    from ctypes import c_uint8, c_uint32, c_uint16, Structure

    weight_offset = 0
    arch_id       = 0
    map_fd        = bpf_obj["arch_weights"].map_fd

    value_size = _get_map_value_size(map_fd)
    print(f"[Pipeline2] arch_weights fd={map_fd} value_size={value_size} bytes/slot")

    for idx, w in enumerate(weights_int8[:N_WEIGHTS_T2]):
        _bpf_map_update_char(map_fd, value_size,
                             index=weight_offset + idx,
                             int8_val=int(w))

    # Post-load sanity check: read back weight[0].
    v0       = _bpf_map_lookup_char(map_fd, value_size, 0)
    expected = ct.c_int8(int(weights_int8[0])).value
    ok       = "OK" if v0 == expected else f"MISMATCH got={v0} expected={expected}"
    print(f"[Pipeline2] arch_weights[0] verify: {ok}")

    class ArchEntry(Structure):
        _pack_ = 1
        _fields_ = [("arch_id",       c_uint8),
                    ("weight_offset",  c_uint32),
                    ("scale_factor",   c_uint16)]

    entry = ArchEntry(arch_id=arch_id, weight_offset=weight_offset,
                      scale_factor=scale)
    bpf_obj["arch_registry"][c_uint8(model_id)] = entry
    print(f"[Pipeline2] arch_registry[{model_id}] = "
          f"arch_id={arch_id} woff={weight_offset} scale={scale} "
          f"weights={len(weights_int8[:N_WEIGHTS_T2])}")
    print(f"[Pipeline2] NOTE: arch_progs wiring is caller's responsibility "
          f"(setup_template already does: b['arch_progs'][0]=leaf_fn.fd)")
