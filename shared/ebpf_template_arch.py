"""
ebpf_template_arch.py  —  Pipeline 2: Pre-built Architectural Template.

Design space position:
  - One eBPF program for the whole "2 hidden-layer MLP" architecture family
  - Any model with that topology (any hidden widths up to the compiled
    ceiling) reuses the same program -- no recompilation per model
  - Weights are stored in BPF_ARRAY maps, loaded at runtime by the CP
  - One tail call: dispatcher -> arch_progs[arch_id] -> arch_generic_2layer

Architecture family supported here: fc1 -> ReLU -> fc2 -> ReLU -> out,
input/output sizes fixed by the IPA packet format, hidden widths dynamic:
  fc1  : T2_N_IN=65 inputs -> n_h1 hidden   (n_h1 <= T2_MAX_H1)
  fc2  : n_h1 hidden       -> n_h2 hidden   (n_h2 <= T2_MAX_H2)
  out  : n_h2 hidden       -> T2_N_OUT=7 outputs
T2_N_IN=65 and T2_N_OUT=7 are fixed by the IPA header/feature encoding
(6 link_state + 6 iface one-hot + 1 ttl + 52 node one-hot = 65 in;
6 egress classes + drop = 7 out) -- they are protocol constants, not model
hyperparameters, so they stay compile-time. n_h1/n_h2 are read at runtime
from arch_registry, up to the compiled ceilings T2_MAX_H1/T2_MAX_H2 (see
arch_weight_count() below for how the flat weight layout depends on them).
A model whose hidden widths exceed the ceiling is rejected at load time by
load_arch_weights() with a clear error, not silently truncated.

Control-plane split of responsibilities
  load_arch_weights() populates:
    - arch_weights    (int8 values via raw bpf(2) syscall)
    - arch_registry   (arch_id, weight_offset, scale_factor, n_h1, n_h2)
  The CALLER must separately wire the tail-call array BEFORE or AFTER:
    leaf_fn = b.load_func("arch_generic_2layer", BPF.XDP)
    b["arch_progs"][ct.c_int(arch_id)] = ct.c_int(leaf_fn.fd)
  This is done in verify_prog_run.py setup_template() already.
  load_arch_weights does NOT touch arch_progs -- BCC does not expose
  loaded XDP programs via bpf_obj[name] (only maps), so the fd must be
  obtained from the .load_func() return value in the caller.

Action (mac_table):
  The NN decides the egress class (argmax). The program then does a single
  lookup mac_table_t2[class] -> {ifindex, src_mac, dst_mac}, rewrites the L2
  header and bpf_redirect()s. mac_table is just the physical next-hop
  dictionary -- no routing decision, no output validation. cls 6 = DROP.
  (Earlier design keyed a fwd_table by the raw argmax value and validated it
  per-TTL via valid_keys; that was over-engineered for a routing action and
  has been removed.)

Implementation notes:
  - Inference uses a sparse dot-product over the one-hot feature vector via
    BPF_ARRAY index arithmetic, avoiding a large on-stack activation array.
  - ingress_ifindex is clamped to [0,6]; under BPF_PROG_TEST_RUN it is a
    sandbox value outside that range and is treated as "no ingress iface".
  - Weights are written through the raw bpf(2) syscall (libbcc does not export
    a stable bpf_update_elem); the real map slot size is detected via
    BPF_OBJ_GET_INFO_BY_FD before writing.
"""

import ctypes as ct
import os

# Protocol-fixed constants: input/output size are dictated by the IPA
# feature encoding (65 in) and the number of egress classes + drop (7 out),
# not by the model. Hidden widths are the actual per-model hyperparameters.
T2_N_IN   = 65
T2_N_OUT  = 7
# Compile-time ceilings for the hidden widths: the eBPF program unrolls its
# neuron loops up to these bounds (verifier requires a compile-time trip
# count) and skips the unused tail at runtime via `if (j >= n_h1)` guards.
# Any model with n_h1 <= T2_MAX_H1 and n_h2 <= T2_MAX_H2 runs on this same
# compiled program -- raise these and reload once if a wider model shows up.
T2_MAX_H1 = 8
T2_MAX_H2 = 8


def arch_weight_count(n_h1: int, n_h2: int) -> int:
    """Flat int8 weight count for a T2_N_IN -> n_h1 -> n_h2 -> T2_N_OUT MLP
    (fc1 weights+bias, fc2 weights+bias, out weights+bias), matching the
    flat layout load_arch_weights() writes and the eBPF program reads."""
    return (T2_N_IN * n_h1 + n_h1) + (n_h1 * n_h2 + n_h2) + (n_h2 * T2_N_OUT + T2_N_OUT)


# Weight count for the one model currently in the repo (65-4-4-7 = 319),
# kept for callers/tests that assumed the old fixed shape.
N_WEIGHTS_T2 = arch_weight_count(4, 4)

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
    __u8  n_h1;   /* fc1 output width  (<= T2_MAX_H1), read at runtime */
    __u8  n_h2;   /* fc2 output width  (<= T2_MAX_H2), read at runtime */
} __attribute__((packed));

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

/* 'char' leaf: BCC str2ctype knows 'char'; '__s8'/'signed char' are not. */
#define MAX_WEIGHT_ENTRIES 1024
BPF_ARRAY(arch_weights, char, MAX_WEIGHT_ENTRIES);

/* link_state[i] = egress iface i up/down (feature [0..5]); written by the
 * userspace carrier monitor, read by the leaf arch program. 1=up, 0=down. */
BPF_ARRAY(link_state, __u32, 6);

BPF_HASH(arch_registry, __u8, struct arch_entry, 256);
BPF_PROG_ARRAY(arch_progs, 8);
/* mac_table: egress class (0..5, the argmax output) -> {ifindex, src/dst MAC}.
 * The NN decides the port; this is only the L2 next-hop dictionary. No routing
 * decision here, no output validation -- just resolve the physical action. */
BPF_HASH(mac_table_t2, __u32, struct fwd_action, 8);
BPF_ARRAY(pkt_stats_t2, __u64, 3);   /* [0]=HIT [1]=MISS [2]=DROP */
BPF_ARRAY(cls_stats_t2, __u64, 7);   /* per-class redirect counter */

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

EBPF_ARCH_GENERIC_2LAYER = r"""
#define T2_N_IN     65
#define T2_N_OUT     7
#define T2_MAX_H1    8
#define T2_MAX_H2    8
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
    __u8  n_h1;
    __u8  n_h2;
} __attribute__((packed));

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

#define MAX_WEIGHT_ENTRIES 1024
BPF_ARRAY(arch_weights, char, MAX_WEIGHT_ENTRIES);
BPF_ARRAY(link_state, __u32, 6);
BPF_HASH(arch_registry, __u8, struct arch_entry, 256);
BPF_HASH(mac_table_t2, __u32, struct fwd_action, 8);
BPF_ARRAY(pkt_stats_t2, __u64, 3);
BPF_ARRAY(cls_stats_t2, __u64, 7);
#endif /* IPA_ARCH_COMBINED */

int arch_generic_2layer(struct xdp_md *ctx) {
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

    /* Hidden widths for THIS model, read at runtime. The neuron loops below
     * are unrolled to the compiled ceilings T2_MAX_H1/T2_MAX_H2 (verifier
     * needs a compile-time trip count) but skip/zero any neuron past the
     * model's actual width -- same program serves any n_h1<=T2_MAX_H1,
     * n_h2<=T2_MAX_H2 without recompiling. */
    __u32 n_h1 = entry->n_h1;
    __u32 n_h2 = entry->n_h2;
    if (n_h1 == 0 || n_h1 > T2_MAX_H1 || n_h2 == 0 || n_h2 > T2_MAX_H2) return XDP_PASS;

    /* Flat weight layout offsets (relative to woff), sized for THIS model's
     * hidden widths -- mirrors arch_weight_count() on the Python side. */
    __u32 fc1_w_off = 0;
    __u32 fc1_b_off = T2_N_IN * n_h1;
    __u32 fc2_w_off = fc1_b_off + n_h1;
    __u32 fc2_b_off = fc2_w_off + n_h1 * n_h2;
    __u32 out_w_off = fc2_b_off + n_h2;
    __u32 out_b_off = out_w_off + n_h2 * T2_N_OUT;

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

    long long h1[T2_MAX_H1];
    #pragma unroll
    for (int j = 0; j < T2_MAX_H1; j++) {
        if (j >= n_h1) { h1[j] = 0LL; continue; }

        int bidx = woff + fc1_b_off + j;
        if (bidx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        char *bp = arch_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*(signed char *)bp) : 0LL;

        int ttl_idx = woff + fc1_w_off + j * T2_N_IN + 12;
        if (ttl_idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        char *ttl_wp = arch_weights.lookup(&ttl_idx);
        if (ttl_wp) acc += (long long)_ttl * (long long)(*(signed char *)ttl_wp);

        /* link_state features [0..5]: acc += ls[i] * w[j, i] */
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            if (ls[i]) {
                int ls_idx = woff + fc1_w_off + j * T2_N_IN + i;
                if (ls_idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
                char *ls_wp = arch_weights.lookup(&ls_idx);
                if (ls_wp) acc += ls[i] * (long long)(*(signed char *)ls_wp);
            }
        }

        if (_iface >= 1 && _iface <= 6) {
            int iface_idx = woff + fc1_w_off + j * T2_N_IN + 5 + _iface;
            if (iface_idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            char *iface_wp = arch_weights.lookup(&iface_idx);
            if (iface_wp) acc += (long long)(*(signed char *)iface_wp);
        }

        if (_node <= 51) {
            int node_idx = woff + fc1_w_off + j * T2_N_IN + 13 + _node;
            if (node_idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            char *node_wp = arch_weights.lookup(&node_idx);
            if (node_wp) acc += (long long)(*(signed char *)node_wp);
        }

        h1[j] = RELU(acc);
    }

    /* h1[i]==0 for i>=n_h1 (set above), so the inner loop can always unroll
     * to T2_MAX_H1: out-of-range weight reads still get multiplied by 0. */
    long long h2[T2_MAX_H2];
    #pragma unroll
    for (int j = 0; j < T2_MAX_H2; j++) {
        if (j >= n_h2) { h2[j] = 0LL; continue; }

        int bidx = woff + fc2_b_off + j;
        if (bidx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        char *bp = arch_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*(signed char *)bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < T2_MAX_H1; i++) {
            int widx = woff + fc2_w_off + j * n_h1 + i;
            if (widx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            char *wp = arch_weights.lookup(&widx);
            if (wp) acc += h1[i] * (long long)(*(signed char *)wp);
        }
        h2[j] = RELU(acc);
    }

    /* Same trick: h2[i]==0 for i>=n_h2, so the output loop is always
     * unrolled to T2_MAX_H2 regardless of this model's actual n_h2. */
    long long best_val = -9999999LL;
    int best_cls = 0;
    #pragma unroll
    for (int k = 0; k < T2_N_OUT; k++) {
        int bidx = woff + out_b_off + k;
        if (bidx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
        char *bp = arch_weights.lookup(&bidx);
        long long acc = bp ? (long long)(*(signed char *)bp) : 0LL;
        #pragma unroll
        for (int i = 0; i < T2_MAX_H2; i++) {
            int widx = woff + out_w_off + k * n_h2 + i;
            if (widx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;
            char *wp = arch_weights.lookup(&widx);
            if (wp) acc += h2[i] * (long long)(*(signed char *)wp);
        }
        if (acc > best_val) { best_val = acc; best_cls = k; }
    }

    /* The NN decided the egress class (argmax). cls 6 = DROP. */
    if (best_cls >= 6) {
        int di = 2; __u64 *dv = pkt_stats_t2.lookup(&di);
        if (dv) __sync_fetch_and_add(dv, 1);
        return XDP_DROP;
    }

    /* mac_table: class -> {ifindex, src/dst MAC}. Single lookup, no key math,
     * no output validation -- resolve the L2 next-hop and redirect. */
    __u32 cls = (__u32)best_cls;
    struct fwd_action *action = mac_table_t2.lookup(&cls);
    if (action != NULL) {
        int si = 0; __u64 *v = pkt_stats_t2.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        __u64 *cv = cls_stats_t2.lookup(&cls);
        if (cv) __sync_fetch_and_add(cv, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    /* no mac_table entry for that class (e.g. link down / not provisioned) */
    int si = 1; __u64 *v = pkt_stats_t2.lookup(&si);
    if (v) __sync_fetch_and_add(v, 1);
    return XDP_PASS;
}
"""


def load_arch_weights(bpf_obj, weights_int8: list,
                      model_id: int = 0, scale: int = 128,
                      weight_offset: int = 0,
                      n_h1: int = 4, n_h2: int = 4) -> None:
    """
    Populate arch_weights and arch_registry for Pipeline 2.

    n_h1/n_h2 are THIS model's hidden widths (input=T2_N_IN=65 and
    output=T2_N_OUT=7 are protocol-fixed, see module docstring). They must
    fit under the compiled ceilings T2_MAX_H1/T2_MAX_H2 -- raises ValueError
    otherwise rather than silently truncating. Any model with hidden widths
    within the ceiling runs on the same compiled arch_generic_2layer program;
    no recompilation needed to change n_h1/n_h2 between models.

    weight_offset lets the caller register several model_id entries in the
    same arch_weights array without overlapping their weight blocks: call
    this once per model_id with a distinct, non-overlapping weight_offset
    (e.g. the running sum of arch_weight_count(n_h1, n_h2) for models already
    registered -- their sizes may differ). All entries share the same arch_id
    (arch_generic_2layer is the only compiled shape), so the dispatcher
    resolves model_id -> (weight_offset, n_h1, n_h2) via arch_registry and
    tail-calls the same leaf program.

    DOES NOT touch arch_progs.  The caller (setup_template in
    verify_prog_run.py) is responsible for wiring the tail-call array:
        leaf_fn = b.load_func("arch_generic_2layer", BPF.XDP)
        b["arch_progs"][ct.c_int(arch_id)] = ct.c_int(leaf_fn.fd)
    BCC does not expose loaded programs via bpf_obj[name] -- only maps
    are accessible that way -- so the fd must come from .load_func().
    """
    from ctypes import c_uint8, c_uint32, c_uint16, Structure

    if n_h1 <= 0 or n_h1 > T2_MAX_H1 or n_h2 <= 0 or n_h2 > T2_MAX_H2:
        raise ValueError(
            f"n_h1={n_h1}/n_h2={n_h2} outside the compiled ceiling "
            f"T2_MAX_H1={T2_MAX_H1}/T2_MAX_H2={T2_MAX_H2} -- raise the "
            f"ceiling in ebpf_template_arch.py and reload to support it")

    n_weights = arch_weight_count(n_h1, n_h2)
    arch_id   = 0
    map_fd    = bpf_obj["arch_weights"].map_fd

    if weight_offset + n_weights > 1024:  # MAX_WEIGHT_ENTRIES in the eBPF source
        raise ValueError(
            f"weight_offset={weight_offset} + n_weights={n_weights} "
            f"exceeds MAX_WEIGHT_ENTRIES=1024 -- too many concurrent model_id's")

    if len(weights_int8) < n_weights:
        raise ValueError(
            f"n_h1={n_h1}/n_h2={n_h2} needs {n_weights} weights, "
            f"got only {len(weights_int8)}")

    value_size = _get_map_value_size(map_fd)
    print(f"[Pipeline2] arch_weights fd={map_fd} value_size={value_size} bytes/slot")

    for idx, w in enumerate(weights_int8[:n_weights]):
        _bpf_map_update_char(map_fd, value_size,
                             index=weight_offset + idx,
                             int8_val=int(w))

    # Post-load sanity check: read back weight[0] of this model's block.
    v0       = _bpf_map_lookup_char(map_fd, value_size, weight_offset)
    expected = ct.c_int8(int(weights_int8[0])).value
    ok       = "OK" if v0 == expected else f"MISMATCH got={v0} expected={expected}"
    print(f"[Pipeline2] arch_weights[{weight_offset}] verify: {ok}")

    class ArchEntry(Structure):
        _pack_ = 1
        _fields_ = [("arch_id",       c_uint8),
                    ("weight_offset",  c_uint32),
                    ("scale_factor",   c_uint16),
                    ("n_h1",           c_uint8),
                    ("n_h2",           c_uint8)]

    entry = ArchEntry(arch_id=arch_id, weight_offset=weight_offset,
                      scale_factor=scale, n_h1=n_h1, n_h2=n_h2)
    bpf_obj["arch_registry"][c_uint8(model_id)] = entry
    print(f"[Pipeline2] arch_registry[{model_id}] = "
          f"arch_id={arch_id} woff={weight_offset} scale={scale} "
          f"shape=65-{n_h1}-{n_h2}-7 weights={n_weights}")
    print(f"[Pipeline2] NOTE: arch_progs wiring is caller's responsibility "
          f"(setup_template already does: b['arch_progs'][0]=leaf_fn.fd)")
