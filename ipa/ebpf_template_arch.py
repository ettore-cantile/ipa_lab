"""ebpf_template_arch.py -- Pipeline 2 (P2): one program per architecture family.

The program is compiled once per depth; hidden widths (up to T2_MAX_H1 and
T2_MAX_H2) and weights are read from maps, so changing the model is a map write.
"""

import ctypes as ct
import os

def reference_widths():
    """(n_in, n_out) of the model this repo is configured for."""
    import model_meta as _mm
    sh = _mm.derive_shape(_mm.load_model_meta(
                              os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "weights.json")),
                          topology_config=_mm.load_topology_config())
    return sh["n_in"], sh["n_out"]
T2_N_OUT  = 7
T2_MAX_H1 = 8
T2_MAX_H2 = 8
MAX_WEIGHT_ENTRIES = 1024


def arch_weight_count(n_h1: int, n_h2: int, n_in: int = None,
                      n_out: int = None, n_hidden: int = 2) -> int:
    """Flat int8 weight count for an n_in -> n_h1 -> n_h2 -> T2_N_OUT MLP (fc1
    weights+bias, fc2 weights+bias, out weights+bias), matching the flat
    layout load_arch_weights() writes and the eBPF program reads."""
    if n_in is None or n_out is None:
        _in, _out = reference_widths()
        n_in = _in if n_in is None else n_in
        n_out = _out if n_out is None else n_out
    if n_hidden == 1:
        return (n_in * n_h1 + n_h1) + (n_h1 * n_out + n_out)
    extra = (n_hidden - 2) * (n_h2 * n_h2 + n_h2)
    return ((n_in * n_h1 + n_h1) + (n_h1 * n_h2 + n_h2) + extra
            + (n_h2 * n_out + n_out))


class _LazyWeightCount:
    """`N_WEIGHTS_T2` as a lazily-evaluated int."""

    def __int__(self):
        return arch_weight_count(4, 4)

    def __index__(self):
        return int(self)

    def __repr__(self):
        return str(int(self))

    def __str__(self):
        return str(int(self))

    def __eq__(self, other):
        return int(self) == other

    def __hash__(self):
        return hash(int(self))

    def __rfloordiv__(self, other):
        return other // int(self)

    def __floordiv__(self, other):
        return int(self) // other

    def __mul__(self, other):
        return int(self) * other

    __rmul__ = __mul__

    def __format__(self, spec):
        return format(int(self), spec)


N_WEIGHTS_T2 = _LazyWeightCount()

# --- Raw bpf(2) syscall helpers ---

_libc = None


def _get_libc():
    global _libc
    if _libc is None:
        _libc = ct.CDLL("libc.so.6", use_errno=True)
    return _libc
_BPF_SYSCALL_NR          = 321
_BPF_MAP_UPDATE_ELEM     = 2
_BPF_MAP_LOOKUP_ELEM     = 1
_BPF_OBJ_GET_INFO_BY_FD  = 15
_BPF_ANY                 = 0


class _BpfAttrMapElem(ct.Structure):
    """union bpf_attr for BPF_MAP_UPDATE/LOOKUP_ELEM."""
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
    """Return kernel-reported value_size for a BPF map fd;"""
    info = _BpfMapInfo()
    attr = _BpfAttrObjInfo(
        bpf_fd   = map_fd,
        info_len = ct.sizeof(info),
        info     = ct.cast(ct.byref(info), ct.c_void_p).value,
    )
    ret = _get_libc().syscall(_BPF_SYSCALL_NR, _BPF_OBJ_GET_INFO_BY_FD,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        print(f"[Pipeline2] BPF_OBJ_GET_INFO_BY_FD errno={ct.get_errno()}, fallback value_size=8")
        return 8
    return max(1, int(info.value_size))


def _bpf_map_read_blk(map_fd: int, value_size: int, index: int = 0) -> bytearray:
    """Read the whole struct-valued arch_weights entry (key `index`) as bytes."""
    key_buf = ct.c_uint32(index)
    val_buf = (ct.c_uint8 * value_size)()
    attr = _BpfAttrMapElem(
        map_fd = map_fd,
        _pad   = 0,
        key    = ct.cast(ct.byref(key_buf), ct.c_void_p).value,
        value  = ct.cast(val_buf, ct.c_void_p).value,
        flags  = 0,
    )
    ret = _get_libc().syscall(_BPF_SYSCALL_NR, _BPF_MAP_LOOKUP_ELEM,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        return bytearray(value_size)
    return bytearray(val_buf)


def _bpf_map_write_blk(map_fd: int, blk: bytearray, index: int = 0) -> None:
    """Write the whole struct-valued arch_weights entry (key `index`) in ONE
    BPF_MAP_UPDATE_ELEM, replacing the previous one-syscall-per-weight loop."""
    key_buf = ct.c_uint32(index)
    val_buf = (ct.c_uint8 * len(blk)).from_buffer_copy(bytes(blk))
    attr = _BpfAttrMapElem(
        map_fd = map_fd,
        _pad   = 0,
        key    = ct.cast(ct.byref(key_buf), ct.c_void_p).value,
        value  = ct.cast(val_buf, ct.c_void_p).value,
        flags  = _BPF_ANY,
    )
    ret = _get_libc().syscall(_BPF_SYSCALL_NR, _BPF_MAP_UPDATE_ELEM,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        e = ct.get_errno()
        raise OSError(e, f"BPF_MAP_UPDATE_ELEM arch_weights block "
                         f"({len(blk)} bytes): {os.strerror(e)}")


EBPF_TEMPLATE_ARCH_DISPATCHER = r"""
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

struct arch_entry {
    __u8  arch_id;
    __u32 weight_offset;
    __u16 scale_factor;
    __u8  n_out;
    __u8  n_h1;   /* fc1 output width  (<= T2_MAX_H1), read at runtime */
    __u8  n_h2;   /* fc2 output width  (<= T2_MAX_H2), read at runtime */
    __u8  sem_bank;
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

#define MAX_WEIGHT_ENTRIES 1024
struct aw_blk { __u8 w[MAX_WEIGHT_ENTRIES]; };
BPF_ARRAY(arch_weights, struct aw_blk, 1);

#define AW_W(blk, i) ((long long)(__s8)((blk)->w[(__u32)(i) & (MAX_WEIGHT_ENTRIES - 1)]))

#define IPA_MAX_IFACES  8
#define IPA_MAX_QUEUES  8
struct ls_vec { __u32 v[IPA_MAX_IFACES]; };
BPF_ARRAY(link_state, struct ls_vec, 1);

struct qs_vec { __u32 v[IPA_MAX_QUEUES]; };
BPF_ARRAY(queue_state, struct qs_vec, 1);

#define MAX_FEAT 4
struct feat_ent { __u8 code; __u8 size; __u8 col_off; __u8 scale; };
struct model_desc { __u8 n_feat; __u8 n_in; __u8 _p0; __u8 _p1; struct feat_ent feats[MAX_FEAT]; };
BPF_HASH(model_desc, __u8, struct model_desc, 256);

BPF_HASH(arch_registry, __u8, struct arch_entry, 256);
BPF_PROG_ARRAY(arch_progs, 8);
/* mac_table: egress class (0..5, the argmax output) -> {ifindex, src/dst MAC}.
 * The NN decides the port; this is only the L2 next-hop dictionary. No routing
 * decision here, no output validation -- just resolve the physical action. */
/* mac_table_t2 is keyed by LOGICAL PORT, not by class. */
BPF_ARRAY(mac_table_t2, struct fwd_action, MAX_N_OUT);
BPF_HASH(ingress_port_t2, __u32, __u32, 64);
BPF_HASH(node_id_t2, __u32, __u32, 1);

/* class_action_t2: (model_id, bank, class) -> {action, logical port},
 * flattened into an ARRAY index: one inlined lookup, O(1) in the number of
 * registered models, and models with different class meanings coexist.
 *
 * Why an index into a separate map and not a cls[] table inside arch_entry
 * (which the datapath already holds): indexing a map value by best_cls is
 * pointer arithmetic, and the verifier then tracks best_cls PRECISELY back
 * through the argmax, so no two argmax paths can be pruned against each other.
 * Measured: P3's layer_hidden stops loading (E2BIG). A lookup KEY on the stack
 * needs no such precision -- which is why the class-only lookup was cheap.
 *
 * Two banks per model_id, selected by arch_entry.sem_bank: re-registering a
 * model writes the INACTIVE bank in full, then flips sem_bank in the same
 * arch_registry update that installs the new n_out. A packet therefore sees
 * the old (n_out, table) or the new one, never a half-written table, and a
 * registration that fails midway leaves the live bank untouched. Other
 * model_ids' rows are never written.
 *
 * Classes at or past a model's n_out are ACT_INVALID in its rows. */
#define CLASS_ACT_BANKS   2
#define CLASS_ACT_MODELS  256   /* model_id is a __u8 */
#define CLASS_ACT_KEY(mid, bank, cls) \
    (((((__u32)(mid) & 0xffU) * CLASS_ACT_BANKS + ((__u32)(bank) & 1U)) \
      * MAX_N_OUT) + (__u32)(cls))
BPF_ARRAY(class_action_t2, struct class_act,
          CLASS_ACT_MODELS * CLASS_ACT_BANKS * MAX_N_OUT);
BPF_PERCPU_ARRAY(pkt_stats_t2, __u64, 3);   /* [0]=HIT [1]=MISS [2]=DROP */
BPF_PERCPU_ARRAY(cls_stats_t2, __u64, MAX_N_OUT);   /* per-class redirect counter */

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

int ipa_switch_template(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    __u8 ip_proto = *((__u8 *)ip + 9);
    if (ip_proto != IPPROTO_UDP)  return XDP_PASS;

    __u32 _ip_hlen = (((__u8 *)ip)[0] & 0x0fU) << 2U;
    if (_ip_hlen < 20U) return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)((void *)ip + _ip_hlen);
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

_ARCH_LEAF_TEMPLATE = r"""
#define T2_MAX_H1    8
#define T2_MAX_H2    8
#define T2_TTL_SCALE 30
#define MAX_N_IN     128
#define MAX_FEAT     4
#define FEAT_LINK_STATE  0x01
#define FEAT_INGRESS_IF  0x02
#define FEAT_TTL         0x03
#define FEAT_NODE_ID     0x04
#define FEAT_QUEUE_OCC   0x05
static __always_inline long long ipa_relu(long long x) {
    long long m = x >> 63;
    asm volatile("" : "+r"(m));
    return x & ~m;
}

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
    __u8  n_out;
    __u8  n_h1;
    __u8  n_h2;
    __u8  sem_bank;
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

#define MAX_WEIGHT_ENTRIES 1024
struct aw_blk { __u8 w[MAX_WEIGHT_ENTRIES]; };
BPF_ARRAY(arch_weights, struct aw_blk, 1);
#define AW_W(blk, i) ((long long)(__s8)((blk)->w[(__u32)(i) & (MAX_WEIGHT_ENTRIES - 1)]))
#define IPA_MAX_IFACES  8
#define IPA_MAX_QUEUES  8
struct ls_vec { __u32 v[IPA_MAX_IFACES]; };
BPF_ARRAY(link_state, struct ls_vec, 1);
struct qs_vec { __u32 v[IPA_MAX_QUEUES]; };
BPF_ARRAY(queue_state, struct qs_vec, 1);
struct feat_ent { __u8 code; __u8 size; __u8 col_off; __u8 scale; };
struct model_desc { __u8 n_feat; __u8 n_in; __u8 _p0; __u8 _p1; struct feat_ent feats[MAX_FEAT]; };

BPF_HASH(model_desc, __u8, struct model_desc, 256);
BPF_HASH(arch_registry, __u8, struct arch_entry, 256);
/* mac_table_t2 is keyed by LOGICAL PORT, not by class. */
BPF_ARRAY(mac_table_t2, struct fwd_action, MAX_N_OUT);
BPF_HASH(ingress_port_t2, __u32, __u32, 64);
BPF_HASH(node_id_t2, __u32, __u32, 1);

/* Same (model_id, bank, class) map as in the dispatcher source. */
#define CLASS_ACT_BANKS   2
#define CLASS_ACT_MODELS  256
#define CLASS_ACT_KEY(mid, bank, cls) \
    (((((__u32)(mid) & 0xffU) * CLASS_ACT_BANKS + ((__u32)(bank) & 1U)) \
      * MAX_N_OUT) + (__u32)(cls))
BPF_ARRAY(class_action_t2, struct class_act,
          CLASS_ACT_MODELS * CLASS_ACT_BANKS * MAX_N_OUT);
BPF_PERCPU_ARRAY(pkt_stats_t2, __u64, 3);
BPF_PERCPU_ARRAY(cls_stats_t2, __u64, MAX_N_OUT);
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
#endif /* IPA_ARCH_COMBINED */

#ifndef IPA_DIV_TRUNC_DEFINED
#define IPA_DIV_TRUNC_DEFINED
static __always_inline long long ipa_div_trunc(long long num, __u64 den)
{
    if (den == 0) den = 1;
    if (num < 0)
        return -(long long)(((__u64)(-num)) / den);
    return (long long)(((__u64)num) / den);
}
#endif

int arch_generic_2layer(struct xdp_md *ctx) {
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
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end)  return XDP_PASS;

    __u8 model_id = ipa->model_id;
    struct arch_entry *entry = arch_registry.lookup(&model_id);
    if (!entry) return XDP_PASS;

    __u32 sem_key0 = CLASS_ACT_KEY(model_id, entry->sem_bank, 0);
    __u32 woff  = entry->weight_offset;
    __u16 scale = entry->scale_factor;
    if (scale == 0) return XDP_PASS;

    /* Bias multipliers. The weights are stored as round(w_float * scale), so
     * after L layers of products the accumulator carries scale**L while a bias
     * stored the same way carries only scale**1. Each layer's bias therefore
     * needs multiplying by scale**(layer-1): 1 for fc1, scale for fc2,
     * scale**2 for the output layer. Without this the biases are progressively
     * under-weighted and the datapath disagrees with the trained model on 28%
     * of decisions (measured: float/int8 argmax agreement 72% -> 96%).
     * long long, not u32: scale**2 with a 16-bit scale would overflow. */
    long long bias_mul_1 = 1LL;
    long long bias_mul_2 = (long long)scale;
    long long bias_mul_3 = /*@BIAS_OUT@*/(long long)scale * (long long)scale;

    __u32 n_h1 = entry->n_h1;
    __u32 n_h2 = entry->n_h2;
    if (n_h1 == 0 || n_h1 > T2_MAX_H1 || n_h2 == 0 || n_h2 > T2_MAX_H2) return XDP_PASS;
    __u32 n_out = entry->n_out;
    if (n_out == 0 || n_out > MAX_N_OUT) return XDP_PASS;

    struct model_desc *desc = model_desc.lookup(&model_id);
    if (!desc) return XDP_PASS;
    __u32 n_in = desc->n_in;
    if (n_in == 0 || n_in > MAX_N_IN) return XDP_PASS;

    __u32 fc1_w_off = 0;
    __u32 fc1_b_off = n_in * n_h1;
    __u32 fc2_w_off = fc1_b_off + n_h1;
    __u32 fc2_b_off = fc2_w_off + n_h1 * n_h2;
    __u32 out_w_off = /*@OUT_W_OFF@*/fc2_b_off + n_h2 + 0;
    __u32 out_b_off = out_w_off + n_h2 * n_out;

    if (woff + out_b_off + n_out > MAX_WEIGHT_ENTRIES) return XDP_PASS;

    int _awz = 0;
    struct aw_blk *AW = arch_weights.lookup(&_awz);
    if (!AW) return XDP_PASS;

    __u32 _ttl       = ((__u32)ip->ttl) & 0xff;
    __u32 _raw_iface = 0;
    { __u32 _kif = ctx->ingress_ifindex;
      __u32 *_lp = ingress_port_t2.lookup(&_kif);
      if (_lp) _raw_iface = *_lp; }
    __u32 _node = 0x100U;
    { __u32 _nz = 0; __u32 *_nid = node_id_t2.lookup(&_nz);
      if (_nid && *_nid <= 0xffU) _node = *_nid; }

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
    for (int f = 0; f < MAX_FEAT; f++)
        if (f < desc->n_feat && desc->feats[f].code == FEAT_QUEUE_OCC) _need_qs = 1;
    if (_need_qs) {
      int qsz = 0; struct qs_vec *qsp = queue_state.lookup(&qsz);
      if (qsp) {
        #pragma unroll
        for (int i = 0; i < IPA_MAX_QUEUES; i++) qs[i] = (long long)(qsp->v[i]);
      }
    }

    long long h1[T2_MAX_H1];

    #pragma unroll
    for (int j = 0; j < T2_MAX_H1; j++)
        h1[j] = AW_W(AW, woff + fc1_b_off + j) * bias_mul_1;

    #pragma unroll
    for (int f = 0; f < MAX_FEAT; f++) {
        if (f >= desc->n_feat) continue;
        __u8  code = desc->feats[f].code;
        __u32 sz   = desc->feats[f].size;
        __u32 coff = desc->feats[f].col_off;
        if (code == FEAT_TTL) {
            __u64 _sc = desc->feats[f].scale ? desc->feats[f].scale
                                              : T2_TTL_SCALE;
            #pragma unroll
            for (int j = 0; j < T2_MAX_H1; j++)
                h1[j] += ipa_div_trunc((long long)_ttl
                          * AW_W(AW, woff + fc1_w_off + j * n_in + coff), _sc);
        } else if (code == FEAT_LINK_STATE) {
            #pragma unroll
            for (int i = 0; i < IPA_MAX_IFACES; i++) {
                if ((__u32)i >= sz) continue;
                long long x = ls[i];
                if (!x) continue;
                #pragma unroll
                for (int j = 0; j < T2_MAX_H1; j++)
                    h1[j] += x * AW_W(AW, woff + fc1_w_off + j * n_in + coff + i);
            }
        } else if (code == FEAT_QUEUE_OCC) {
            #pragma unroll
            for (int i = 0; i < IPA_MAX_QUEUES; i++) {
                if ((__u32)i >= sz) continue;
                long long x = qs[i];
                if (!x) continue;
                #pragma unroll
                for (int j = 0; j < T2_MAX_H1; j++)
                    h1[j] += x * AW_W(AW, woff + fc1_w_off + j * n_in + coff + i);
            }
        } else if (code == FEAT_INGRESS_IF) {
            if (_raw_iface >= 1 && _raw_iface <= sz) {
                __u32 c = coff + (_raw_iface - 1);
                #pragma unroll
                for (int j = 0; j < T2_MAX_H1; j++)
                    h1[j] += AW_W(AW, woff + fc1_w_off + j * n_in + c);
            }
        } else if (code == FEAT_NODE_ID) {
            if (_node < sz) {
                __u32 c = coff + _node;
                #pragma unroll
                for (int j = 0; j < T2_MAX_H1; j++)
                    h1[j] += AW_W(AW, woff + fc1_w_off + j * n_in + c);
            }
        }
    }

    #pragma unroll
    for (int j = 0; j < T2_MAX_H1; j++)
        h1[j] = (j < n_h1) ? ipa_relu(h1[j]) : 0LL;

/*@FC2_BLOCK@*/
/*@EXTRA_LAYERS@*/
    long long best_val = -9223372036854775807LL - 1LL;
    int best_cls = 0;
    #pragma unroll
    for (int k = 0; k < MAX_N_OUT; k++) {
        if ((__u32)k >= n_out) continue;
        long long acc = AW_W(AW, woff + out_b_off + k) * bias_mul_3;
        #pragma unroll
        for (int i = 0; i < T2_MAX_H2; i++) {
            acc += h2[i] * AW_W(AW, woff + out_w_off + k * n_h2 + i);
        }
        if (acc > best_val) { best_val = acc; best_cls = k; }
    }

    if (best_cls < 0 || (__u32)best_cls >= n_out) {
        int mi = 1; __u64 *mv = pkt_stats_t2.lookup(&mi);
        if (mv) *mv += 1;
        return XDP_PASS;                       /* argmax outside [0, n_out) */
    }
    __u32 _ci = (__u32)best_cls;
    __u32 _sk = sem_key0 + _ci;
    struct class_act *ca = class_action_t2.lookup(&_sk);
    if (!ca || ca->action == ACT_INVALID) {
        int mi = 1; __u64 *mv = pkt_stats_t2.lookup(&mi);
        if (mv) *mv += 1;
        return XDP_PASS;                       /* no semantics registered */
    }
    if (ca->action == ACT_DROP) {
        int di = 2; __u64 *dv = pkt_stats_t2.lookup(&di);
        if (dv) *dv += 1;
        __u64 *dcv = cls_stats_t2.lookup(&_ci);
        if (dcv) *dcv += 1;
        return XDP_DROP;
    }
    if (ca->action != ACT_FORWARD) {           /* ACT_UNUSED */
        __u64 *ucv = cls_stats_t2.lookup(&_ci);
        if (ucv) *ucv += 1;
        int mi = 1; __u64 *mv = pkt_stats_t2.lookup(&mi);
        if (mv) *mv += 1;
        return XDP_PASS;
    }

    __u32 port = (__u32)ca->port;
    struct fwd_action *action = mac_table_t2.lookup(&port);
    if (action != NULL && action->ifindex != 0) {
        if (ip->ttl <= 1) {
            int ti = 1; __u64 *tv = pkt_stats_t2.lookup(&ti);
            if (tv) *tv += 1;
            return XDP_PASS;
        }
        ipa_ttl_dec(ip);
        int si = 0; __u64 *v = pkt_stats_t2.lookup(&si);
        if (v) *v += 1;
        __u64 *cv = cls_stats_t2.lookup(&_ci);   /* keyed by CLASS */
        if (cv) *cv += 1;
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    int si = 1; __u64 *v = pkt_stats_t2.lookup(&si);
    if (v) *v += 1;
    return XDP_PASS;
}
"""


# --- Compiled depth: how many hidden layers this leaf can run ---
T2_MIN_HIDDEN = 1
_FC2_BLOCK = """    long long h2[T2_MAX_H2];
    #pragma unroll
    for (int j = 0; j < T2_MAX_H2; j++) {
        if (j >= n_h2) { h2[j] = 0LL; continue; }

        long long acc = AW_W(AW, woff + fc2_b_off + j) * bias_mul_2;
        #pragma unroll
        for (int i = 0; i < T2_MAX_H1; i++) {
            acc += h1[i] * AW_W(AW, woff + fc2_w_off + j * n_h1 + i);
        }
        h2[j] = ipa_relu(acc);
    }

"""


def build_arch_leaf(n_hidden: int = 2) -> str:
    """The arch_generic_2layer leaf source, compiled for `n_hidden` hidden
    layers."""
    if n_hidden < T2_MIN_HIDDEN:
        raise ValueError(
            f"build_arch_leaf: n_hidden={n_hidden}, but a leaf needs at least "
            f"{T2_MIN_HIDDEN} hidden layer.")
    n_extra = max(0, n_hidden - 2)

    span = ("0" if n_extra == 0
            else f"{n_extra}U * (n_h2 * n_h2 + n_h2)")
    bias_out = " * ".join(["(long long)scale"] * n_hidden)

    blocks = []
    for e in range(n_extra):
        w_off = f"fc2_b_off + n_h2 + {e}U * (n_h2 * n_h2 + n_h2)"
        bias_mul = " * ".join(["(long long)scale"] * (2 + e))
        blocks.append(f"""
    /* extra hidden layer {e + 1} of {n_extra}: n_h2 -> n_h2, dense.
     * Computed into a scratch row and copied back into h2, so the output
     * layer below needs no knowledge of how deep this leaf was built. */
    {{
        __u32 xw_off = {w_off};
        __u32 xb_off = xw_off + n_h2 * n_h2;
        long long hx[T2_MAX_H2];
        #pragma unroll
        for (int j = 0; j < T2_MAX_H2; j++) {{
            if (j >= n_h2) {{ hx[j] = 0LL; continue; }}
            long long acc = AW_W(AW, woff + xb_off + j) * ({bias_mul});
            #pragma unroll
            for (int i = 0; i < T2_MAX_H2; i++)
                acc += h2[i] * AW_W(AW, woff + xw_off + j * n_h2 + i);
            hx[j] = ipa_relu(acc);
        }}
        #pragma unroll
        for (int j = 0; j < T2_MAX_H2; j++) h2[j] = hx[j];
    }}""")

    if n_hidden == 1:
        fc2_block = """    /* n_hidden == 1: no fc2. h1 is carried into h2 unchanged so the output
     * layer below -- which reads h2 with stride n_h2, and n_h2 == n_h1 for a
     * 1-hidden-layer model -- needs no special case. */
    long long h2[T2_MAX_H2];
    #pragma unroll
    for (int j = 0; j < T2_MAX_H2; j++) h2[j] = (j < n_h1) ? h1[j] : 0LL;
"""
        out_w = "fc1_b_off + n_h1"
    else:
        fc2_block = _FC2_BLOCK
        out_w = "fc2_b_off + n_h2 + " + span

    src = _ARCH_LEAF_TEMPLATE
    src = src.replace("/*@FC2_BLOCK@*/", fc2_block)
    src = src.replace("/*@OUT_W_OFF@*/fc2_b_off + n_h2 + 0", out_w)
    src = src.replace("/*@BIAS_OUT@*/(long long)scale * (long long)scale",
                      bias_out)
    src = src.replace("/*@EXTRA_LAYERS@*/", "".join(blocks))
    return src


EBPF_ARCH_GENERIC_2LAYER = build_arch_leaf(2)


def load_arch_weights(bpf_obj, weights_int8: list,
                      model_id: int = 0, scale: int = 128,
                      weight_offset: int = 0,
                      n_h1: int = 4, n_h2: int = 4,
                      features: list = None, n_in: int = None,
                      semantics=None, n_hidden: int = 2) -> None:
    """Populate arch_weights and arch_registry for Pipeline 2."""
    from ctypes import c_uint8, c_uint32, c_uint16, Structure

    if n_h1 <= 0 or n_h1 > T2_MAX_H1 or n_h2 <= 0 or n_h2 > T2_MAX_H2:
        raise ValueError(
            f"n_h1={n_h1}/n_h2={n_h2} outside the compiled ceiling "
            f"T2_MAX_H1={T2_MAX_H1}/T2_MAX_H2={T2_MAX_H2} -- raise the "
            f"ceiling in ebpf_template_arch.py and reload to support it")

    if features is None:
        from model_meta import derive_shape, DEFAULT_META, load_topology_config
        _sh = derive_shape(dict(DEFAULT_META), topology_config=load_topology_config())
        features = _sh["features"]
        n_in = _sh["n_in"]
    elif n_in is None:
        n_in = sum(f["size"] for f in features)

    if semantics is None:
        from model_meta import descriptor_semantics_or_reference
        semantics = descriptor_semantics_or_reference(reference_widths()[1],
                                                     "Pipeline2")
    semantics.validate()

    if n_hidden == 1 and n_h2 != n_h1:
        raise ValueError(
            f"n_hidden=1 leaves P2 with one hidden layer, and the datapath "
            f"carries h1 into h2 unchanged -- so n_h2 must equal n_h1 "
            f"({n_h1}), not {n_h2}. See build_arch_leaf.")
    n_weights = arch_weight_count(n_h1, n_h2, n_in, semantics.n_out,
                                  n_hidden=n_hidden)
    arch_id   = 0
    map_fd    = bpf_obj["arch_weights"].map_fd

    if weight_offset + n_weights > MAX_WEIGHT_ENTRIES:
        raise ValueError(
            f"weight_offset={weight_offset} + n_weights={n_weights} "
            f"exceeds MAX_WEIGHT_ENTRIES={MAX_WEIGHT_ENTRIES} -- too many "
            f"concurrent model_id's ({MAX_WEIGHT_ENTRIES // n_weights} fit at "
            f"{n_weights} weights each). Raise MAX_WEIGHT_ENTRIES here AND the "
            f"matching #define in the eBPF source (keep it a power of two).")

    if len(weights_int8) < n_weights:
        raise ValueError(
            f"n_h1={n_h1}/n_h2={n_h2} needs {n_weights} weights, "
            f"got only {len(weights_int8)}")

    value_size = _get_map_value_size(map_fd)

    blk = _bpf_map_read_blk(map_fd, value_size)
    for idx, w in enumerate(weights_int8[:n_weights]):
        blk[weight_offset + idx] = int(w) & 0xFF
    _bpf_map_write_blk(map_fd, blk)

    v0       = ct.c_int8(_bpf_map_read_blk(map_fd, value_size)[weight_offset]).value
    expected = ct.c_int8(int(weights_int8[0])).value
    ok       = "OK" if v0 == expected else f"MISMATCH got={v0} expected={expected}"
    if ok != "OK":
        print(f"[P2] weights written wrongly: {ok}")

    class ArchEntry(Structure):
        _pack_ = 1
        _fields_ = [("arch_id",       c_uint8),
                    ("weight_offset",  c_uint32),
                    ("scale_factor",   c_uint16),
                    ("n_out",          c_uint8),
                    ("n_h1",           c_uint8),
                    ("n_h2",           c_uint8),
                    ("sem_bank",       c_uint8)]

    load_model_desc(bpf_obj, features, n_in, model_id=model_id)

    bank = load_class_action(bpf_obj, "class_action_t2", "arch_registry",
                             model_id, semantics)
    entry = ArchEntry(arch_id=arch_id, weight_offset=weight_offset,
                      scale_factor=scale, n_out=semantics.n_out,
                      n_h1=n_h1, n_h2=n_h2, sem_bank=bank)
    bpf_obj["arch_registry"][c_uint8(model_id)] = entry
    print(f"[P2] model {model_id} registered: shape "
          f"{n_in}-{n_h1}-{n_h2}-{semantics.n_out}, {n_weights} weights from "
          f"{weight_offset}, scale {scale}")


T2_MAX_FEAT = 4


def load_model_desc(bpf_obj, features: list, n_in: int, model_id: int = 0) -> None:
    """Populate model_desc[model_id] so arch_generic_2layer builds the input
    vector GENERICALLY from a per-model descriptor (instead of the old
    hardcoded 65-feature layout)."""
    from ctypes import c_uint8, Structure
    from model_meta import resolve_descriptor

    ents = resolve_descriptor(features)
    if len(ents) > T2_MAX_FEAT:
        raise ValueError(
            f"descriptor has {len(ents)} features, exceeds MAX_FEAT={T2_MAX_FEAT} "
            f"(raise MAX_FEAT in ebpf_template_arch.py and reload to support it)")
    if n_in > 128:
        raise ValueError(f"n_in={n_in} exceeds MAX_N_IN=128")

    class FeatEnt(Structure):
        _pack_ = 1
        _fields_ = [("code", c_uint8), ("size", c_uint8),
                    ("col_off", c_uint8), ("scale", c_uint8)]

    class ModelDesc(Structure):
        _pack_ = 1
        _fields_ = [("n_feat", c_uint8), ("n_in", c_uint8),
                    ("_p0", c_uint8), ("_p1", c_uint8),
                    ("feats", FeatEnt * T2_MAX_FEAT)]

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


CLASS_ACT_BANKS = 2
CLASS_ACT_MODELS = 256


def class_act_key(model_id: int, bank: int, cls: int) -> int:
    """CLASS_ACT_KEY(model_id, bank, class) of the eBPF sources."""
    from class_semantics import MAX_N_OUT
    return (((int(model_id) & 0xFF) * CLASS_ACT_BANKS + (int(bank) & 1))
            * MAX_N_OUT + int(cls))


def load_class_action(bpf_obj, map_name: str, registry_name: str,
                      model_id: int, semantics) -> int:
    """Write model_id's class semantics into its inactive class_action bank."""
    from ctypes import c_uint8, c_uint32, Structure
    from class_semantics import MAX_N_OUT

    class ClassAct(Structure):
        _pack_ = 1
        _fields_ = [("action", c_uint8), ("port", c_uint8),
                    ("_p0", c_uint8), ("_p1", c_uint8)]

    if not 0 <= int(model_id) < CLASS_ACT_MODELS:
        raise ValueError(f"model_id={model_id} outside [0, {CLASS_ACT_MODELS})")
    try:
        live = int(bpf_obj[registry_name][c_uint8(model_id)].sem_bank)
        bank = (live & 1) ^ 1
    except KeyError:
        bank = 0
    tbl = bpf_obj[map_name]
    table = semantics.action_table()
    for cid in range(MAX_N_OUT):
        act, port = table[cid]
        tbl[c_uint32(class_act_key(model_id, bank, cid))] = \
            ClassAct(action=act, port=port, _p0=0, _p1=0)
    print(f"     classes of model {model_id}: " + ", ".join(
        f"{cid} {semantics.classes[cid].describe()}"
        for cid in range(semantics.n_out)))
    return bank
