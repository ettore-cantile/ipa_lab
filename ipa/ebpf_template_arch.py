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
  fc1  : n_in inputs -> n_h1 hidden         (n_h1 <= T2_MAX_H1)
  fc2  : n_h1 hidden       -> n_h2 hidden   (n_h2 <= T2_MAX_H2)
  out  : n_h2 hidden       -> n_out outputs   (n_out <= MAX_N_OUT)
n_in comes from the feature descriptor, not from this file; n_out is NOT
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
  lookup class_action_t2[class] -> {action, logical port}, then
  mac_table_t2[port] -> {ifindex, src_mac, dst_mac}, rewrites the L2
  header and bpf_redirect()s. mac_table is just the physical next-hop
  dictionary -- no routing decision, no output validation. cls 6 = DROP.
  (Earlier design keyed a fwd_table by the raw argmax value and validated it
  per-TTL via valid_keys; that was over-engineered for a routing action and
  has been removed.)

Implementation notes:
  - Inference uses a sparse dot-product over the one-hot feature vector via
    index arithmetic into the weight block, avoiding a large on-stack
    activation array.
  - arch_weights is ONE struct-valued entry holding the whole weight block, so
    the datapath pays a SINGLE bpf_map_lookup_elem for all the weights instead
    of one helper call per weight byte (~139 of P2's former 147 lookups per
    packet). Same "N lookups -> 1" transformation as the dense feature vectors.
  - the ingress one-hot is indexed by LOGICAL PORT, resolved from
    ctx->ingress_ifindex through the `ingress_port` map. An ifindex with no
    entry yields 0, i.e. "not one of this node's ports", and contributes
    nothing -- which is also what happens under BPF_PROG_TEST_RUN, where no
    entry is installed. All three pipelines resolve it the same way: the
    earlier asymmetry, where P1 used a compiled-in table and P2/P3 used the raw
    ifindex and so selected DIFFERENT columns for the same packet, is gone.
  - The weight block is written through the raw bpf(2) syscall (libbcc does not
    export a stable bpf_update_elem); the real map value size is detected via
    BPF_OBJ_GET_INFO_BY_FD before writing.
"""

import ctypes as ct
import os

# Protocol-fixed constants: input/output size are dictated by the IPA
# feature encoding (65 in) and the number of egress classes + drop (7 out),
# not by the model. Hidden widths are the actual per-model hyperparameters.
# The reference model's widths, RESOLVED FROM THE DESCRIPTOR, not written here.
#
# These were `T2_N_IN = 65` and `T2_N_OUT = 7`, described as "fixed by the IPA
# header/feature encoding". 65 is not a protocol constant: it is
# 6 link_state + 6 ingress_iface + 1 ttl + 52 node, i.e. the Germany50 lab's
# dimensions summed. Neither value appears in the compiled C at all -- the
# program reads the feature layout from model_desc and n_out from
# arch_registry -- so they only ever served as Python defaults, and as defaults
# they silently assumed that topology.
#
# Resolved lazily: importing this module must not require a scenario to be
# configured (the codegen is importable on any host).
def reference_widths():
    """(n_in, n_out) of the model this repo is configured for."""
    import model_meta as _mm
    sh = _mm.derive_shape(_mm.load_model_meta(
                              os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "weights.json")),
                          topology_config=_mm.load_topology_config())
    return sh["n_in"], sh["n_out"]
# Output width of the CHECKED-IN model, used only as a default for
# arch_weight_count(). NOT a constraint: the datapath reads n_out from
# arch_registry, and the compile-time ceiling is MAX_N_OUT (class_semantics.py).
T2_N_OUT  = 7
# Compile-time ceilings for the hidden widths: the eBPF program unrolls its
# neuron loops up to these bounds (verifier requires a compile-time trip
# count) and skips the unused tail at runtime via `if (j >= n_h1)` guards.
# Any model with n_h1 <= T2_MAX_H1 and n_h2 <= T2_MAX_H2 runs on this same
# compiled program -- raise these and reload once if a wider model shows up.
T2_MAX_H1 = 8
T2_MAX_H2 = 8

# Size of the single shared arch_weights block, in int8 slots. MUST stay equal
# to the MAX_WEIGHT_ENTRIES #define in the eBPF source below (and a power of
# two: the datapath masks its weight index with MAX_WEIGHT_ENTRIES-1 to keep a
# runtime-variable index verifier-safe). Every concurrently registered model_id
# carves a non-overlapping slice out of this one block, so this constant is
# also the hard cap on concurrent models: 1024 / 319 = 3 for the 65-4-4-7
# shape. Exported so callers check the cap against the real value instead of
# re-hardcoding 1024.
MAX_WEIGHT_ENTRIES = 1024


def arch_weight_count(n_h1: int, n_h2: int, n_in: int = None,
                      n_out: int = None, n_hidden: int = 2) -> int:
    """Flat int8 weight count for an n_in -> n_h1 -> n_h2 -> T2_N_OUT MLP
    (fc1 weights+bias, fc2 weights+bias, out weights+bias), matching the
    flat layout load_arch_weights() writes and the eBPF program reads.

    n_in/n_out default to the CONFIGURED model's widths, resolved from the
    descriptor. They used to default to the literals 65 and 7, so a caller that
    omitted them got the Germany50 model's block size for whatever model it was
    actually registering."""
    if n_in is None or n_out is None:
        _in, _out = reference_widths()
        n_in = _in if n_in is None else n_in
        n_out = _out if n_out is None else n_out
    if n_hidden == 1:
        # fc1 then straight to the output: no fc2 block at all. The datapath
        # copies h1 into h2 and registers n_h2 == n_h1, so the output term is
        # the same expression.
        return (n_in * n_h1 + n_h1) + (n_h1 * n_out + n_out)
    # Layers beyond the second are n_h2 -> n_h2 (see build_arch_leaf), so each
    # contributes one square weight matrix plus a bias row. n_hidden=2 leaves
    # the term at zero and the expression is the original one.
    extra = (n_hidden - 2) * (n_h2 * n_h2 + n_h2)
    return ((n_in * n_h1 + n_h1) + (n_h1 * n_h2 + n_h2) + extra
            + (n_h2 * n_out + n_out))


class _LazyWeightCount:
    """`N_WEIGHTS_T2` as a lazily-evaluated int.

    It was `arch_weight_count(4, 4)` evaluated at import time against the
    literal 65/7. Resolving it eagerly now would make importing this module
    require a configured scenario, which would break `--only kernel` on a host
    with no descriptor. It resolves on first use instead.
    """

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

# ---------------------------------------------------------------------------
# Raw bpf(2) syscall helpers
# ---------------------------------------------------------------------------

# Binding libc at import time made this module Linux-only to IMPORT, not just
# to run -- and the biggest thing it exports is C source text, which is
# generated offline precisely so the node needs no toolchain, and read by
# tooling that may run anywhere. Bound lazily: the syscall helpers raise if
# libc is actually needed and unavailable, which is the point where a caller
# genuinely needs a kernel.
_libc = None


def _get_libc():
    global _libc
    if _libc is None:
        _libc = ct.CDLL("libc.so.6", use_errno=True)
    return _libc
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
    ret = _get_libc().syscall(_BPF_SYSCALL_NR, _BPF_OBJ_GET_INFO_BY_FD,
                        ct.byref(attr), ct.sizeof(attr))
    if ret != 0:
        print(f"[Pipeline2] BPF_OBJ_GET_INFO_BY_FD errno={ct.get_errno()}, fallback value_size=8")
        return 8
    return max(1, int(info.value_size))


def _bpf_map_read_blk(map_fd: int, value_size: int, index: int = 0) -> bytearray:
    """Read the whole struct-valued arch_weights entry (key `index`) as bytes.
    Returns a zeroed buffer if the entry cannot be read (fresh map)."""
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

/* Same fallback ebpf_program.py carries: some minimal-header setups do
 * not get IPPROTO_UDP from the includes above. RFC 791 value. */
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
    /* n_out is the MODEL's output width, read at runtime. It used to be the
     * compile-time T2_N_OUT=7, which made both the weight layout and the DROP
     * condition specific to one model. MAX_N_OUT is the separate L1 ceiling. */
    __u8  n_out;
    __u8  n_h1;   /* fc1 output width  (<= T2_MAX_H1), read at runtime */
    __u8  n_h2;   /* fc2 output width  (<= T2_MAX_H2), read at runtime */
} __attribute__((packed));

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

/* ---- class semantics: class -> action -> logical port --------------------
 * Filled by the control plane from the model descriptor. The datapath does NOT
 * infer an action from a class index: `best_cls >= 6` used to hardcode both the
 * DROP class AND the assumption that classes map onto interfaces one-to-one.
 * Neither held -- the trained DROP class of the checked-in model is 5, and
 * class 6 was never a training target.
 *
 * Sized to MAX_N_OUT (an L1 compile-time ceiling, NOT the model's n_out):
 * entries at or past the model's n_out stay ACT_INVALID, so a class the
 * datapath should never see yields an explicit "invalid" instead of a zeroed
 * entry that would look like a valid action. */
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

/* arch_weights: the WHOLE weight block in ONE struct-valued entry (key 0),
 * so the datapath reads every weight it needs after a SINGLE
 * bpf_map_lookup_elem instead of one helper call per weight byte. This is the
 * same "N lookups -> 1" transformation already applied to the dense feature
 * vectors (link_state / queue_state, see common.py): all the values live in
 * one map entry anyway, so making the entry a struct turns per-weight helper
 * calls into plain pointer reads, which cost the verifier nothing.
 *
 * Measured before this change: ~139 of P2's 147 map lookups per packet were
 * single-byte weight reads (one lookup + one NULL check per weight).
 *
 * __u8 storage (not 'char'): the value is never a BCC leaf type here -- the
 * control plane writes the block through the raw bpf(2) syscall below -- and
 * the eBPF side re-casts each byte to __s8 via AW_W(), exactly like Pipeline
 * 3's WEIGHT() macro. */
#define MAX_WEIGHT_ENTRIES 1024
struct aw_blk { __u8 w[MAX_WEIGHT_ENTRIES]; };
BPF_ARRAY(arch_weights, struct aw_blk, 1);

/* Read weight `i` out of an already-looked-up block. The AND is what makes the
 * variable index verifier-safe: MAX_WEIGHT_ENTRIES is a power of two, so the
 * masked index is provably within the map value's size and needs no per-access
 * bound check. It never actually wraps -- arch_generic_2layer bound-checks the
 * model's whole block ONCE, up front (see the woff + out_b_off check). */
#define AW_W(blk, i) ((long long)(__s8)((blk)->w[(__u32)(i) & (MAX_WEIGHT_ENTRIES - 1)]))

/* link_state: 6 egress up/down slots (feature [0..5]), held in ONE struct-valued
 * entry (key 0) so the leaf reads the whole vector with a SINGLE lookup instead
 * of 6. Written by the userspace carrier monitor. 1=up, 0=down. */
/* COMPILED CEILINGS for the dense per-slot features, not deployment values.
 *
 * These were the literals 6 and 4 -- the Germany50 lab's interface count and
 * its queue count -- written into the struct sizes AND into every loop bound,
 * so the compiled datapath only fit that one network. The consumption loops
 * are already gated by the descriptor's per-feature `sz`, so widening the
 * compiled bound costs a few unrolled iterations and changes no result: slots
 * past the model's real size are skipped, never summed.
 *
 * A deployment whose n_interfaces / n_queues exceeds these must raise the
 * ceiling and recompile -- the control plane checks and says so, instead of
 * silently reading past the vector. See model_meta.MAX_N_IFACES/MAX_N_QUEUES. */
#define IPA_MAX_IFACES  8
#define IPA_MAX_QUEUES  8
struct ls_vec { __u32 v[IPA_MAX_IFACES]; };
BPF_ARRAY(link_state, struct ls_vec, 1);

/* queue_occupancy feature: n_queues occupancy slots in one struct-valued entry
 * (key 0), seeded by queue_state_monitor.py. Present so a descriptor can use the
 * queue_occupancy feature type; unused if the model's descriptor omits it. */
struct qs_vec { __u32 v[IPA_MAX_QUEUES]; };
BPF_ARRAY(queue_state, struct qs_vec, 1);

/* Per-model feature descriptor (model_desc registry): which feature types the
 * model uses, their size and starting column in the fc1 input row. Populated by
 * the control plane from model_meta.resolve_descriptor(); read at runtime by
 * arch_generic_2layer to build the IV generically -> different models use
 * different feature subsets/orders WITHOUT recompiling. */
#define MAX_FEAT 4
/* `scale` era `_pad`. E' la normalizzazione con cui il modello e' stato
 * addestrato (ttl/30, ttl/16, ...): una proprieta' del MODELLO, quindi va
 * nel descrittore a runtime e non in un #define. Con 0 si ricade sul
 * default compilato, cosi' i descrittori scritti prima restano validi. */
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
/* Kernel ingress ifindex -> LOGICAL PORT (1-based; absent means "not one of
 * this node's ports", which contributes nothing).
 *
 * The ingress_iface one-hot used to be indexed by ctx->ingress_ifindex
 * DIRECTLY, i.e. by a kernel ifindex. Kernel ifindexes are allocated by the
 * kernel and are arbitrary -- 2 and 3 on a container, 207 and 209 on a box
 * that has created a few veths -- so on real hardware the guard
 * (_raw_iface >= 1 && _raw_iface <= n_interfaces) is false and the trained
 * feature contributes NOTHING. Pipeline 1 had a table for this but baked it at
 * compile time as [2, 3, 4, ...], which is the same assumption spelled
 * differently.
 *
 * Which interface realises which logical port is a NODE fact, discovered at
 * runtime, exactly like mac_table. This is that map, on the ingress side.
 */
BPF_HASH(ingress_port_t2, __u32, __u32, 64);
/* This node's index in the node one-hot, a single entry written by the control
 * plane at deploy time.
 *
 * The one-hot used to be indexed by ipa->model_id -- the MODEL identifier from
 * the packet header. That is not a node identity: the same packet carries the
 * same model_id along its whole path, so with one registered model every node
 * fired slot 0 and the feature contributed the same constant everywhere. 52 of
 * the 65 inputs, carrying no information.
 *
 * Which node this is, is a fact of the node, resolved when the node exists --
 * exactly like mac_table and ingress_port.
 *
 * A HASH and not an ARRAY, deliberately: a BPF_ARRAY is pre-allocated and
 * zero-filled, so a lookup always succeeds and "nothing installed" reads back
 * as node 0 -- indistinguishable from a real node 0, which is the very defect
 * this map exists to remove. With a hash, absent means absent.
 */
BPF_HASH(node_id_t2, __u32, __u32, 1);

BPF_ARRAY(class_action_t2, struct class_act, MAX_N_OUT);
BPF_ARRAY(pkt_stats_t2, __u64, 3);   /* [0]=HIT [1]=MISS [2]=DROP */
BPF_ARRAY(cls_stats_t2, __u64, MAX_N_OUT);   /* per-class redirect counter */

/* CTR_INC(): real per-packet map-lookup counter, active only when
 * IPA_COUNT_LOOKUPS is #defined before this source (measurement builds --
 * see common.py instrument_map_lookups()). No-op otherwise. */
#ifdef IPA_COUNT_LOOKUPS
BPF_PERCPU_ARRAY(lookup_ctr, __u64, 1);
/* BCC's rewriter refuses table.lookup() calls that appear textually inside
 * a macro expansion -- must be a real function (static inline), not a
 * #define body. */
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
    /* Same FIX(#4) Pipeline 1 already applies (see ebpf_program.py): read the
     * protocol at its absolute RFC 791 offset (byte 9) instead of ip->protocol,
     * because struct iphdr's ihl:4/version:4 bitfield can be packed differently
     * by clang against minimal container headers, making every
     * UDP packet fail the check; and derive the UDP header from the real ihl*4
     * instead of sizeof(struct iphdr), which is wrong when IP options present. */
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
/* No T2_N_IN / T2_N_OUT here any more. They were 65 and 7 -- the Germany50
 * feature sum and the reference model's class count -- and neither was read by
 * a single line of this program: the input layout comes from model_desc and
 * n_out from arch_registry, both per-model at runtime. A #define nobody reads
 * is still a claim, and this one claimed the datapath only ever runs one
 * topology's model. The real bounds are the ceilings below. */
#define T2_MAX_H1    8
#define T2_MAX_H2    8
/* Must match model_meta.DEFAULT_TTL_SCALE (the checkpoint's initial_ttl). */
#define T2_TTL_SCALE 30
#define MAX_N_IN     128
#define MAX_FEAT     4
#define FEAT_LINK_STATE  0x01
#define FEAT_INGRESS_IF  0x02
#define FEAT_TTL         0x03
#define FEAT_NODE_ID     0x04
#define FEAT_QUEUE_OCC   0x05
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
    /* n_out is the MODEL's output width, read at runtime. It used to be the
     * compile-time T2_N_OUT=7, which made both the weight layout and the DROP
     * condition specific to one model. MAX_N_OUT is the separate L1 ceiling. */
    __u8  n_out;
    __u8  n_h1;
    __u8  n_h2;
} __attribute__((packed));

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

/* ---- class semantics: class -> action -> logical port --------------------
 * Filled by the control plane from the model descriptor. The datapath does NOT
 * infer an action from a class index: `best_cls >= 6` used to hardcode both the
 * DROP class AND the assumption that classes map onto interfaces one-to-one.
 * Neither held -- the trained DROP class of the checked-in model is 5, and
 * class 6 was never a training target.
 *
 * Sized to MAX_N_OUT (an L1 compile-time ceiling, NOT the model's n_out):
 * entries at or past the model's n_out stay ACT_INVALID, so a class the
 * datapath should never see yields an explicit "invalid" instead of a zeroed
 * entry that would look like a valid action. */
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
/* COMPILED CEILINGS for the dense per-slot features, not deployment values.
 *
 * These were the literals 6 and 4 -- the Germany50 lab's interface count and
 * its queue count -- written into the struct sizes AND into every loop bound,
 * so the compiled datapath only fit that one network. The consumption loops
 * are already gated by the descriptor's per-feature `sz`, so widening the
 * compiled bound costs a few unrolled iterations and changes no result: slots
 * past the model's real size are skipped, never summed.
 *
 * A deployment whose n_interfaces / n_queues exceeds these must raise the
 * ceiling and recompile -- the control plane checks and says so, instead of
 * silently reading past the vector. See model_meta.MAX_N_IFACES/MAX_N_QUEUES. */
#define IPA_MAX_IFACES  8
#define IPA_MAX_QUEUES  8
struct ls_vec { __u32 v[IPA_MAX_IFACES]; };
BPF_ARRAY(link_state, struct ls_vec, 1);
struct qs_vec { __u32 v[IPA_MAX_QUEUES]; };
BPF_ARRAY(queue_state, struct qs_vec, 1);
/* `scale` era `_pad`. E' la normalizzazione con cui il modello e' stato
 * addestrato (ttl/30, ttl/16, ...): una proprieta' del MODELLO, quindi va
 * nel descrittore a runtime e non in un #define. Con 0 si ricade sul
 * default compilato, cosi' i descrittori scritti prima restano validi. */
struct feat_ent { __u8 code; __u8 size; __u8 col_off; __u8 scale; };
struct model_desc { __u8 n_feat; __u8 n_in; __u8 _p0; __u8 _p1; struct feat_ent feats[MAX_FEAT]; };
BPF_HASH(model_desc, __u8, struct model_desc, 256);
BPF_HASH(arch_registry, __u8, struct arch_entry, 256);
/* mac_table_t2 is keyed by LOGICAL PORT, not by class. */
BPF_ARRAY(mac_table_t2, struct fwd_action, MAX_N_OUT);
/* Kernel ingress ifindex -> LOGICAL PORT (1-based; absent means "not one of
 * this node's ports", which contributes nothing).
 *
 * The ingress_iface one-hot used to be indexed by ctx->ingress_ifindex
 * DIRECTLY, i.e. by a kernel ifindex. Kernel ifindexes are allocated by the
 * kernel and are arbitrary -- 2 and 3 on a container, 207 and 209 on a box
 * that has created a few veths -- so on real hardware the guard
 * (_raw_iface >= 1 && _raw_iface <= n_interfaces) is false and the trained
 * feature contributes NOTHING. Pipeline 1 had a table for this but baked it at
 * compile time as [2, 3, 4, ...], which is the same assumption spelled
 * differently.
 *
 * Which interface realises which logical port is a NODE fact, discovered at
 * runtime, exactly like mac_table. This is that map, on the ingress side.
 */
BPF_HASH(ingress_port_t2, __u32, __u32, 64);
/* This node's index in the node one-hot, a single entry written by the control
 * plane at deploy time.
 *
 * The one-hot used to be indexed by ipa->model_id -- the MODEL identifier from
 * the packet header. That is not a node identity: the same packet carries the
 * same model_id along its whole path, so with one registered model every node
 * fired slot 0 and the feature contributed the same constant everywhere. 52 of
 * the 65 inputs, carrying no information.
 *
 * Which node this is, is a fact of the node, resolved when the node exists --
 * exactly like mac_table and ingress_port.
 *
 * A HASH and not an ARRAY, deliberately: a BPF_ARRAY is pre-allocated and
 * zero-filled, so a lookup always succeeds and "nothing installed" reads back
 * as node 0 -- indistinguishable from a real node 0, which is the very defect
 * this map exists to remove. With a hash, absent means absent.
 */
BPF_HASH(node_id_t2, __u32, __u32, 1);

BPF_ARRAY(class_action_t2, struct class_act, MAX_N_OUT);
BPF_ARRAY(pkt_stats_t2, __u64, 3);
BPF_ARRAY(cls_stats_t2, __u64, MAX_N_OUT);
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

int arch_generic_2layer(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)  return XDP_PASS;
    /* FIX(#4), same as the dispatcher above: byte-9 protocol read + ihl*4. */
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

    __u32 woff  = entry->weight_offset;
    __u16 scale = entry->scale_factor;
    if (scale == 0) return XDP_PASS;

    /* Hidden widths for THIS model, read at runtime. The neuron loops below
     * are unrolled to the compiled ceilings T2_MAX_H1/T2_MAX_H2 (verifier
     * needs a compile-time trip count) but skip/zero any neuron past the
     * model's actual width -- same program serves any n_h1<=T2_MAX_H1,
     * n_h2<=T2_MAX_H2 without recompiling. */
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
    /* Layer L's products carry scale**L while a bias stored the same way
     * carries scale**1, so layer L's bias needs scale**L. The output layer is
     * layer n_hidden, hence scale to the power of the COMPILED depth. */
    long long bias_mul_3 = /*@BIAS_OUT@*/(long long)scale * (long long)scale;

    __u32 n_h1 = entry->n_h1;
    __u32 n_h2 = entry->n_h2;
    if (n_h1 == 0 || n_h1 > T2_MAX_H1 || n_h2 == 0 || n_h2 > T2_MAX_H2) return XDP_PASS;
    __u32 n_out = entry->n_out;
    if (n_out == 0 || n_out > MAX_N_OUT) return XDP_PASS;

    /* Per-model feature descriptor: which feature types the model uses, their
     * size and starting column in the fc1 input row. n_in (= sum of feature
     * sizes) is read here and drives the flat weight layout below -> the IV is
     * built GENERICALLY from the descriptor instead of the old hardcoded
     * 65-feature layout. Populated by the CP via model_meta.resolve_descriptor. */
    struct model_desc *desc = model_desc.lookup(&model_id);
    if (!desc) return XDP_PASS;
    __u32 n_in = desc->n_in;
    if (n_in == 0 || n_in > MAX_N_IN) return XDP_PASS;

    /* Flat weight layout offsets (relative to woff), sized for THIS model's
     * n_in + hidden widths -- mirrors arch_weight_count() on the Python side. */
    __u32 fc1_w_off = 0;
    __u32 fc1_b_off = n_in * n_h1;
    __u32 fc2_w_off = fc1_b_off + n_h1;
    __u32 fc2_b_off = fc2_w_off + n_h1 * n_h2;
    /* out_w_off skips the EXTRA hidden layers (if this leaf was built with
     * any): each is n_h2 -> n_h2, so weights + bias = n_h2*n_h2 + n_h2. With
     * no extra layers the term is zero and this is the original expression. */
    __u32 out_w_off = /*@OUT_W_OFF@*/fc2_b_off + n_h2 + 0;
    __u32 out_b_off = out_w_off + n_h2 * n_out;

    /* ONE bound check for this model's whole weight block, replacing the ~139
     * per-weight `if (idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS` checks that
     * used to guard every single weight read. out_b_off + n_out is the
     * highest index the loops below can reach (the fc2/out inner loops run to
     * the compiled ceiling with a smaller runtime stride, but those overshoots
     * stay inside the block and are multiplied by a zeroed activation). */
    if (woff + out_b_off + n_out > MAX_WEIGHT_ENTRIES) return XDP_PASS;

    /* Whole weight block in ONE lookup -- every AW_W() below is a plain
     * pointer read, not a helper call. */
    int _awz = 0;
    struct aw_blk *AW = arch_weights.lookup(&_awz);
    if (!AW) return XDP_PASS;

    __u32 _ttl       = ((__u32)ip->ttl) & 0xff;
    /* Kernel ifindex -> logical port, 1-based. Not the raw ifindex: see
     * the ingress_port_t2 declaration. 0 when this node has no logical port
     * on the interface the packet arrived on, which the feature guard below
     * reads as "no ingress-port bit set". */
    __u32 _raw_iface = 0;
    { __u32 _kif = ctx->ingress_ifindex;
      __u32 *_lp = ingress_port_t2.lookup(&_kif);
      if (_lp) _raw_iface = *_lp; }
    /* The NODE's own index, not the packet's model_id -- see node_id_t2.
     * Bounded to a byte on purpose: this used to come from a __u8, and the
     * verifier needs that bound to reason about the weight column `coff +
     * _node` inside the unrolled feature loop. 256 is the "unknown" sentinel
     * -- outside any
     * valid index, so no bit is set. An index above 255 is refused by the
     * control plane rather than truncated here. */
    __u32 _node = 0x100U;
    { __u32 _nz = 0; __u32 *_nid = node_id_t2.lookup(&_nz);
      if (_nid && *_nid <= 0xffU) _node = *_nid; }

    /* dense feature vectors, each read once with a SINGLE lookup, reused across
     * neurons. Sized to the COMPILED CEILINGS, gated per-feature by the
     * descriptor's size below; the
     * descriptor's per-feature size gates how many slots actually contribute. */
    long long ls[IPA_MAX_IFACES];
    { int lsz = 0; struct ls_vec *lsp = link_state.lookup(&lsz);
      #pragma unroll
      for (int i = 0; i < IPA_MAX_IFACES; i++)
          ls[i] = lsp ? (long long)(lsp->v[i]) : 0LL; }
    /* queue_state is only read if the model's descriptor actually declares the
     * queue_occupancy feature. The default descriptor does not, so this saves
     * an unconditional lookup on the common path. */
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

    /* Feature loop OUTSIDE, neuron loop INSIDE -- the inverse of the obvious
     * nest, and the same rewrite layer_first in ebpf_modular.py carries. See
     * the long comment there for the reasoning; in short: a descriptor entry's
     * code/size/col_off do not depend on the neuron, so with the neuron loop
     * outside the five-way dispatch on `code` ran T2_MAX_H1 * MAX_FEAT = 32
     * times per packet and each dense-vector gate 8 * 8 = 64 times, all to
     * re-derive the same answer. Inverted: 4 dispatches, 8 gates, and inner
     * neuron loops that are straight-line multiply-accumulate.
     *
     * Same terms, same values, different summation order -- and int64 addition
     * in two's complement is associative and commutative, so each accumulator
     * ends bit-identical. h1[] becomes the accumulator; it was already live
     * across the loop, so no state is added. */
    #pragma unroll
    for (int j = 0; j < T2_MAX_H1; j++)
        h1[j] = AW_W(AW, woff + fc1_b_off + j) * bias_mul_1;

    /* Deliberately NOT gated on `j < n_h1` here: neurons past the model's
     * width are computed and discarded, and zeroed below before anything
     * reads them. AW_W masks every index into the compiled array, so a weight
     * row past this model's block is an in-bounds read of another model's
     * bytes -- meaningless, never observed. Gating instead would put 8
     * branches in the TTL arm and 64 in the link_state arm, which is the cost
     * this rewrite removes. */
    #pragma unroll
    for (int f = 0; f < MAX_FEAT; f++) {
        if (f >= desc->n_feat) continue;
        __u8  code = desc->feats[f].code;
        __u32 sz   = desc->feats[f].size;
        __u32 coff = desc->feats[f].col_off;
        if (code == FEAT_TTL) {
            /* Divided by the training scale: the model was trained on
             * ttl/initial_ttl in (0,1], not on the raw hop count. See
             * model_meta.DEFAULT_TTL_SCALE. The PRODUCT is divided --
             * dividing _ttl itself would collapse it to 0 or 1. */
            /* La scala viene dal descrittore. Lo zero vuol dire "non
             * dichiarata" e ricade sul default compilato; il ternario e' anche
             * cio' che rende ovvia al verificatore l'impossibilita' di una
             * divisione per zero. */
            long long _sc = desc->feats[f].scale ? desc->feats[f].scale
                                                 : T2_TTL_SCALE;
            #pragma unroll
            for (int j = 0; j < T2_MAX_H1; j++)
                h1[j] += ((long long)_ttl
                          * AW_W(AW, woff + fc1_w_off + j * n_in + coff))
                         / _sc;
        } else if (code == FEAT_LINK_STATE) {
            #pragma unroll
            for (int i = 0; i < IPA_MAX_IFACES; i++) {
                if ((__u32)i >= sz) continue;
                long long x = ls[i];
                /* The zero skip is kept -- it was `&& ls[i]` before -- but it
                 * now runs once per interface instead of once per
                 * (interface, neuron) pair. Adding zero is a no-op either
                 * way, so skipping or not cannot change the result. */
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
            /* One-hot: one column, the same for every neuron, so the bound
             * check happens once rather than once per neuron. */
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

    /* ReLU over the real neurons, zero over the rest. The zeroing is not
     * cosmetic: the fc2 loop below unrolls to T2_MAX_H1 with NO n_h1 gate and
     * relies on h1[i] == 0 past the model's width. */
    #pragma unroll
    for (int j = 0; j < T2_MAX_H1; j++)
        h1[j] = (j < n_h1) ? RELU(h1[j]) : 0LL;

/*@FC2_BLOCK@*/
/*@EXTRA_LAYERS@*/
    /* Same trick: h2[i]==0 for i>=n_h2, so the output loop is always
     * unrolled to T2_MAX_H2 regardless of this model's actual n_h2. */
    /* Sentinel must be LOWER than any reachable logit, otherwise a model whose
     * output logits are ALL below it never updates best_cls and silently
     * argmaxes to class 0. That is reachable here: h1/h2 are unbounded int64
     * ReLU accumulations (ttl up to 255 x int8 weights, then two more int8
     * layers), so |logit| can reach ~1e9 -- far past the old -9999999 (-1e7)
     * sentinel. It also has to match the Python reference argmax in
     * verify_prog_run.ref_infer*, which uses a true minimum. LLONG_MIN written
     * as (-MAX - 1) so the literal itself stays in range. */
    long long best_val = -9223372036854775807LL - 1LL;
    int best_cls = 0;
    /* Unrolled to the L1 ceiling because the verifier needs a constant trip
     * count; classes past the model's n_out are skipped. Same shape P3 already
     * used for its layer widths. */
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

    /* Class -> action -> logical port, read from the descriptor-filled map.
     * No index arithmetic decides what a class means. */
    if (best_cls < 0 || (__u32)best_cls >= n_out) {
        int mi = 1; __u64 *mv = pkt_stats_t2.lookup(&mi);
        if (mv) __sync_fetch_and_add(mv, 1);
        return XDP_PASS;                       /* argmax outside [0, n_out) */
    }
    __u32 _ci = (__u32)best_cls;
    struct class_act *ca = class_action_t2.lookup(&_ci);
    if (!ca || ca->action == ACT_INVALID) {
        int mi = 1; __u64 *mv = pkt_stats_t2.lookup(&mi);
        if (mv) __sync_fetch_and_add(mv, 1);
        return XDP_PASS;                       /* no semantics registered */
    }
    if (ca->action == ACT_DROP) {
        int di = 2; __u64 *dv = pkt_stats_t2.lookup(&di);
        if (dv) __sync_fetch_and_add(dv, 1);
        /* The class was decided; record it. Without this a DROP is visible
         * only as a pkt_stats counter, and "the model chose the DROP class"
         * cannot be told apart from "the program never reached argmax". */
        __u64 *dcv = cls_stats_t2.lookup(&_ci);
        if (dcv) __sync_fetch_and_add(dcv, 1);
        return XDP_DROP;
    }
    if (ca->action != ACT_FORWARD) {           /* ACT_UNUSED */
        __u64 *ucv = cls_stats_t2.lookup(&_ci);
        if (ucv) __sync_fetch_and_add(ucv, 1);
        int mi = 1; __u64 *mv = pkt_stats_t2.lookup(&mi);
        if (mv) __sync_fetch_and_add(mv, 1);
        return XDP_PASS;
    }

    /* mac_table_t2 is keyed by LOGICAL PORT: the node decides which interface
     * realises the port the model asked for. cls_stats_t2 below is keyed by
     * CLASS. Two index spaces, two variables -- they were one variable named
     * `cls` holding the port, so the per-class counter was written at a port
     * index and only looked right because the reference model numbers its
     * ports the same as its forwarding classes. */
    __u32 port = (__u32)ca->port;
    struct fwd_action *action = mac_table_t2.lookup(&port);
    if (action != NULL && action->ifindex != 0) {
        /* A hop must not forward a packet whose TTL would reach 0. See the
         * ipa_ttl_dec() comment: counted as MISS and passed to the kernel. */
        if (ip->ttl <= 1) {
            int ti = 1; __u64 *tv = pkt_stats_t2.lookup(&ti);
            if (tv) __sync_fetch_and_add(tv, 1);
            return XDP_PASS;
        }
        ipa_ttl_dec(ip);
        int si = 0; __u64 *v = pkt_stats_t2.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        __u64 *cv = cls_stats_t2.lookup(&_ci);   /* keyed by CLASS */
        if (cv) __sync_fetch_and_add(cv, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    /* no mac_table entry for that LOGICAL PORT (link down / not provisioned) */
    int si = 1; __u64 *v = pkt_stats_t2.lookup(&si);
    if (v) __sync_fetch_and_add(v, 1);
    return XDP_PASS;
}
"""


# ---------------------------------------------------------------------------
# Compiled depth: how many hidden layers this leaf can run
# ---------------------------------------------------------------------------
# P2's genericity is a set of COMPILE-TIME envelopes -- T2_MAX_H1, T2_MAX_H2,
# MAX_N_IN, MAX_N_OUT -- inside which any model runs with no recompilation.
# Depth used to be the one dimension that was not an envelope but a constant:
# the source wrote fc1 and fc2 and stopped, so a 3-hidden-layer model had
# nowhere to go.
#
# build_arch_leaf(n_hidden) makes depth an envelope like the others. It emits
# (n_hidden - 2) additional dense blocks after fc2, each n_h2 -> n_h2.
#
# Two honest limits, both different from P3's:
#
#   1. The extra layers are all n_h2 wide. fc1 and fc2 keep independent widths
#      (n_h1, n_h2) exactly as before, so every existing model -- including the
#      65-6-5-7 in verify_multi_model -- is unaffected. A model whose layers
#      have different widths beyond the second does not fit.
#   2. A leaf built for n_hidden runs models of EXACTLY that depth. Changing
#      depth means recompiling, which is precisely what P3 does not need. That
#      is the trade-off the depth axis of bench_scaling.py measures: P2 buys
#      depth with a recompile and with instructions paid on every packet,
#      P3 buys it with a tail call.
#
# n_hidden=2 reproduces the previous source exactly: the extra-span term is 0,
# the bias multiplier is scale**2, and no block is inserted.
T2_MIN_HIDDEN = 1

# The fc1 -> fc2 block, lifted out of the template so a 1-hidden-layer leaf can
# leave it out. Unchanged from what the source always said.
_FC2_BLOCK = """    /* h1[i]==0 for i>=n_h1 (set above), so the inner loop can always unroll
     * to T2_MAX_H1: out-of-range weight reads still get multiplied by 0. */
    long long h2[T2_MAX_H2];
    #pragma unroll
    for (int j = 0; j < T2_MAX_H2; j++) {
        if (j >= n_h2) { h2[j] = 0LL; continue; }

        long long acc = AW_W(AW, woff + fc2_b_off + j) * bias_mul_2;
        #pragma unroll
        for (int i = 0; i < T2_MAX_H1; i++) {
            acc += h1[i] * AW_W(AW, woff + fc2_w_off + j * n_h1 + i);
        }
        h2[j] = RELU(acc);
    }

"""


def build_arch_leaf(n_hidden: int = 2) -> str:
    """The arch_generic_2layer leaf source, compiled for `n_hidden` hidden
    layers. See the comment above for what that does and does not buy."""
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
            hx[j] = RELU(acc);
        }}
        #pragma unroll
        for (int j = 0; j < T2_MAX_H2; j++) h2[j] = hx[j];
    }}""")

    if n_hidden == 1:
        # One hidden layer: fc1 feeds the output directly. Rather than
        # templating the output loop -- which reads h2 with stride n_h2 -- fc2
        # becomes a COPY of h1 into h2 and the control plane registers
        # n_h2 = n_h1. The output loop then reads the right values with the
        # right stride, unchanged. No fc2 weights exist, so out_w_off skips
        # straight past fc1's bias row.
        #
        # The copy costs T2_MAX_H2 moves per packet, which is the price of not
        # having a second variant of the output layer to keep in step with the
        # first. load_arch_weights enforces the n_h2 == n_h1 half of this.
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


# The historical name, kept so every existing caller is untouched. It is the
# 2-hidden-layer leaf, which is byte-for-byte what the source said before
# depth became a parameter.
EBPF_ARCH_GENERIC_2LAYER = build_arch_leaf(2)



def load_arch_weights(bpf_obj, weights_int8: list,
                      model_id: int = 0, scale: int = 128,
                      weight_offset: int = 0,
                      n_h1: int = 4, n_h2: int = 4,
                      features: list = None, n_in: int = None,
                      semantics=None, n_hidden: int = 2) -> None:
    """
    Populate arch_weights and arch_registry for Pipeline 2.

    n_h1/n_h2 are THIS model's hidden widths (input width from the
    descriptor and
    output width n_out is read from the descriptor). They must
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

    # Resolve the feature descriptor (default 65-feature layout unless a custom
    # one is passed). n_in drives both the flat weight-block size here and the
    # runtime IV width read from model_desc -> they stay consistent.
    if features is None:
        from model_meta import derive_shape, DEFAULT_META, load_topology_config
        _sh = derive_shape(dict(DEFAULT_META), topology_config=load_topology_config())
        features = _sh["features"]
        n_in = _sh["n_in"]
    elif n_in is None:
        n_in = sum(f["size"] for f in features)

    # Class semantics. Required, not derived: inferring DROP as n_out-1 is the
    # assumption this parameter exists to remove. With no argument the shared
    # resolver reads the descriptor and announces any fallback.
    if semantics is None:
        from model_meta import descriptor_semantics_or_reference
        semantics = descriptor_semantics_or_reference(reference_widths()[1],
                                                     "Pipeline2")
    semantics.validate()


    if semantics.n_out != reference_widths()[1]:
        raise ValueError(
            f"class semantics declare n_out={semantics.n_out} but the "
            f"descriptor's output width is {reference_widths()[1]}. Descriptor "
            f"and model must agree before either reaches the datapath.")

    # n_hidden MUST match the depth the leaf was compiled for: the datapath
    # reads a fixed number of blocks out of this flat vector, so a mismatch
    # does not fail, it silently reads the wrong bytes as weights. There is no
    # runtime field to check it against -- arch_entry carries widths, not
    # depth -- so the caller is responsible for passing the same number it
    # passed to build_arch_leaf().
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

    # arch_weights is ONE struct-valued entry holding the whole 1024-byte weight
    # block (see the aw_blk declaration in the eBPF source). Registering a model
    # is therefore a read-modify-write of that single entry -- ONE update syscall
    # instead of one per weight (was 319 for the 65-4-4-7 model). Read-modify
    # matters: several model_id's share the block at different weight_offsets,
    # so writing a fresh buffer would wipe the models registered before this one.
    value_size = _get_map_value_size(map_fd)
    print(f"[Pipeline2] arch_weights fd={map_fd} block={value_size} bytes")

    blk = _bpf_map_read_blk(map_fd, value_size)
    for idx, w in enumerate(weights_int8[:n_weights]):
        blk[weight_offset + idx] = int(w) & 0xFF
    _bpf_map_write_blk(map_fd, blk)

    # Post-load sanity check: read the block back and check weight[0] of this
    # model's slice survived the round trip.
    v0       = ct.c_int8(_bpf_map_read_blk(map_fd, value_size)[weight_offset]).value
    expected = ct.c_int8(int(weights_int8[0])).value
    ok       = "OK" if v0 == expected else f"MISMATCH got={v0} expected={expected}"
    print(f"[Pipeline2] arch_weights[{weight_offset}] verify: {ok}")

    class ArchEntry(Structure):
        _pack_ = 1
        _fields_ = [("arch_id",       c_uint8),
                    ("weight_offset",  c_uint32),
                    ("scale_factor",   c_uint16),
                    ("n_out",          c_uint8),
                    ("n_h1",           c_uint8),
                    ("n_h2",           c_uint8)]

    entry = ArchEntry(arch_id=arch_id, weight_offset=weight_offset,
                      scale_factor=scale, n_out=semantics.n_out,
                      n_h1=n_h1, n_h2=n_h2)
    bpf_obj["arch_registry"][c_uint8(model_id)] = entry
    load_class_action(bpf_obj, "class_action_t2", semantics)
    print(f"[Pipeline2] arch_registry[{model_id}] = "
          f"arch_id={arch_id} woff={weight_offset} scale={scale} "
          f"shape={n_in}-{n_h1}-{n_h2}-{semantics.n_out} weights={n_weights}")
    print("[Pipeline2] NOTE: arch_progs wiring is caller's responsibility "
          "(setup_template already does: b['arch_progs'][0]=leaf_fn.fd)")

    # Seed the per-model feature descriptor so the leaf builds its IV
    # generically. Folded in here so every existing caller (methods + test
    # harnesses) registers model_desc without a separate call.
    load_model_desc(bpf_obj, features, n_in, model_id=model_id)


# Max features per descriptor -- must match MAX_FEAT in the eBPF source.
T2_MAX_FEAT = 4


def load_model_desc(bpf_obj, features: list, n_in: int, model_id: int = 0) -> None:
    """
    Populate model_desc[model_id] so arch_generic_2layer builds the input vector
    GENERICALLY from a per-model descriptor (instead of the old hardcoded
    65-feature layout). Call once per registered model_id, alongside
    load_arch_weights().

    features: resolved descriptor (list of {"type","size"}, from
              model_meta.derive_shape) -- feature types + topology sizes, in the
              exact order the model was trained on. Its flat (code,size,col_off)
              form comes from model_meta.resolve_descriptor(); col_off is the
              feature's starting column in the fc1 input row, so the runtime IV
              matches the trained weight layout.
    n_in:     sum of feature sizes (fc1 input width).

    With the default descriptor [link_state, ingress_iface, ttl, node] / n_in=65
    the registry reproduces the historical layout (link_state cols 0-5, iface
    6-11, ttl 12, node 13-64) -> byte-compatible with the old fixed program.
    """
    from ctypes import c_uint8, Structure
    from model_meta import resolve_descriptor

    ents = resolve_descriptor(features)
    if len(ents) > T2_MAX_FEAT:
        raise ValueError(
            f"descriptor has {len(ents)} features, exceeds MAX_FEAT={T2_MAX_FEAT} "
            f"(raise MAX_FEAT in ebpf_template_arch.py and reload to support it)")
    if n_in > 128:  # MAX_N_IN in the eBPF source
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

    d = ModelDesc(n_feat=len(ents), n_in=n_in)
    for i, e in enumerate(ents):
        d.feats[i] = FeatEnt(code=e["code"], size=e["size"],
                             col_off=e["col_off"],
                             scale=min(255, int(e.get("scale", 0) or 0)))
    bpf_obj["model_desc"][c_uint8(model_id)] = d
    print(f"[Pipeline2] model_desc[{model_id}] = n_feat={len(ents)} n_in={n_in} "
          f"feats={[(e['code'], e['size'], e['col_off'], e.get('scale'))
                    for e in ents]}")


def load_class_action(bpf_obj, map_name: str, semantics) -> None:
    """Write a ClassSemantics into a class_action BPF map.

    Shared by P2 and P3 -- the map layout and the ACT_* codes are the same
    contract in both. Entries past the model's n_out are left ACT_INVALID, so a
    class the datapath should never produce is rejected explicitly instead of
    reading as a zeroed (and therefore plausible-looking) action.
    """
    from ctypes import c_uint8, c_uint32, Structure
    from class_semantics import MAX_N_OUT

    class ClassAct(Structure):
        _pack_ = 1
        _fields_ = [("action", c_uint8), ("port", c_uint8),
                    ("_p0", c_uint8), ("_p1", c_uint8)]

    tbl = bpf_obj[map_name]
    table = semantics.action_table()
    for cid in range(MAX_N_OUT):
        act, port = table[cid]
        tbl[c_uint32(cid)] = ClassAct(action=act, port=port, _p0=0, _p1=0)
    print(f"[class_action] {map_name}: n_out={semantics.n_out} "
          f"drop_class={semantics.drop_class} ports={semantics.logical_ports}")
    for cid in range(semantics.n_out):
        print(f"[class_action]   class {cid}: {semantics.classes[cid].describe()}")
