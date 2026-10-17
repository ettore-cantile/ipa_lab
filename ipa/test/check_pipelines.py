#!/usr/bin/env python3
"""check_pipelines.py -- every pipeline under BPF_PROG_TEST_RUN: it loads, passes
the verifier and decides like an independent integer reference. Also the
shared setup code the other tests import. Needs root.

    sudo python3 ipa/test/check_pipelines.py --method hardcoded
"""

import os
import sys
import json
import struct
import argparse
import ctypes as ct

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

from bcc import BPF

_libc = ct.CDLL("libc.so.6", use_errno=True)
BPF_PROG_TEST_RUN = 10

class _BpfAttrTest(ct.Structure):
    _fields_ = [
        ("prog_fd",       ct.c_uint32),
        ("retval",        ct.c_uint32),
        ("data_size_in",  ct.c_uint32),
        ("data_size_out", ct.c_uint32),
        ("data_in",       ct.c_uint64),
        ("data_out",      ct.c_uint64),
        ("repeat",        ct.c_uint32),
        ("duration",      ct.c_uint32),
        ("ctx_size_in",   ct.c_uint32),
        ("ctx_size_out",  ct.c_uint32),
        ("ctx_in",        ct.c_uint64),
        ("ctx_out",       ct.c_uint64),
        ("flags",         ct.c_uint32),
        ("cpu",           ct.c_uint32),
        ("batch_size",    ct.c_uint32),
    ]


TEST_RUN_DEFAULT_INGRESS_IFINDEX = 1

def prog_test_run(prog_fd: int, frame: bytes, repeat: int = 1, ingress_ifindex: int = None):
    """Run an XDP program on `frame` via BPF_PROG_TEST_RUN (no ctx_in -- ctx_in
    field semantics for xdp_md are not reliably portable across kernels, see
    TEST_RUN_DEFAULT_INGRESS_IFINDEX)."""
    out = (ct.c_uint8 * 2048)()
    buf = ct.create_string_buffer(frame, len(frame))
    a = _BpfAttrTest(
        prog_fd       = prog_fd,
        data_size_in  = len(frame),
        data_size_out = ct.sizeof(out),
        data_in       = ct.cast(buf, ct.c_void_p).value,
        data_out      = ct.cast(out, ct.c_void_p).value,
        repeat        = repeat,
    )
    r = _libc.syscall(321, BPF_PROG_TEST_RUN, ct.byref(a), ct.sizeof(a))
    if r != 0:
        e = ct.get_errno()
        raise OSError(e, os.strerror(e))
    return a.retval, a.duration


TEST_RUN_MAX_CHUNK = 200
BENCH_TTL          = 255


TEST_RUN_MAX_CHUNKS = 25


def prog_test_run_bench(prog_fd: int, make_frame, total_repeat: int,
                        max_chunks: int = TEST_RUN_MAX_CHUNKS):
    """Time a packet-mutating program in TTL-safe chunks."""
    chunks = max(1, min(max_chunks,
                        (max(1, total_repeat) + TEST_RUN_MAX_CHUNK - 1)
                        // TEST_RUN_MAX_CHUNK))
    best = None
    last_retval = None
    for _ in range(chunks):
        last_retval, dur = prog_test_run(prog_fd, make_frame(),
                                         repeat=TEST_RUN_MAX_CHUNK)
        if dur and (best is None or dur < best):
            best = dur
    return last_retval, (best if best is not None else 0)


def prog_test_run_data(prog_fd: int, frame: bytes):
    """Like prog_test_run(), but also returns the packet the program produced."""
    out = (ct.c_uint8 * 2048)()
    buf = ct.create_string_buffer(frame, len(frame))
    a = _BpfAttrTest(
        prog_fd       = prog_fd,
        data_size_in  = len(frame),
        data_size_out = ct.sizeof(out),
        data_in       = ct.cast(buf, ct.c_void_p).value,
        data_out      = ct.cast(out, ct.c_void_p).value,
        repeat        = 1,
    )
    r = _libc.syscall(321, BPF_PROG_TEST_RUN, ct.byref(a), ct.sizeof(a))
    if r != 0:
        e = ct.get_errno()
        raise OSError(e, os.strerror(e))
    return a.retval, a.duration, bytes(bytearray(out)[:a.data_size_out])


def ip_checksum_ok(hdr: bytes) -> bool:
    """True if the 20-byte IPv4 header checksums correctly."""
    if len(hdr) < 20:
        return False
    total = 0
    for i in range(0, 20, 2):
        total += (hdr[i] << 8) | hdr[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF

_BPF_OBJ_GET_INFO_BY_FD = 15

class _BpfProgInfo(ct.Structure):
    _fields_ = [
        ("type",            ct.c_uint32),
        ("id",              ct.c_uint32),
        ("tag",             ct.c_uint8 * 8),
        ("jited_prog_len",  ct.c_uint32),
        ("xlated_prog_len", ct.c_uint32),
    ]

class _BpfAttrObjInfo(ct.Structure):
    _fields_ = [
        ("bpf_fd",   ct.c_uint32),
        ("info_len", ct.c_uint32),
        ("info",     ct.c_uint64),
    ]

def prog_insn_count(prog_fd: int):
    buf  = (ct.c_uint8 * 256)()
    info = ct.cast(buf, ct.POINTER(_BpfProgInfo)).contents
    attr = _BpfAttrObjInfo(
        bpf_fd   = prog_fd,
        info_len = ct.sizeof(buf),
        info     = ct.cast(buf, ct.c_void_p).value,
    )
    r = _libc.syscall(321, _BPF_OBJ_GET_INFO_BY_FD, ct.byref(attr), ct.sizeof(attr))
    if r != 0:
        return None, None
    return int(info.xlated_prog_len) // 8, int(info.jited_prog_len)

class _BpfMapInfo(ct.Structure):
    _fields_ = [
        ("map_type",    ct.c_uint32),
        ("id",          ct.c_uint32),
        ("key_size",    ct.c_uint32),
        ("value_size",  ct.c_uint32),
        ("max_entries", ct.c_uint32),
    ]

_PERCPU_MAP_TYPES = frozenset({5, 6, 10, 21})

def map_info(map_fd: int):
    info = _BpfMapInfo()
    attr = _BpfAttrObjInfo(
        bpf_fd   = map_fd,
        info_len = ct.sizeof(info),
        info     = ct.cast(ct.byref(info), ct.c_void_p).value,
    )
    r = _libc.syscall(321, _BPF_OBJ_GET_INFO_BY_FD, ct.byref(attr), ct.sizeof(attr))
    if r != 0:
        return None
    return (int(info.map_type), int(info.key_size), int(info.value_size), int(info.max_entries))

def map_bytes(map_fd: int, nr_cpus: int = 1) -> int:
    mi = map_info(map_fd)
    if mi is None:
        return 0
    map_type, ksz, vsz, ment = mi
    per_cpu = nr_cpus if map_type in _PERCPU_MAP_TYPES else 1
    return (ksz + vsz * per_cpu) * ment

from model_meta import default_checkpoint
MODEL_PT     = default_checkpoint()
WEIGHTS_JSON = os.path.join(SHARED_DIR, "weights_float.json")

def _nr_cpus() -> int:
    try:
        with open("/sys/devices/system/cpu/online") as f:
            s = f.read().strip()
        count = 0
        for part in s.split(","):
            if "-" in part:
                a, b2 = part.split("-")
                count += int(b2) - int(a) + 1
            else:
                count += 1
        return max(1, count)
    except Exception:
        return max(1, os.cpu_count() or 1)

_NR_CPUS = _nr_cpus()


def _mut():
    """The model under test (--model / $IPA_MODEL), or None."""
    import model_under_test as MUT
    return MUT.active()


def _setup_mut(pipeline, model_id, m):
    """setup_* for the model under test."""
    import pipeline_setup as PS
    setup = PS.build(pipeline, m)
    if model_id != 0:
        PS.register_model_id(setup, model_id)
    PS.seed_inputs(setup)
    return setup


def load_weights(model_path=MODEL_PT):
    m = _mut()
    if m is not None:
        return list(m.weights), m.scale
    from extract_weights import extract_weights_int8
    weights = extract_weights_int8(model_path)
    scale = 128
    if os.path.exists(WEIGHTS_JSON):
        with open(WEIGHTS_JSON) as f:
            scale = int(json.load(f).get("scale_factor", 128))
    return weights, scale

def _ip_csum(hdr20: bytes) -> int:
    """Standard IPv4 header checksum over a 20-byte header whose checksum field
    is zero."""
    total = 0
    for i in range(0, 20, 2):
        total += (hdr20[i] << 8) | hdr20[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_frame(model_id: int, ttl: int, scale: int) -> bytes:
    eth = b'\x00'*6 + b'\x00'*6 + struct.pack('!H', 0x0800)
    ip  = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 48, 0, 0, ttl, 17, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    ip  = ip[:10] + struct.pack('!H', _ip_csum(ip)) + ip[12:]
    udp = struct.pack('!HHHH', 12345, 9999, 28, 0)
    ipa = struct.pack('!BBBHBBBBBBBBBBBBBBBB', model_id, 0, 0, scale, 65, 7, 2, 4, 3, 0, 65, 0, 0, 0, 0, 0, 0, 1, 0, 7)
    return eth + ip + udp + ipa

def _trunc_div(a: int, b: int) -> int:
    """Integer division truncating toward ZERO, like C."""
    if b == 1:
        return a
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _feature_scales(features) -> list:
    """Per-COLUMN divisor for a resolved descriptor."""
    import model_meta as _mm
    out = []
    for f in features:
        out += [_mm.feature_scale_of(f)] * int(f["size"])
    return out


def ref_infer(weights, scale: int, ttl: int, model_id: int, ingress_port: int = 0,
              link_state=None, node_index=None):
    """Integer reference for the checked-in 65-4-4-7 model."""
    m = _mut()
    if m is not None:
        import pipeline_setup as PS
        cls, val = PS.reference(m, ttl, link_state=link_state,
                                ingress_port=ingress_port,
                                node_index=node_index)
        return cls, val, [], []

    def s8(v):
        return ct.c_int8(int(v) & 0xFF).value
    N_IN, N_H1, N_H2, N_OUT = 65, 4, 4, 7
    off_fc1_b = N_IN * N_H1
    off_fc2_w = off_fc1_b + N_H1
    off_fc2_b = off_fc2_w + N_H1 * N_H2
    off_out_w = off_fc2_b + N_H2
    off_out_b = off_out_w + N_H2 * N_OUT
    x = [0] * N_IN
    ls = [1] * 6 if link_state is None else list(link_state)[:6]
    for i in range(6):
        x[i] = int(ls[i]) if i < len(ls) else 0
    x[12] = ttl
    if 1 <= ingress_port <= 6:
        x[5 + ingress_port] = 1
    _node = node_index
    if _node is not None and 0 <= _node <= 51:
        x[13 + _node] = 1
    import model_meta as _mm
    col_scale = [1] * N_IN
    col_scale[12] = _mm.feature_scale("ttl")

    h1 = []
    for j in range(N_H1):
        acc = s8(weights[off_fc1_b + j])
        for i in range(N_IN):
            acc += _trunc_div(x[i] * s8(weights[j * N_IN + i]), col_scale[i])
        h1.append(max(0, acc))
    h2 = []
    for j in range(N_H2):
        acc = s8(weights[off_fc2_b + j]) * scale
        for i in range(N_H1):
            acc += h1[i] * s8(weights[off_fc2_w + j * N_H1 + i])
        h2.append(max(0, acc))
    best_val, best_cls = None, 0
    out_bias_mul = scale * scale
    for k in range(N_OUT):
        acc = s8(weights[off_out_b + k]) * out_bias_mul
        for i in range(N_H2):
            acc += h2[i] * s8(weights[off_out_w + k * N_H2 + i])
        if best_val is None or acc > best_val:
            best_val, best_cls = acc, k
    return best_cls, best_val, h1, h2


def build_frame_sparse(model_id: int, ttl: int, scale: int, n_in: int, n_out: int) -> bytes:
    """Frame for a heterogeneous sparse model."""
    eth = b'\x00'*6 + b'\x00'*6 + struct.pack('!H', 0x0800)
    ip  = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 48, 0, 0, ttl, 17, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    ip  = ip[:10] + struct.pack('!H', _ip_csum(ip)) + ip[12:]
    udp = struct.pack('!HHHH', 12345, 9999, 28, 0)
    ipa = struct.pack('!BBBHBBBBBBBBBBBBBBBB', model_id, 0, 0, scale, n_in, n_out, 2, 4,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, n_out)
    return eth + ip + udp + ipa


def ref_infer_sparse(weights, features, hidden_dims, n_out, ttl, model_id,
                     map_values, ingress_port=0, scale: int = 1,
                     node_index=None):
    """Python reference for the heterogeneous sparse route."""
    import model_meta as mm
    def s8(v):
        return ct.c_int8(int(v) & 0xFF).value

    n_in = sum(f["size"] for f in features)
    x = [0] * n_in
    o = 0
    for f in features:
        t, size = f["type"], f["size"]
        kind = mm.FEATURE_CATALOG[t]["kind"]
        if kind == "scalar":
            x[o] = ttl & 0xff
        elif kind == "dense_vector_map":
            vals = map_values.get(mm.FEATURE_CATALOG[t]["map"], [0] * size)
            for i in range(size):
                x[o + i] = vals[i]
        elif kind == "onehot" and t == "ingress_iface":
            logical = int(ingress_port)
            if 1 <= logical <= size:
                x[o + (logical - 1)] = 1
        elif kind == "onehot" and t == "node":
            _n = node_index if node_index is not None else -1
            if 0 <= _n < size:
                x[o + _n] = 1
        o += size

    layer_sizes = [n_in] + [int(d) for d in hidden_dims] + [n_out]
    off = 0
    acts = x
    for li in range(1, len(layer_sizes)):
        n_prev, n_cur = layer_sizes[li - 1], layer_sizes[li]
        w_off, b_off = off, off + n_prev * n_cur
        off = b_off + n_cur
        is_out = (li == len(layer_sizes) - 1)
        nxt = []
        scales = _feature_scales(features) if li == 1 else [1] * n_prev
        for j in range(n_cur):
            acc = s8(weights[b_off + j]) * (scale ** (li - 1))
            for i in range(n_prev):
                acc += _trunc_div(acts[i] * s8(weights[w_off + j * n_prev + i]),
                                  scales[i])
            nxt.append(acc if is_out else max(0, acc))
        acts = nxt

    best_val, best_cls = None, 0
    for k, v in enumerate(acts):
        if best_val is None or v > best_val:
            best_val, best_cls = v, k
    return best_cls, best_val


class _FwdAction(ct.Structure):
    _pack_ = 1
    _fields_ = [("ifindex",  ct.c_uint32), ("src_mac",  ct.c_uint8 * 6), ("dst_mac",  ct.c_uint8 * 6)]

def _install_mac_table(b, name, ifindex=2, semantics=None, ports=None):
    """Pre-install the logical-port -> action map the datapath reads after
    argmax."""
    if ports is None:
        if semantics is None:
            semantics = _default_semantics_for(b, name)
        ports = semantics.logical_ports
    action = _FwdAction(
        ifindex=ifindex,
        src_mac=(ct.c_uint8 * 6)(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        dst_mac=(ct.c_uint8 * 6)(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
    )
    for port in ports:
        b[name][ct.c_uint32(port)] = action
    return list(ports)


def _default_semantics_for(b, name):
    """Semantics for a setup that did not pass any."""
    m = _mut()
    if m is not None:
        return m.semantics
    import model_meta as mm
    n_out = None
    try:
        n_out = b["cls_stats"].max_entries if "cls_stats" in dir(b) else None
    except Exception:
        n_out = None
    if n_out is None:
        n_out = mm.derive_shape(mm.load_model_meta(
            os.path.join(SHARED_DIR, "weights.json")))["n_out"]
    return mm.descriptor_semantics_or_reference(n_out, f"verify:{name}")


def _seed_link_state(b, val: int = 1):
    """Seed the link_state map [0..5] with `val` (1=up) if the program has it."""
    try:
        from common import write_vector_map
        import model_meta as _mm
        _n = int(_mm.load_topology_config()["n_interfaces"])
        write_vector_map(b, "link_state", [int(val)] * _n)
    except Exception:
        pass


EBPF_BASELINE = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

struct ipa_hdr {
    __u8 model_id; __u8 model_type; __u8 param_size; __be16 scale_factor;
    __u8 input_size; __u8 output_size; __u8 hidden_layers; __u8 neurons_per_layer;
    __u8 n_feature_types;
    __u8 f0c,f0n,f1c,f1n,f2c,f2n,f3c,f3n; __u8 n_output_types; __u8 o0c,o0n;
} __attribute__((packed));

struct fwd_action { __u32 ifindex; __u8 src_mac[6]; __u8 dst_mac[6]; } __attribute__((packed));

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

BPF_ARRAY(mac_table, struct fwd_action, 8);
BPF_PERCPU_ARRAY(pkt_stats, __u64, 3);
BPF_PERCPU_ARRAY(cls_stats, __u64, 7);

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

int xdp_baseline(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;

    __u32 cls = 0;   /* fixed egress class -- no inference, no argmax */
    struct fwd_action *action = mac_table.lookup(&cls);
    if (action && action->ifindex != 0) {
        if (ip->ttl <= 1) {
            int ti = 1; __u64 *tv = pkt_stats.lookup(&ti);
            if (tv) *tv += 1;
            return XDP_PASS;
        }
        ipa_ttl_dec(ip);
        int si = 0; __u64 *v = pkt_stats.lookup(&si);
        if (v) *v += 1;
        __u64 *cv = cls_stats.lookup(&cls);
        if (cv) *cv += 1;
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    int mi = 1; __u64 *mv = pkt_stats.lookup(&mi);
    if (mv) *mv += 1;
    return XDP_PASS;
}
"""


def setup_baseline(model_id: int, model_path: str):
    """Empty/baseline pipeline."""
    m = _mut()
    if m is not None:
        return _setup_mut("baseline", model_id, m)
    weights, scale = load_weights(model_path)
    b = BPF(text=EBPF_BASELINE)
    fn = b.load_func("xdp_baseline", BPF.XDP)
    _install_mac_table(b, "mac_table")
    return {
        "b": b, "fn": fn, "disp": fn,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats"],
        "pkt_stats": b["pkt_stats"],
        "pipeline": 0,
        "progs": {"xdp_baseline": fn.fd},
        "n_tail": 0,
    }


EBPF_BASELINE_TAILCALL = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

struct ipa_hdr {
    __u8 model_id; __u8 model_type; __u8 param_size; __be16 scale_factor;
    __u8 input_size; __u8 output_size; __u8 hidden_layers; __u8 neurons_per_layer;
    __u8 n_feature_types;
    __u8 f0c,f0n,f1c,f1n,f2c,f2n,f3c,f3n; __u8 n_output_types; __u8 o0c,o0n;
} __attribute__((packed));

struct fwd_action { __u32 ifindex; __u8 src_mac[6]; __u8 dst_mac[6]; } __attribute__((packed));

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

BPF_ARRAY(mac_table, struct fwd_action, 8);
BPF_PERCPU_ARRAY(pkt_stats, __u64, 3);
BPF_PERCPU_ARRAY(cls_stats, __u64, 7);
BPF_PROG_ARRAY(tail_progs, 2);

int xdp_baseline_dispatch(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;

    tail_progs.call(ctx, 0);
    /* fallthrough only if the tail call itself failed to attach */
    int mi = 1; __u64 *mv = pkt_stats.lookup(&mi);
    if (mv) *mv += 1;
    return XDP_PASS;
}

int xdp_baseline_action(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 cls = 0;   /* fixed egress class -- no inference, no argmax */
    struct fwd_action *action = mac_table.lookup(&cls);
    if (action && action->ifindex != 0) {
        if (ip->ttl <= 1) {
            int ti = 1; __u64 *tv = pkt_stats.lookup(&ti);
            if (tv) *tv += 1;
            return XDP_PASS;
        }
        ipa_ttl_dec(ip);
        int si = 0; __u64 *v = pkt_stats.lookup(&si);
        if (v) *v += 1;
        __u64 *cv = cls_stats.lookup(&cls);
        if (cv) *cv += 1;
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    int mi = 1; __u64 *mv = pkt_stats.lookup(&mi);
    if (mv) *mv += 1;
    return XDP_PASS;
}
"""


def setup_baseline_tailcall(model_id: int, model_path: str):
    """Same floor as setup_baseline(), but the redirect action is reached via
    ONE bpf_tail_call hop (see EBPF_BASELINE_TAILCALL docstring)."""
    weights, scale = load_weights(model_path)
    b = BPF(text=EBPF_BASELINE_TAILCALL)
    fn_disp   = b.load_func("xdp_baseline_dispatch", BPF.XDP)
    fn_action = b.load_func("xdp_baseline_action", BPF.XDP)
    b["tail_progs"][ct.c_int(0)] = ct.c_int(fn_action.fd)
    _install_mac_table(b, "mac_table")
    return {
        "b": b, "fn": fn_disp, "disp": fn_disp,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats"],
        "pkt_stats": b["pkt_stats"],
        "pipeline": 0,
        "progs": {"xdp_baseline_dispatch": fn_disp.fd, "xdp_baseline_action": fn_action.fd},
        "n_tail": 1,
    }


def setup_hardcoded(model_id: int, model_path: str):
    """Pipeline 1 (P1.5: weights compiled in, node read from the node_id map),
    as it is DEPLOYED: the AOT object built by gen_full_c and loaded by
    loader_aot, driven through bpffs (p1_aot.load_p1)."""
    m = _mut()
    if m is not None:
        return _setup_mut("hardcoded", model_id, m)
    import p1_aot
    weights, scale = load_weights(model_path)
    setup = p1_aot.load_p1([(model_id, weights, scale)])
    setup.update(weights=weights, scale=scale)
    _seed_link_state(setup["b"], 1)
    _install_mac_table(setup["b"], "mac_table")
    return setup


STATIC_NODE = 7


def setup_p1_static(model_id: int, model_path: str, node: int = STATIC_NODE):
    """Pipeline 1 specialised (P1)."""
    m = _mut()
    if m is not None:
        import pipeline_setup as PS
        setup = PS.build("p1_static", m, node_index=PS.node_index_for(m, node))
        if model_id != 0:
            PS.register_model_id(setup, model_id)
        PS.seed_inputs(setup)
        return setup
    import p1_aot
    weights, scale = load_weights(model_path)
    setup = p1_aot.load_p1([(model_id, weights, scale)], static_node=node)
    setup.update(weights=weights, scale=scale, static_node=node)
    _seed_link_state(setup["b"], 1)
    _install_mac_table(setup["b"], "mac_table")
    return setup


def setup_template(model_id: int, model_path: str):
    m = _mut()
    if m is not None:
        return _setup_mut("template", model_id, m)
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_GENERIC_2LAYER, load_arch_weights)
    weights, scale = load_weights(model_path)
    src = "#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_GENERIC_2LAYER
    b = BPF(text=src)
    disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
    leaf_fn = b.load_func("arch_generic_2layer", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
    load_arch_weights(b, weights, model_id=model_id, scale=scale)
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table_t2")
    return {
        "b": b, "fn": leaf_fn, "disp": disp_fn,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats_t2"],
        "pkt_stats": b["pkt_stats_t2"],
        "pipeline": 2,
        "progs": {"ipa_switch_template": disp_fn.fd, "arch_generic_2layer": leaf_fn.fd},
    }


def setup_modular(model_id: int, model_path: str):
    m = _mut()
    if m is not None:
        return _setup_mut("modular", model_id, m)
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights, scale = load_weights(model_path)
    b = BPF(text=EBPF_MODULAR_FULL)
    disp_fn   = b.load_func("modular_dispatcher", BPF.XDP)
    fn_first  = b.load_func("layer_first",  BPF.XDP)
    fn_hidden = b.load_func("layer_hidden", BPF.XDP)
    b["layer_chain"][ct.c_int(0)] = ct.c_int(fn_first.fd)
    for i in range(1, 16):
        b["layer_chain"][ct.c_int(i)] = ct.c_int(fn_hidden.fd)
    layer_dims = [(65, 4), (4, 4), (4, 7)]
    n_layers = len(layer_dims)
    load_modular_weights(b, weights, model_id=model_id, scale=scale, layer_dims=layer_dims)
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table_t3")
    print(f"[P3 setup] nr_cpus={_NR_CPUS}  PERCPU ctypes Array enabled")
    return {
        "b": b, "fn": fn_hidden, "disp": disp_fn,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats_t3"],
        "pkt_stats": b["pkt_stats_t3"],
        "pipeline": 3,
        "last_layer_idx": n_layers - 1,
        "n_tail": n_layers,
        "progs": {
            "modular_dispatcher": disp_fn.fd,
            "layer_first": fn_first.fd,
            "layer_hidden": fn_hidden.fd,
        },
    }


def setup_sparse_hetero(model_id: int, model_dir: str):
    """Load a heterogeneous sparse model (explicit per-model feature
    descriptor, see model_meta.py) from a fixture directory."""
    from ebpf_program import load_and_generate
    import model_meta as mm

    model_path = os.path.join(model_dir, "model.pt")
    meta = mm.load_model_meta(model_path)
    if meta.get("scenario", "sparse") != "sparse" or not meta.get("features"):
        raise ValueError(f"{model_dir}/model_meta.json is not a sparse model with a 'features' descriptor")
    shape = mm.derive_shape(meta)

    import p1_aot
    _, weights, scale = load_and_generate(model_path, model_id=model_id, meta=meta)
    n_out = shape["n_out"]
    semantics = mm.descriptor_semantics_or_reference(n_out, "verify:sparse")
    setup = p1_aot.load_p1([(model_id, weights, scale)],
                           features=shape["features"], n_out=n_out,
                           hidden_dims=tuple(shape["hidden_dims"]),
                           semantics=semantics)
    b = setup["b"]
    _install_mac_table(b, "mac_table", semantics=semantics)

    from common import write_vector_map
    map_values = {}
    for feat_type, map_name in mm.feature_maps(shape["features"]).items():
        size = next(f["size"] for f in shape["features"] if f["type"] == feat_type)
        vals = [(i * 7 + 3) % 16 for i in range(size)]
        write_vector_map(b, map_name, vals)
        map_values[map_name] = vals

    setup.update(weights=weights, scale=scale, shape=shape,
                 map_values=map_values, semantics=semantics)
    return setup


def count_lookups(method: str, model_id: int, model_path: str, ttl: int = None, repeat: int = None) -> float:
    """Real per-packet map-lookup count for `method`, measured via a dedicated
    instrumented build (every `.lookup()` call wrapped with CTR_INC(), see
    common.py instrument_map_lookups())."""
    from common import instrument_map_lookups, count_instrumented_sites

    def _report(raw_src):
        """Print where the instrumentation weight lands, per eBPF function, so
        a 'program too large' rejection of the measurement build is
        diagnosable from the log instead of being a bare failure."""
        sites = count_instrumented_sites(raw_src)
        total = sum(sites.values())
        detail = "  ".join(f"{k}={v}" for k, v in sorted(sites.items()))
        print(f"[count_lookups] {method}: instrumenting {total} lookup sites "
              f"({detail})")

    ttl, repeat = _count_lookups_defaults(ttl, repeat)
    weights, scale = load_weights(model_path)

    m = _mut()
    if m is not None:
        import pipeline_setup as PS
        node = PS.node_index_for(m, STATIC_NODE) if method == "p1_static" else None
        setup = PS.build(method, m, node_index=node, instrument=True)
        if model_id != 0:
            PS.register_model_id(setup, model_id)
        PS.seed_inputs(setup)
        if method in ("p1_static", "hardcoded"):
            print(f"[count_lookups] {method}: instrumenting "
                  f"{setup['lookup_sites']} lookup sites (AOT object)")
        return _lookups_per_packet(method, setup["b"], setup["disp"],
                                   build_frame(model_id, ttl, scale), repeat)

    if method == "baseline":
        src = "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(EBPF_BASELINE)
        _report(EBPF_BASELINE)
        b = BPF(text=src)
        disp_fn = b.load_func("xdp_baseline", BPF.XDP)
        _install_mac_table(b, "mac_table")
    elif method in ("p1_static", "hardcoded"):
        import p1_aot
        setup = p1_aot.load_p1(
            [(model_id, weights, scale)], instrument=True,
            static_node=STATIC_NODE if method == "p1_static" else None)
        print(f"[count_lookups] {method}: instrumenting "
              f"{setup['lookup_sites']} lookup sites (AOT object)")
        b, disp_fn = setup["b"], setup["disp"]
        _seed_link_state(b, 1)
        _install_mac_table(b, "mac_table")
    elif method == "template":
        from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_GENERIC_2LAYER, load_arch_weights)
        raw = "#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_GENERIC_2LAYER
        src = "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(raw)
        _report(raw)
        b = BPF(text=src)
        disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
        leaf_fn = b.load_func("arch_generic_2layer", BPF.XDP)
        b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
        load_arch_weights(b, weights, model_id=model_id, scale=scale)
        _seed_link_state(b, 1)
        _install_mac_table(b, "mac_table_t2")
    elif method == "modular":
        from ebpf_modular import (EBPF_MODULAR_FULL, load_modular_weights,
                                  LAYER_CHAIN_SIZE)
        src = "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(EBPF_MODULAR_FULL)
        _report(EBPF_MODULAR_FULL)
        b = BPF(text=src)
        disp_fn   = b.load_func("modular_dispatcher", BPF.XDP)
        fn_first  = b.load_func("layer_first",  BPF.XDP)
        fn_hidden = b.load_func("layer_hidden", BPF.XDP)
        b["layer_chain"][ct.c_int(0)] = ct.c_int(fn_first.fd)
        for i in range(1, LAYER_CHAIN_SIZE):
            b["layer_chain"][ct.c_int(i)] = ct.c_int(fn_hidden.fd)
        load_modular_weights(b, weights, model_id=model_id, scale=scale,
                             layer_dims=[(65, 4), (4, 4), (4, 7)])
        _seed_link_state(b, 1)
        _install_mac_table(b, "mac_table_t3")
    else:
        raise ValueError(f"count_lookups: unknown method {method!r}")

    return _lookups_per_packet(method, b, disp_fn,
                               build_frame(model_id, ttl, scale), repeat)


def _lookups_per_packet(method, b, disp_fn, frame, repeat):
    """Run `repeat` packets through the instrumented build, return the lookups
    per packet."""
    ctr = b["lookup_ctr"]
    if method in ("p1_static", "hardcoded"):
        ctr[ct.c_int(0)] = ct.c_ulonglong(0)
        prog_test_run(disp_fn.fd, frame, repeat=repeat)
        return int.from_bytes(ctr[ct.c_int(0)], "little") / float(repeat)
    ctr[ct.c_int(0)] = ctr.Leaf()
    prog_test_run(disp_fn.fd, frame, repeat=repeat)
    total = sum(int(v) for v in ctr[ct.c_int(0)])
    return total / float(repeat)


def _count_lookups_defaults(ttl, repeat):
    """TTL and repetition count for a lookup measurement."""
    return (BENCH_TTL if ttl is None else ttl,
            TEST_RUN_MAX_CHUNK if repeat is None else repeat)


def _read_u64(table, key_val):
    """A counter, summed over every CPU (pkt_stats/cls_stats are per-CPU)."""
    from stats_maps import read_counter
    return read_counter(table, key_val)

def _reset_stats(setup, n_classes=7):
    from stats_maps import zero_all
    zero_all(setup["pkt_stats"], 3)
    cs = setup.get("cls_stats")
    if cs is not None:
        zero_all(cs, min(n_classes, len(cs)))

XDP_PASS = 2
XDP_REDIRECT_PASS = frozenset({0, 4})


def _fired_cls_p1(setup) -> int:
    """After a single-packet run of Pipeline 1, return the egress class that
    fired."""
    cs = setup["cls_stats"]
    for c in range(6):
        if _read_u64(cs, c) > 0:
            return c
    if _read_u64(setup["pkt_stats"], 2) > 0:
        return 6
    return -1


def verify_ttl_handling(method: str, model_id: int, model_path: str):
    """Prove the forwarding hop behaves like a router with respect to the TTL."""
    setup_fn = {"p1_static": setup_p1_static,
                "hardcoded": setup_hardcoded,
                "template":  setup_template,
                "modular":   setup_modular}[method]
    setup = setup_fn(model_id, model_path)
    b, disp = setup["b"], setup["disp"]  # noqa: F841 (b keeps maps alive)
    scale = setup["scale"]
    ps = setup["pkt_stats"]
    node = setup.get("static_node")

    npass, nfail, details = 0, 0, []

    t_fwd = 5
    m = _mut()
    if m is not None:
        import model_under_test as MUT
        t_fwd = next((t for t in range(5, MUT.initial_ttl(m) + 1)
                      if m.semantics.action_of(ref_infer(
                          None, scale, t, model_id,
                          node_index=node)[0]) == "FORWARD"), None)
        if t_fwd is None:
            details.append(f"{method}: no TTL leads to a FORWARD class "
                           f"with every link up: forwarding not verifiable")
    _reset_stats(setup)
    frame = build_frame(model_id, t_fwd or 5, scale)
    retval, _, out = prog_test_run_data(disp.fd, frame)
    if len(out) >= 34:
        ttl_out = out[14 + 8]
        csum_ok = ip_checksum_ok(out[14:34])
    else:
        ttl_out, csum_ok = None, False
    forwarded = retval in (0, 4)
    if t_fwd is None:
        pass
    elif forwarded and ttl_out == t_fwd - 1 and csum_ok:
        npass += 1
        details.append(f"{method}: TTL {t_fwd} -> forwarded, out TTL={ttl_out}, checksum OK")
    else:
        nfail += 1
        details.append(f"{method}: TTL {t_fwd} -> retval={retval} out_ttl={ttl_out} "
                       f"csum_ok={csum_ok} (expected retval in (0,4), ttl {t_fwd - 1}, csum OK)")

    _reset_stats(setup)
    frame = build_frame(model_id, 1, scale)
    retval, _, out = prog_test_run_data(disp.fd, frame)
    hits = _read_u64(ps, 0)
    if retval not in (0, 4) and hits == 0:
        npass += 1
        details.append(f"{method}: TTL 1 -> not forwarded (retval={retval}, hits=0)")
    else:
        nfail += 1
        details.append(f"{method}: TTL 1 -> retval={retval} hits={hits} "
                       f"(expected NOT forwarded)")

    return npass, nfail, details


def probe_link_down(model_path, model_id: int = 0, ttl_min: int = 2, ttl_max: int = 6):
    """Prove that link_state is a live routing input."""
    setup = setup_hardcoded(model_id, model_path)
    b, fn, scale = setup["b"], setup["fn"], setup["scale"]
    changes, tested = [], 0
    for ttl in range(ttl_min, ttl_max + 1):
        frame = build_frame(model_id, ttl, scale)
        _seed_link_state(b, 1)
        _reset_stats(setup)
        prog_test_run(fn.fd, frame, repeat=1)
        cls_up = _fired_cls_p1(setup)
        from common import set_vector_slot
        import model_meta as _mm
        _n_if = int(_mm.load_topology_config()["n_interfaces"])
        for k in range(_n_if):
            _seed_link_state(b, 1)
            set_vector_slot(b, "link_state", k, 0)
            _reset_stats(setup)
            prog_test_run(fn.fd, frame, repeat=1)
            cls_down = _fired_cls_p1(setup)
            tested += 1
            if cls_down != cls_up:
                changes.append((ttl, k, cls_up, cls_down))
    _seed_link_state(b, 1)
    return changes, tested

def run(method: str, model_id: int, model_path: str, ttl_min: int, ttl_max: int, repeat: int):
    print("=" * 70)
    print(f" IPA/eBPF BPF_PROG_TEST_RUN  --  method={method}  model_id={model_id}")
    print("=" * 70)
    print()
    print("NOTE: bpf_redirect() runs in the TEST_RUN sandbox.")
    print("      PASS = retval in {0,4} (redirect fire) + cls_stats/pkt_stats hit.")
    print()
    setup_fn = {"p1_static": setup_p1_static, "hardcoded": setup_hardcoded,
                "template": setup_template, "modular": setup_modular}[method]
    setup = setup_fn(model_id, model_path)
    b, fn, disp = setup["b"], setup["fn"], setup["disp"]  # noqa: F841
    weights = setup["weights"]
    scale = setup["scale"]
    ps = setup["pkt_stats"]
    cs = setup.get("cls_stats")
    pipeline = setup["pipeline"]

    if pipeline == 1:
        t_redir = setup.get("t_redirect_s", 0.0)
        t_ins   = setup.get("t_insert_s", 0.0)
        print(f"[M1 update timing] reload on the node (AOT open+load): {t_redir*1000:.3f} ms"
              f"   [clang, offline: {setup.get('t_compile_s', 0.0)*1000:.1f} ms, 0 if cached]")
        print(f"[M1 update timing] weight insert   (n/a, pure hardcoded): {t_ins*1000:.3f} ms")
        print(f"[M1 update timing] total:                               {(t_redir+t_ins)*1000:.3f} ms")
        print()

    print(f"[setup] scale={scale}  weights={len(weights)}  disp_fd={disp.fd}")
    print("      All pipelines tested via the REAL dispatcher (full tail-call chain,")
    print("      dispatcher -> ... -> action) -- no leaf-priming shortcut.")
    print("      argmax -> mac_table[class] -> bpf_redirect.")
    print("      PASS = retval in {0,4} (redirect) AND cls_stats[ref_cls] > 0.")
    ref_ingress_port = 0

    ref_node_index = setup.get("static_node")

    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        ref_cls, ref_val, h1, h2 = ref_infer(weights, scale, ttl, model_id,
                                             ingress_port=ref_ingress_port,
                                             node_index=ref_node_index)
        frame = build_frame(model_id, ttl, scale)
        _reset_stats(setup)
        retval, dur_ns = prog_test_run(disp.fd, frame, repeat=1, ingress_ifindex=0)
        cls_count = _read_u64(cs, ref_cls) if cs is not None else 0
        expect = XDP_REDIRECT_PASS
        m = _mut()
        if m is not None:
            import model_under_test as MUT
            expect = MUT.expected_retvals(m, ref_cls)
        ok = (retval in expect) and (cls_count > 0)
        detail = f"retval={retval} cls_stats[{ref_cls}]={cls_count}"
        if m is not None:
            detail += f" ({m.semantics.action_of(ref_cls)})"
        if retval == XDP_PASS and XDP_PASS not in expect:
            ok = False
            detail += "  <-- XDP_PASS: inference did not complete / no mac_table entry"
        lat_us = dur_ns / 1000
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"  TTL={ttl:3d}  ref_cls={ref_cls}  ref_val={ref_val:8d}  {detail}  lat={lat_us:.2f}us  [{status}]")
    print("-" * 70)
    print(f"Results: {passed} PASS / {failed} FAIL  (TTL range [{ttl_min},{ttl_max}])")
    print(f"pkt_stats: HIT={_read_u64(ps,0)}  MISS={_read_u64(ps,1)}  DROP={_read_u64(ps,2)}")
    return failed


def run_sparse_hetero(model_dir: str, model_id: int, ttl_min: int, ttl_max: int, repeat: int) -> int:
    """Heterogeneous-sparse counterpart to run()."""
    print("=" * 70)
    print(f" IPA/eBPF BPF_PROG_TEST_RUN  --  method=sparse-hetero  model_id={model_id}  dir={model_dir}")
    print("=" * 70)
    print()
    setup = setup_sparse_hetero(model_id, model_dir)
    b, disp = setup["b"], setup["disp"]  # noqa: F841  (b keeps the maps/program alive)
    weights, scale, shape = setup["weights"], setup["scale"], setup["shape"]
    n_in, n_out, hidden_dims = shape["n_in"], shape["n_out"], tuple(shape["hidden_dims"])
    features = shape["features"]
    ps, cs = setup["pkt_stats"], setup["cls_stats"]
    map_values = setup["map_values"]

    iface_size = next((f["size"] for f in features if f["type"] == "ingress_iface"), 0)

    feats_str = ", ".join(f"{f['type']}[{f['size']}]" for f in features)
    print(f"[setup] scale={scale}  weights={len(weights)}  n_in={n_in}  n_out={n_out}")
    print(f"      features: {feats_str}")
    print(f"      seeded maps: {map_values}")
    semantics = setup["semantics"]
    for _l in semantics.summary().splitlines():
        print(f"      {_l}")
    print("      IV built locally (maps + TTL + node one-hot). PASS = the "
          "action the semantics declare for ref_cls.")

    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        ref_cls, ref_val = ref_infer_sparse(
            weights, features, hidden_dims, n_out, ttl, model_id,
            map_values, ingress_port=0, scale=scale)
        frame = build_frame_sparse(model_id, ttl, scale, n_in, n_out)
        _reset_stats(setup, n_classes=n_out)
        retval, dur_ns = prog_test_run(disp.fd, frame, repeat=1)
        action = semantics.action_of(ref_cls)
        if action == "FORWARD":
            cls_count = _read_u64(cs, ref_cls)
            ok = (retval in XDP_REDIRECT_PASS) and (cls_count > 0)
            detail = (f"FORWARD(port {semantics.port_of(ref_cls)}) "
                      f"retval={retval} cls_stats[{ref_cls}]={cls_count}")
        elif action == "DROP":
            cls_count = _read_u64(ps, 2)
            ok = (retval == 1) and (cls_count > 0)
            detail = f"DROP retval={retval} pkt_stats[DROP]={cls_count}"
        else:
            cls_count = _read_u64(cs, ref_cls)
            ok = (retval == 2) and (cls_count > 0)
            detail = (f"UNUSED retval={retval} (expect XDP_PASS=2) "
                      f"cls_stats[{ref_cls}]={cls_count}")
        lat_us = dur_ns / 1000
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"  TTL={ttl:3d}  ref_cls={ref_cls}  ref_val={ref_val:8d}  {detail}  lat={lat_us:.2f}us  [{status}]")
    print("-" * 70)
    print(f"Results: {passed} PASS / {failed} FAIL  (TTL range [{ttl_min},{ttl_max}])")
    print(f"pkt_stats: HIT={_read_u64(ps,0)}  MISS={_read_u64(ps,1)}  DROP={_read_u64(ps,2)}")
    return failed


def main():
    p = argparse.ArgumentParser(description="IPA/eBPF pipeline verifier")
    p.add_argument("--method", choices=["p1_static", "hardcoded", "template", "modular", "sparse-hetero"],
                   default="hardcoded")
    p.add_argument("--model-id", type=int, default=0)
    p.add_argument("--model", default=None,
                   help="model (see model_under_test.py); without it: the "
                        "configured checkpoint")
    p.add_argument("--topology", default=None,
                   help="scenario in topologies/ (without it: the compatible one)")
    p.add_argument("--model-dir", default=os.path.join(SHARED_DIR, "test", "fixtures", "sparse_hetero_11"),
                   help="sparse-hetero: directory with model_meta.json (+ weights.json)")
    p.add_argument("--ttl-min", type=int, default=2)
    p.add_argument("--ttl-max", type=int, default=10)
    p.add_argument("--repeat", type=int, default=1000, help="BPF_PROG_TEST_RUN repeat count for latency measurement")
    args = p.parse_args()
    import model_under_test as MUT
    MUT.select(args.model, args.topology)
    if MUT.active() is None:
        args.model = MODEL_PT
    if args.method == "sparse-hetero":
        sys.exit(run_sparse_hetero(args.model_dir, args.model_id, args.ttl_min, args.ttl_max, args.repeat))
    sys.exit(run(args.method, args.model_id, args.model, args.ttl_min, args.ttl_max, args.repeat))

if __name__ == "__main__":
    main()
