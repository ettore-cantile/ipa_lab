#!/usr/bin/env python3
"""
verify_prog_run.py  --  BPF_PROG_TEST_RUN verifier for the 3 IPA pipelines.

Lives in shared/test/; the pipeline modules it imports (ebpf_program,
ebpf_template_arch, ebpf_modular, extract_weights) live one level up in
shared/, so SHARED_DIR is added to sys.path below.
"""

import os
import sys
import json
import struct
import time
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

class _XdpMd(ct.Structure):
    """struct xdp_md — kept for reference; NOT passed as ctx_in (see below)."""
    _fields_ = [
        ("data",            ct.c_uint32),
        ("data_end",        ct.c_uint32),
        ("data_meta",       ct.c_uint32),
        ("ingress_ifindex", ct.c_uint32),
        ("rx_queue_index",  ct.c_uint32),
        ("egress_ifindex",  ct.c_uint32),
    ]

# TEST_RUN_DEFAULT_INGRESS_IFINDEX: empirically observed value of
# ctx->ingress_ifindex under BPF_PROG_TEST_RUN when no ctx_in is supplied
# (this kernel's dummy test device). A prior attempt to force it to 0 via a
# zeroed xdp_md ctx_in caused every packet to be dropped before inference
# (100% XDP_PASS on all 3 pipelines) -- the exact data/data_end/data_meta
# semantics BPF_PROG_TEST_RUN expects for ctx_in are kernel-version-specific
# and were not verified against this kernel. Simpler and verified-safe:
# don't fight the default, just match it on the Python reference side.
TEST_RUN_DEFAULT_INGRESS_IFINDEX = 1

def prog_test_run(prog_fd: int, frame: bytes, repeat: int = 1, ingress_ifindex: int = None):
    """Run an XDP program on `frame` via BPF_PROG_TEST_RUN (no ctx_in --
    ctx_in field semantics for xdp_md are not reliably portable across
    kernels, see TEST_RUN_DEFAULT_INGRESS_IFINDEX). `ingress_ifindex` is
    accepted for API compatibility but unused; the kernel's default test
    device ifindex is used (see TEST_RUN_DEFAULT_INGRESS_IFINDEX)."""
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


# Max BPF_PROG_TEST_RUN repetitions per syscall when the program MUTATES the
# packet. The kernel copies data_in into a page once and then re-runs the
# program on THAT page `repeat` times, never restoring it in between. The
# datapath decrements the TTL, so one large `repeat` walks the TTL down to 1
# after a couple of hundred runs and every run after that measures the
# TTL-expired short-circuit instead of the inference path. Chunking with a fresh
# frame keeps every measured run on the real path. 200 < 255-1, so a frame built
# with BENCH_TTL survives a whole chunk.
TEST_RUN_MAX_CHUNK = 200
BENCH_TTL          = 255


# Chunks per measurement. The point of a large `repeat` is to amortise the
# syscall cost over many in-kernel runs; 200 runs already does that, and the
# reported figure is the MINIMUM per-run average across chunks, which stops
# improving long before 250 chunks. Capping here keeps the suite fast: without
# it a repeat=50000 request became 250 syscalls per trial (1750 per pipeline,
# 7000 for the suite) for no gain in the statistic actually reported.
TEST_RUN_MAX_CHUNKS = 25


def prog_test_run_bench(prog_fd: int, make_frame, total_repeat: int,
                        max_chunks: int = TEST_RUN_MAX_CHUNKS):
    """Time a packet-mutating program in TTL-safe chunks.

    `make_frame` is called once per chunk to get a pristine frame -- required
    because the kernel never restores the packet buffer between repetitions and
    the datapath decrements the TTL (see TEST_RUN_MAX_CHUNK).

    The kernel reports the AVERAGE ns/run for each chunk; the minimum across
    chunks is returned, the same one-sided-noise reasoning the suite uses for
    its min-of-N trials. `total_repeat` is a target: it is capped at
    max_chunks * TEST_RUN_MAX_CHUNK runs, because the minimum-of-averages does
    not keep improving past that and the extra syscalls are pure wall time.

    Returns (retval_of_last_chunk, min_ns_per_run).
    """
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
    """Like prog_test_run(), but also returns the packet the program produced.

    BPF_PROG_TEST_RUN writes the (possibly modified) packet back into data_out,
    which is how the TTL decrement and the recomputed IP checksum can be checked
    for real instead of being taken on trust. Separate from prog_test_run() so
    the latency path keeps its exact shape.
    """
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
    """True if the 20-byte IPv4 header checksums correctly. A valid header sums
    (in one's complement, 16-bit words, checksum field included) to 0xFFFF."""
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

MODEL_PT     = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
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
_PercpuLeaf = ct.c_longlong * _NR_CPUS

def _percpu_arr(val: int) -> "_PercpuLeaf":
    return _PercpuLeaf(*([int(val)] * _NR_CPUS))

def load_weights(model_path=MODEL_PT):
    from extract_weights import extract_weights_int8
    weights = extract_weights_int8(model_path)
    scale = 128
    if os.path.exists(WEIGHTS_JSON):
        with open(WEIGHTS_JSON) as f:
            scale = int(json.load(f).get("scale_factor", 128))
    return weights, scale

def _ip_csum(hdr20: bytes) -> int:
    """Standard IPv4 header checksum over a 20-byte header whose checksum field
    is zero.

    The synthetic frames used to ship with checksum 0 -- an invalid header. That
    was harmless while the datapath never touched the IP header, but the TTL
    decrement now updates the checksum INCREMENTALLY, and an incremental update
    only preserves correctness if the input was already correct. So the frames
    have to carry a real checksum, or the output checksum is unverifiable.
    """
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
    # exactly 20 format letters (3 B + 1 H + 16 B) = 21 bytes, matching
    # sizeof(struct ipa_hdr) in the eBPF C source.
    ipa = struct.pack('!BBBHBBBBBBBBBBBBBBBB', model_id, 0, 0, scale, 65, 7, 2, 4, 3, 0, 65, 0, 0, 0, 0, 0, 0, 1, 0, 7)
    return eth + ip + udp + ipa

def ref_infer(weights, scale: int, ttl: int, model_id: int, ifindex: int = 0):
    def s8(v):
        return ct.c_int8(int(v) & 0xFF).value
    N_IN, N_H1, N_H2, N_OUT = 65, 4, 4, 7
    off_fc1_b = N_IN * N_H1
    off_fc2_w = off_fc1_b + N_H1
    off_fc2_b = off_fc2_w + N_H1 * N_H2
    off_out_w = off_fc2_b + N_H2
    off_out_b = off_out_w + N_H2 * N_OUT
    x = [0] * N_IN
    # link_state features [0..5] = 1 (all egress links up) -- matches the
    # verify baseline where the link_state map is seeded to all-up.
    for i in range(6):
        x[i] = 1
    x[12] = ttl
    if 1 <= ifindex <= 6:
        x[5 + ifindex] = 1
    if 0 <= model_id <= 51:
        x[13 + model_id] = 1
    h1 = []
    for j in range(N_H1):
        acc = s8(weights[off_fc1_b + j])
        for i in range(N_IN):
            acc += x[i] * s8(weights[j * N_IN + i])
        h1.append(max(0, acc))
    h2 = []
    for j in range(N_H2):
        acc = s8(weights[off_fc2_b + j])
        for i in range(N_H1):
            acc += h1[i] * s8(weights[off_fc2_w + j * N_H1 + i])
        h2.append(max(0, acc))
    # No numeric sentinel: the logits are unbounded int64-scale accumulations, so
    # any finite starting value can be above ALL of them and pin best_cls to 0.
    best_val, best_cls = None, 0
    for k in range(N_OUT):
        acc = s8(weights[off_out_b + k])
        for i in range(N_H2):
            acc += h2[i] * s8(weights[off_out_w + k * N_H2 + i])
        if best_val is None or acc > best_val:
            best_val, best_cls = acc, k
    return best_cls, best_val, h1, h2


def build_frame_sparse(model_id: int, ttl: int, scale: int, n_in: int, n_out: int) -> bytes:
    """Frame for a heterogeneous sparse model: same skeleton as build_frame()
    but the IPA header carries the descriptor's real input_size/output_size.
    No payload -- the sparse route builds the IV locally (TTL from this frame's
    IP header, dense_vector features from BPF maps seeded by the caller, node
    one-hot from model_id, ingress_iface from ctx->ingress_ifindex)."""
    eth = b'\x00'*6 + b'\x00'*6 + struct.pack('!H', 0x0800)
    ip  = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 48, 0, 0, ttl, 17, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    ip  = ip[:10] + struct.pack('!H', _ip_csum(ip)) + ip[12:]
    udp = struct.pack('!HHHH', 12345, 9999, 28, 0)
    ipa = struct.pack('!BBBHBBBBBBBBBBBBBBBB', model_id, 0, 0, scale, n_in, n_out, 2, 4,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, n_out)
    return eth + ip + udp + ipa


def ref_infer_sparse(weights, features, hidden_dims, n_out, ttl, model_id,
                     map_values, ifindex, ifindex_table):
    """Python reference for the heterogeneous sparse route: builds the input
    vector feature by feature from the descriptor (mirroring the per-kind C
    generators in ebpf_program.py), then runs the MLP + argmax. Returns
    (best_cls, best_val); best_cls == n_out-1 means DROP.

    map_values: {map_name: [values]} the caller seeded into the dense_vector
    maps (link_state, queue_state). ifindex/ifindex_table: the raw
    ctx->ingress_ifindex and the kernel-ifindex->logical mapping used by the
    ingress_iface one-hot (mirrors generate_ebpf_hardcoded's default table)."""
    import model_meta as mm
    def s8(v):
        return ct.c_int8(int(v) & 0xFF).value

    n_in = sum(f["size"] for f in features)
    x = [0] * n_in
    o = 0
    for f in features:
        t, size = f["type"], f["size"]
        kind = mm.FEATURE_CATALOG[t]["kind"]
        if kind == "scalar":                       # ttl
            x[o] = ttl & 0xff
        elif kind == "dense_vector_map":           # link_state / queue_occupancy
            vals = map_values.get(mm.FEATURE_CATALOG[t]["map"], [0] * size)
            for i in range(size):
                x[o + i] = vals[i]
        elif kind == "onehot" and t == "ingress_iface":
            logical = 0
            for li, ki in enumerate(ifindex_table[:size], start=1):
                if ki == ifindex:
                    logical = li
                    break
            if 1 <= logical <= size:
                x[o + (logical - 1)] = 1
        elif kind == "onehot" and t == "node":
            if 0 <= model_id < size:
                x[o + model_id] = 1
        o += size

    # Generic per-layer reference: layer_sizes = [n_in, h1, ..., hk, n_out].
    # Same weight layout ebpf_program.generate_ebpf_hardcoded now emits (n_prev*n_cur
    # weights then n_cur biases, layer by layer) -- reduces to the historical
    # 2-hidden-layer math when hidden_dims == (n_h1, n_h2).
    layer_sizes = [n_in] + [int(d) for d in hidden_dims] + [n_out]
    off = 0
    acts = x
    for li in range(1, len(layer_sizes)):
        n_prev, n_cur = layer_sizes[li - 1], layer_sizes[li]
        w_off, b_off = off, off + n_prev * n_cur
        off = b_off + n_cur
        is_out = (li == len(layer_sizes) - 1)
        nxt = []
        for j in range(n_cur):
            acc = s8(weights[b_off + j])
            for i in range(n_prev):
                acc += acts[i] * s8(weights[w_off + j * n_prev + i])
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

def _install_mac_table(b, name, ifindex=2, n_classes=6):
    """Pre-install the class->action map for classes 0..n_classes-1 (the
    argmax output). The NN picks the class; this dictionary resolves it to
    {ifindex, MACs}. n_classes defaults to 6 (the historical egress count);
    pass n_out-1 for a model with a different number of egress classes."""
    action = _FwdAction(
        ifindex=ifindex,
        src_mac=(ct.c_uint8 * 6)(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
        dst_mac=(ct.c_uint8 * 6)(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
    )
    for cls in range(n_classes):
        b[name][ct.c_uint32(cls)] = action

def _prime_scratch_p3(b, h2: list, scale: int, model_id: int, layer_idx: int, ingress_ifindex: int = 0, ttl: int = 0):
    """Seed scratch_acts/scratch_meta so that calling layer_hidden directly
    (bypassing dispatcher + earlier hops) exercises just the model's LAST
    layer: layer_idx must be n_layers-1 so layer_hidden's own
    (layer_idx+1==n_layers) check resolves to argmax+forward. The weight
    offset for that layer comes from layer_shapes[{model_id, layer_idx}]
    (already populated by load_modular_weights), not from scratch_meta --
    unlike the old fixed 3-block design there is no w_off_out slot anymore."""
    # scratch_acts is now ONE struct-valued per-CPU entry (struct act_vec) holding
    # the whole activation vector, not one entry per slot -- see ebpf_modular.py.
    # Seed key 0 with the activations placed in the struct's v[] array.
    acts_tbl = b["scratch_acts"]
    leaf = acts_tbl.Leaf()
    for cpu in range(len(leaf)):
        for i, v in enumerate(h2[:4]):
            leaf[cpu].v[i] = int(v)
    acts_tbl[ct.c_int(0)] = leaf
    meta = {0: model_id, 1: scale, 2: layer_idx, 3: ingress_ifindex, 4: ttl}
    for slot, val in meta.items():
        b["scratch_meta"][ct.c_int(slot)] = _percpu_arr(val)


def _seed_link_state(b, val: int = 1):
    """Seed the link_state map [0..5] with `val` (1=up) if the program has it.
    All three pipelines read these 6 slots as the model's first input features
    (egress up/down). Verify runs the 'all links up' baseline, so it must match
    ref_infer's x[0..5]=1."""
    try:
        from common import write_vector_map
        write_vector_map(b, "link_state", [int(val)] * 6)
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
BPF_ARRAY(pkt_stats, __u64, 3);
BPF_ARRAY(cls_stats, __u64, 7);

/* CTR_INC(): real per-packet map-lookup counter, active only when
 * IPA_COUNT_LOOKUPS is #defined before this source (measurement builds --
 * see common.py instrument_map_lookups()). No-op otherwise, so the baseline
 * program whose instructions and latency are measured is byte-identical to
 * what it was before this block existed.
 *
 * Added so the baseline gets a MEASURED lookup count like the three pipelines.
 * count_lookups() had no 'baseline' branch, so the design-space table printed
 * n/a for it -- and the figure that had been reported for the baseline was 0,
 * which is wrong: the hit path below does three lookups (mac_table, pkt_stats,
 * cls_stats). The baseline is the reference floor the other pipelines are
 * compared against, so its floor of map lookups has to be measured, not
 * assumed to be zero. */
#ifdef IPA_COUNT_LOOKUPS
BPF_PERCPU_ARRAY(lookup_ctr, __u64, 1);
/* BCC's rewriter refuses table.lookup() calls that appear textually inside a
 * macro expansion -- must be a real function, not a #define body. */
static inline __attribute__((always_inline)) void ctr_inc(void) {
    int _lci = 0;
    __u64 *_lcv = lookup_ctr.lookup(&_lci);
    if (_lcv) *_lcv += 1;   /* per-CPU: no atomic needed */
}
#define CTR_INC() ctr_inc()
#else
#define CTR_INC() do {} while (0)
#endif

/* EMPTY/BASELINE pipeline: the SAME packet parse as the hardcoded dispatcher
 * (eth/ip/udp/ipa, bounds-checked) + the SAME action (mac_table -> MAC rewrite
 * -> bpf_redirect), but NO dispatch tail-call and NO neural-net inference. It
 * redirects a FIXED class 0 (no argmax). Measured with the identical
 * BPF_PROG_TEST_RUN harness as the real pipelines, so it is the reference floor:
 * hardcoded_latency - baseline_latency isolates the cost of the extra work
 * hardcoded does (tail-call + double parse + the MLP). If hardcoded ~ baseline,
 * the XDP+parse+redirect FRAMEWORK floor dominates and the int8 65-4-4-7 net is
 * nearly free -- which is why the hardcoded --kernel throughput looks so high. */
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
        /* The baseline is the reference floor the pipelines are compared
         * against, so it must do the SAME framework work they do -- TTL
         * decrement included. Leaving it out would push the cost of the TTL
         * update into the "cost of the neural network" subtraction. */
        if (ip->ttl <= 1) {
            int ti = 1; __u64 *tv = pkt_stats.lookup(&ti);
            if (tv) __sync_fetch_and_add(tv, 1);
            return XDP_PASS;
        }
        ipa_ttl_dec(ip);
        int si = 0; __u64 *v = pkt_stats.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        __u64 *cv = cls_stats.lookup(&cls);
        if (cv) __sync_fetch_and_add(cv, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    int mi = 1; __u64 *mv = pkt_stats.lookup(&mi);
    if (mv) __sync_fetch_and_add(mv, 1);
    return XDP_PASS;
}
"""


def setup_baseline(model_id: int, model_path: str):
    """Empty/baseline pipeline: XDP parse + redirect, NO neural-net inference,
    NO tail-call. Same BPF_PROG_TEST_RUN harness as the real pipelines, so it is
    the reference FLOOR for the throughput/latency comparison -- it answers "how
    much of the hardcoded number is just the XDP+parse+redirect framework vs the
    actual inference". Returns the same dict shape as the other setups."""
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
BPF_ARRAY(pkt_stats, __u64, 3);
BPF_ARRAY(cls_stats, __u64, 7);
BPF_PROG_ARRAY(tail_progs, 2);

/* SAME parse + SAME action as xdp_baseline (EBPF_BASELINE), but the action is
 * reached via ONE bpf_tail_call hop instead of inline. Comparing this
 * program's latency against xdp_baseline's isolates PURE tail-call overhead
 * (one PROG_ARRAY jump), with the parse and the redirect logic held
 * identical -- neither MLP cost nor a second packet parse is in this delta,
 * unlike hardcoded_latency - baseline_latency which bundles tail-call +
 * double-parse + MLP together. */
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
    if (mv) __sync_fetch_and_add(mv, 1);
    return XDP_PASS;
}

int xdp_baseline_action(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    /* Re-parse the IP header: this leaf is reached through a tail call, so it
     * does not inherit the dispatcher's pointers. Needed only for the TTL
     * decrement -- the packet was already validated upstream, but the verifier
     * requires the bounds check again regardless. */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 cls = 0;   /* fixed egress class -- no inference, no argmax */
    struct fwd_action *action = mac_table.lookup(&cls);
    if (action && action->ifindex != 0) {
        /* The baseline is the reference floor the pipelines are compared
         * against, so it must do the SAME framework work they do -- TTL
         * decrement included. Leaving it out would push the cost of the TTL
         * update into the "cost of the neural network" subtraction. */
        if (ip->ttl <= 1) {
            int ti = 1; __u64 *tv = pkt_stats.lookup(&ti);
            if (tv) __sync_fetch_and_add(tv, 1);
            return XDP_PASS;
        }
        ipa_ttl_dec(ip);
        int si = 0; __u64 *v = pkt_stats.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        __u64 *cv = cls_stats.lookup(&cls);
        if (cv) __sync_fetch_and_add(cv, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    int mi = 1; __u64 *mv = pkt_stats.lookup(&mi);
    if (mv) __sync_fetch_and_add(mv, 1);
    return XDP_PASS;
}
"""


def setup_baseline_tailcall(model_id: int, model_path: str):
    """Same floor as setup_baseline(), but the redirect action is reached via
    ONE bpf_tail_call hop (see EBPF_BASELINE_TAILCALL docstring). Comparing
    against setup_baseline() isolates pure tail-call overhead, decoupled from
    any MLP cost or second packet parse."""
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
    """
    Load the pure hardcoded eBPF program (Pipeline 1).

    There is NO model_cache / weight map anymore: the weights are C literals
    compiled into the program, so updating the model = recompiling+reloading the
    whole program. We therefore measure only the redirect/reload cost:
      - t_redirect_s : BPF compile + load_func into the kernel (the real update cost)
      - t_insert_s   : 0 (no runtime weight insertion in the pure hardcoded design)
    """
    from ebpf_program import build_combined_hardcoded_source
    weights, scale = load_weights(model_path)
    src = build_combined_hardcoded_source([(model_id, weights, scale, None)])

    # --- redirect/reload: eBPF compile + load into the kernel ---
    t0 = time.perf_counter()
    b  = BPF(text=src)
    model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
    fn = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ct.c_int(model_id)] = ct.c_int(model_fn.fd)
    t_redirect_s = time.perf_counter() - t0

    # Dispatcher tail-calls model_progs[model_id] -- 1 tail call, matching
    # the design-space spec's hardcoded pipeline (packet -> dispatcher ->
    # tail call -> model_<id> -> action). Still zero weight-map lookups.
    disp = fn

    # link_state[0..5] = 1 (all egress links up) -- input feature, not a weight.
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table")

    progs = {"ipa_switch_hardcoded": fn.fd, f"model_{model_id}": model_fn.fd}

    return {
        "b": b, "fn": model_fn, "disp": disp,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats"],
        "pkt_stats": b["pkt_stats"],
        "pipeline": 1,
        "progs": progs,
        # real model-update timing: pure hardcoded = full recompile, no weight insert
        "t_redirect_s": t_redirect_s,
        "t_insert_s": 0.0,
    }


def setup_template(model_id: int, model_path: str):
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_GENERIC_2LAYER, load_arch_weights)
    weights, scale = load_weights(model_path)
    src = "#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_GENERIC_2LAYER
    b = BPF(text=src)
    disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
    leaf_fn = b.load_func("arch_generic_2layer", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
    load_arch_weights(b, weights, model_id=model_id, scale=scale)  # default n_h1=n_h2=4 matches weights.json
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
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights, scale = load_weights(model_path)
    b = BPF(text=EBPF_MODULAR_FULL)
    disp_fn   = b.load_func("modular_dispatcher", BPF.XDP)
    fn_first  = b.load_func("layer_first",  BPF.XDP)
    fn_hidden = b.load_func("layer_hidden", BPF.XDP)
    # slot 0 = layer_first (always hop 0), slots 1..15 = layer_hidden
    # (always a later hop) -- see ebpf_modular.py module docstring for why.
    b["layer_chain"][ct.c_int(0)] = ct.c_int(fn_first.fd)
    for i in range(1, 16):  # LAYER_CHAIN_SIZE
        b["layer_chain"][ct.c_int(i)] = ct.c_int(fn_hidden.fd)
    layer_dims = [(65, 4), (4, 4), (4, 7)]
    n_layers = len(layer_dims)
    load_modular_weights(b, weights, model_id=model_id, scale=scale, layer_dims=layer_dims)
    _seed_link_state(b, 1)
    _install_mac_table(b, "mac_table_t3")
    print(f"[P3 setup] nr_cpus={_NR_CPUS}  PERCPU ctypes Array enabled")
    return {
        # "fn" is the direct BPF_PROG_TEST_RUN target used by run() below to
        # exercise the model's LAST layer in isolation (see _prime_scratch_p3):
        # for a 3-layer model that's always layer_hidden (layer_idx>=1).
        "b": b, "fn": fn_hidden, "disp": disp_fn,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats_t3"],
        "pkt_stats": b["pkt_stats_t3"],
        "pipeline": 3,
        "last_layer_idx": n_layers - 1,
        # n_tail = actual runtime tail-call hops for this model (dispatcher ->
        # layer_first -> layer_hidden x (n_layers-1)): NOT len(progs)-1 --
        # there are only 2 distinct layer programs regardless of depth.
        "n_tail": n_layers,
        "progs": {
            "modular_dispatcher": disp_fn.fd,
            "layer_first": fn_first.fd,
            "layer_hidden": fn_hidden.fd,
        },
    }


def setup_sparse_hetero(model_id: int, model_dir: str):
    """
    Load a heterogeneous sparse model (explicit per-model feature descriptor,
    see model_meta.py) from a fixture directory. Seeds every dense_vector map
    the descriptor uses (link_state and/or queue_state) with KNOWN
    deterministic values and returns them under "map_values" so
    ref_infer_sparse can rebuild the same input vector on the Python side.
    """
    from ebpf_program import load_and_generate
    import model_meta as mm

    model_path = os.path.join(model_dir, "model.pt")  # need not exist
    meta = mm.load_model_meta(model_path)
    if meta.get("scenario", "sparse") != "sparse" or not meta.get("features"):
        raise ValueError(f"{model_dir}/model_meta.json is not a sparse model with a 'features' descriptor")
    shape = mm.derive_shape(meta)

    src, weights, scale = load_and_generate(model_path, model_id=model_id, meta=meta)
    b = BPF(text=src)
    model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
    fn = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ct.c_int(model_id)] = ct.c_int(model_fn.fd)

    n_out = shape["n_out"]
    _install_mac_table(b, "mac_table", n_classes=n_out - 1)

    # Seed each dense_vector map with known values (deterministic, arbitrary).
    # Each map holds all its slots in one struct-valued entry (single lookup).
    from common import write_vector_map
    map_values = {}
    for feat_type, map_name in mm.feature_maps(shape["features"]).items():
        size = next(f["size"] for f in shape["features"] if f["type"] == feat_type)
        vals = [(i * 7 + 3) % 16 for i in range(size)]
        write_vector_map(b, map_name, vals)
        map_values[map_name] = vals

    return {
        "b": b, "fn": model_fn, "disp": fn,
        "weights": weights, "scale": scale, "shape": shape,
        "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"],
        "pipeline": 1, "map_values": map_values,
        "progs": {"ipa_switch_hardcoded": fn.fd, f"model_{model_id}": model_fn.fd},
    }


def count_lookups(method: str, model_id: int, model_path: str, ttl: int = None, repeat: int = None) -> float:
    """
    Real per-packet map-lookup count for `method`, measured via a dedicated
    instrumented build (every `.lookup()` call wrapped with CTR_INC(), see
    common.py instrument_map_lookups()). This compiles a SEPARATE BPF object
    from the one used for latency/instruction measurement -- the counting
    overhead never contaminates the hardware-measured performance numbers,
    only this metric. Runs `repeat` packets through the dispatcher (the real
    per-packet path, tail calls included) and returns lookup_ctr[0]/repeat.

    """
    from common import instrument_map_lookups, count_instrumented_sites

    def _report(raw_src):
        """Print where the instrumentation weight lands, per eBPF function, so a
        'program too large' rejection of the measurement build is diagnosable
        from the log instead of being a bare failure."""
        sites = count_instrumented_sites(raw_src)
        total = sum(sites.values())
        detail = "  ".join(f"{k}={v}" for k, v in sorted(sites.items()))
        print(f"[count_lookups] {method}: instrumenting {total} lookup sites "
              f"({detail})")

    ttl, repeat = _count_lookups_defaults(ttl, repeat)
    weights, scale = load_weights(model_path)

    if method == "baseline":
        # The reference floor: same parse + same mac_table action as the real
        # pipelines, no inference. Its lookups are the framework cost every
        # pipeline pays, so subtracting it isolates the model's own lookups.
        src = "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(EBPF_BASELINE)
        _report(EBPF_BASELINE)
        b = BPF(text=src)
        disp_fn = b.load_func("xdp_baseline", BPF.XDP)
        _install_mac_table(b, "mac_table")
    elif method == "hardcoded":
        from ebpf_program import build_combined_hardcoded_source
        raw = build_combined_hardcoded_source([(model_id, weights, scale, None)])
        src = "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(raw)
        _report(raw)
        b = BPF(text=src)
        model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
        disp_fn  = b.load_func("ipa_switch_hardcoded", BPF.XDP)
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(model_fn.fd)
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

    frame = build_frame(model_id, ttl, scale)
    # lookup_ctr is a BPF_PERCPU_ARRAY (no atomic on the hot path -- the same
    # per-CPU counter pattern the design-space analysis recommends for
    # pkt_stats/cls_stats). Zero every CPU's copy, then sum them back.
    ctr = b["lookup_ctr"]
    ctr[ct.c_int(0)] = ctr.Leaf()          # zeroed per-CPU array
    prog_test_run(disp_fn.fd, frame, repeat=repeat)
    total = sum(int(v) for v in ctr[ct.c_int(0)])
    return total / float(repeat)


def _count_lookups_defaults(ttl, repeat):
    """TTL and repetition count for a lookup measurement.

    Both default to values that keep every run on the FORWARDING path. The old
    defaults (ttl=5, repeat=2000) were written when the datapath did not modify
    the packet. Now it decrements the TTL and BPF_PROG_TEST_RUN never restores
    the buffer between repetitions, so the TTL hit 1 after four runs and the
    remaining 1996 took the expiry short-circuit -- which does one lookup fewer
    (no cls_stats on a non-forward). The reported figure was therefore the
    EXPIRY path's lookup count, off by one on every pipeline.
    """
    return (BENCH_TTL if ttl is None else ttl,
            TEST_RUN_MAX_CHUNK if repeat is None else repeat)


def _read_u64(table, key_val):
    try:
        return int(table[ct.c_int(key_val)].value)
    except Exception:
        try:
            return int(table[ct.c_uint32(key_val)].value)
        except Exception:
            return 0

def _reset_stats(setup, n_classes=7):
    ps = setup["pkt_stats"]
    for i in range(3):
        ps[ct.c_int(i)] = ct.c_ulonglong(0)
    cs = setup.get("cls_stats")
    if cs is not None:
        for i in range(n_classes):
            try:
                cs[ct.c_uint32(i)] = ct.c_ulonglong(0)
            except Exception:
                pass

XDP_PASS = 2
XDP_REDIRECT_PASS = frozenset({0, 4})


def _fired_cls_p1(setup) -> int:
    """After a single-packet run of Pipeline 1, return the egress class that
    fired: 0..5 = redirect on that class, 6 = DROP, -1 = nothing."""
    cs = setup["cls_stats"]
    for c in range(6):
        if _read_u64(cs, c) > 0:
            return c
    if _read_u64(setup["pkt_stats"], 2) > 0:
        return 6
    return -1


# TTL sweeps start at 2, not 1: a forwarding hop now decrements the TTL and
# refuses to forward a packet whose TTL would reach 0 (see ipa_ttl_dec in the
# eBPF sources). TTL=1 is therefore a legitimate NON-forward, and including it
# in a sweep that asserts 'the packet was redirected' would fail by design.
# TTL=1 is covered separately by the dedicated expiry test.
def verify_ttl_handling(method: str, model_id: int, model_path: str):
    """Prove the forwarding hop behaves like a router with respect to the TTL.

    Two properties, both checked against the packet the program actually
    produced (BPF_PROG_TEST_RUN writes it back to data_out), not against the
    source code:

      forwarded  -- a packet with a healthy TTL is redirected AND comes out
                    with TTL decremented by exactly 1 AND with a valid IP
                    header checksum. Without the incremental checksum fix the
                    TTL would change and the checksum would not, producing a
                    packet every downstream router silently discards -- a
                    failure that is invisible in a return-code-only test.
      expired    -- a packet with TTL=1 is NOT forwarded. A hop must not emit a
                    packet with TTL 0; before this existed the datapath never
                    wrote the TTL at all, so a redirected packet looped forever.

    Returns (n_pass, n_fail, details).
    """
    setup_fn = {"hardcoded": setup_hardcoded,
                "template":  setup_template,
                "modular":   setup_modular}[method]
    setup = setup_fn(model_id, model_path)
    b, disp = setup["b"], setup["disp"]          # noqa: F841 (b keeps maps alive)
    scale = setup["scale"]
    ps = setup["pkt_stats"]

    npass, nfail, details = 0, 0, []

    # --- forwarded: TTL 5 must come out as TTL 4 with a valid checksum ---
    _reset_stats(setup)
    frame = build_frame(model_id, 5, scale)
    retval, _, out = prog_test_run_data(disp.fd, frame)
    if len(out) >= 34:
        ttl_out = out[14 + 8]                    # eth(14) + offset of TTL in IP hdr
        csum_ok = ip_checksum_ok(out[14:34])
    else:
        ttl_out, csum_ok = None, False
    forwarded = retval in (0, 4)
    if forwarded and ttl_out == 4 and csum_ok:
        npass += 1
        details.append(f"{method}: TTL 5 -> forwarded, out TTL={ttl_out}, checksum OK")
    else:
        nfail += 1
        details.append(f"{method}: TTL 5 -> retval={retval} out_ttl={ttl_out} "
                       f"csum_ok={csum_ok} (atteso retval in (0,4), ttl 4, csum OK)")

    # --- expired: TTL 1 must NOT be forwarded ---
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
                       f"(atteso NON inoltrato)")

    return npass, nfail, details


def probe_link_down(model_path, model_id: int = 0, ttl_min: int = 2, ttl_max: int = 6):
    """Prove that link_state is a live routing input: for each TTL and each
    egress k, run Pipeline 1 with all links up, then with link k down
    (link_state[k]=0), and record the cases where the argmax egress class
    changes. Returns (changes, tested) where changes is a list of
    (ttl, k, cls_up, cls_down). A non-empty result means a link failure
    actually reroutes the packet."""
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
        for k in range(6):
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
    setup_fn = {"hardcoded": setup_hardcoded, "template": setup_template, "modular": setup_modular}[method]
    setup = setup_fn(model_id, model_path)
    # b and fn are not referenced again but must stay in scope: they own the
    # BCC object and the loaded program: letting them be garbage-collected
    # closes the map/program fds the TEST_RUN calls below still use.
    b, fn, disp = setup["b"], setup["fn"], setup["disp"]  # noqa: F841
    weights = setup["weights"]
    scale = setup["scale"]
    ps = setup["pkt_stats"]
    cs = setup.get("cls_stats")
    pipeline = setup["pipeline"]

    # Model-update timing for Method 1
    if pipeline == 1:
        t_redir = setup.get("t_redirect_s", 0.0)
        t_ins   = setup.get("t_insert_s", 0.0)
        print(f"[M1 update timing] redirect/reload (BPF compile+load): {t_redir*1000:.3f} ms")
        print(f"[M1 update timing] weight insert   (n/a, pure hardcoded): {t_ins*1000:.3f} ms")
        print(f"[M1 update timing] total:                               {(t_redir+t_ins)*1000:.3f} ms")
        print()

    print(f"[setup] scale={scale}  weights={len(weights)}  disp_fd={disp.fd}")
    print("      All pipelines tested via the REAL dispatcher (full tail-call chain,")
    print("      dispatcher -> ... -> action) -- no leaf-priming shortcut.")
    print("      argmax -> mac_table[class] -> bpf_redirect.")
    print("      PASS = retval in {0,4} (redirect) AND cls_stats[ref_cls] > 0.")
    # Reference ingress_ifindex: under BPF_PROG_TEST_RUN, the sandbox's real
    # default ctx->ingress_ifindex is 1 (empirically confirmed -- see
    # TEST_RUN_DEFAULT_INGRESS_IFINDEX above and the multi-model diagnostics
    # in verify_multi_model.py). P1 translates it through its OWN
    # ifindex_table (default [2..7]), which does NOT map 1 -> _iface stays 0.
    # P2/P3 clamp the raw value directly (1<=x<=6), so 1 DOES contribute an
    # iface feature there. This only ever flips a close/tied argmax; the
    # real trained 65-4-4-7 model isn't sensitive to it (class 0 dominates),
    # which is why ifindex=0 "worked" here for years without anyone noticing.
    ref_ifindex = 0 if pipeline == 1 else 1
    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        ref_cls, ref_val, h1, h2 = ref_infer(weights, scale, ttl, model_id, ifindex=ref_ifindex)
        frame = build_frame(model_id, ttl, scale)
        _reset_stats(setup)
        # repeat=1: the program mutates the packet (TTL decrement) and
        # BPF_PROG_TEST_RUN does not restore the buffer between repetitions, so
        # re-running would walk the TTL down and end up testing the expiry path
        # instead of the decision under test. One run is all a class check needs;
        # latency for the tables is measured by prog_test_run_bench().
        retval, dur_ns = prog_test_run(disp.fd, frame, repeat=1, ingress_ifindex=0)
        cls_count = _read_u64(cs, ref_cls) if cs is not None else 0
        ok = (retval in XDP_REDIRECT_PASS) and (cls_count > 0)
        detail = f"retval={retval} cls_stats[{ref_cls}]={cls_count}"
        if retval == XDP_PASS:
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
    """
    Heterogeneous-sparse counterpart to run(): a model with an explicit
    per-model feature descriptor (different feature TYPES, not just sizes --
    the professor's scenario). The IV is built locally from the seeded
    dense_vector maps + the packet TTL + node one-hot; ref_infer_sparse
    rebuilds the same IV and we sweep TTL to exercise the scalar feature.
    """
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

    # ifindex table the generator used by default (only relevant if the
    # descriptor has an ingress_iface feature); TEST_RUN default ingress
    # ifindex is 1, which this table does not map -> no iface contribution.
    iface_size = next((f["size"] for f in features if f["type"] == "ingress_iface"), 0)
    ifindex_table = list(range(2, 2 + max(iface_size, 1)))

    feats_str = ", ".join(f"{f['type']}[{f['size']}]" for f in features)
    print(f"[setup] scale={scale}  weights={len(weights)}  n_in={n_in}  n_out={n_out}")
    print(f"      features: {feats_str}")
    print(f"      seeded maps: {map_values}")
    print(f"      IV built locally (maps + TTL + node one-hot). PASS = redirect on ref_cls "
          f"(or DROP for ref_cls == {n_out - 1}).")

    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        ref_cls, ref_val = ref_infer_sparse(
            weights, features, hidden_dims, n_out, ttl, model_id,
            map_values, ifindex=TEST_RUN_DEFAULT_INGRESS_IFINDEX, ifindex_table=ifindex_table)
        frame = build_frame_sparse(model_id, ttl, scale, n_in, n_out)
        _reset_stats(setup, n_classes=n_out)
        # repeat=1: the program mutates the packet (TTL decrement) and
        # BPF_PROG_TEST_RUN does not restore the buffer between repetitions, so
        # re-running would walk the TTL down and end up testing the expiry path
        # instead of the decision under test. One run is all a class check needs;
        # latency for the tables is measured by prog_test_run_bench().
        retval, dur_ns = prog_test_run(disp.fd, frame, repeat=1)
        if ref_cls < n_out - 1:
            cls_count = _read_u64(cs, ref_cls)
            ok = (retval in XDP_REDIRECT_PASS) and (cls_count > 0)
            detail = f"retval={retval} cls_stats[{ref_cls}]={cls_count}"
        else:
            cls_count = _read_u64(ps, 2)
            ok = (retval == 1) and (cls_count > 0)
            detail = f"retval={retval} pkt_stats[DROP]={cls_count}"
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
    p.add_argument("--method", choices=["hardcoded", "template", "modular", "sparse-hetero"],
                   default="hardcoded")
    p.add_argument("--model-id", type=int, default=0)
    p.add_argument("--model", default=MODEL_PT)
    p.add_argument("--model-dir", default=os.path.join(SHARED_DIR, "test", "fixtures", "sparse_hetero_11"),
                   help="sparse-hetero: directory with model_meta.json (+ weights.json)")
    p.add_argument("--ttl-min", type=int, default=2)   # 1 = expired, never forwarded
    p.add_argument("--ttl-max", type=int, default=10)
    p.add_argument("--repeat", type=int, default=1000, help="BPF_PROG_TEST_RUN repeat count for latency measurement")
    args = p.parse_args()
    if args.method == "sparse-hetero":
        sys.exit(run_sparse_hetero(args.model_dir, args.model_id, args.ttl_min, args.ttl_max, args.repeat))
    sys.exit(run(args.method, args.model_id, args.model, args.ttl_min, args.ttl_max, args.repeat))

if __name__ == "__main__":
    main()
