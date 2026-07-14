#!/usr/bin/env python3
"""
gen_full_c.py  --  AOT-literal generator for the recompilation PoC.

Emits the ARCHITECTURE-FAITHFUL, weights-literal libbpf program for Pipeline 1:
a dispatcher + PROG_ARRAY tail-call + a model that re-parses (the double parse),
i.e. byte-for-byte the same topology as the BCC hardcoded path
(ipa_switch_hardcoded -> model_progs.call -> model_<id>). Compiled OFFLINE by
clang into a .o, it is the "models known a priori" alternative to BCC's
clang-at-runtime: the datapath node only does open+load at deploy time (~ms, no
clang), and the weights stay C literals so clang -O2's per-weight strength
reduction is preserved -> the full literal performance, identical to BCC.

The per-packet work reproduced (same as test_suite --kernel hardcoded):
    eth/ip/udp/ipa parse (bounds checks)
    link_state[6] via ONE struct-valued map lookup (vector-map layout)
    ttl from ip->ttl
    ingress_iface one-hot from ctx->ingress_ifindex via a single switch
    node one-hot from ipa->model_id via a single switch
    fc1/fc2/out + argmax
    mac_table hash lookup + eth MAC rewrite + pkt_stats/cls_stats + bpf_redirect

The loader (loader_aot.c) populates model_progs, seeds link_state/mac_table,
crafts a UDP/IPA frame and BPF_PROG_TEST_RUNs the dispatcher 1e6 times.

Run:  python3 gen_full_c.py -> nn_aot_arch.bpf.c
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_HERE)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

N_LS, N_IFACE, N_TTL, N_NODE = 6, 6, 1, 52
N_IN = N_LS + N_IFACE + N_TTL + N_NODE   # 65
N_H1, N_H2, N_OUT = 4, 4, 7
N_WEIGHTS = N_IN*N_H1 + N_H1 + N_H1*N_H2 + N_H2 + N_H2*N_OUT + N_OUT  # 319
OFF_LS, OFF_IFACE, OFF_TTL, OFF_NODE = 0, N_LS, N_LS+N_IFACE, N_LS+N_IFACE+N_TTL
# kernel ifindex -> logical port 1..6 (loader sets ctx->ingress_ifindex = 2)
IFINDEX_TABLE = [2, 3, 4, 5, 6, 7]


def _weights():
    from extract_weights import extract_weights_int8
    w = extract_weights_int8()
    if len(w) != N_WEIGHTS:
        raise SystemExit(f"expected {N_WEIGHTS} weights, got {len(w)}")
    return w


def _slices(w):
    fc1_w = w[0:N_IN*N_H1]
    fc1_b = w[N_IN*N_H1:N_IN*N_H1+N_H1]
    b2 = N_IN*N_H1+N_H1
    fc2_w = w[b2:b2+N_H1*N_H2]
    fc2_b = w[b2+N_H1*N_H2:b2+N_H1*N_H2+N_H2]
    b3 = b2+N_H1*N_H2+N_H2
    out_w = w[b3:b3+N_H2*N_OUT]
    out_b = w[b3+N_H2*N_OUT:b3+N_H2*N_OUT+N_OUT]
    off = {"fc1_b": N_IN*N_H1, "fc2_w": b2, "fc2_b": b2+N_H1*N_H2,
           "out_w": b3, "out_b": b3+N_H2*N_OUT}
    return fc1_w, fc1_b, fc2_w, fc2_b, out_w, out_b, off


_PARSE = """    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    __u8 ip_proto = *((__u8 *)ip + 9);
    if (ip_proto != 17) return XDP_PASS;
    __u32 ihl = (((__u8 *)ip)[0] & 0x0f) << 2;
    if (ihl < 20) return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)((void *)ip + ihl);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;"""


def _emit_model_body(w) -> list:
    """The IV + MLP + argmax + action body of the tail-called model program
    (weights as literals). ctx/data/eth/ip/udp/ipa are already parsed by the
    caller-emitted _PARSE block (this is the SECOND parse -- the double-parse
    the BCC dispatcher+tail-call architecture forces, replicated faithfully)."""
    fc1_w, fc1_b, fc2_w, fc2_b, out_w, out_b, off = _slices(w)
    def wref(idx, value): return f"{int(value)}LL"
    def fc1(j, pos): return j*N_IN + pos
    L = []; A = L.append
    A("    long long ttl = (long long)ip->ttl;")
    A("    long long ls0=0,ls1=0,ls2=0,ls3=0,ls4=0,ls5=0;")
    A("    { __u32 z=0; struct ls_vec *lv = bpf_map_lookup_elem(&link_state,&z);")
    A("      if (lv) {")
    for i in range(N_LS):
        A(f"        ls{i}=(long long)(lv->v[{i}]);")
    A("      } }")
    A("    __u32 _iface = 0;")
    A("    switch (ctx->ingress_ifindex) {")
    for logical, kern in enumerate(IFINDEX_TABLE, start=1):
        A(f"        case {kern}: _iface = {logical}; break;")
    A("        default: break;")
    A("    }")
    for j in range(N_H1):
        A(f"    long long w_iface_{j} = 0;")
    A("    switch (_iface) {")
    for k in range(1, N_IFACE + 1):
        assigns = " ".join(
            f"w_iface_{j} = {wref(fc1(j, OFF_IFACE + (k-1)), fc1_w[fc1(j, OFF_IFACE + (k-1))])};"
            for j in range(N_H1))
        A(f"        case {k}: {assigns} break;")
    A("        default: break;")
    A("    }")
    A("    __u32 _node = (__u32)ipa->model_id;")
    for j in range(N_H1):
        A(f"    long long w_node_{j} = 0;")
    A("    switch (_node) {")
    for k in range(N_NODE):
        assigns = " ".join(
            f"w_node_{j} = {wref(fc1(j, OFF_NODE + k), fc1_w[fc1(j, OFF_NODE + k)])};"
            for j in range(N_H1))
        A(f"        case {k}: {assigns} break;")
    A("        default: break;")
    A("    }")
    for j in range(N_H1):
        ls_terms = " + ".join(
            f"ls{i} * {wref(fc1(j, OFF_LS + i), fc1_w[fc1(j, OFF_LS + i)])}" for i in range(N_LS))
        ttl_term = f"ttl * {wref(fc1(j, OFF_TTL), fc1_w[fc1(j, OFF_TTL)])}"
        bias = wref(off["fc1_b"]+j, fc1_b[j])
        A(f"    long long a1_{j} = {ls_terms} + {ttl_term} + w_iface_{j} + w_node_{j} + {bias};")
        A(f"    long long h1_{j} = a1_{j} > 0 ? a1_{j} : 0;")
    for j in range(N_H2):
        terms = " + ".join(f"h1_{i} * {wref(off['fc2_w']+j*N_H1+i, fc2_w[j*N_H1+i])}" for i in range(N_H1))
        A(f"    long long a2_{j} = {terms} + {wref(off['fc2_b']+j, fc2_b[j])};")
        A(f"    long long h2_{j} = a2_{j} > 0 ? a2_{j} : 0;")
    for j in range(N_OUT):
        terms = " + ".join(f"h2_{i} * {wref(off['out_w']+j*N_H2+i, out_w[j*N_H2+i])}" for i in range(N_H2))
        A(f"    long long o_{j} = {terms} + {wref(off['out_b']+j, out_b[j])};")
    A("    long long best_val = o_0; int best_cls = 0;")
    for k in range(1, N_OUT):
        A(f"    if (o_{k} > best_val) {{ best_val = o_{k}; best_cls = {k}; }}")
    A(f"    if (best_cls >= {N_OUT - 1}) {{")
    A("        __u32 di = 2; __u64 *dv = bpf_map_lookup_elem(&pkt_stats, &di);")
    A("        if (dv) __sync_fetch_and_add(dv, 1);")
    A("        return XDP_DROP;")
    A("    }")
    A("    __u32 _cls = (__u32)best_cls;")
    A("    struct fwd_action *act = bpf_map_lookup_elem(&mac_table, &_cls);")
    A("    if (act) {")
    A("        __u32 hi = 0; __u64 *hv = bpf_map_lookup_elem(&pkt_stats, &hi);")
    A("        if (hv) __sync_fetch_and_add(hv, 1);")
    A("        __u64 *cv = bpf_map_lookup_elem(&cls_stats, &_cls);")
    A("        if (cv) __sync_fetch_and_add(cv, 1);")
    A("        __builtin_memcpy(eth->h_source, act->src_mac, 6);")
    A("        __builtin_memcpy(eth->h_dest,   act->dst_mac, 6);")
    A("        return bpf_redirect(act->ifindex, 0);")
    A("    }")
    A("    __u32 mi = 1; __u64 *mv = bpf_map_lookup_elem(&pkt_stats, &mi);")
    A("    if (mv) __sync_fetch_and_add(mv, 1);")
    A("    return XDP_PASS;")
    return L


def _emit_arch(w) -> str:
    """FULL-PATH, ARCHITECTURE-FAITHFUL literal program: dispatcher +
    PROG_ARRAY tail-call + model that RE-parses (double parse) -- byte-for-byte
    the same topology as the BCC hardcoded path (ipa_switch_hardcoded ->
    model_progs.call -> model_<id>), so BPF_PROG_TEST_RUN on the dispatcher
    measures the identical per-packet work test_suite --kernel measures. The
    only intentional difference from a real attach is that ctx->ingress_ifindex
    is not forged -- but test_suite doesn't forge it either (no ctx_in), so the
    ingress_iface one-hot takes the same default path in BOTH."""
    L = []; A = L.append
    A("// AUTO-GENERATED by gen_full_c.py (arch-faithful) -- do not edit by hand.")
    A("// dispatcher + tail-call + double-parse == BCC hardcoded architecture.")
    A("#include <linux/bpf.h>")
    A("#include <linux/if_ether.h>")
    A("#include <linux/ip.h>")
    A("#include <linux/udp.h>")
    A("#include <linux/in.h>")
    A("#include <bpf/bpf_helpers.h>")
    A("#include <bpf/bpf_endian.h>")
    A("")
    A("struct ipa_hdr {")
    A("    __u8 model_id; __u8 model_type; __u8 param_size; __be16 scale_factor;")
    A("    __u8 input_size; __u8 output_size; __u8 hidden_layers; __u8 neurons_per_layer;")
    A("    __u8 n_feature_types;")
    A("    __u8 f0c,f0n,f1c,f1n,f2c,f2n,f3c,f3n; __u8 n_output_types; __u8 o0c,o0n;")
    A("} __attribute__((packed));")
    A("struct fwd_action { __u32 ifindex; __u8 src_mac[6]; __u8 dst_mac[6]; } __attribute__((packed));")
    A("")
    A("struct ls_vec { __u32 v[%d]; };" % N_LS)
    A("struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);")
    A("         __type(key, __u32); __type(value, struct ls_vec); } link_state SEC(\".maps\");")
    A("struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 3);")
    A("         __type(key, __u32); __type(value, __u64); } pkt_stats SEC(\".maps\");")
    A("struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, %d);" % N_OUT)
    A("         __type(key, __u32); __type(value, __u64); } cls_stats SEC(\".maps\");")
    A("struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16);")
    A("         __type(key, __u32); __type(value, struct fwd_action); } mac_table SEC(\".maps\");")
    A("struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 256);")
    A("         __type(key, __u32); __type(value, __u32); } model_progs SEC(\".maps\");")
    A("")
    # --- model program (tail-call target): re-parses, then infers ---
    A("SEC(\"xdp\")")
    A("int xdp_model(struct xdp_md *ctx) {")
    A(_PARSE)
    L.extend(_emit_model_body(w))
    A("}")
    A("")
    # --- dispatcher (entry): parses, tail-calls model_progs[model_id] ---
    A("SEC(\"xdp\")")
    A("int xdp_dispatch(struct xdp_md *ctx) {")
    A(_PARSE)
    A("    __u32 mid = (__u32)ipa->model_id;")
    A("    bpf_tail_call(ctx, &model_progs, mid);")
    A("    return XDP_PASS;   // only if model_id has no registered program")
    A("}")
    A("")
    A("char _license[] SEC(\"license\") = \"GPL\";")
    return "\n".join(L) + "\n"


def generate_arch_literal_c(model_path: str = None) -> str:
    """Importable: the ARCHITECTURE-FAITHFUL literal program (dispatcher +
    tail-call + double-parse), for the AOT deploy bench that is apples-to-apples
    with test_suite --kernel hardcoded. Real int8 weights from model_path."""
    from extract_weights import extract_weights_int8
    w = extract_weights_int8(model_path) if model_path else _weights()
    if len(w) != N_WEIGHTS:
        raise SystemExit(f"expected {N_WEIGHTS} weights, got {len(w)}")
    return _emit_arch(w)


def main():
    with open(os.path.join(_HERE, "nn_aot_arch.bpf.c"), "w") as f:
        f.write(generate_arch_literal_c())
    print(f"wrote nn_aot_arch.bpf.c (arch-faithful literal, {N_WEIGHTS} weights) in {_HERE}")


if __name__ == "__main__":
    main()
