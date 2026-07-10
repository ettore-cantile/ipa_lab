"""
ebpf_program.py  —  Pipeline 1: Hardcoded Model (design-space baseline).

Design space position:
  - Maximum performance, minimum flexibility
  - Each model -> a dedicated eBPF program
  - Weights hardcoded as literals in the C source
  - Inference: fc1 (65->4, ReLU) + fc2 (4->4, ReLU) + out (4->7, argmax)
  - A single tail call, NO map lookup for the weights (pure hardcoded).
    The ONLY map read is link_state[0..5] (egress up/down), which is an
    input feature, not a weight -- see below.
  - Per-class hardcoded action: best_cls -> ifindex[best_cls]
    (cls 0-5 = bpf_redirect on the corresponding iface, cls 6 = XDP_DROP)
  - No fwd_table, no valid_keys lookup: a TRUE HIT = the redirect fired
  - No model_cache: the old is_valid gate + weight blob was a residue of an
    earlier design; a pure hardcoded program already knows its weights, so it
    always runs inference. Removed.

Stack budget:
  iv[65] as int array  -> 260B (too much)
  iv0..iv64 long long  -> 520B (exceeds 512B alone)

  Solution: the feature vector has only a handful of live entries at runtime:
    iv[0..5]            = link_state[0..5]  (egress up/down, from map)
    iv[12]              = ip->ttl           (always set)
    iv[5+ingress_iface] = 1                 (one-hot, indices 6..11)
    iv[13+model_id]     = 1                 (one-hot, indices 13..64)
  All other indices are 0, so weight*0 terms vanish from fc1.
  We generate fc1 as:
    h1_j = RELU( sum_i(link_state[i]*w[j,i])           (i in 0..5)
               + w[j,12]*ttl + w[j, 5+iface]*iface_weight
               + w[j, 13+node]*node_weight + bias_j )

Verifier constraints (why the code is shaped this way):
  1) switch(_iface){...}; switch(_node){...} REPEATED per hidden neuron
     (once per j in 0..N_H1-1): each neuron's pair of switches multiplies
     the number of CFG paths the verifier must explore, so the total
     explodes as O((7*52)^N_H1) ~= 1.75e10 for N_H1=4 -> "Permission
     denied" (verifier gives up after the 1,000,000-instruction budget).
  2) Replacing per-neuron switches with per-neuron `static const __s64`
     lookup arrays (W_IFACEj[7], W_NODEj[64]) avoided the path explosion,
     but `static const` arrays declared inside a BCC-compiled function are
     placed in a global/.rodata symbol that BCC's legacy (non-CO-RE)
     compilation pipeline cannot relocate for XDP programs: the emitted
     LD_IMM64 address collapses to a literal 0, and the verifier rejects
     the subsequent load ("R1 invalid mem access 'scalar'").
  Fix: emit ONE switch(_iface) and ONE switch(_node) TOTAL (not per
  neuron), each case assigning the per-neuron contribution for ALL
  N_H1 neurons at once (w_iface_0..w_iface_{N_H1-1} / w_node_0..*).
  This keeps the same O(7 + 52) ~= 59 branch total regardless of
  N_H1 (no combinatorial blow-up) and only ever touches plain scalar
  stack locals (8 x `long long`, 64B) -- no globals, no maps, verifier
  proves the bound trivially because every case is a concrete constant
  assignment merging into the same variable.

  3) The SAME broken-global-array pattern (root cause #2 above) also
     existed in the post-argmax action code as `static const __u32
     IFINDEX_TABLE[6]` indexed by `best_cls`. Same symptom ("R7 invalid
     mem access 'scalar'"), same fix: a `switch (best_cls) { case 0:
     egress_ifindex = ...; break; ... }` (6 cases, single decision
     point, no loop -> no explosion risk) replaces the array lookup.

  4) ip->protocol bitfield ambiguity on BCC/Kathara (DBG_NOT_UDP=100%):
     struct iphdr declares ihl:4,version:4 as a bitfield at byte 0.
     On BCC with minimal kernel headers inside Kathara containers,
     Clang's packing of this bitfield can cause ip->protocol (byte 9)
     to be read at the wrong offset, making ALL UDP packets fail the
     IPPROTO_UDP check even though tcpdump confirms proto=17.
     Fix: read protocol via *((__u8 *)ip + 9) -- absolute RFC 791 offset,
     independent of any struct packing or bitfield layout.
     Additionally, the UDP header pointer now uses ip->ihl*4 (the actual
     IP header length) instead of sizeof(struct iphdr)=20, which is
     correct when IP Options are present (ihl > 5).

  5) Feature vector iface one-hot always zero (chosen_port=DROP, 100%):
     _iface = ctx->ingress_ifindex & 0x7 produced e.g. 655 & 7 = 7,
     which never matched case 1..6 in switch(_iface), so w_iface_j = 0
     for all neurons. With the iface contribution silenced, fc1 only
     saw TTL and node one-hot, which was not enough to produce a valid
     egress class -- the model defaulted to cls 6 (DROP) on every packet.
     Fix: emit a preliminary switch(ctx->ingress_ifindex) that maps each
     hardcoded kernel ifindex (from ifindex_table, resolved at pipeline
     startup via socket.if_nametoindex) to the logical index 1..6 used
     by the training feature encoding.  The result is stored in _iface
     before the existing switch(_iface) that picks w_iface_j, so the
     rest of fc1 is unchanged.
"""

N_IN   = 65
N_H1   =  4
N_H2   =  4
N_OUT  =  7
N_WEIGHTS = N_IN*N_H1 + N_H1 + N_H1*N_H2 + N_H2 + N_H2*N_OUT + N_OUT  # 319

_EBPF_STATIC_HEADER = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

/* Fallback: in some Kathara/minimal-header environments IPPROTO_UDP may
 * not be defined via the includes above. Hardcode the RFC 791 value. */
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

/* link_state[i] = operational up/down of egress iface i (feature slots 0..5).
 * Written by the userspace carrier monitor (link_state_monitor.py); read here
 * into the first 6 feature-vector entries. 1 = link up, 0 = link down.
 * This is the ONLY map read in the inference path -- it is an INPUT feature,
 * not a weight. The weights remain C literals (pure hardcoded design). */
BPF_ARRAY(link_state,       __u32, 6);
BPF_ARRAY(pkt_stats,        __u64, 3);   /* [0]=hit [1]=miss(unused) [2]=drop */
BPF_ARRAY(cls_stats,        __u64, 7);   /* per-class redirect counter */

#define RELU_LL(x)    ((x) > 0LL ? (x) : 0LL)
"""


def generate_ebpf_hardcoded(
    weights_int8: list,
    scale: int,
    model_id: int = 0,
    ifindex_table: list = None,
) -> str:
    """
    Generate a self-contained eBPF XDP program for model `model_id`.

    After argmax the program:
      - resolves egress_ifindex via switch(best_cls) over hardcoded constants
      - cls 0-5: bpf_redirect(ifindex, 0)  -> pkt_stats[0]++, cls_stats[cls]++
      - cls  6:  XDP_DROP                  -> pkt_stats[2]++
      - inference always runs (pure hardcoded, no cache gate)

    ifindex_table: list of 6 integers mapping cls 0-5 to kernel ifindex.
                   Defaults to [2,3,4,5,6,7] (eth1..eth6).

    Verifier fix: see the module docstring "Verifier history" section.
    A single switch(_iface) and a single switch(_node) (not one per
    neuron) assign the per-neuron contributions for all N_H1 neurons at
    once, avoiding both the combinatorial CFG explosion of per-neuron
    switches and the broken global-array codegen of per-neuron
    `static const` lookup tables.
    """
    if len(weights_int8) != N_WEIGHTS:
        raise ValueError(f"Expected {N_WEIGHTS} weights, got {len(weights_int8)}")

    if ifindex_table is None:
        ifindex_table = [2, 3, 4, 5, 6, 7]   # eth1..eth6 default
    if len(ifindex_table) < 6:
        ifindex_table = list(ifindex_table) + [2] * (6 - len(ifindex_table))

    w = weights_int8
    fc1_w = w[0           : N_IN*N_H1]
    fc1_b = w[N_IN*N_H1   : N_IN*N_H1 + N_H1]
    base2 = N_IN*N_H1 + N_H1
    fc2_w = w[base2        : base2 + N_H1*N_H2]
    fc2_b = w[base2+N_H1*N_H2 : base2+N_H1*N_H2+N_H2]
    base3 = base2 + N_H1*N_H2 + N_H2
    out_w = w[base3        : base3 + N_H2*N_OUT]
    out_b = w[base3+N_H2*N_OUT : base3+N_H2*N_OUT+N_OUT]

    def lit(v):
        return str(int(v))

    fc1_lines = []
    fc1_lines.append("    /* fc1: only 3 live features -- ttl, iface one-hot, node one-hot */")
    fc1_lines.append("    __u32 _ttl  = ((__u32)ip->ttl) & 0xff;")
    fc1_lines.append("    __u32 _node = ((__u32)ipa->model_id) & 0x3f;  /* 0..51 */")

    fc1_lines.append("    /* FIX(#5): map raw kernel ifindex -> logical 1..6 for one-hot */")
    fc1_lines.append("    __u32 _iface = 0U;")
    fc1_lines.append("    switch (ctx->ingress_ifindex) {")
    _seen_ifindex = set()
    for logical_idx, kern_ifindex in enumerate(ifindex_table[:6], start=1):
        ki = int(kern_ifindex)
        if ki in _seen_ifindex:
            continue
        _seen_ifindex.add(ki)
        fc1_lines.append(f"        case {ki}U: _iface = {logical_idx}U; break;")
    fc1_lines.append("        default: break;")
    fc1_lines.append("    }")

    for j in range(N_H1):
        fc1_lines.append(f"    long long w_iface_{j} = 0LL, w_node_{j} = 0LL;")

    fc1_lines.append("    switch (_iface) {")
    for iface in range(1, 7):
        assigns = " ".join(
            f"w_iface_{j} = {lit(int(fc1_w[j * N_IN + 5 + iface]))}LL;"
            for j in range(N_H1)
        )
        fc1_lines.append(f"        case {iface}: {assigns} break;")
    fc1_lines.append("        default: break;")
    fc1_lines.append("    }")

    fc1_lines.append("    switch (_node) {")
    for node in range(52):
        assigns = " ".join(
            f"w_node_{j} = {lit(int(fc1_w[j * N_IN + 13 + node]))}LL;"
            for j in range(N_H1)
        )
        fc1_lines.append(f"        case {node}: {assigns} break;")
    fc1_lines.append("        default: break;")
    fc1_lines.append("    }")

    for j in range(N_H1):
        w_ttl = int(fc1_w[j * N_IN + 12])
        b_j   = int(fc1_b[j])
        ls_terms = " + ".join(
            f"ls{i} * {lit(int(fc1_w[j * N_IN + i]))}LL" for i in range(6)
        )
        fc1_lines.append(
            f"    long long h1_{j} = RELU_LL("
            f"(__s64)_ttl * {lit(w_ttl)}LL"
            f" + w_iface_{j}"
            f" + w_node_{j}"
            f" + {ls_terms}"
            f" + {lit(b_j)}LL);"
        )

    fc2_lines = []
    for j in range(N_H2):
        terms = " + ".join(f"h1_{i} * {lit(fc2_w[j*N_H1+i])}LL" for i in range(N_H1))
        fc2_lines.append(f"    long long h2_{j} = RELU_LL({terms} + {lit(fc2_b[j])}LL);")

    out_lines = []
    for k in range(N_OUT):
        terms = " + ".join(f"h2_{i} * {lit(out_w[k*N_H2+i])}LL" for i in range(N_H2))
        out_lines.append(f"    long long out_{k} = {terms} + {lit(out_b[k])}LL;")

    argmax_lines = ["    long long best_val = out_0;", "    int best_cls = 0;"]
    for k in range(1, N_OUT):
        argmax_lines.append(
            f"    if (out_{k} > best_val) {{ best_val = out_{k}; best_cls = {k}; }}"
        )

    fc1_src    = "\n".join(fc1_lines)
    fc2_src    = "\n".join(fc2_lines)
    out_src    = "\n".join(out_lines)
    argmax_src = "\n".join(argmax_lines)

    ifindex_cases = "\n".join(
        f"        case {cls}: egress_ifindex = {int(ifindex_table[cls])}U; break;"
        for cls in range(6)
    )

    body = f"""
int ipa_switch(struct xdp_md *ctx) {{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr  *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr   *ip  = (struct iphdr *)(eth + 1);
    if ((void *)(ip  + 1) > data_end) return XDP_PASS;

    /* FIX(#4): read protocol via absolute RFC 791 byte offset (byte 9) */
    __u8 ip_proto = *((__u8 *)ip + 9);
    if (ip_proto != 17U) return XDP_PASS;

    /* FIX(#4): compute UDP header pointer from actual ihl*4 */
    __u32 _ip_hlen = (((__u8 *)ip)[0] & 0x0fU) << 2U;
    if (_ip_hlen < 20U) return XDP_PASS;
    struct udphdr  *udp = (struct udphdr *)((void *)ip + _ip_hlen);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;

    /* Pure hardcoded: weights are C literals below, no weight map.
     * Always run inference. */
    __u16 scale = {scale}U;
    if (scale == 0) return XDP_PASS;

    /* link_state[0..5]: egress up/down read from map into feature slots 0..5. */
    long long ls0=0LL, ls1=0LL, ls2=0LL, ls3=0LL, ls4=0LL, ls5=0LL;
    {{ int _lk; __u32 *_lp;
       _lk=0; _lp=link_state.lookup(&_lk); if (_lp) ls0=(long long)(*_lp);
       _lk=1; _lp=link_state.lookup(&_lk); if (_lp) ls1=(long long)(*_lp);
       _lk=2; _lp=link_state.lookup(&_lk); if (_lp) ls2=(long long)(*_lp);
       _lk=3; _lp=link_state.lookup(&_lk); if (_lp) ls3=(long long)(*_lp);
       _lk=4; _lp=link_state.lookup(&_lk); if (_lp) ls4=(long long)(*_lp);
       _lk=5; _lp=link_state.lookup(&_lk); if (_lp) ls5=(long long)(*_lp); }}

{fc1_src}

{fc2_src}

{out_src}

{argmax_src}

    /* --- Hardcoded action: class -> egress port (no map lookup) --- */
    if (best_cls >= 6) {{
        /* cls 6 = DROP */
        int _di = 2; __u64 *_dv = pkt_stats.lookup(&_di);
        if (_dv) __sync_fetch_and_add(_dv, 1);
        return XDP_DROP;
    }}

    __u32 egress_ifindex = 0;
    switch (best_cls) {{
{ifindex_cases}
        default: break;
    }}

    /* per-class counter */
    __u32 _cls = (__u32)best_cls;
    __u64 *_cv = cls_stats.lookup(&_cls);
    if (_cv) __sync_fetch_and_add(_cv, 1);

    /* global hit counter */
    int _hi = 0; __u64 *_hv = pkt_stats.lookup(&_hi);
    if (_hv) __sync_fetch_and_add(_hv, 1);

    return bpf_redirect(egress_ifindex, 0);
}}
"""
    return _EBPF_STATIC_HEADER + f"\n/* Pipeline 1 — model_id={model_id}, scale={scale} */\n" + body


def load_and_generate(
    model_path: str = "shared/frr_germany50_5_model_4x2.pt",
    model_id: int = 0,
    ifindex_table: list = None,
) -> tuple:
    """
    Returns (ebpf_src, weights_int8, scale).
    ifindex_table is forwarded to generate_ebpf_hardcoded.
    """
    from extract_weights import extract_weights_int8
    import json, os
    weights_path = os.path.join(os.path.dirname(model_path), "weights_float.json")
    if os.path.exists(weights_path):
        with open(weights_path) as f:
            data = json.load(f)
        scale = int(data["scale_factor"])
    else:
        import torch
        from FRR_model import FastRerouteMLP
        m = FastRerouteMLP(n_interfaces=6, n_nodes=52, hidden_dim=4)
        m.load_state_dict(torch.load(model_path))
        floats  = [w for p in m.parameters() for w in p.data.view(-1).tolist()]
        max_abs = max(abs(w) for w in floats)
        scale   = int(127 / max_abs)
    weights_int8 = extract_weights_int8(model_path)
    ebpf_src     = generate_ebpf_hardcoded(weights_int8, scale, model_id, ifindex_table)
    return ebpf_src, weights_int8, scale


EBPF_PROGRAM = generate_ebpf_hardcoded(weights_int8=[0]*N_WEIGHTS, scale=128, model_id=0)

if __name__ == "__main__":
    import sys
    model_path = sys.argv[1] if len(sys.argv) > 1 else "shared/frr_germany50_5_model_4x2.pt"
    src, w, s = load_and_generate(model_path)
    print(src)
