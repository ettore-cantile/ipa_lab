"""
ebpf_program.py  —  Pipeline 1: Hardcoded Model (design-space baseline).

Design space position:
  - Massime prestazioni, minima flessibilita
  - Ogni modello -> un programma eBPF dedicato
  - Pesi hardcoded come letterali nel sorgente C
  - Inferenza: fc1 (65->4, ReLU) + fc2 (4->4, ReLU) + out (4->7, argmax)
  - Una sola tail call, nessuna map lookup per i pesi
  - Azione hardcodata per classe: best_cls -> ifindex[best_cls]
    (cls 0-5 = bpf_redirect su iface corrispondente, cls 6 = XDP_DROP)
  - Nessuna fwd_table, nessuna valid_keys lookup: TRUE HIT = redirect riuscito

Stack budget fix:
  iv[65] as int array  -> 260B (too much)
  iv0..iv64 long long  -> 520B (exceeds 512B alone)

  Solution: the feature vector has only 3 non-zero entries at runtime:
    iv[12]              = ip->ttl          (always set)
    iv[5+ingress_iface] = 1                (one-hot, indices 6..11)
    iv[13+model_id]     = 1                (one-hot, indices 13..64)
  All other indices are 0, so weight*0 terms vanish from fc1.
  We generate fc1 as:
    h1_j = RELU( w[j,12]*ttl + w[j, 5+iface]*iface_weight
               + w[j, 13+node]*node_weight + bias_j )
  where the iface/node weights are stored in static const arrays
  (verifier-friendly: O(1) bounded array access instead of switch trees).
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

struct model_data {
    __u8  weights[319];
    __u8  is_valid;
    __u16 scale_factor;
};

struct miss_event {
    __u8  model_id;
    __u8  ttl;
    __u32 ingress_ifindex;
    __u8  input_size;
    __u8  chosen_cls;
};

struct model_miss_event {
    __u8  model_id;
    __u8  ttl;
    __u32 ingress_ifindex;
    __u8  input_size;
    __u8  w0; __u8 w1; __u8 w2; __u8 w3;
    __u8  n_weights;
};

BPF_HASH(model_cache,       __u8,  struct model_data, 256);
BPF_ARRAY(pkt_stats,        __u64, 3);   /* [0]=hit [1]=miss [2]=drop */
BPF_ARRAY(cls_stats,        __u64, 7);   /* per-class redirect counter */
BPF_PERF_OUTPUT(miss_events);
BPF_PERF_OUTPUT(model_miss_events);
/* percpu scratch to keep event structs off the stack */
BPF_PERCPU_ARRAY(ev_scratch,  struct miss_event,        1);
BPF_PERCPU_ARRAY(mev_scratch, struct model_miss_event,  1);

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
      - reads ifindex from the HARDCODED array IFINDEX_TABLE[best_cls]
      - cls 0-5: bpf_redirect(ifindex, 0)  -> pkt_stats[0]++, cls_stats[cls]++
      - cls  6:  XDP_DROP                  -> pkt_stats[2]++
      - model_cache miss:                  -> pkt_stats[1]++

    ifindex_table: list of 6 integers mapping cls 0-5 to kernel ifindex.
                   Defaults to [2,3,4,5,6,7] (eth1..eth6).

    Verifier fix (bpf: Failed to load program: Permission denied):
      The previous implementation used switch(_node){case 0:..case 51:}
      repeated for each of the 4 hidden neurons. This created a CFG with
      O(52^4) paths that the BPF verifier could not explore within its
      complexity limit. Fix: replace both switch trees with static const
      __s64 arrays (W_NODE_j[52] and W_IFACE_j[7]) indexed with a bounded
      variable. The verifier proves the access is in-bounds trivially via
      the & mask, and the program compiles to a single array read per
      neuron instead of a binary-search tree of branches.
    """
    if len(weights_int8) != N_WEIGHTS:
        raise ValueError(f"Expected {N_WEIGHTS} weights, got {len(weights_int8)}")

    if ifindex_table is None:
        ifindex_table = [2, 3, 4, 5, 6, 7]   # eth1..eth6 default
    if len(ifindex_table) < 6:
        ifindex_table = list(ifindex_table) + [2] * (6 - len(ifindex_table))

    ifindex_literal = ", ".join(str(int(x)) for x in ifindex_table[:6])

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

    # ----------------------------------------------------------------
    # Feature vector structure (65 dims, only 3 non-zero at runtime):
    #   [0..5]   unused (always 0)
    #   [6..11]  ingress_ifindex one-hot  (index = 5 + ifindex, ifindex 1..6)
    #   [12]     ip->ttl
    #   [13..64] model_id / node_id one-hot (index = 13 + model_id, 0..51)
    #
    # Verifier-friendly encoding:
    #   - W_NODE_j[52]: static const array of node weights for neuron j
    #     accessed as W_NODE_j[node & 0x3f]  (63 >= 51, always in bounds)
    #   - W_IFACE_j[7]: static const array for iface weights (indices 0..6)
    #     accessed as W_IFACE_j[iface & 0x7] (7 >= 6, always in bounds)
    #     index 0 is unused (ifindex is 1-based), set to 0.
    # ----------------------------------------------------------------

    fc1_lines = []
    fc1_lines.append("    /* fc1: only 3 live features -- ttl, iface one-hot, node one-hot */")
    fc1_lines.append("    __u32 _ttl   = ((__u32)ip->ttl) & 0xff;")
    fc1_lines.append("    __u32 _iface = ((__u32)ctx->ingress_ifindex) & 0x7;  /* 1..6 */")
    fc1_lines.append("    __u32 _node  = ((__u32)ipa->model_id) & 0x3f;        /* 0..51 */")

    for j in range(N_H1):
        w_ttl = int(fc1_w[j * N_IN + 12])
        b_j   = int(fc1_b[j])

        # W_IFACE_j: index 0 unused (ifindex is 1-based), indices 1..6 hold real weights
        iface_vals = ["0LL"]  # index 0 placeholder
        for iface in range(1, 7):
            wi = int(fc1_w[j * N_IN + 5 + iface])
            iface_vals.append(f"{lit(wi)}LL")
        iface_literal = ", ".join(iface_vals)

        # W_NODE_j: indices 0..51 hold real weights, fill up to 64 with 0
        node_vals = []
        for node in range(64):
            if node < 52:
                wn = int(fc1_w[j * N_IN + 13 + node])
                node_vals.append(f"{lit(wn)}LL")
            else:
                node_vals.append("0LL")
        node_literal = ", ".join(node_vals)

        fc1_lines.append(
            f"    static const __s64 W_IFACE{j}[7] = {{ {iface_literal} }};"
        )
        fc1_lines.append(
            f"    static const __s64 W_NODE{j}[64] = {{ {node_literal} }};"
        )
        fc1_lines.append(
            f"    long long h1_{j} = RELU_LL("
            f"(__s64)_ttl * {lit(w_ttl)}LL"
            f" + W_IFACE{j}[_iface]"
            f" + W_NODE{j}[_node]"
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

    body = f"""
/* Hardcoded ifindex table: cls 0-5 -> egress ifindex, cls 6 -> DROP */
static const __u32 IFINDEX_TABLE[6] = {{ {ifindex_literal} }};

int ipa_switch(struct xdp_md *ctx) {{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr  *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr   *ip  = (struct iphdr *)(eth + 1);
    if ((void *)(ip  + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)  return XDP_PASS;
    struct udphdr  *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;

    /* model_cache check: if model not loaded, count as miss and pass */
    struct model_data *m = model_cache.lookup(&ipa->model_id);
    if (!m || m->is_valid == 0) {{
        __u8 *wp = (__u8 *)(ipa + 1);
        if ((void *)(wp + 4) > data_end) return XDP_PASS;
        __u32 _z = 0;
        struct model_miss_event *mev = mev_scratch.lookup(&_z);
        if (mev) {{
            mev->model_id        = ipa->model_id;
            mev->ttl             = ip->ttl;
            mev->ingress_ifindex = ctx->ingress_ifindex;
            mev->input_size      = ipa->input_size;
            mev->w0=wp[0]; mev->w1=wp[1]; mev->w2=wp[2]; mev->w3=wp[3];
            mev->n_weights       = 4;
            model_miss_events.perf_submit(ctx, mev, sizeof(*mev));
        }}
        int _ms = 1; __u64 *_mv = pkt_stats.lookup(&_ms);
        if (_mv) __sync_fetch_and_add(_mv, 1);
        return XDP_PASS;
    }}

    __u16 scale = {scale}U;
    if (scale == 0) return XDP_PASS;

{fc1_src}

{fc2_src}

{out_src}

{argmax_src}

    /* --- Hardcoded action: class -> egress port (no map lookup) --- */
    if (best_cls >= 6) {{
        /* cls 6 = DROP */
        int _di = 2; __u64 *_dv = pkt_stats.lookup(&_di);
        if (_dv) __sync_fetch_and_add(_dv, 1);
        bpf_trace_printk("IPA p1 DROP: model=%d ttl=%d\\n",
                         ipa->model_id, ip->ttl);
        return XDP_DROP;
    }}

    __u32 egress_ifindex = IFINDEX_TABLE[best_cls];

    /* per-class counter */
    __u32 _cls = (__u32)best_cls;
    __u64 *_cv = cls_stats.lookup(&_cls);
    if (_cv) __sync_fetch_and_add(_cv, 1);

    /* global hit counter */
    int _hi = 0; __u64 *_hv = pkt_stats.lookup(&_hi);
    if (_hv) __sync_fetch_and_add(_hv, 1);

    bpf_trace_printk("IPA p1: model=%d ttl=%d\\n",
                     ipa->model_id, ip->ttl);
    bpf_trace_printk("IPA p1: cls=%d ifindex=%d\\n",
                     best_cls, egress_ifindex);

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
