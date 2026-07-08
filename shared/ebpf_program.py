"""
ebpf_program.py  —  Pipeline 1: Hardcoded Model (design-space baseline).

Design space position:
  - Massime prestazioni, minima flessibilita
  - Ogni modello -> un programma eBPF dedicato
  - Pesi hardcoded come letterali nel sorgente C
  - Inferenza: fc1 (65->4, ReLU) + fc2 (4->4, ReLU) + out (4->7, argmax)
  - Una sola tail call, nessuna map lookup per i pesi

Stack budget fix:
  iv[65] as int array  -> 260B (too much)
  iv0..iv64 long long  -> 520B (exceeds 512B alone)

  Solution: the feature vector has only 3 non-zero entries at runtime:
    iv[12]              = ip->ttl          (always set)
    iv[5+ingress_iface] = 1                (one-hot, indices 6..11)
    iv[13+model_id]     = 1                (one-hot, indices 13..64)
  All other indices are 0, so weight*0 terms vanish from fc1.
  We generate fc1 as:
    h1_j = RELU( w[j,12]*ttl + w[j, 5+iface]*iface_flag
               + w[j, 13+node]*node_flag + folded_bias_j )
  where folded_bias_j = bias_j (zero-index weights contribute 0).
  Only 3 runtime int values on the stack instead of 65.
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

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

struct miss_event {
    __u8  model_id;
    __u8  ttl;
    __u32 ingress_ifindex;
    __u8  input_size;
    __u64 key;
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
BPF_HASH(fwd_table,         __u64, struct fwd_action, 256);
BPF_HASH(valid_keys,        __u8,  __u64,             256);
BPF_ARRAY(pkt_stats,        __u64, 3);
BPF_PERF_OUTPUT(miss_events);
BPF_PERF_OUTPUT(model_miss_events);
/* percpu scratch to keep event structs off the stack */
BPF_PERCPU_ARRAY(ev_scratch,  struct miss_event,        1);
BPF_PERCPU_ARRAY(mev_scratch, struct model_miss_event,  1);

#define OUTPUT_OFFSET 100000ULL
#define RELU_LL(x)    ((x) > 0LL ? (x) : 0LL)
"""


def generate_ebpf_hardcoded(weights_int8: list, scale: int, model_id: int = 0) -> str:
    if len(weights_int8) != N_WEIGHTS:
        raise ValueError(f"Expected {N_WEIGHTS} weights, got {len(weights_int8)}")

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
    # fc1 for neuron j:
    #   sum_i( w[j,i] * iv[i] )
    #   = w[j,12]*ttl  +  w[j, 5+iface]*1  +  w[j, 13+node]*1  +  0*(others)
    #   + bias[j]
    #
    # We generate a switch on ingress_ifindex (1..6) and model_id (0..51).
    # ttl is a runtime int (8-bit, fits easily in a single stack slot).
    # ----------------------------------------------------------------

    fc1_lines = []
    fc1_lines.append("    /* fc1: only 3 live features — ttl, iface one-hot, node one-hot */")
    fc1_lines.append("    int _ttl    = (int)ip->ttl;")
    fc1_lines.append("    int _iface  = (int)ctx->ingress_ifindex;  /* 1..6 */")
    fc1_lines.append("    int _node   = (int)ipa->model_id;          /* 0..51 */")

    for j in range(N_H1):
        # weight for ttl (index 12)
        w_ttl = int(fc1_w[j * N_IN + 12])
        b_j   = int(fc1_b[j])

        # iface branch: w[j, 5+iface] for iface=1..6 (indices 6..11)
        iface_cases = ""
        for iface in range(1, 7):
            wi = int(fc1_w[j * N_IN + 5 + iface])
            iface_cases += f"case {iface}: _wiface{j}={lit(wi)}LL; break; "

        # node branch: w[j, 13+node] for node=0..51 (indices 13..64)
        node_cases = ""
        for node in range(52):
            wn = int(fc1_w[j * N_IN + 13 + node])
            node_cases += f"case {node}: _wnode{j}={lit(wn)}LL; break; "

        fc1_lines.append(f"    long long _wiface{j} = 0LL, _wnode{j} = 0LL;")
        fc1_lines.append(f"    switch (_iface) {{ {iface_cases}default: break; }}")
        fc1_lines.append(f"    switch (_node)  {{ {node_cases}default: break; }}")
        fc1_lines.append(
            f"    long long h1_{j} = RELU_LL("
            f"(long long)_ttl * {lit(w_ttl)}LL + _wiface{j} + _wnode{j} + {lit(b_j)}LL);"
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

    /* model cache check */
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
        return XDP_PASS;
    }}

    __u16 scale = {scale}U;
    if (scale == 0) return XDP_PASS;

{fc1_src}

{fc2_src}

{out_src}

{argmax_src}
    (void)best_cls;

    __u64 key = (__u64)((best_val +
        (long long)(OUTPUT_OFFSET * (__u64)scale)) / (__u64)scale);

    struct fwd_action *action      = fwd_table.lookup(&key);
    __u64             *correct_key = valid_keys.lookup(&ip->ttl);

    if (action != NULL) {{
        if (correct_key && *correct_key == key) {{
            int si = 0; __u64 *v = pkt_stats.lookup(&si);
            if (v) __sync_fetch_and_add(v, 1);
            __builtin_memcpy(eth->h_source, action->src_mac, 6);
            __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
            return bpf_redirect(action->ifindex, 0);
        }} else {{
            int si = 2; __u64 *v = pkt_stats.lookup(&si);
            if (v) __sync_fetch_and_add(v, 1);
            __u32 _z = 0;
            struct miss_event *ev = ev_scratch.lookup(&_z);
            if (ev) {{
                ev->model_id=ipa->model_id; ev->ttl=ip->ttl;
                ev->ingress_ifindex=ctx->ingress_ifindex;
                ev->input_size=ipa->input_size; ev->key=key;
                miss_events.perf_submit(ctx, ev, sizeof(*ev));
            }}
            return XDP_PASS;
        }}
    }} else {{
        int si = 1; __u64 *v = pkt_stats.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        __u32 _z = 0;
        struct miss_event *ev = ev_scratch.lookup(&_z);
        if (ev) {{
            ev->model_id=ipa->model_id; ev->ttl=ip->ttl;
            ev->ingress_ifindex=ctx->ingress_ifindex;
            ev->input_size=ipa->input_size; ev->key=key;
            miss_events.perf_submit(ctx, ev, sizeof(*ev));
        }}
        return XDP_PASS;
    }}
}}
"""
    return _EBPF_STATIC_HEADER + f"\n/* Pipeline 1 — model_id={model_id}, scale={scale} */\n" + body


def load_and_generate(model_path: str = "shared/frr_germany50_5_model_4x2.pt",
                      model_id: int = 0) -> tuple:
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
    ebpf_src     = generate_ebpf_hardcoded(weights_int8, scale, model_id)
    return ebpf_src, weights_int8, scale


EBPF_PROGRAM = generate_ebpf_hardcoded(weights_int8=[0]*N_WEIGHTS, scale=128, model_id=0)

if __name__ == "__main__":
    import sys
    model_path = sys.argv[1] if len(sys.argv) > 1 else "shared/frr_germany50_5_model_4x2.pt"
    src, w, s = load_and_generate(model_path)
    print(src)
