"""
ebpf_program.py  —  Pipeline 1: Hardcoded Model (design-space baseline).

Design space position:
  - Massime prestazioni, minima flessibilità
  - Ogni modello → un programma eBPF dedicato (model_id → model_<id>.o)
  - Pesi hardcoded come letterali signed char nel sorgente C
  - Inferenza completa: fc1 (65→4, ReLU) + fc2 (4→4, ReLU) + out (4→7, argmax)
  - Una sola tail call (dispatcher → model_<id>)
  - Nessuna BPF map lookup per i pesi
  - Codice completamente unrolled (#pragma unroll)

IPA header structure (21 bytes packed):
  [Model Description]     5 byte
    model_id        : u8
    model_type      : u8   (0x00 = FC-NN)
    param_size      : u8   (7 = int8/7-bit)
    scale_factor    : u16  big-endian  (usato solo dal CP in Method 4)

  [Model Specifications]  4 byte
    input_size      : u8   (65)
    output_size     : u8   (7)
    hidden_layers   : u8   (2)
    neurons_per_layer: u8  (4)

  [Input Descriptor]      9 byte
    n_feature_types : u8
    feat0_code/count: u8,u8  (0x01, 6)  link_state
    feat1_code/count: u8,u8  (0x02, 6)  ingress_if
    feat2_code/count: u8,u8  (0x03, 1)  ttl
    feat3_code/count: u8,u8  (0x04, 52) node_id

  [Output Descriptor]     3 byte
    n_output_types  : u8
    out0_code/count : u8,u8  (0x05, 7)  next_hop

Architecture (frr_germany50_5_model_4x2.pt):
  fc1 : 65 → 4  (ReLU)   264 params (260 weights + 4 biases)
  fc2 :  4 → 4  (ReLU)    20 params  (16 weights + 4 biases)
  out :  4 → 7  (argmax)  35 params  (28 weights + 7 biases)
  Total: 319 int8 params

eBPF verifier notes:
  - All loops use #pragma unroll with compile-time bounds → accepted
  - Input vector iv[] is fixed-size stack array [65] stored as 32-bit ints
    to stay within the 512-byte BPF stack limit
  - All weight literals are signed char constants → no map lookup
  - scale != 0 guard before division
  - No runtime-variable loop bounds
  - Instruction count estimate:
      fc1: 65*4 muls + 4 adds + 4 relu    ≈ 540 insns
      fc2:  4*4 muls + 4 adds + 4 relu    ≈  60 insns
      out:  4*7 muls + 7 adds + argmax    ≈ 100 insns
      header parsing + forward            ≈  80 insns
      Total ≈ 780 insns — well within 1M limit (kernel ≥ 5.1)
             and within 4096 limit (kernel ≥ 4.15 with JIT)

Maps:
  model_cache       : model_id → model_data  (weights NOT used for inference;
                      kept for Method-4 control-plane model-miss handling)
  fwd_table         : u64 key → fwd_action
  valid_keys        : u8 ttl  → u64 key
  pkt_stats         : [0]=TRUE HIT  [1]=MISS  [2]=FAKE HIT
  miss_events       : perf buffer (fwd miss)
  model_miss_events : perf buffer (model miss, Method 4)
"""

# Architecture constants — must match frr_germany50_5_model_4x2.pt
N_IN   = 65
N_H1   =  4
N_H2   =  4
N_OUT  =  7

# Weight layout in the flat int8 array:
#   [0            .. N_IN*N_H1 - 1]          fc1 weights  (260)
#   [N_IN*N_H1    .. N_IN*N_H1+N_H1-1]       fc1 biases   (  4)
#   [264          .. 264+N_H1*N_H2-1]         fc2 weights  ( 16)
#   [280          .. 280+N_H2-1]              fc2 biases   (  4)
#   [284          .. 284+N_H2*N_OUT-1]        out weights  ( 28)
#   [312          .. 318]                     out biases   (  7)
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

#define OUTPUT_OFFSET 100000ULL
#define RELU_LL(x)    ((x) > 0LL ? (x) : 0LL)
"""


def generate_ebpf_hardcoded(weights_int8: list, scale: int, model_id: int = 0) -> str:
    if len(weights_int8) != N_WEIGHTS:
        raise ValueError(f"Expected {N_WEIGHTS} weights, got {len(weights_int8)}")

    w = weights_int8
    fc1_w  = w[0          : N_IN*N_H1]
    fc1_b  = w[N_IN*N_H1  : N_IN*N_H1 + N_H1]
    base2  = N_IN*N_H1 + N_H1
    fc2_w  = w[base2       : base2 + N_H1*N_H2]
    fc2_b  = w[base2+N_H1*N_H2 : base2+N_H1*N_H2+N_H2]
    base3  = base2 + N_H1*N_H2 + N_H2
    out_w  = w[base3       : base3 + N_H2*N_OUT]
    out_b  = w[base3+N_H2*N_OUT : base3+N_H2*N_OUT+N_OUT]

    def lit(v):
        return str(int(v))

    fc1_lines = []
    for j in range(N_H1):
        terms = " + ".join(f"((long long)iv[{i}]) * {lit(fc1_w[j*N_IN + i])}LL" for i in range(N_IN))
        fc1_lines.append(f"    long long h1_{j} = RELU_LL({terms} + {lit(fc1_b[j])}LL);")

    fc2_lines = []
    for j in range(N_H2):
        terms = " + ".join(f"h1_{i} * {lit(fc2_w[j*N_H1 + i])}LL" for i in range(N_H1))
        fc2_lines.append(f"    long long h2_{j} = RELU_LL({terms} + {lit(fc2_b[j])}LL);")

    out_lines = []
    for k in range(N_OUT):
        terms = " + ".join(f"h2_{i} * {lit(out_w[k*N_H2 + i])}LL" for i in range(N_H2))
        out_lines.append(f"    long long out_{k} = {terms} + {lit(out_b[k])}LL;")

    argmax_lines = ["    long long best_val = out_0;", "    int best_cls = 0;"]
    for k in range(1, N_OUT):
        argmax_lines.append(f"    if (out_{k} > best_val) {{ best_val = out_{k}; best_cls = {k}; }}")

    feat_lines = []
    feat_lines.append("    int iv[65];")
    feat_lines.append("    __builtin_memset(iv, 0, sizeof(iv));")
    feat_lines.append("    iv[12] = (int)ip->ttl;")
    feat_lines.append("    if (ctx->ingress_ifindex >= 1 && ctx->ingress_ifindex <= 6)")
    feat_lines.append("        iv[5 + ctx->ingress_ifindex] = 1;")
    feat_lines.append("    if (ipa->model_id < 52)")
    feat_lines.append("        iv[13 + ipa->model_id] = 1;")

    fc1_src   = "\n".join(fc1_lines)
    fc2_src   = "\n".join(fc2_lines)
    out_src   = "\n".join(out_lines)
    argmax_src= "\n".join(argmax_lines)
    feat_src  = "\n".join(feat_lines)

    body = f"""
int ipa_switch(struct xdp_md *ctx) {{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)  return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)   return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)  return XDP_PASS;
    if (udp->dest != bpf_htons(9999))  return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end)  return XDP_PASS;

    struct model_data *m = model_cache.lookup(&ipa->model_id);
    if (!m || m->is_valid == 0) {{
        __u8 *wp = (__u8 *)(ipa + 1);
        if ((void *)(wp + 4) > data_end) return XDP_PASS;
        struct model_miss_event mev = {{}};
        mev.model_id        = ipa->model_id;
        mev.ttl             = ip->ttl;
        mev.ingress_ifindex = ctx->ingress_ifindex;
        mev.input_size      = ipa->input_size;
        mev.w0 = wp[0]; mev.w1 = wp[1]; mev.w2 = wp[2]; mev.w3 = wp[3];
        mev.n_weights       = 4;
        model_miss_events.perf_submit(ctx, &mev, sizeof(mev));
        return XDP_PASS;
    }}

    __u16 scale = {scale}U;
    if (scale == 0) return XDP_PASS;

{feat_src}

{fc1_src}

{fc2_src}

{out_src}

{argmax_src}

    __u64 key = (__u64)((best_val + (long long)(OUTPUT_OFFSET * (__u64)scale)) / (__u64)scale);

    struct fwd_action *action = fwd_table.lookup(&key);
    __u64 *correct_key        = valid_keys.lookup(&ip->ttl);

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
            struct miss_event ev = {{}};
            ev.model_id        = ipa->model_id;
            ev.ttl             = ip->ttl;
            ev.ingress_ifindex = ctx->ingress_ifindex;
            ev.input_size      = ipa->input_size;
            ev.key             = key;
            miss_events.perf_submit(ctx, &ev, sizeof(ev));
            return XDP_PASS;
        }}
    }} else {{
        int si = 1; __u64 *v = pkt_stats.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        struct miss_event ev = {{}};
        ev.model_id        = ipa->model_id;
        ev.ttl             = ip->ttl;
        ev.ingress_ifindex = ctx->ingress_ifindex;
        ev.input_size      = ipa->input_size;
        ev.key             = key;
        miss_events.perf_submit(ctx, &ev, sizeof(ev));
        return XDP_PASS;
    }}
}}
"""

    return _EBPF_STATIC_HEADER + f"\n/* Pipeline 1 — model_id={model_id}, scale={scale} */\n" + body


def load_and_generate(model_path: str = "shared/frr_germany50_5_model_4x2.pt", model_id: int = 0) -> tuple:
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


EBPF_PROGRAM = generate_ebpf_hardcoded(weights_int8=[0] * N_WEIGHTS, scale=128, model_id=0)

if __name__ == "__main__":
    import sys
    model_path = sys.argv[1] if len(sys.argv) > 1 else "shared/frr_germany50_5_model_4x2.pt"
    src, w, s = load_and_generate(model_path)
    print(src)
