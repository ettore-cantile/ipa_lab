"""
ebpf_program.py — eBPF/XDP program paper-compliant.

Struttura ipa_hdr letta dal kernel (21 byte fissi, packed):

  [Model Description]     5 byte
    model_id        : u8
    model_type      : u8   (0x00 = FC-NN)
    param_size      : u8   (7 = int8/7-bit)
    scale_factor    : u16  big-endian — presente nell'header ma NON usato
                           dal kernel per l'inferenza: il kernel usa sempre
                           m->scale_factor dalla model_cache (caricato dal CP).
                           Usato solo dal CP nel Method 4 (model_miss_event).

  [Model Specifications]  4 byte
    input_size      : u8   (65)
    output_size     : u8   (7)
    hidden_layers   : u8   (2)
    neurons_per_layer: u8  (4)

  [Input Descriptor]      9 byte
    n_feature_types : u8
    feat0_code/count: u8,u8  (0x01, 6)
    feat1_code/count: u8,u8  (0x02, 6)
    feat2_code/count: u8,u8  (0x03, 1)
    feat3_code/count: u8,u8  (0x04, 52)

  [Output Descriptor]     3 byte
    n_output_types  : u8
    out0_code/count : u8,u8  (0x05, 7)

Payload dopo l'header: 319 byte di pesi int8 (solo nel primo pacchetto).

Nota verifier eBPF:
  - ipa_hdr ha dimensione FISSA nota a compile-time -> bound check statico OK
  - model_miss: unico bound check su (ipa+1)+4 byte -> verifier OK
  - nessun loop su variabili runtime
  - N_WEIGHTS e' una macro compile-time -> #pragma unroll funzionera'
    quando si aggiungera' l'inferenza completa

Maps:
  model_cache       : model_id -> weights[319] + scale_factor
  fwd_table         : u64 key  -> fwd_action
  valid_keys        : u8 ttl   -> u64 key
  miss_events       : perf buffer (fwd miss, Methods 3 & 4)
  model_miss_events : perf buffer (model miss, Method 4)
  pkt_stats         : [0]=TRUE HIT  [1]=MISS  [2]=FAKE HIT
"""

N_WEIGHTS = 319  # fc1(260+4) + fc2(16+4) + out(28+7)

EBPF_PROGRAM = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

/* =============================================================
 * IPA Header paper-compliant — 21 byte fissi (__packed)
 * ============================================================= */
struct ipa_hdr {
    /* Model Description (5 byte) */
    __u8   model_id;
    __u8   model_type;         /* 0x00 = fully-connected NN          */
    __u8   param_size;         /* 7    = int8 / 7-bit quantization   */
    __be16 scale_factor;       /* big-endian — letto dal CP nel Method 4,
                                  NON usato dal kernel per l'inferenza  */

    /* Model Specifications (4 byte) */
    __u8   input_size;         /* 65 = 6+6+1+52                      */
    __u8   output_size;        /* 7  = 6 iface + DROP                */
    __u8   hidden_layers;      /* 2                                  */
    __u8   neurons_per_layer;  /* 4                                  */

    /* Input Descriptor (9 byte): n_types + 4 coppie (code, count) */
    __u8   n_feature_types;    /* 4                                  */
    __u8   feat0_code;  __u8   feat0_count;  /* 0x01, 6  link_state  */
    __u8   feat1_code;  __u8   feat1_count;  /* 0x02, 6  ingress_if  */
    __u8   feat2_code;  __u8   feat2_count;  /* 0x03, 1  ttl         */
    __u8   feat3_code;  __u8   feat3_count;  /* 0x04, 52 node_id     */

    /* Output Descriptor (3 byte): n_types + 1 coppia (code, count) */
    __u8   n_output_types;     /* 1                                  */
    __u8   out0_code;   __u8   out0_count;   /* 0x05, 7  next_hop    */
} __attribute__((packed));

/* Pesi: fc1(260+4) + fc2(16+4) + out(28+7) = 319 */
#define N_WEIGHTS 319

struct model_data {
    __u8  weights[N_WEIGHTS];
    __u8  is_valid;
    __u16 scale_factor;
};

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

/* Emesso su fwd miss (model in cache, regola mancante) — Methods 3 & 4 */
struct miss_event {
    __u8  model_id;
    __u8  ttl;
    __u32 ingress_ifindex;
    __u8  input_size;
    __u64 key;
};

/*
 * Emesso su model miss (model NON in cache) — Method 4.
 * Copia i primi 4 pesi con accessi a offset FISSO dopo l'header IPA.
 * Bound check unico e statico su 4 byte -> verifier eBPF accetta.
 */
struct model_miss_event {
    __u8  model_id;
    __u8  ttl;
    __u32 ingress_ifindex;
    __u8  input_size;
    __u8  w0; __u8 w1; __u8 w2; __u8 w3;
    __u8  n_weights;
};

BPF_HASH(model_cache, __u8, struct model_data, 256);
BPF_HASH(fwd_table, __u64, struct fwd_action, 256);
BPF_HASH(valid_keys, __u8, __u64, 256);
BPF_ARRAY(pkt_stats, __u64, 3);        /* [0]=TRUE HIT [1]=MISS [2]=FAKE HIT */
BPF_PERF_OUTPUT(miss_events);
BPF_PERF_OUTPUT(model_miss_events);

#define OUTPUT_OFFSET 100000ULL

int ipa_switch(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)  return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;

    /* Parsing IPA header: dimensione fissa 21 byte -> bound check statico */
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;

    __u8 target_model = ipa->model_id;

    struct model_data *m = model_cache.lookup(&target_model);

    /* ================================================================
     * MODEL MISS: modello non in cache (Method 4).
     * Legge i primi 4 pesi dal payload con offset fisso.
     * Bound check unico su 4 byte -> verifier OK.
     * ================================================================ */
    if (!m || m->is_valid == 0) {
        __u8 *w = (__u8 *)(ipa + 1);
        if ((void *)(w + 4) > data_end) return XDP_PASS;

        struct model_miss_event mev = {};
        mev.model_id        = ipa->model_id;
        mev.ttl             = ip->ttl;
        mev.ingress_ifindex = ctx->ingress_ifindex;
        mev.input_size      = ipa->input_size;
        mev.w0 = w[0]; mev.w1 = w[1]; mev.w2 = w[2]; mev.w3 = w[3];
        mev.n_weights = 4;

        model_miss_events.perf_submit(ctx, &mev, sizeof(mev));
        return XDP_PASS;
    }

    /*
     * scale_factor: usa SEMPRE quello dalla model_cache (caricato dal CP).
     * Il valore nell'header IPA e' ignorato per l'inferenza — serve solo
     * al CP nel Method 4 per popolare la cache al primo pacchetto.
     */
    __u16 scale = m->scale_factor;
    if (scale == 0) return XDP_PASS;

    /* ================================================================
     * INFERENCE — 4 feature fisse (placeholder per inferenza completa).
     * input vector: [model_id, ttl, ingress_ifindex, input_size]
     * L'input_size ora vale 65 (valore reale nel nuovo header).
     * ================================================================ */
    long long iv[4];
    iv[0] = ipa->model_id;
    iv[1] = ip->ttl;
    iv[2] = ctx->ingress_ifindex;
    iv[3] = ipa->input_size;   /* 65 nel nuovo header */

    long long output_raw = 0;
    output_raw += iv[0] * (long long)(signed char)m->weights[0];
    output_raw += iv[1] * (long long)(signed char)m->weights[1];
    output_raw += iv[2] * (long long)(signed char)m->weights[2];
    output_raw += iv[3] * (long long)(signed char)m->weights[3];

    __u64 output_u = (__u64)(output_raw + (long long)(OUTPUT_OFFSET * scale));
    __u64 key      = output_u / (__u64)scale;

    struct fwd_action *action  = fwd_table.lookup(&key);
    __u64 *correct_key         = valid_keys.lookup(&ip->ttl);

    if (action != NULL) {
        int stat_index = 2;  /* FAKE HIT default */
        if (correct_key && *correct_key == key)
            stat_index = 0;  /* TRUE HIT */
        __u64 *val = pkt_stats.lookup(&stat_index);
        if (val) __sync_fetch_and_add(val, 1);

        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    } else {
        int stat_index = 1;  /* MISS */
        __u64 *val = pkt_stats.lookup(&stat_index);
        if (val) __sync_fetch_and_add(val, 1);

        struct miss_event ev = {};
        ev.model_id        = ipa->model_id;
        ev.ttl             = ip->ttl;
        ev.ingress_ifindex = ctx->ingress_ifindex;
        ev.input_size      = ipa->input_size;
        ev.key             = key;
        miss_events.perf_submit(ctx, &ev, sizeof(ev));
        return XDP_PASS;
    }
}
"""
