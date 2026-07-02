"""
ebpf_program.py — Shared C eBPF code used by all methods.

Maps:
  model_cache   : model_id  -> int8 weights + scale_factor
  fwd_table     : u64 key -> forwarding action (ifindex + MAC)
  valid_keys    : u8 ttl  -> correct u64 key (for fake hit detection)
  miss_events   : perf buffer to the CP (Method 3)
  pkt_stats     : 3-slot array -> [0]=TRUE HIT  [1]=MISS  [2]=FAKE HIT
"""

EBPF_PROGRAM = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

struct ipa_hdr {
    __u8  model_id;
    __u8  type_and_param_sz;
    __be16 scaling;
    __u8  input_size;
    __u8  output_size;
    __u8  hidden_layers;
    __u8  neurons_per_layer;
} __attribute__((packed));

struct model_data {
    __u8  weights[100];
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

BPF_HASH(model_cache, __u8, struct model_data, 256);
BPF_HASH(fwd_table, __u64, struct fwd_action, 256);
BPF_HASH(valid_keys, __u8, __u64, 256);   // TTL -> correct CP key
BPF_ARRAY(pkt_stats, __u64, 3);           // [0]=TRUE HIT [1]=MISS [2]=FAKE HIT
BPF_PERF_OUTPUT(miss_events);             // used only by Method 3

#define OUTPUT_OFFSET 100000ULL

int ipa_switch(struct xdp_md *ctx) {
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

    __u8 target_model = ipa->model_id;
    struct model_data *m = model_cache.lookup(&target_model);
    if (!m || m->is_valid == 0) return XDP_PASS;

    __u16 scale = m->scale_factor;
    if (scale == 0) return XDP_PASS;

    long long iv[4];
    iv[0] = ipa->model_id;
    iv[1] = ip->ttl;
    iv[2] = ctx->ingress_ifindex;
    iv[3] = ipa->input_size;

    long long output_raw = 0;
    output_raw += iv[0] * (long long)(signed char)m->weights[0];
    output_raw += iv[1] * (long long)(signed char)m->weights[1];
    output_raw += iv[2] * (long long)(signed char)m->weights[2];
    output_raw += iv[3] * (long long)(signed char)m->weights[3];

    __u64 output_u = (__u64)(output_raw + (long long)(OUTPUT_OFFSET * scale));
    __u64 key      = output_u / (__u64)scale;

    struct fwd_action *action = fwd_table.lookup(&key);
    __u64 *correct_key = valid_keys.lookup(&ip->ttl);

    if (action != NULL) {
        // TRUE HIT if the computed key matches the CP key for this TTL
        int stat_index = 2; // default: FAKE HIT
        if (correct_key && *correct_key == key) {
            stat_index = 0; // TRUE HIT
        }
        __u64 *val = pkt_stats.lookup(&stat_index);
        if (val) __sync_fetch_and_add(val, 1);

        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    } else {
        int stat_index = 1; // MISS
        __u64 *val = pkt_stats.lookup(&stat_index);
        if (val) __sync_fetch_and_add(val, 1);

        // Notify the CP (Method 3); in other methods the buffer is not consumed
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
