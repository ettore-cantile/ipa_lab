// SPDX-License-Identifier: GPL-2.0
// model_dispatcher.c — IPA/eBPF hardcoded model dispatcher
//
// Reads the model_id from the IPA header embedded in the UDP payload,
// then performs a BPF tail call into the per-model program.
// This is the entry point for Level 1 (Hardcoded) of the design space.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// IPA header layout (matches the project's existing IPA format)
struct ipa_hdr {
    __u8  version;     // IPA version
    __u8  num_fields;  // number of telemetry fields
    __u16 model_id;    // which model to run
    // telemetry fields follow (variable length)
} __attribute__((packed));

// Jump table: model_id → dedicated eBPF model program
// Populated by load_hardcoded.py at load time.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} model_jmp_table SEC(".maps");

SEC("xdp")
int dispatcher(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --- Ethernet header ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // --- IP header ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // --- UDP header ---
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // IPA packets use a well-known destination port (9999)
    if (bpf_ntohs(udp->dest) != 9999)
        return XDP_PASS;

    // --- IPA header (immediately after UDP) ---
    struct ipa_hdr *ipa = (void *)(udp + 1);
    if ((void *)(ipa + 1) > data_end)
        return XDP_PASS;

    __u32 model_id = bpf_ntohs(ipa->model_id);

    // Tail call into the dedicated model program.
    // If model_id is not in the table (e.g. not loaded), fall through to XDP_PASS.
    bpf_tail_call(ctx, &model_jmp_table, model_id);

    // Tail call failed or model not registered — pass packet to kernel
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
