// SPDX-License-Identifier: GPL-2.0
// model_42.c — Hardcoded eBPF inference program for model ID 42
//
// Architecture: FRR model, 5 input features → hidden(4) → 2 output classes
// Weights: INT8 quantized, hardcoded as compile-time constants.
// Source weights: shared/weights.json (model_id=42)
//
// This program implements the complete inference pipeline:
//   feature extraction → linear layer 1 (ReLU) → linear layer 2 → argmax → action
//
// No BPF map lookups are performed during inference.
// Tail-called from model_dispatcher.c.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --------------------------------------------------------------------------
// Model architecture constants
// --------------------------------------------------------------------------
#define N_FEATURES   5
#define HIDDEN_SIZE  4
#define N_CLASSES    2

// Quantisation scale factor (matches shared/weights.json method)
// Weights are stored as INT8; scale = 1/128 in the original float model.
#define SCALE        128

// --------------------------------------------------------------------------
// Hardcoded INT8 weights (quantized from shared/weights.json, model_id=42)
//
// Layer 1: W1[HIDDEN_SIZE][N_FEATURES], b1[HIDDEN_SIZE]
// Layer 2: W2[N_CLASSES][HIDDEN_SIZE],  b2[N_CLASSES]
//
// NOTE: Replace these placeholder values with the actual quantized weights
//       extracted via shared/extract_weights.py before benchmarking.
// --------------------------------------------------------------------------
static const int W1[HIDDEN_SIZE][N_FEATURES] = {
    {  64,  32, -16,   8,  48 },
    {  16, -48,  32,  64, -32 },
    { -32,  16,  64, -48,  16 },
    {  48, -32,  16,  32, -64 },
};
static const int b1[HIDDEN_SIZE] = { 8, -4, 12, -8 };

static const int W2[N_CLASSES][HIDDEN_SIZE] = {
    {  64, -32,  16, -48 },
    { -64,  32, -16,  48 },
};
static const int b2[N_CLASSES] = { 4, -4 };

// --------------------------------------------------------------------------
// IPA header (must match model_dispatcher.c)
// --------------------------------------------------------------------------
struct ipa_hdr {
    __u8  version;
    __u8  num_fields;
    __u16 model_id;
} __attribute__((packed));

// Telemetry field immediately following IPA header
struct ipa_field {
    __u8  field_id;
    __u8  length;   // in bytes
    // value follows
} __attribute__((packed));

// --------------------------------------------------------------------------
// Helper: ReLU (integer)
// --------------------------------------------------------------------------
static __always_inline int relu(int x) { return x > 0 ? x : 0; }

// --------------------------------------------------------------------------
// XDP entry point (called via tail call from dispatcher)
// --------------------------------------------------------------------------
SEC("xdp")
int model_42(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Navigate to IPA payload (skip Ethernet + IP + UDP + IPA header)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    struct ipa_hdr *ipa = (void *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;

    // Feature extraction: read N_FEATURES INT8 values after IPA header.
    // The IPA telemetry fields are packed as raw INT8 values in this baseline.
    __s8 *feat_ptr = (__s8 *)(ipa + 1);
    if ((void *)(feat_ptr + N_FEATURES) > data_end) return XDP_PASS;

    int features[N_FEATURES];
    // Unrolled loop — verifier-friendly
    features[0] = feat_ptr[0];
    features[1] = feat_ptr[1];
    features[2] = feat_ptr[2];
    features[3] = feat_ptr[3];
    features[4] = feat_ptr[4];

    // ---------- Layer 1: linear + ReLU ----------
    int h[HIDDEN_SIZE];
    h[0] = relu(W1[0][0]*features[0] + W1[0][1]*features[1] +
                W1[0][2]*features[2] + W1[0][3]*features[3] +
                W1[0][4]*features[4] + b1[0] * SCALE);
    h[1] = relu(W1[1][0]*features[0] + W1[1][1]*features[1] +
                W1[1][2]*features[2] + W1[1][3]*features[3] +
                W1[1][4]*features[4] + b1[1] * SCALE);
    h[2] = relu(W1[2][0]*features[0] + W1[2][1]*features[1] +
                W1[2][2]*features[2] + W1[2][3]*features[3] +
                W1[2][4]*features[4] + b1[2] * SCALE);
    h[3] = relu(W1[3][0]*features[0] + W1[3][1]*features[1] +
                W1[3][2]*features[2] + W1[3][3]*features[3] +
                W1[3][4]*features[4] + b1[3] * SCALE);

    // ---------- Layer 2: linear ----------
    int out[N_CLASSES];
    out[0] = W2[0][0]*h[0] + W2[0][1]*h[1] + W2[0][2]*h[2] + W2[0][3]*h[3]
             + b2[0] * SCALE * SCALE;
    out[1] = W2[1][0]*h[0] + W2[1][1]*h[1] + W2[1][2]*h[2] + W2[1][3]*h[3]
             + b2[1] * SCALE * SCALE;

    // ---------- Argmax → action ----------
    int action = (out[0] >= out[1]) ? 0 : 1;

    // Action 0 → forward (XDP_PASS), action 1 → drop (XDP_DROP)
    // Extend with XDP_TX for redirect as needed.
    return (action == 0) ? XDP_PASS : XDP_DROP;
}

char _license[] SEC("license") = "GPL";
