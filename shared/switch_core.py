from bcc import BPF
import time
import socket
import json
import os
import ctypes
import sys

# ---------------------------------------------------------------------------
# Selezione file pesi:
#   Metodo 1 (PTQ, default): weights.json          -> python3 switch_core.py
#   Metodo 2 (QAT):          weights_method2.json  -> python3 switch_core.py weights_method2.json
# ---------------------------------------------------------------------------
WEIGHTS_FILE = sys.argv[1] if len(sys.argv) > 1 else "weights.json"
WEIGHTS_PATH = f"/shared/{WEIGHTS_FILE}"

# --- Kernel Space (eBPF C Code) ---
program = """
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
    __u8 weights[100];
    __u8 is_valid;
};

struct fwd_action {
    __u32 ifindex;
    __u8 src_mac[6];
    __u8 dst_mac[6];
} __attribute__((packed));

BPF_HASH(model_cache, __u8, struct model_data, 256);
BPF_HASH(fwd_table, __u64, struct fwd_action, 256);

// Array per le statistiche: Indice 0 = REDIRECT, Indice 1 = TABLE MISS
BPF_ARRAY(pkt_stats, __u64, 2);

#define SCALE_SHIFT 7

int ipa_switch(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
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

    // 1. Controllo Cache
    __u8 target_model = ipa->model_id;
    struct model_data *m = model_cache.lookup(&target_model);
    if (!m || m->is_valid == 0) return XDP_PASS;

    // 2. Estrazione feature dal pacchetto
    long long iv[4];
    iv[0] = ipa->model_id;
    iv[1] = ip->ttl;
    iv[2] = ctx->ingress_ifindex;
    iv[3] = ipa->input_size;

    // 3. Inferenza int8 nel data plane
    long long output_raw = 0;
    output_raw += iv[0] * (long long)(signed char)m->weights[0];
    output_raw += iv[1] * (long long)(signed char)m->weights[1];
    output_raw += iv[2] * (long long)(signed char)m->weights[2];
    output_raw += iv[3] * (long long)(signed char)m->weights[3];

    __u64 output = (__u64)(output_raw >> SCALE_SHIFT);

    // 4. Table Lookup
    struct fwd_action *action = fwd_table.lookup(&output);

    if (action != NULL) {
        int key = 0;
        __u64 *val = pkt_stats.lookup(&key);
        if (val) __sync_fetch_and_add(val, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest, action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    } else {
        int key = 1;
        __u64 *val = pkt_stats.lookup(&key);
        if (val) __sync_fetch_and_add(val, 1);
        return XDP_PASS;
    }
}
"""

# --- User Space ---
print("IPA Switch Iniziato!")
print(f"Pesi selezionati: {WEIGHTS_FILE}")

b = BPF(text=program)
fn = b.load_func("ipa_switch", BPF.XDP)

ingress_iface = "eth1"
egress_iface  = "eth2"
egress_ifindex = socket.if_nametoindex(egress_iface)

# --- Carica pesi int8 nel kernel
print(f"Caricamento pesi da {WEIGHTS_PATH} ...")
with open(WEIGHTS_PATH, "r") as f:
    integer_weights = json.load(f)

cache = b.get_table("model_cache")
my_model = cache.Leaf()
my_model.is_valid = 1
for i in range(min(len(integer_weights), 100)):
    my_model.weights[i] = ctypes.c_uint8(integer_weights[i]).value
cache[cache.Key(42)] = my_model
print("Modello 42 caricato nella Cache eBPF!")

# --- Preparazione azione di inoltro
fwd = b.get_table("fwd_table")
my_action = fwd.Leaf()
my_action.ifindex = egress_ifindex
src_mac = [0x22, 0x8e, 0x26, 0xbb, 0xdf, 0xf5]
dst_mac = [0x62, 0x45, 0x3d, 0xec, 0xc9, 0x80]
for i in range(6):
    my_action.src_mac[i] = src_mac[i]
    my_action.dst_mac[i] = dst_mac[i]

# ---------------------------------------------------------------------------
# Popolamento fwd_table — control plane
#
# Il control plane deve calcolare la stessa chiave che produrra' il kernel.
# Il kernel usa: output = (sum(iv[i] * int8(w[i]))) >> SCALE_SHIFT
# Per replicarlo esattamente usiamo ctypes.c_int8 che fa lo stesso cast.
#
# Metodo 1 (PTQ, weights.json):
#   I pesi int8 sono il risultato di round(float * 128) con clamp.
#   Il control plane usa int8/128 come approssimazione dei float originali.
#   L'errore di arrotondamento PTQ puo' causare alcuni TABLE MISS per certi TTL.
#
# Metodo 2 (QAT, weights_method2.json):
#   I pesi sono stati ottimizzati durante il training per minimizzare l'errore
#   di quantizzazione. Il control plane usa int8/128 e combacia col kernel
#   -> zero miss garantiti.
# ---------------------------------------------------------------------------
print("Popolamento fwd_table...")
if_index_eth1 = socket.if_nametoindex(ingress_iface)
SCALE_SHIFT = 7

# Replica esatta del cast (signed char) del kernel
cp_weights = [ctypes.c_int8(int(w)).value / 128.0 for w in integer_weights[:4]]
print(f"  Pesi control plane (int8/128): {[f'{w:.4f}' for w in cp_weights]}")

for test_ttl in range(30, 65):
    iv_test = [42, test_ttl, if_index_eth1, 4]
    ideal_raw = sum(iv * fw for iv, fw in zip(iv_test, cp_weights))
    expected_key = int(ideal_raw * 128) >> SCALE_SHIFT  # equivalente a int(ideal_raw)
    fwd[ctypes.c_ulonglong(expected_key)] = my_action

print("Regole di inoltro caricate per TTL 30-64.")

# --- Attach XDP solo su ingress
print(f"\nAttach XDP sull'interfaccia ingress: {ingress_iface}")
try:
    b.attach_xdp(ingress_iface, fn, flags=2)
    print(f"XDP attaccato a {ingress_iface}")
except Exception as e:
    print(f"Errore XDP: {e}")

stats = b.get_table("pkt_stats")

print("\nIn ascolto di pacchetti... (Ctrl+C per fermare)")
print(f"{'REDIRECT (Fast Path)':<25} | {'PASS (Table Miss)':<25}")
print("-" * 55)

try:
    while True:
        time.sleep(1)
        try:
            redirects = stats[stats.Key(0)].value
            misses    = stats[stats.Key(1)].value
            print(f"\r{redirects:<25} | {misses:<25}", end="")
        except Exception:
            pass
except KeyboardInterrupt:
    b.remove_xdp(ingress_iface, flags=2)
    print("\n\nXDP rimosso. Esco.")
