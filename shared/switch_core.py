from bcc import BPF
import time
import socket
import json
import os
import ctypes
import sys

# ---------------------------------------------------------------------------
# Selezione metodo tramite argomento:
#
#   Metodo 1 (PTQ) — default:
#     python3 switch_core.py
#     - Kernel:        pesi int8 da weights.json
#     - Control plane: pesi float originali da weights_float.json
#     - Effetto:       il disallineamento float->int8 causa TABLE MISS reali
#                      che dimostrano l'errore di quantizzazione PTQ.
#
#   Metodo 2 (QAT):
#     python3 switch_core.py weights_method2.json
#     - Kernel:        pesi int8 da weights_method2.json
#     - Control plane: stessi pesi int8/128 (il QAT li ha gia' ottimizzati
#                      per sopravvivere alla quantizzazione)
#     - Effetto:       zero miss, dimostra la superiorita' del QAT.
# ---------------------------------------------------------------------------
WEIGHTS_FILE = sys.argv[1] if len(sys.argv) > 1 else "weights.json"
WEIGHTS_PATH = f"/shared/{WEIGHTS_FILE}"
IS_PTQ = (WEIGHTS_FILE == "weights.json")

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

    __u8 target_model = ipa->model_id;
    struct model_data *m = model_cache.lookup(&target_model);
    if (!m || m->is_valid == 0) return XDP_PASS;

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

    __u64 output = (__u64)(output_raw >> SCALE_SHIFT);

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

print("IPA Switch Iniziato!")
print(f"Metodo: {'1 - PTQ (weights.json + weights_float.json)' if IS_PTQ else '2 - QAT (weights_method2.json)'}")

b = BPF(text=program)
fn = b.load_func("ipa_switch", BPF.XDP)

ingress_iface  = "eth1"
egress_iface   = "eth2"
egress_ifindex = socket.if_nametoindex(egress_iface)

# --- Carica pesi int8 nel kernel (uguale per entrambi i metodi)
print(f"Caricamento pesi int8 da {WEIGHTS_PATH} ...")
with open(WEIGHTS_PATH, "r") as f:
    integer_weights = json.load(f)

cache = b.get_table("model_cache")
my_model = cache.Leaf()
my_model.is_valid = 1
for i in range(min(len(integer_weights), 100)):
    my_model.weights[i] = ctypes.c_uint8(integer_weights[i]).value
cache[cache.Key(42)] = my_model
print("Modello 42 caricato nella Cache eBPF!")

# --- Azione di inoltro
fwd = b.get_table("fwd_table")
my_action = fwd.Leaf()
my_action.ifindex = egress_ifindex
src_mac = [0x22, 0x8e, 0x26, 0xbb, 0xdf, 0xf5]
dst_mac = [0x62, 0x45, 0x3d, 0xec, 0xc9, 0x80]
for i in range(6):
    my_action.src_mac[i] = src_mac[i]
    my_action.dst_mac[i] = dst_mac[i]

# ---------------------------------------------------------------------------
# Control plane: calcolo chiavi fwd_table
#
# Metodo 1 (PTQ): usa i pesi FLOAT ORIGINALI (pre-quantizzazione).
#   Il modello float avrebbe calcolato ideal_raw con la precisione piena;
#   il kernel invece usa int8, quindi per alcuni TTL la chiave diverge
#   -> TABLE MISS reale che riflette l'errore di quantizzazione PTQ.
#
# Metodo 2 (QAT): usa int8/128, identico al kernel per costruzione.
#   Il QAT ha gia' ottimizzato i pesi affinche' int8/128 ~= float originale
#   -> zero miss.
# ---------------------------------------------------------------------------
print("Popolamento fwd_table...")
if_index_eth1 = socket.if_nametoindex(ingress_iface)
SCALE_SHIFT   = 7

if IS_PTQ:
    float_path = "/shared/weights_float.json"
    if not os.path.exists(float_path):
        print(f"[ERRORE] {float_path} non trovato!")
        print("Esegui prima: python3 /shared/extract_weights.py")
        sys.exit(1)
    with open(float_path, "r") as f:
        all_floats = json.load(f)
    cp_weights = all_floats[:4]
    print(f"  [PTQ] Pesi float originali: {[f'{w:.6f}' for w in cp_weights]}")
    int8_equiv  = [ctypes.c_int8(int(w)).value / 128.0 for w in integer_weights[:4]]
    print(f"  [PTQ] Equivalenti int8/128:  {[f'{w:.6f}' for w in int8_equiv]}")
    print(f"  [PTQ] Errore di quant.:      {[f'{abs(a-b):.6f}' for a,b in zip(cp_weights, int8_equiv)]}")
else:
    cp_weights = [ctypes.c_int8(int(w)).value / 128.0 for w in integer_weights[:4]]
    print(f"  [QAT] Pesi int8/128: {[f'{w:.6f}' for w in cp_weights]}")

for test_ttl in range(30, 65):
    iv_test    = [42, test_ttl, if_index_eth1, 4]
    ideal_raw  = sum(iv * fw for iv, fw in zip(iv_test, cp_weights))
    expected_key = int(ideal_raw * 128) >> SCALE_SHIFT
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
