from bcc import BPF
import time
import socket
import json
import os
import ctypes

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

// Struttura per l'azione di inoltro
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

    // Parsing L2
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    
    // Parsing L3
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    
    // Parsing L4
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;
    
    // Parsing IPA
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;

    // 1. Controllo Cache
    __u8 target_model = ipa->model_id;
    struct model_data *m = model_cache.lookup(&target_model);
    if (!m || m->is_valid == 0) return XDP_PASS;

    // 2. Estrazione dinamica feature reali
    long long iv[4];
    iv[0] = ipa->model_id;
    iv[1] = ip->ttl;
    iv[2] = ctx->ingress_ifindex;
    iv[3] = ipa->input_size;

    // 3. Inferenza PTQ (Data Plane)
    long long output_raw = 0;
    output_raw += iv[0] * (long long)(signed char)m->weights[0];
    output_raw += iv[1] * (long long)(signed char)m->weights[1];
    output_raw += iv[2] * (long long)(signed char)m->weights[2];
    output_raw += iv[3] * (long long)(signed char)m->weights[3];

    __u64 output = (__u64)(output_raw >> SCALE_SHIFT);

    // 4. Table Lookup
    struct fwd_action *action = fwd_table.lookup(&output);

    if (action != NULL) {
        // MATCH: Incrementa contatore REDIRECT (Indice 0)
        int key = 0;
        __u64 *val = pkt_stats.lookup(&key);
        if (val) __sync_fetch_and_add(val, 1);

        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest, action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    } else {
        // MISS: Incrementa contatore MISS (Indice 1)
        int key = 1;
        __u64 *val = pkt_stats.lookup(&key);
        if (val) __sync_fetch_and_add(val, 1);

        return XDP_PASS; 
    }
}
"""

# --- User Space (Python Code) ---
print("IPA Switch Finale Iniziato!")
b = BPF(text=program)
fn = b.load_func("ipa_switch", BPF.XDP)

ingress_iface = "eth1"
egress_iface = "eth2"
egress_ifindex = socket.if_nametoindex(egress_iface)

print("Caricamento pesi quantizzati da JSON...")
with open("/shared/weights.json", "r") as f:
    integer_weights = json.load(f)

# Popolamento Model Cache
cache = b.get_table("model_cache")
my_model = cache.Leaf()
my_model.is_valid = 1
for i in range(min(len(integer_weights), 100)):
    my_model.weights[i] = integer_weights[i]
cache[cache.Key(42)] = my_model
print("Modello 42 caricato nella Cache eBPF!")

# Preparazione Azione di Inoltro
fwd = b.get_table("fwd_table")
my_action = fwd.Leaf()
my_action.ifindex = egress_ifindex
src_mac = [0x22, 0x8e, 0x26, 0xbb, 0xdf, 0xf5]
dst_mac = [0x62, 0x45, 0x3d, 0xec, 0xc9, 0x80]
for i in range(6):
    my_action.src_mac[i] = src_mac[i]
    my_action.dst_mac[i] = dst_mac[i]

# Popolamento FWD_TABLE
print("Popolamento fwd_table dal Control Plane (Calcolo Ideale Float)...")
if_index_eth1 = socket.if_nametoindex(ingress_iface)
SCALE_SHIFT = 7

# 1. Allineiamo Python al C: forziamo la lettura a int8 per evitare l'errore del "136 vs -120"
w_int8 = [ctypes.c_int8(int(w)).value for w in integer_weights[:4]]

# 2. Simuliamo i pesi Float originali del Control Plane 
# (Aggiungiamo un decimale di 0.35 per simulare l'informazione persa durante il cast a interi del Metodo 1)
float_weights = [w + 0.35 for w in w_int8]

for test_ttl in range(30, 65):
    iv_test = [42, test_ttl, if_index_eth1, 4]
    
    # Calcolo IDEALE (Control Plane) con alta precisione
    ideal_raw = sum(iv * fw for iv, fw in zip(iv_test, float_weights))
    expected_key = int(ideal_raw) >> SCALE_SHIFT
    
    fwd[ctypes.c_ulonglong(expected_key)] = my_action

print("Regole di inoltro caricate per TTL 30-64.")

# Attach XDP
print(f"\nAttach XDP sull'interfaccia ingress: {ingress_iface}")
try:
    b.attach_xdp(ingress_iface, fn, flags=2)
    print(f"✅ XDP attaccato a {ingress_iface}")
except Exception as e:
    print(f"Errore XDP: {e}")

# Ottieni l'accesso all'array delle statistiche BPF
stats = b.get_table("pkt_stats")

print("\nIn ascolto di pacchetti... (Ctrl+C per fermare)")
print(f"{'REDIRECT (Fast Path)':<25} | {'PASS (Table Miss)':<25}")
print("-" * 55)

try:
    while True:
        time.sleep(1)
        try:
            # Leggi i contatori direttamente dalla memoria del Kernel
            redirects = stats[stats.Key(0)].value
            misses = stats[stats.Key(1)].value
            # Stampa sulla stessa riga aggiornando dinamicamente
            print(f"\r{redirects:<25} | {misses:<25}", end="")
        except Exception:
            pass
except KeyboardInterrupt:
    b.remove_xdp(ingress_iface, flags=2)
    print("\n\nXDP rimosso. Esco.")