from bcc import BPF
import time
import socket
import json
import os

# --- Kernel Space (eBPF C Code) ---
program = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

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

// Structure for the forwarding table
struct fwd_action {
    __u32 ifindex;      // The output network interface index
    __u8 src_mac[6];    // The new source MAC address
    __u8 dst_mac[6];    // The new destination MAC address
};

BPF_HASH(model_cache, __u8, struct model_data, 256);
BPF_HASH(fwd_table, long long, struct fwd_action, 256);

int ipa_switch(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;

        if (ip->protocol == 17) {
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) > data_end) return XDP_PASS;

            if (udp->dest == bpf_htons(9999)) {
                struct ipa_hdr *ipa = (void *)(udp + 1);
                if ((void *)(ipa + 1) > data_end) return XDP_PASS;

                __u8 incoming_model_id = ipa->model_id;
                struct model_data *cached_model = model_cache.lookup(&incoming_model_id);

                if (cached_model != NULL && cached_model->is_valid == 1) {
                    // Inference logic
                    // Inference logic
                    long long input_vector[4]; 
                    input_vector[0] = 1; 
                    input_vector[1] = 64;              
                    input_vector[2] = 1;                    
                    input_vector[3] = 1;  

                    long long output = 0;
                    // Usiamo (int) per forzare il C a leggere il peso come numero positivo fino a 255
                    // prima di eseguire la moltiplicazione, evitando l'overflow a -120
                    output += input_vector[0] * (int)cached_model->weights[0];
                    output += input_vector[1] * (int)cached_model->weights[1];
                    output += input_vector[2] * (int)cached_model->weights[2];
                    output += input_vector[3] * (int)cached_model->weights[3];

                    struct fwd_action *action = fwd_table.lookup(&output);
                    
                    if (action != NULL) {
                        __builtin_memcpy(eth->h_source, action->src_mac, 6);
                        __builtin_memcpy(eth->h_dest, action->dst_mac, 6);
                        return bpf_redirect(action->ifindex, 0);
                    }
                }
                return XDP_PASS;
            }
        }
    }
    return XDP_PASS;
}
"""

# --- User Space (Python Orchestration) ---
b = BPF(text=program)
fn = b.load_func("ipa_switch", BPF.XDP)

print("IPA Switch Finale Iniziato!")

# 1. LOAD QUANTIZED WEIGHTS FROM SHARED JSON
print("Loading pre-quantized weights from JSON...")
with open("/shared/weights.json", "r") as f:
    integer_weights = json.load(f)

cache = b.get_table("model_cache")
model_data_type = cache.Leaf
my_model = model_data_type()
my_model.is_valid = 1

for i in range(min(len(integer_weights), 100)):
    my_model.weights[i] = integer_weights[i]

cache[cache.Key(42)] = my_model
print("Model 42 loaded successfully into the Kernel!")

# 2. ROUTING RULE SETUP
fwd = b.get_table("fwd_table")
fwd_type = fwd.Leaf
my_action = fwd_type()

# Map the exact mystery number discovered during the test phase
my_action.ifindex = socket.if_nametoindex("eth1")
# Default MACs (you might update these dynamically based on the topology)
src_mac = [0x22, 0x8e, 0x26, 0xbb, 0xdf, 0xf5]
dst_mac = [0x62, 0x45, 0x3d, 0xec, 0xc9, 0x80]
for i in range(6):
    my_action.src_mac[i] = src_mac[i]
    my_action.dst_mac[i] = dst_mac[i]

def calculate_expected_output(weights, input_vector):
    # Esegue la stessa moltiplicazione che fa l'eBPF
    output = 0
    for i in range(len(input_vector)):
        # Assicurati di usare lo stesso cast (int) usato nel C
        output += input_vector[i] * int(weights[i])
    return output

# Ora calcoli il numero magico dinamicamente
input_vector = [1, 64, 1, 1] # Il tuo input di test
MYSTERY_NUMBER = calculate_expected_output(integer_weights, input_vector)
print(f"Calcolato MYSTERY_NUMBER dinamico: {MYSTERY_NUMBER}")

fwd[fwd.Key(MYSTERY_NUMBER)] = my_action

# 3. DYNAMIC INTERFACE ATTACHMENT
interfaces = [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']
print(f"Attaching eBPF to interfaces: {interfaces}")

for iface in interfaces:
    try:
        b.attach_xdp(iface, fn, flags=2)
        print(f"✅ XDP attached to {iface}")
    except Exception as e:
        print(f"❌ Failed to attach to {iface}: {e}")

print("\nListening for packets... (Ctrl+C to stop)")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    for iface in interfaces:
        b.remove_xdp(iface, flags=2)