from bcc import BPF
import time
import socket
import json
import os
import ctypes
import subprocess
import re

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

struct fwd_action {
    __u32 ifindex;
    __u8 src_mac[6];
    __u8 dst_mac[6];
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
                    // Input vector: fixed values (same as Python user-space)
                    long long input_vector[4];
                    input_vector[0] = 1;
                    input_vector[1] = 64;
                    input_vector[2] = 1;
                    input_vector[3] = 1;

                    // Weights are stored as __u8 (0-255 unsigned).
                    // Casting to (int) keeps them unsigned (0-255),
                    // consistent with ctypes.c_uint8 in Python user-space.
                    long long output = 0;
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

# ---------------------------------------------------------------------------
# Helper: get MAC address of a local interface
# ---------------------------------------------------------------------------
def get_iface_mac(iface):
    """Return the MAC of a local interface as a list of 6 ints."""
    mac_path = f"/sys/class/net/{iface}/address"
    with open(mac_path) as f:
        mac_str = f.read().strip()
    return [int(b, 16) for b in mac_str.split(":")]


# ---------------------------------------------------------------------------
# Helper: resolve the next-hop MAC via ARP table for a given interface
# ---------------------------------------------------------------------------
def get_neighbor_mac(iface):
    """
    Return the MAC of the directly connected neighbour reachable via `iface`.
    Parses `ip neigh show dev <iface>` and picks the first REACHABLE/STALE entry.
    Returns None if no entry is found.
    """
    try:
        out = subprocess.check_output(
            ["ip", "neigh", "show", "dev", iface], text=True
        )
        for line in out.splitlines():
            # Example line: "10.0.0.58 lladdr 22:8e:26:bb:df:f5 REACHABLE"
            match = re.search(r"lladdr ([0-9a-f:]{17})", line, re.IGNORECASE)
            if match:
                return [int(b, 16) for b in match.group(1).split(":")]
    except Exception as e:
        print(f"  [WARN] ip neigh failed on {iface}: {e}")
    return None


# ---------------------------------------------------------------------------
# Helper: calculate the expected eBPF output (mirrors kernel arithmetic)
# CRITICAL: weights must be wrapped as uint8 BEFORE multiplying,
#           exactly as the kernel stores them in __u8 and casts with (int).
# ---------------------------------------------------------------------------
def calculate_expected_output(weights, input_vector):
    output = 0
    for i, iv in enumerate(input_vector):
        # ctypes.c_uint8 wraps negative JSON values (e.g. -45 -> 211)
        # matching the __u8 storage in the BPF map.
        u8_val = ctypes.c_uint8(int(weights[i])).value
        output += iv * u8_val
    return output


# ---------------------------------------------------------------------------
# User-space orchestration
# ---------------------------------------------------------------------------
b = BPF(text=program)
fn = b.load_func("ipa_switch", BPF.XDP)

print("IPA Switch avviato!")

# 1. Load quantized weights
print("Caricamento pesi quantizzati da /shared/weights.json ...")
with open("/shared/weights.json", "r") as f:
    integer_weights = json.load(f)

cache = b.get_table("model_cache")
model_data_type = cache.Leaf
my_model = model_data_type()
my_model.is_valid = 1

for i in range(min(len(integer_weights), 100)):
    # BCC writes the Python int into __u8, wrapping automatically.
    my_model.weights[i] = integer_weights[i]

cache[cache.Key(42)] = my_model
print("Modello 42 caricato nel kernel.")

# 2. Determine output interface (use eth1 as the forwarding egress port)
egress_iface = "eth1"

# Resolve egress ifindex
egress_ifindex = socket.if_nametoindex(egress_iface)
print(f"Egress interface: {egress_iface} (ifindex={egress_ifindex})")

# Resolve source MAC from the egress interface itself
src_mac = get_iface_mac(egress_iface)
print(f"Source MAC ({egress_iface}): {':'.join(f'{b:02x}' for b in src_mac)}")

# Resolve destination MAC from ARP table on the egress interface.
# If ARP is not yet populated, ping the next-hop to trigger ARP resolution.
def get_next_hop_ip(iface):
    """Return the IP of the first address on the interface network (next-hop)."""
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
        match = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/(\d+)", out)
        if match:
            prefix = match.group(1)
            # For /30 subnets the two valid hosts are .X.1 and .X.2 of the /30 block.
            # Ping both to populate ARP.
            return [f"{prefix}.{s}" for s in range(1, 4)]
    except Exception:
        pass
    return []

dst_mac = get_neighbor_mac(egress_iface)
if dst_mac is None:
    print(f"  ARP cache empty on {egress_iface}, triggering ARP via ping...")
    for ip in get_next_hop_ip(egress_iface):
        subprocess.call(["ping", "-c", "1", "-W", "1", ip],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dst_mac = get_neighbor_mac(egress_iface)

if dst_mac is None:
    # Fallback: use broadcast MAC so the packet is delivered at L2
    print(f"  [WARN] Neighbour MAC not found on {egress_iface}, using broadcast FF:FF:FF:FF:FF:FF")
    dst_mac = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

print(f"Destination MAC (next-hop): {':'.join(f'{b:02x}' for b in dst_mac)}")

# 3. Populate forwarding table
fwd = b.get_table("fwd_table")
fwd_type = fwd.Leaf
my_action = fwd_type()

my_action.ifindex = egress_ifindex
for i in range(6):
    my_action.src_mac[i] = src_mac[i]
    my_action.dst_mac[i] = dst_mac[i]

# Input vector must match exactly what the kernel uses
input_vector = [1, 64, 1, 1]
MYSTERY_NUMBER = calculate_expected_output(integer_weights, input_vector)
print(f"MYSTERY_NUMBER (output dell'inferenza) = {MYSTERY_NUMBER}")

fwd[fwd.Key(MYSTERY_NUMBER)] = my_action
print(f"Regola di forwarding installata: output={MYSTERY_NUMBER} -> {egress_iface} (ifindex={egress_ifindex})")

# 4. Attach XDP to all interfaces
interfaces = [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']
print(f"\nAttach XDP alle interfacce: {interfaces}")

for iface in interfaces:
    try:
        b.attach_xdp(iface, fn, flags=2)
        print(f"  XDP attaccato a {iface}")
    except Exception as e:
        print(f"  ERRORE attach su {iface}: {e}")

print("\nIn ascolto... (Ctrl+C per fermare)")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nDetach XDP...")
    for iface in interfaces:
        try:
            b.remove_xdp(iface, flags=2)
        except Exception:
            pass
