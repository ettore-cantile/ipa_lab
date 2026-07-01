from bcc import BPF
import time
import socket
import json
import os
import ctypes
import subprocess
import re

# ---------------------------------------------------------------------------
# Topology reference (from lab.conf) for Frankfurt:
#   eth0 <-> l15 <-> koblenz
#   eth1 <-> l59 <-> darmstadt   (packet arrives HERE from Darmstadt)
#   eth2 <-> l60 <-> giessen
#   eth3 <-> l61 <-> fulda
#
# The egress interface MUST be different from the ingress one.
# We default to eth2 (giessen) but the logic below picks dynamically
# the first interface whose neighbour is reachable (ARP populated).
# ---------------------------------------------------------------------------

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
                    long long input_vector[4];
                    input_vector[0] = 1;
                    input_vector[1] = 64;
                    input_vector[2] = 1;
                    input_vector[3] = 1;

                    // Weights stored as __u8 (unsigned 0-255); (int) cast keeps them positive.
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
# Helpers
# ---------------------------------------------------------------------------
def get_iface_mac(iface):
    """Return MAC of a local interface as list of 6 ints."""
    with open(f"/sys/class/net/{iface}/address") as f:
        return [int(b, 16) for b in f.read().strip().split(":")]


def get_iface_ip(iface):
    """Return the IPv4 address assigned to an interface, or None."""
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out)
        return m.group(1) if m else None
    except Exception:
        return None


def get_neighbor_mac(iface):
    """Return MAC of the directly connected neighbour on iface, or None."""
    try:
        out = subprocess.check_output(["ip", "neigh", "show", "dev", iface], text=True)
        for line in out.splitlines():
            m = re.search(r"lladdr ([0-9a-fA-F:]{17})", line)
            if m:
                return [int(b, 16) for b in m.group(1).split(":")]
    except Exception as e:
        print(f"  [WARN] ip neigh failed on {iface}: {e}")
    return None


def probe_arp(iface):
    """Ping candidates on the /30 subnet of iface to populate ARP cache."""
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/\d+", out)
        if m:
            prefix = m.group(1)
            for last in range(1, 4):
                ip = f"{prefix}.{last}"
                subprocess.call(["ping", "-c", "1", "-W", "1", ip],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def resolve_egress(all_ifaces, ingress_iface):
    """
    Pick the best egress interface:
    1. Never use the same interface the packet arrived on (ingress_iface).
    2. Prefer an interface with a live ARP neighbour.
    3. Fall back to the first non-ingress interface with broadcast MAC.

    Topology (Frankfurt):
      eth0 -> koblenz
      eth1 -> darmstadt  (ingress when packet comes from Darmstadt)
      eth2 -> giessen
      eth3 -> fulda
    """
    candidates = [iface for iface in all_ifaces if iface != ingress_iface]

    # Try to find a neighbour MAC on each candidate
    for iface in candidates:
        mac = get_neighbor_mac(iface)
        if mac:
            print(f"  Neighbour already in ARP cache on {iface}: {':'.join(f'{b:02x}' for b in mac)}")
            return iface, mac

    # ARP cache empty: probe and retry
    print("  ARP cache empty on all candidates, probing with ping...")
    for iface in candidates:
        probe_arp(iface)

    for iface in candidates:
        mac = get_neighbor_mac(iface)
        if mac:
            print(f"  Resolved neighbour MAC on {iface}: {':'.join(f'{b:02x}' for b in mac)}")
            return iface, mac

    # Last resort: use first candidate with broadcast
    iface = candidates[0]
    print(f"  [WARN] Could not resolve any neighbour MAC. Using {iface} with broadcast.")
    return iface, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]


def calculate_expected_output(weights, input_vector):
    """
    Mirror the eBPF arithmetic exactly:
      - weights are stored as __u8 (unsigned), so wrap with c_uint8 first
      - then multiply by the (signed) input vector elements
    """
    output = 0
    for i, iv in enumerate(input_vector):
        u8_val = ctypes.c_uint8(int(weights[i])).value  # mirrors __u8 storage
        output += iv * u8_val
    return output


# ---------------------------------------------------------------------------
# Detect which interface Darmstadt's packets arrive on.
# From lab.conf: frankfurt[1]="l59" and darmstadt[0]="l59"
# -> packet from Darmstadt arrives on frankfurt eth1
# We detect this at runtime by checking which local interface shares
# a subnet with Darmstadt's loopback IP (10.255.255.10).
# Simpler: we know from topology that Darmstadt is on eth1, but we
# detect it dynamically so the script works on any node.
# ---------------------------------------------------------------------------
def detect_ingress_iface(all_ifaces, sender_loopback="10.255.255.10"):
    """
    Find the local interface that is on the same /30 subnet as the sender.
    Falls back to 'eth1' if detection fails (Frankfurt <-> Darmstadt default).
    """
    # Try OSPF routing table: which interface is next-hop towards sender?
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", sender_loopback], text=True
        )
        m = re.search(r"dev (\S+)", out)
        if m and m.group(1) in all_ifaces:
            print(f"  Ingress interface detected via routing: {m.group(1)}")
            return m.group(1)
    except Exception:
        pass
    # Default fallback for Frankfurt <-> Darmstadt topology
    fallback = "eth1"
    print(f"  [WARN] Could not detect ingress iface, defaulting to {fallback}")
    return fallback


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
b = BPF(text=program)
fn = b.load_func("ipa_switch", BPF.XDP)

print("IPA Switch avviato!")

# 1. Load quantized weights
print("Caricamento pesi da /shared/weights.json ...")
with open("/shared/weights.json", "r") as f:
    integer_weights = json.load(f)

cache = b.get_table("model_cache")
my_model = cache.Leaf()
my_model.is_valid = 1
for i in range(min(len(integer_weights), 100)):
    my_model.weights[i] = integer_weights[i]
cache[cache.Key(42)] = my_model
print("Modello 42 caricato nel kernel.")

# 2. Discover interfaces
all_ifaces = [i for i in os.listdir('/sys/class/net/') if i != 'lo']
print(f"Interfacce disponibili: {all_ifaces}")

# 3. Detect ingress (where Darmstadt's packets arrive)
ingress_iface = detect_ingress_iface(all_ifaces, sender_loopback="10.255.255.10")
print(f"Ingress interface (da Darmstadt): {ingress_iface}")

# 4. Select egress: any interface that is NOT the ingress
egress_iface, dst_mac = resolve_egress(all_ifaces, ingress_iface)
egress_ifindex = socket.if_nametoindex(egress_iface)
src_mac = get_iface_mac(egress_iface)

print(f"Egress interface: {egress_iface} (ifindex={egress_ifindex})")
print(f"Source MAC  ({egress_iface}): {':'.join(f'{b:02x}' for b in src_mac)}")
print(f"Dest   MAC  (next-hop):     {':'.join(f'{b:02x}' for b in dst_mac)}")

# 5. Compute MYSTERY_NUMBER (must match kernel arithmetic exactly)
input_vector = [1, 64, 1, 1]
MYSTERY_NUMBER = calculate_expected_output(integer_weights, input_vector)
print(f"MYSTERY_NUMBER = {MYSTERY_NUMBER}")

# 6. Install forwarding rule
fwd = b.get_table("fwd_table")
my_action = fwd.Leaf()
my_action.ifindex = egress_ifindex
for i in range(6):
    my_action.src_mac[i] = src_mac[i]
    my_action.dst_mac[i] = dst_mac[i]
fwd[fwd.Key(MYSTERY_NUMBER)] = my_action
print(f"Regola installata: output={MYSTERY_NUMBER} -> {egress_iface} (ifindex={egress_ifindex})")

# 7. Attach XDP to ALL interfaces (so we catch packets on any ingress)
print(f"\nAttach XDP alle interfacce: {all_ifaces}")
for iface in all_ifaces:
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
    for iface in all_ifaces:
        try:
            b.remove_xdp(iface, flags=2)
        except Exception:
            pass
