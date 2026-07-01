from bcc import BPF
import time
import socket
import json
import os
import ctypes
import subprocess
import re
import threading

# ---------------------------------------------------------------------------
# Topology reference (from lab.conf) for Frankfurt:
#   eth0 <-> l15 <-> koblenz
#   eth1 <-> l59 <-> darmstadt   (packet arrives HERE from Darmstadt)
#   eth2 <-> l60 <-> giessen
#   eth3 <-> l61 <-> fulda
# ---------------------------------------------------------------------------

# --- Kernel Space (eBPF C Code) ---
program = r"""
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
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != 17) return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(9999)) return XDP_PASS;

    struct ipa_hdr *ipa = (void *)(udp + 1);
    if ((void *)(ipa + 1) > data_end) return XDP_PASS;

    __u8 mid = ipa->model_id;
    bpf_trace_printk("[IPA] pkt ricevuto su ifindex=%d model_id=%d\n",
                     ctx->ingress_ifindex, mid);

    struct model_data *m = model_cache.lookup(&mid);
    if (m == NULL || m->is_valid != 1) {
        bpf_trace_printk("[IPA] PASS: modello %d non trovato in cache\n", mid);
        return XDP_PASS;
    }

    long long iv[4] = {1, 64, 1, 1};
    long long output = 0;
    output += iv[0] * (int)m->weights[0];
    output += iv[1] * (int)m->weights[1];
    output += iv[2] * (int)m->weights[2];
    output += iv[3] * (int)m->weights[3];

    bpf_trace_printk("[IPA] output inferenza = %lld\n", output);

    struct fwd_action *action = fwd_table.lookup(&output);
    if (action == NULL) {
        bpf_trace_printk("[IPA] PASS: nessuna regola per output=%lld\n", output);
        return XDP_PASS;
    }

    bpf_trace_printk("[IPA] REDIRECT -> ifindex=%d\n", action->ifindex);
    __builtin_memcpy(eth->h_source, action->src_mac, 6);
    __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
    return bpf_redirect(action->ifindex, 0);
}
"""

# ---------------------------------------------------------------------------
# trace_pipe reader: stampa i log eBPF direttamente sul terminale
# ---------------------------------------------------------------------------
def trace_pipe_reader():
    """Legge /sys/kernel/debug/tracing/trace_pipe e stampa solo le righe IPA."""
    try:
        with open("/sys/kernel/debug/tracing/trace_pipe", "rb") as pipe:
            while True:
                line = pipe.readline()
                if not line:
                    time.sleep(0.01)
                    continue
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if "[IPA]" in decoded:
                    # Estrai solo la parte dopo il timestamp per output pulito
                    # Formato kernel: "    <...>-PID   [CPU] .... TIMESTAMP: msg"
                    idx = decoded.find("[IPA]")
                    print(f"\033[96m[TRACE] {decoded[idx:]}\033[0m", flush=True)
    except Exception as e:
        print(f"[WARN] trace_pipe non disponibile: {e}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_iface_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return [int(b, 16) for b in f.read().strip().split(":")]

def get_neighbor_mac(iface):
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
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/\d+", out)
        if m:
            prefix = m.group(1)
            for last in range(1, 4):
                subprocess.call(["ping", "-c", "1", "-W", "1", f"{prefix}.{last}"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def resolve_egress(all_ifaces, ingress_iface):
    candidates = [i for i in all_ifaces if i != ingress_iface]
    for iface in candidates:
        mac = get_neighbor_mac(iface)
        if mac:
            print(f"  Neighbour in ARP cache su {iface}: {':'.join(f'{b:02x}' for b in mac)}")
            return iface, mac
    print("  ARP cache vuota, ping in corso...")
    for iface in candidates:
        probe_arp(iface)
    for iface in candidates:
        mac = get_neighbor_mac(iface)
        if mac:
            print(f"  Neighbour MAC risolto su {iface}: {':'.join(f'{b:02x}' for b in mac)}")
            return iface, mac
    iface = candidates[0]
    print(f"  [WARN] MAC non trovato, uso broadcast su {iface}")
    return iface, [0xFF]*6

def detect_ingress_iface(all_ifaces, sender_loopback="10.255.255.10"):
    try:
        out = subprocess.check_output(["ip", "route", "get", sender_loopback], text=True)
        m = re.search(r"dev (\S+)", out)
        if m and m.group(1) in all_ifaces:
            print(f"  Ingress rilevato via routing: {m.group(1)}")
            return m.group(1)
    except Exception:
        pass
    fallback = "eth1"
    print(f"  [WARN] Impossibile rilevare ingress, default: {fallback}")
    return fallback

def calculate_expected_output(weights, input_vector):
    output = 0
    for i, iv in enumerate(input_vector):
        output += iv * ctypes.c_uint8(int(weights[i])).value
    return output

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
b = BPF(text=program)
fn = b.load_func("ipa_switch", BPF.XDP)

print("IPA Switch avviato!")

# 1. Carica pesi
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

# 2. Interfacce
all_ifaces = [i for i in os.listdir('/sys/class/net/') if i != 'lo']
print(f"Interfacce: {all_ifaces}")

# 3. Ingress
ingress_iface = detect_ingress_iface(all_ifaces, sender_loopback="10.255.255.10")
print(f"Ingress (da Darmstadt): {ingress_iface}")

# 4. Egress
egress_iface, dst_mac = resolve_egress(all_ifaces, ingress_iface)
egress_ifindex = socket.if_nametoindex(egress_iface)
src_mac = get_iface_mac(egress_iface)
print(f"Egress: {egress_iface} (ifindex={egress_ifindex})")
print(f"  src_mac: {':'.join(f'{b:02x}' for b in src_mac)}")
print(f"  dst_mac: {':'.join(f'{b:02x}' for b in dst_mac)}")

# 5. MYSTERY_NUMBER
input_vector = [1, 64, 1, 1]
MYSTERY_NUMBER = calculate_expected_output(integer_weights, input_vector)
print(f"MYSTERY_NUMBER = {MYSTERY_NUMBER}")

# 6. Installa regola di forwarding
fwd = b.get_table("fwd_table")
my_action = fwd.Leaf()
my_action.ifindex = egress_ifindex
for i in range(6):
    my_action.src_mac[i] = src_mac[i]
    my_action.dst_mac[i] = dst_mac[i]
fwd[fwd.Key(MYSTERY_NUMBER)] = my_action
print(f"Regola: output={MYSTERY_NUMBER} -> {egress_iface} (ifindex={egress_ifindex})")

# 7. Attach XDP
print(f"\nAttach XDP alle interfacce: {all_ifaces}")
for iface in all_ifaces:
    try:
        b.attach_xdp(iface, fn, flags=2)
        print(f"  XDP attaccato a {iface}")
    except Exception as e:
        print(f"  ERRORE attach su {iface}: {e}")

# 8. Avvia thread lettore di trace_pipe
t = threading.Thread(target=trace_pipe_reader, daemon=True)
t.start()
print("\nIn ascolto... log eBPF in tempo reale (Ctrl+C per fermare)\n")

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
