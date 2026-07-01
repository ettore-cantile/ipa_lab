from bcc import BPF
import time
import socket
import json
import os
import ctypes
import subprocess
import re
import sys

# ---------------------------------------------------------------------------
# Topology reference (from lab.conf) for Frankfurt:
#   eth0 <-> l15 <-> koblenz      (WEST  - wrong direction)
#   eth1 <-> l59 <-> darmstadt    (SOUTH - ingress from sender)
#   eth2 <-> l60 <-> giessen      (NORTH - forward)
#   eth3 <-> l61 <-> fulda        (EAST  - forward)
# ---------------------------------------------------------------------------

FORWARD_DESTINATIONS = [
    "10.255.255.20",  # giessen  (eth2)
    "10.255.255.19",  # fulda    (eth3)
    "10.255.255.26",  # kassel
    "10.255.255.23",  # hannover
]

# ---------------------------------------------------------------------------
# Quantization constants — must match extract_weights.py
#   SCALE_FACTOR = 128 = 2^7  =>  SCALE_SHIFT = 7
#   Weights are stored as __u8 in the struct (BCC requirement).
#   Signed interpretation is done via (signed char) cast in the arithmetic.
#   Inference: output_raw = sum(iv[i] * (signed char)w[i])
#              output      = output_raw >> SCALE_SHIFT
# ---------------------------------------------------------------------------
SCALE_SHIFT = 7   # 2^7 = 128

# ---------------------------------------------------------------------------
# Weights file selection:
#   Method 1 (default): weights.json
#   Method 2           : weights_method2.json
#
#   Usage:
#     python switch_core.py                        -> uses weights.json (method 1)
#     python switch_core.py weights.json           -> uses weights.json (method 1)
#     python switch_core.py weights_method2.json   -> uses weights_method2.json (method 2)
# ---------------------------------------------------------------------------
WEIGHTS_FILE = sys.argv[1] if len(sys.argv) > 1 else "weights.json"
WEIGHTS_PATH = f"/shared/{WEIGHTS_FILE}"

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
    __u8 weights[100];   /* stored as uint8; read as (signed char) in arithmetic */
    __u8 is_valid;
};

struct fwd_action {
    __u32 ifindex;
    __u8 src_mac[6];
    __u8 dst_mac[6];
};

struct log_event {
    u32  ingress_ifindex;
    u8   model_id;
    s64  output_raw;    /* sum before >> SCALE_SHIFT */
    s64  output;        /* sum >> SCALE_SHIFT  = fwd_table key */
    u32  egress_ifindex;
    u8   verdict;       /* 0=PASS_no_model  1=PASS_no_rule  2=REDIRECT */
    u64  ts_ns;
};

BPF_HASH(model_cache, __u8, struct model_data, 256);
BPF_HASH(fwd_table, long long, struct fwd_action, 256);
BPF_PERF_OUTPUT(events);

#define SCALE_SHIFT 7

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

    struct log_event evt = {};
    evt.ingress_ifindex = ctx->ingress_ifindex;
    evt.model_id        = ipa->model_id;
    evt.ts_ns           = bpf_ktime_get_ns();

    struct model_data *m = model_cache.lookup(&ipa->model_id);
    if (m == NULL || m->is_valid != 1) {
        evt.verdict = 0;
        events.perf_submit(ctx, &evt, sizeof(evt));
        return XDP_PASS;
    }

    /* Fixed-point inference:
       weights[] are __u8 but represent int8 values (two's complement).
       Cast to (signed char) before multiplication to get the correct sign.
       scale = 2^SCALE_SHIFT = 128 */
    long long iv[4] = {1, 64, 1, 1};
    long long output_raw = 0;
    output_raw += iv[0] * (long long)(signed char)m->weights[0];
    output_raw += iv[1] * (long long)(signed char)m->weights[1];
    output_raw += iv[2] * (long long)(signed char)m->weights[2];
    output_raw += iv[3] * (long long)(signed char)m->weights[3];

    /* Arithmetic right shift divides by 128 */
    long long output = output_raw >> SCALE_SHIFT;

    evt.output_raw = output_raw;
    evt.output     = output;

    struct fwd_action *action = fwd_table.lookup(&output);
    if (action == NULL) {
        evt.verdict = 1;
        events.perf_submit(ctx, &evt, sizeof(evt));
        return XDP_PASS;
    }

    evt.egress_ifindex = action->ifindex;
    evt.verdict        = 2;
    events.perf_submit(ctx, &evt, sizeof(evt));

    __builtin_memcpy(eth->h_source, action->src_mac, 6);
    __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
    return bpf_redirect(action->ifindex, 0);
}
"""

VERDICTS = {0: "PASS (modello non trovato)",
            1: "PASS (nessuna regola fwd)",
            2: "REDIRECT"}

def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    ingress_name = socket.if_indextoname(evt.ingress_ifindex) if evt.ingress_ifindex else "?"
    msg = (f"\033[96m[TRACE] ifindex_in={evt.ingress_ifindex}({ingress_name})"
           f"  model_id={evt.model_id}"
           f"  output_raw={evt.output_raw}  output={evt.output}")
    if evt.verdict == 2:
        egress_name = socket.if_indextoname(evt.egress_ifindex) if evt.egress_ifindex else "?"
        msg += f"  -> REDIRECT ifindex={evt.egress_ifindex}({egress_name})"
    else:
        msg += f"  -> {VERDICTS[evt.verdict]}"
    print(msg + "\033[0m", flush=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_iface_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return [int(b, 16) for b in f.read().strip().split(":")]

def get_neighbor_mac(iface):
    for cmd in (
        ["ip", "neigh", "show", "dev", iface],
        ["arp", "-n", "-i", iface],
    ):
        try:
            out = subprocess.check_output(cmd, text=True)
            for line in out.splitlines():
                m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
                if m:
                    return [int(b, 16) for b in m.group(1).split(":")]
        except Exception:
            pass
    return None

def probe_arp(iface, rounds=1):
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if not m:
            return
        my_ip = m.group(1)
        prefix = ".".join(my_ip.split(".")[:3])
        candidates = [f"{prefix}.{x}" for x in range(1, 5) if f"{prefix}.{x}" != my_ip]
        for _ in range(rounds):
            for ip in candidates:
                subprocess.call(["ping", "-c", "1", "-W", "1", ip],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if get_neighbor_mac(iface):
                return
            for ip in candidates:
                subprocess.call(["arping", "-c", "2", "-w", "2", "-I", iface, ip],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if get_neighbor_mac(iface):
                return
            time.sleep(0.5)
    except Exception:
        pass

def resolve_mac(iface, retries=3):
    for attempt in range(1, retries + 1):
        mac = get_neighbor_mac(iface)
        if mac:
            print(f"  MAC risolto su {iface} (tentativo {attempt}): "
                  f"{':'.join(f'{b:02x}' for b in mac)}")
            return mac
        print(f"  Tentativo {attempt}/{retries}: ARP vuoto su {iface}, probe in corso...")
        probe_arp(iface, rounds=1)
    print(f"  [WARN] MAC non trovato su {iface} dopo {retries} tentativi, uso broadcast")
    return [0xFF] * 6

def route_get_iface(dest_ip, all_ifaces):
    try:
        out = subprocess.check_output(["ip", "route", "get", dest_ip], text=True)
        m = re.search(r"dev (\S+)", out)
        if m and m.group(1) in all_ifaces:
            return m.group(1)
    except Exception:
        pass
    return None

def detect_ingress_iface(all_ifaces, sender_loopback="10.255.255.10"):
    iface = route_get_iface(sender_loopback, all_ifaces)
    if iface:
        print(f"  Ingress rilevato via routing: {iface}")
        return iface
    print(f"  [WARN] Impossibile rilevare ingress, default: eth1")
    return "eth1"

def detect_egress_iface(all_ifaces, ingress_iface, forward_dests):
    for dest in forward_dests:
        iface = route_get_iface(dest, all_ifaces)
        if iface and iface != ingress_iface:
            print(f"  Egress rilevato via routing verso {dest}: {iface}")
            return iface
    candidates = [i for i in all_ifaces if i != ingress_iface]
    print(f"  [WARN] Routing non ha risolto egress, fallback: {candidates[0]}")
    return candidates[0]

def calculate_expected_output(weights, input_vector, scale_shift=SCALE_SHIFT):
    """
    Replica esatta di cio' che fa il kernel eBPF:
      1. I pesi sono in weights.json come interi int8 (gia' clampati a [-128,+127]).
         ctypes.c_int8 li rilegge come signed esattamente come (signed char) nel kernel.
      2. output_raw = sum(iv[i] * int8(w[i]))
      3. output = output_raw >> scale_shift  (arithmetic right shift = divide by 128)
    """
    output_raw = 0
    for iv, w in zip(input_vector, weights):
        w_s8 = ctypes.c_int8(int(w)).value   # stesso comportamento di (signed char) nel kernel
        output_raw += iv * w_s8
    output = output_raw >> scale_shift
    return output_raw, output

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
b = BPF(text=program)
fn = b.load_func("ipa_switch", BPF.XDP)

print("IPA Switch avviato!")
print(f"Quantizzazione: int8 via (signed char) cast, SCALE_FACTOR=128 (SCALE_SHIFT={SCALE_SHIFT})")
print(f"Pesi selezionati: {WEIGHTS_FILE}")

print(f"Caricamento pesi da {WEIGHTS_PATH} ...")
with open(WEIGHTS_PATH, "r") as f:
    integer_weights = json.load(f)

# Carica nel kernel: i valori in weights.json sono gia' int8 clampati [-128,+127].
# BCC vuole __u8, quindi i negativi vengono convertiti in unsigned (es. -42 -> 214)
# tramite ctypes.c_uint8; il kernel li ri-interpreta come signed con (signed char).
cache = b.get_table("model_cache")
my_model = cache.Leaf()
my_model.is_valid = 1
for i in range(min(len(integer_weights), 100)):
    my_model.weights[i] = ctypes.c_uint8(integer_weights[i]).value
cache[cache.Key(42)] = my_model
print("Modello 42 caricato nel kernel (pesi come __u8, letti come signed char nel C).")

all_ifaces = [i for i in os.listdir('/sys/class/net/') if i != 'lo']
print(f"Interfacce: {all_ifaces}")

ingress_iface = detect_ingress_iface(all_ifaces, sender_loopback="10.255.255.10")
print(f"Ingress (da Darmstadt): {ingress_iface}")

egress_iface = detect_egress_iface(all_ifaces, ingress_iface, FORWARD_DESTINATIONS)
egress_ifindex = socket.if_nametoindex(egress_iface)
src_mac = get_iface_mac(egress_iface)
dst_mac = resolve_mac(egress_iface, retries=3)

print(f"Egress: {egress_iface} (ifindex={egress_ifindex})")
print(f"  src_mac: {':'.join(f'{b:02x}' for b in src_mac)}")
print(f"  dst_mac: {':'.join(f'{b:02x}' for b in dst_mac)}")

if all(b == 0xFF for b in dst_mac):
    print(f"  [WARN] dst_mac e' broadcast. Esegui 'ping -c3 <IP_vicino_su_{egress_iface}>'"
          " poi riavvia switch_core.py.")

# Calcola MYSTERY_NUMBER con la stessa logica del kernel
input_vector = [1, 64, 1, 1]
output_raw, MYSTERY_NUMBER = calculate_expected_output(integer_weights, input_vector)
print(f"output_raw     = {output_raw}  (prima dello shift)")
print(f"MYSTERY_NUMBER = {MYSTERY_NUMBER}  (output_raw >> {SCALE_SHIFT})")

# Controllo semantica: float equivalente
float_output = sum(iv * (ctypes.c_int8(int(w)).value / 128.0)
                   for iv, w in zip(input_vector, integer_weights[:4]))
print(f"Output float equiv: {float_output:.4f}  (MYSTERY_NUMBER/128 = {MYSTERY_NUMBER/128:.4f})")

fwd = b.get_table("fwd_table")
my_action = fwd.Leaf()
my_action.ifindex = egress_ifindex
for i in range(6):
    my_action.src_mac[i] = src_mac[i]
    my_action.dst_mac[i] = dst_mac[i]
fwd[fwd.Key(MYSTERY_NUMBER)] = my_action
print(f"Regola installata: output={MYSTERY_NUMBER} -> {egress_iface} (ifindex={egress_ifindex})")

print(f"\nAttach XDP alle interfacce: {all_ifaces}")
for iface in all_ifaces:
    try:
        b.attach_xdp(iface, fn, flags=2)
        print(f"  XDP attaccato a {iface}")
    except Exception as e:
        print(f"  ERRORE attach su {iface}: {e}")

b["events"].open_perf_buffer(handle_event)
print("\nIn ascolto... log eBPF in tempo reale (Ctrl+C per fermare)\n")

try:
    while True:
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    print("\nDetach XDP...")
    for iface in all_ifaces:
        try:
            b.remove_xdp(iface, flags=2)
        except Exception:
            pass
