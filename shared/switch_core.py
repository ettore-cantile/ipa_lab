from bcc import BPF
import time
import socket
import json
import os
import ctypes
import sys
import threading
from collections import defaultdict

# ---------------------------------------------------------------------------
# Selezione metodo:
#   Metodo 1 (PTQ):             python3 switch_core.py
#   Metodo 2 (QAT):             python3 switch_core.py weights_method2.json
#   Metodo 3 (OpenFlow-like):   python3 switch_core.py weights.json openflow
# ---------------------------------------------------------------------------
WEIGHTS_FILE = sys.argv[1] if len(sys.argv) > 1 else "weights.json"
WEIGHTS_PATH = f"/shared/{WEIGHTS_FILE}"
IS_PTQ       = (WEIGHTS_FILE == "weights.json")
IS_OPENFLOW  = (len(sys.argv) > 2 and sys.argv[2] == "openflow")

# ---------------------------------------------------------------------------
# Kernel eBPF
# ---------------------------------------------------------------------------
# Nel Metodo 3 il miss viene gestito tramite BPF_PERF_OUTPUT: il kernel
# notifica il control plane che inserisce la regola mancante on-demand.
# ---------------------------------------------------------------------------
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
    __u8  weights[100];
    __u8  is_valid;
    __u16 scale_factor;
};

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

// Evento inviato al control plane su table miss (Metodo 3)
struct miss_event {
    __u8  model_id;
    __u8  ttl;
    __u32 ingress_ifindex;
    __u8  input_size;
    __u64 key;
};

BPF_HASH(model_cache, __u8, struct model_data, 256);
BPF_HASH(fwd_table, __u64, struct fwd_action, 256);
BPF_ARRAY(pkt_stats, __u64, 3);   // [0]=redirect [1]=miss [2]=riservato
BPF_PERF_OUTPUT(miss_events);

#define OUTPUT_OFFSET 100000ULL

int ipa_switch(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
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

    __u16 scale = m->scale_factor;
    if (scale == 0) return XDP_PASS;

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

    __u64 output_u = (__u64)(output_raw + (long long)(OUTPUT_OFFSET * scale));
    __u64 key      = output_u / (__u64)scale;

    struct fwd_action *action = fwd_table.lookup(&key);
    if (action != NULL) {
        int s = 0;
        __u64 *val = pkt_stats.lookup(&s);
        if (val) __sync_fetch_and_add(val, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    } else {
        int s = 1;
        __u64 *val = pkt_stats.lookup(&s);
        if (val) __sync_fetch_and_add(val, 1);

        // Metodo 3: notifica il control plane con model_id + ttl + key
        struct miss_event ev = {};
        ev.model_id        = ipa->model_id;
        ev.ttl             = ip->ttl;
        ev.ingress_ifindex = ctx->ingress_ifindex;
        ev.input_size      = ipa->input_size;
        ev.key             = key;
        miss_events.perf_submit(ctx, &ev, sizeof(ev));

        return XDP_PASS;
    }
}
"""

# ---------------------------------------------------------------------------
# Stampa intestazione
# ---------------------------------------------------------------------------
metodo_str = "3 - OpenFlow-like" if IS_OPENFLOW else ("1 - PTQ" if IS_PTQ else "2 - QAT")
print("IPA Switch Iniziato!")
print(f"Metodo: {metodo_str}  |  File pesi: {WEIGHTS_FILE}")

b = BPF(text=program)
fn = b.load_func("ipa_switch", BPF.XDP)

ingress_iface  = "eth1"
egress_iface   = "eth2"
egress_ifindex = socket.if_nametoindex(egress_iface)

# ---------------------------------------------------------------------------
# Carica pesi int8 nel kernel
# ---------------------------------------------------------------------------
print(f"Caricamento pesi int8 da {WEIGHTS_PATH} ...")
with open(WEIGHTS_PATH, "r") as f:
    integer_weights = json.load(f)

if IS_PTQ:
    float_path = "/shared/weights_float.json"
    if not os.path.exists(float_path):
        print(f"[ERRORE] {float_path} non trovato. Esegui prima extract_weights.py")
        sys.exit(1)
    with open(float_path, "r") as f:
        float_data = json.load(f)
    SCALE_FACTOR = float_data["scale_factor"]
    cp_weights   = float_data["weights"][:4]
    print(f"  [PTQ] SCALE_FACTOR automatico = {SCALE_FACTOR}")
    print(f"  [PTQ] Pesi float originali: {[f'{w:.6f}' for w in cp_weights]}")
    int8_equiv = [ctypes.c_int8(int(w)).value / SCALE_FACTOR for w in integer_weights[:4]]
    print(f"  [PTQ] Equivalenti int8/SF:  {[f'{w:.6f}' for w in int8_equiv]}")
    print(f"  [PTQ] Errore di quant.:     {[f'{abs(a-b):.6f}' for a,b in zip(cp_weights, int8_equiv)]}")
else:
    SCALE_FACTOR = 128
    cp_weights   = [ctypes.c_int8(int(w)).value / SCALE_FACTOR for w in integer_weights[:4]]
    print(f"  [{'QAT' if not IS_OPENFLOW else 'OpenFlow'}] SCALE_FACTOR = {SCALE_FACTOR}")
    print(f"  [{'QAT' if not IS_OPENFLOW else 'OpenFlow'}] Pesi int8/128: {[f'{w:.6f}' for w in cp_weights]}")

# ---------------------------------------------------------------------------
# Popola model_cache
# ---------------------------------------------------------------------------
OFFSET = 100000

cache    = b.get_table("model_cache")
my_model = cache.Leaf()
my_model.is_valid     = 1
my_model.scale_factor = SCALE_FACTOR
for i in range(min(len(integer_weights), 100)):
    my_model.weights[i] = ctypes.c_uint8(integer_weights[i]).value
cache[cache.Key(42)] = my_model
print(f"Modello 42 caricato nella Cache eBPF (scale_factor={SCALE_FACTOR})!")

# ---------------------------------------------------------------------------
# Azione di inoltro base
# ---------------------------------------------------------------------------
fwd       = b.get_table("fwd_table")
my_action = fwd.Leaf()
my_action.ifindex = egress_ifindex
src_mac = [0x22, 0x8e, 0x26, 0xbb, 0xdf, 0xf5]
dst_mac = [0x62, 0x45, 0x3d, 0xec, 0xc9, 0x80]
for i in range(6):
    my_action.src_mac[i] = src_mac[i]
    my_action.dst_mac[i] = dst_mac[i]

# ---------------------------------------------------------------------------
# Strutture user-space per tracciamento hit_vero / falso_hit / miss
# ---------------------------------------------------------------------------
key_to_ttl   = defaultdict(list)   # key -> [ttl attesi]
key_to_stats = {}                  # key -> contatori per debug

# ---------------------------------------------------------------------------
# Popolamento fwd_table (Metodo 1 e 2 pre-popolano tutto)
# Nel Metodo 3 la tabella parte vuota: le regole vengono inserite on-demand
# ---------------------------------------------------------------------------
if not IS_OPENFLOW:
    print("Popolamento fwd_table...")
    if_index_eth1 = socket.if_nametoindex(ingress_iface)
    for test_ttl in range(30, 65):
        iv_test      = [42, test_ttl, if_index_eth1, 4]
        ideal_raw    = sum(iv * fw for iv, fw in zip(iv_test, cp_weights))
        expected_key = int(ideal_raw) + OFFSET
        fwd[ctypes.c_ulonglong(expected_key)] = my_action
        key_to_ttl[expected_key].append(test_ttl)
        print(f"  [CP] TTL={test_ttl:3d} -> key={expected_key}")
    print("Regole di inoltro caricate per TTL 30-64.")
else:
    print("[Metodo 3] fwd_table vuota: le regole verranno inserite on-demand dal CP.")
    if_index_eth1 = socket.if_nametoindex(ingress_iface)

# ---------------------------------------------------------------------------
# Metodo 3 — handler miss_events: il CP riceve la notifica dal kernel,
# calcola la chiave con i pesi float, inserisce la regola nella fwd_table.
# Questo emula il comportamento OpenFlow: table miss -> controller -> regola.
# ---------------------------------------------------------------------------
def handle_miss_event(cpu, data, size):
    """Callback chiamata dal perf buffer ad ogni table miss (Metodo 3)."""
    event = b["miss_events"].event(data)
    ttl   = event.ttl
    iv    = [event.model_id, ttl, event.ingress_ifindex, event.input_size]
    ideal_raw    = sum(v * w for v, w in zip(iv, cp_weights))
    cp_key       = int(ideal_raw) + OFFSET
    kernel_key   = event.key

    print(f"\n[CP-MISS] TTL={ttl} | kernel_key={kernel_key} | cp_key={cp_key}", end="")

    if cp_key not in [k.value for k in fwd.keys()]:
        fwd[ctypes.c_ulonglong(cp_key)] = my_action
        key_to_ttl[cp_key].append(ttl)
        print(f" -> INSTALLATA regola per key={cp_key}")
    else:
        print(f" -> regola già presente")

if IS_OPENFLOW:
    b["miss_events"].open_perf_buffer(handle_miss_event)
    perf_thread = threading.Thread(
        target=lambda: _perf_loop(b),
        daemon=True
    )
    perf_thread.start()
    print("[Metodo 3] Listener CP attivo su miss_events.")

def _perf_loop(bpf_inst):
    while True:
        try:
            bpf_inst.perf_buffer_poll(timeout=100)
        except Exception:
            break

# ---------------------------------------------------------------------------
# Attach XDP
# ---------------------------------------------------------------------------
print(f"\nAttach XDP sull'interfaccia ingress: {ingress_iface}")
try:
    b.attach_xdp(ingress_iface, fn, flags=2)
    print(f"XDP attaccato a {ingress_iface}")
except Exception as e:
    print(f"Errore XDP: {e}")

# ---------------------------------------------------------------------------
# Loop principale — stampa contatori + classificazione hit_vero/falso_hit/miss
# ---------------------------------------------------------------------------
stats_map = b.get_table("pkt_stats")
print("\nIn ascolto di pacchetti... (Ctrl+C per fermare)")
print(f"{'REDIRECT':<12} | {'MISS (kernel)':<15} | {'hit_vero':<10} | {'falso_hit':<10} | {'miss_cp':<10}")
print("-" * 70)

hit_vero  = 0
falso_hit = 0
miss_cp   = 0

prev_redirects = 0
prev_misses    = 0

try:
    while True:
        time.sleep(1)
        try:
            redirects = stats_map[stats_map.Key(0)].value
            misses    = stats_map[stats_map.Key(1)].value

            # ---------------------------------------------------------------
            # Classificazione user-space dei nuovi redirect
            # ---------------------------------------------------------------
            new_redirects = redirects - prev_redirects
            prev_redirects = redirects
            prev_misses    = misses

            print(f"\r{redirects:<12} | {misses:<15} | {hit_vero:<10} | {falso_hit:<10} | {miss_cp:<10}", end="")
        except Exception:
            pass
except KeyboardInterrupt:
    b.remove_xdp(ingress_iface, flags=2)

    # -----------------------------------------------------------------------
    # Riepilogo finale con classificazione per TTL
    # -----------------------------------------------------------------------
    print("\n\n" + "=" * 70)
    print("RIEPILOGO FINALE")
    print("=" * 70)
    print(f"{'TTL atteso':<12} | {'Key attesa':<14} | {'Esito'}")
    print("-" * 45)
    for key, ttl_list in sorted(key_to_ttl.items()):
        for ttl in ttl_list:
            iv    = [42, ttl, socket.if_nametoindex(ingress_iface), 4]
            raw   = sum(v * w for v, w in zip(iv, cp_weights))
            exp_k = int(raw) + OFFSET
            if exp_k == key:
                esito = "hit_vero potenziale"
            else:
                esito = f"falso_hit (key reale={exp_k})"
            print(f"  TTL={ttl:<5} | key={key:<12} | {esito}")

    print("\nXDP rimosso. Esco.")
