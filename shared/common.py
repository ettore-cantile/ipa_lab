"""
common.py — Funzioni condivise da tutti i metodi.

Funzioni esportate:
  load_bpf(program_str)                                   -> BPF
  load_weights(path)                                      -> list[int]
  build_fwd_action(b, egress_ifindex)                     -> Leaf
  populate_model_cache(b, model_id, weights, scale)       -> None
  populate_fwd_and_valid_keys(b, action, cp_weights,
                              scale_factor, ingress_iface) -> None
  attach_xdp(b, fn, iface)                                -> None
  detach_xdp(b, iface)                                    -> None
  stats_loop(b, iface, extra_poll_fn)                     -> None
"""
import json
import ctypes
import socket
import time
from bcc import BPF

INGRESS_IFACE = "eth1"
EGRESS_IFACE  = "eth2"
OFFSET        = 100000
SRC_MAC       = [0x22, 0x8e, 0x26, 0xbb, 0xdf, 0xf5]
DST_MAC       = [0x62, 0x45, 0x3d, 0xec, 0xc9, 0x80]


def load_bpf(program_str: str) -> BPF:
    return BPF(text=program_str)


def load_weights(path: str) -> list:
    with open(path, "r") as f:
        return json.load(f)


def build_fwd_action(b: BPF, egress_ifindex: int,
                     src_mac=None, dst_mac=None):
    src_mac = src_mac or SRC_MAC
    dst_mac = dst_mac or DST_MAC
    fwd    = b.get_table("fwd_table")
    action = fwd.Leaf()
    action.ifindex = egress_ifindex
    for i in range(6):
        action.src_mac[i] = src_mac[i]
        action.dst_mac[i] = dst_mac[i]
    return action


def populate_model_cache(b: BPF, model_id: int,
                         integer_weights: list, scale_factor: int):
    cache = b.get_table("model_cache")
    entry = cache.Leaf()
    entry.is_valid     = 1
    entry.scale_factor = scale_factor
    for i in range(min(len(integer_weights), 100)):
        entry.weights[i] = ctypes.c_uint8(integer_weights[i]).value
    cache[cache.Key(model_id)] = entry
    print(f"Modello {model_id} caricato nella Cache eBPF (scale_factor={scale_factor})")


def populate_fwd_and_valid_keys(b: BPF, action, cp_weights: list,
                                scale_factor: int,
                                ingress_iface: str = INGRESS_IFACE):
    """
    Pre-popola fwd_table e valid_keys per TTL 30-64.
    valid_keys mappa TTL -> chiave corretta del CP,
    usata dal kernel per distinguere TRUE HIT da FAKE HIT.
    """
    fwd        = b.get_table("fwd_table")
    vk         = b.get_table("valid_keys")
    if_idx     = socket.if_nametoindex(ingress_iface)

    for ttl in range(30, 65):
        iv          = [42, ttl, if_idx, 4]
        ideal_raw   = sum(v * w for v, w in zip(iv, cp_weights))
        key         = int(ideal_raw) + OFFSET
        fwd[ctypes.c_ulonglong(key)]  = action
        vk[ctypes.c_uint8(ttl)]       = ctypes.c_ulonglong(key)

    print("fwd_table e valid_keys caricati per TTL 30-64.")


def attach_xdp(b: BPF, fn, iface: str = INGRESS_IFACE):
    print(f"Attach XDP su {iface} ...")
    try:
        b.attach_xdp(iface, fn, flags=2)
        print(f"XDP attaccato a {iface}")
    except Exception as e:
        print(f"Errore XDP: {e}")


def detach_xdp(b: BPF, iface: str = INGRESS_IFACE):
    b.remove_xdp(iface, flags=2)
    print(f"XDP rimosso da {iface}")


def stats_loop(b: BPF, iface: str = INGRESS_IFACE,
               extra_poll_fn=None):
    """
    Loop principale. Stampa TRUE HIT / FAKE HIT / MISS in tempo reale.
    extra_poll_fn: callable opzionale chiamato ogni iterazione
                  (usato dal Metodo 3 per perf_buffer_poll).
    """
    stats = b.get_table("pkt_stats")
    print("\nIn ascolto di pacchetti... (Ctrl+C per fermare)")
    print(f"{'TRUE HIT':<22} | {'FAKE HIT':<22} | {'MISS':<20}")
    print("-" * 70)
    try:
        while True:
            if extra_poll_fn:
                extra_poll_fn()
            else:
                time.sleep(1)
            try:
                true_hits = stats[stats.Key(0)].value
                misses    = stats[stats.Key(1)].value
                fake_hits = stats[stats.Key(2)].value
                print(f"\r{true_hits:<22} | {fake_hits:<22} | {misses:<20}",
                      end="", flush=True)
            except Exception:
                pass
    except KeyboardInterrupt:
        detach_xdp(b, iface)
        print("\n\nXDP rimosso. Esco.")
