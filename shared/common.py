"""
common.py — Shared helpers usati da tutti i metodi.

Nota chiave sul campo input_size:
  Nel nuovo header IPA paper-compliant, input_size=65 (valore reale).
  Il CP usa iv = [42, ttl, ifindex, 65] per calcolare le chiavi della
  fwd_table, allineato con il kernel XDP che legge ipa->input_size.
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

# Numero totale pesi: fc1(260+4) + fc2(16+4) + out(28+7) = 319
N_WEIGHTS = 319


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
    """
    Carica i pesi nella BPF map model_cache (capacity: N_WEIGHTS=319).
    Se la lista e' piu' corta i byte restanti rimangono 0.
    """
    cache = b.get_table("model_cache")
    entry = cache.Leaf()
    entry.is_valid     = 1
    entry.scale_factor = scale_factor
    for i in range(min(len(integer_weights), N_WEIGHTS)):
        entry.weights[i] = ctypes.c_uint8(integer_weights[i]).value
    cache[cache.Key(model_id)] = entry
    print(f"[cache] Model {model_id} loaded | "
          f"{min(len(integer_weights), N_WEIGHTS)} weights | "
          f"scale_factor={scale_factor}")


def _compute_key_float(iv: list, cp_weights: list) -> int:
    """Method 1 PTQ: chiave con float originali -> FAKE HIT intenzionale."""
    return int(sum(v * w for v, w in zip(iv, cp_weights))) + OFFSET


def _compute_key_integer(iv: list, int8_weights: list, scale: int) -> int:
    """Method 2/3 QAT: aritmetica intera identica al kernel -> TRUE HIT."""
    output_raw = sum(v * ctypes.c_int8(w).value
                     for v, w in zip(iv, int8_weights))
    return (output_raw + OFFSET * scale) // scale


def populate_fwd_and_valid_keys(b: BPF, action, cp_weights: list,
                                scale_factor: int,
                                ingress_iface: str = INGRESS_IFACE,
                                integer_arithmetic: bool = False):
    """
    Pre-popola fwd_table e valid_keys per TTL 30-64.
    iv = [model_id=42, ttl, ifindex, input_size=65]
    input_size=65 riflette il valore reale nel nuovo header IPA.
    """
    fwd    = b.get_table("fwd_table")
    vk     = b.get_table("valid_keys")
    if_idx = socket.if_nametoindex(ingress_iface)

    for ttl in range(30, 65):
        iv = [42, ttl, if_idx, 65]  # input_size=65 (era 4)
        if integer_arithmetic:
            key = _compute_key_integer(iv, cp_weights, scale_factor)
        else:
            key = _compute_key_float(iv, cp_weights)
        fwd[ctypes.c_ulonglong(key)] = action
        vk[ctypes.c_uint8(ttl)]      = ctypes.c_ulonglong(key)

    mode = "intera/QAT" if integer_arithmetic else "float/PTQ"
    print(f"[fwd] fwd_table e valid_keys caricati per TTL 30-64 [{mode}]")


def attach_xdp(b: BPF, fn, iface: str = INGRESS_IFACE):
    print(f"[xdp] Attaching XDP to {iface}...")
    try:
        b.attach_xdp(iface, fn, flags=2)
        print(f"[xdp] XDP attached to {iface}")
    except Exception as e:
        print(f"[xdp] Error: {e}")


def detach_xdp(b: BPF, iface: str = INGRESS_IFACE):
    b.remove_xdp(iface, flags=2)
    print(f"[xdp] XDP rimosso da {iface}")


def stats_loop(b: BPF, iface: str = INGRESS_IFACE,
               extra_poll_fn=None):
    stats = b.get_table("pkt_stats")
    print("\nListening for packets... (Ctrl+C to stop)")
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
        print("\n\nXDP removed. Exiting.")
