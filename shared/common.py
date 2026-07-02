"""
common.py — Funzioni condivise da tutti i metodi.

Funzioni esportate:
  load_bpf(program_str)                                   -> BPF
  load_weights(path)                                      -> list[int]
  build_fwd_action(b, egress_ifindex)                     -> Leaf
  populate_model_cache(b, model_id, weights, scale)       -> None
  populate_fwd_and_valid_keys(b, action, cp_weights,
                              scale_factor, ingress_iface,
                              integer_arithmetic)          -> None
  attach_xdp(b, fn, iface)                                -> None
  detach_xdp(b, iface)                                    -> None
  stats_loop(b, iface, extra_poll_fn)                     -> None

Nota sul calcolo della chiave:
  - Metodo 1 (PTQ): usa pesi float originali -> chiave float-troncata
    Le FAKE HIT emergono naturalmente dall'errore di quantizzazione:
    il kernel usa int8, il CP usa float -> chiavi divergono -> FAKE HIT.
    integer_arithmetic=False (default)

  - Metodo 2 (QAT): usa pesi int8/scale -> aritmetica intera pura
    Kernel e CP allineati -> quasi tutte TRUE HIT.
    integer_arithmetic=True
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


def _compute_key_float(iv: list, cp_weights: list) -> int:
    """Metodo 1 PTQ: chiave calcolata con pesi float originali.
    Deliberatamente non allineata al kernel -> produce FAKE HIT."""
    ideal_raw = sum(v * w for v, w in zip(iv, cp_weights))
    return int(ideal_raw) + OFFSET


def _compute_key_integer(iv: list, int8_weights: list, scale: int) -> int:
    """Metodo 2/3 QAT: aritmetica intera pura, identica al kernel.
    output_raw = sum(iv[i] * (signed char)weights[i])
    key        = (output_raw + OFFSET * scale) // scale"""
    output_raw = sum(v * ctypes.c_int8(w).value
                     for v, w in zip(iv, int8_weights))
    return (output_raw + OFFSET * scale) // scale


def populate_fwd_and_valid_keys(b: BPF, action, cp_weights: list,
                                scale_factor: int,
                                ingress_iface: str = INGRESS_IFACE,
                                integer_arithmetic: bool = False):
    """
    Pre-popola fwd_table e valid_keys per TTL 30-64.

    integer_arithmetic=False (Metodo 1 PTQ):
        cp_weights sono float originali; chiave calcolata con float.
        Il kernel usera' int8 -> divergenza intenzionale -> FAKE HIT visibili.

    integer_arithmetic=True (Metodo 2 QAT):
        cp_weights sono int8 raw; chiave calcolata con interi puri.
        Kernel e CP allineati -> TRUE HIT.
    """
    fwd    = b.get_table("fwd_table")
    vk     = b.get_table("valid_keys")
    if_idx = socket.if_nametoindex(ingress_iface)

    for ttl in range(30, 65):
        iv = [42, ttl, if_idx, 4]
        if integer_arithmetic:
            key = _compute_key_integer(iv, cp_weights, scale_factor)
        else:
            key = _compute_key_float(iv, cp_weights)
        fwd[ctypes.c_ulonglong(key)] = action
        vk[ctypes.c_uint8(ttl)]      = ctypes.c_ulonglong(key)

    mode = "intera (QAT)" if integer_arithmetic else "float (PTQ)"
    print(f"fwd_table e valid_keys caricati per TTL 30-64 [{mode}].")


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
