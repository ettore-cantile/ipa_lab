"""
common.py — Shared helpers used by all methods.

Key computation note:
  - Method 1 (PTQ) integer_arithmetic=False:
      uses original float weights -> truncated float key
      diverges from the kernel (int8) -> produces intentional FAKE HITs
  - Method 2 (QAT) integer_arithmetic=True:
      uses raw int8 weights -> pure integer arithmetic identical to the kernel
      -> nearly all TRUE HITs
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
    print(f"Model {model_id} loaded into eBPF cache (scale_factor={scale_factor})")


def _compute_key_float(iv: list, cp_weights: list) -> int:
    """Method 1 PTQ: key computed with original float weights.
    Deliberately misaligned with the kernel -> produces FAKE HIT."""
    return int(sum(v * w for v, w in zip(iv, cp_weights))) + OFFSET


def _compute_key_integer(iv: list, int8_weights: list, scale: int) -> int:
    """Method 2/3 QAT: pure integer arithmetic identical to the kernel.
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
    Pre-populates fwd_table and valid_keys for TTL 30-64.

    integer_arithmetic=False (Method 1 PTQ):
        cp_weights are original floats; key is computed with floats.
        Intentional divergence from the kernel -> visible FAKE HITs.

    integer_arithmetic=True (Method 2 QAT):
        cp_weights are raw int8; key is computed with pure integers.
        Kernel and CP aligned -> TRUE HIT.
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

    mode = "intera/QAT" if integer_arithmetic else "float/PTQ"
    print(f"fwd_table and valid_keys loaded for TTL 30-64 [{mode}].")


def attach_xdp(b: BPF, fn, iface: str = INGRESS_IFACE):
    print(f"Attaching XDP to {iface}...")
    try:
        b.attach_xdp(iface, fn, flags=2)
        print(f"XDP attached to {iface}")
    except Exception as e:
        print(f"XDP error: {e}")


def detach_xdp(b: BPF, iface: str = INGRESS_IFACE):
    b.remove_xdp(iface, flags=2)
    print(f"XDP rimosso da {iface}")


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
