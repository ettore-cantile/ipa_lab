"""
Method 4 - IPA Demo ("Wow Factor")

The model travels INSIDE the packet payload.
model_cache and fwd_table start EMPTY.
On the first packet for a new model_id:
  1. The kernel detects that the model is not in cache.
  2. It emits a model_miss_event with the 4 weight bytes from the payload.
  3. The CP loads the weights into model_cache (~1-3 ms).
  4. The CP installs the rule ONLY for the first packet's TTL.
For later TTL values not seen yet: FWD MISS -> the safety net installs
the rule on-demand (realistic IPA behavior).
For later packets with already-seen TTL values: TRUE HIT (<1 ms).

Files used:
  /shared/weights_method2.json : used by the sender for the payload
  (not loaded by the CP at boot - it arrives in the packet)

Usage on the router (for example, frankfurt):
  python3 /shared/switch_core.py ipa_demo

Usage on the sender:
  python3 /shared/test_ipa.py --dest frankfurt --count 50 \\
          --model-id 42 --weights-file /shared/weights_method2.json
"""
import ctypes
import socket
import threading
import time
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, build_fwd_action, populate_model_cache,
    attach_xdp, stats_loop, EGRESS_IFACE
)

SCALE_FACTOR = 128
OFFSET       = 100000


class MissEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("model_id",        ctypes.c_uint8),
        ("ttl",             ctypes.c_uint8),
        ("_pad0",           ctypes.c_uint8 * 2),
        ("ingress_ifindex", ctypes.c_uint32),
        ("input_size",      ctypes.c_uint8),
        ("_pad1",           ctypes.c_uint8 * 7),
        ("key",             ctypes.c_uint64),
    ]


class ModelMissEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("model_id",        ctypes.c_uint8),
        ("ttl",             ctypes.c_uint8),
        ("_pad0",           ctypes.c_uint8 * 2),
        ("ingress_ifindex", ctypes.c_uint32),
        ("input_size",      ctypes.c_uint8),
        ("w0",              ctypes.c_uint8),
        ("w1",              ctypes.c_uint8),
        ("w2",              ctypes.c_uint8),
        ("w3",              ctypes.c_uint8),
        ("n_weights",       ctypes.c_uint8),
    ]


def run(model_id: int = 42):
    print("[Method 4 - IPA Demo] | model_cache and fwd_table start EMPTY")
    print("  The model travels in the packet. First packet loads the model.")
    print("  Rule installed only for the TTL of the 1st packet.")
    print("  Later unseen TTL values: FWD MISS -> safety net on-demand.")
    print("  Later packets for already-seen TTL values: TRUE HIT (<1 ms).")
    print()

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)
    fwd    = b.get_table("fwd_table")
    vk     = b.get_table("valid_keys")

    loaded_models = set()

    def handle_model_miss(cpu, data, size):
        t0  = time.perf_counter()
        raw = ctypes.cast(data, ctypes.POINTER(ctypes.c_byte * size)).contents
        ev  = ModelMissEvent.from_buffer_copy(raw)

        if ev.model_id in loaded_models:
            return

        weights = [
            ctypes.c_int8(ev.w0).value,
            ctypes.c_int8(ev.w1).value,
            ctypes.c_int8(ev.w2).value,
            ctypes.c_int8(ev.w3).value,
        ]
        print(f"\n[CP] MODEL MISS | model_id={ev.model_id} | "
              f"weights extracted from packet: {weights}")

        populate_model_cache(b, ev.model_id, weights, SCALE_FACTOR)
        loaded_models.add(ev.model_id)

        # Install the rule ONLY for the TTL of the first packet
        iv = [ev.model_id, ev.ttl, ev.ingress_ifindex, ev.input_size]
        output_raw = sum(iv[i] * weights[i] for i in range(4))
        key = (output_raw + OFFSET * SCALE_FACTOR) // SCALE_FACTOR
        fwd[ctypes.c_ulonglong(key)] = action
        vk[ctypes.c_uint8(ev.ttl)]   = ctypes.c_ulonglong(key)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"[CP] model_id={ev.model_id} LOADED & rule INSTALLED | "
              f"key={key} | TTL={ev.ttl} | elapsed={elapsed_ms:.2f} ms")
        print(f"[CP] Next packets for model_id={ev.model_id} -> TRUE HIT (<1 ms)")

    def handle_fwd_miss(cpu, data, size):
        raw = ctypes.cast(data, ctypes.POINTER(ctypes.c_byte * size)).contents
        ev  = MissEvent.from_buffer_copy(raw)
        already = any(k.value == ev.key for k in fwd.keys())
        if not already:
            fwd[ctypes.c_ulonglong(ev.key)] = action
            vk[ctypes.c_uint8(ev.ttl)]      = ctypes.c_ulonglong(ev.key)
            print(f"\n[CP] FWD MISS (safety net) | TTL={ev.ttl} | key={ev.key} -> INSTALLED")

    b["model_miss_events"].open_perf_buffer(handle_model_miss)
    b["miss_events"].open_perf_buffer(handle_fwd_miss)

    def perf_loop():
        while True:
            try:
                b.perf_buffer_poll(timeout=100)
            except Exception:
                break

    threading.Thread(target=perf_loop, daemon=True).start()
    print("[Method 4] CP listeners active. Waiting for packets...")

    attach_xdp(b, fn)
    stats_loop(b)
