"""
Method 4 — IPA Demo ("Wow Factor")

This method demonstrates the core IPA paradigm:
  - The model travels INSIDE the packet payload.
  - model_cache and fwd_table start EMPTY.
  - On the FIRST packet for a new model_id:
      1. The kernel detects the model is not in cache.
      2. It emits a model_miss_event carrying the raw weights from the payload.
      3. The CP extracts the weights and loads them into model_cache (~3 ms).
      4. The CP also installs the forwarding rule in fwd_table immediately.
  - On ALL SUBSEQUENT packets for the same model_id:
      The kernel finds the model in cache, computes the key, finds the
      forwarding rule -> TRUE HIT (<1 ms). No CP involvement.

This is the experiment described in IPA_Demo.pdf.

Usage on the router node (e.g. frankfurt):
  python3 /shared/switch_core.py weights_method2.json ipa_demo

Usage on a sender node:
  python3 /shared/send_ipa.py frankfurt 99 /shared/weights_method2.json   # 1st pkt: model extraction
  python3 /shared/send_ipa.py frankfurt 99                                 # 2nd+: TRUE HIT
"""
import ctypes
import socket
import threading
import time
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, attach_xdp, stats_loop,
    EGRESS_IFACE, INGRESS_IFACE
)

SCALE_FACTOR = 128


# ---------------------------------------------------------------------------
# ctypes mirror of miss_event (fwd miss — model already in cache)
# Layout: model_id(1) + ttl(1) + pad(2) + ingress_ifindex(4)
#       + input_size(1) + pad(7) + key(8) = 24 bytes
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# ctypes mirror of model_miss_event (model NOT in cache)
# Layout: model_id(1) + ttl(1) + pad(2) + ingress_ifindex(4)
#       + input_size(1) + weights(100) + n_weights(1) + pad(?) = ~110 bytes
# ---------------------------------------------------------------------------
class ModelMissEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("model_id",        ctypes.c_uint8),
        ("ttl",             ctypes.c_uint8),
        ("_pad0",           ctypes.c_uint8 * 2),
        ("ingress_ifindex", ctypes.c_uint32),
        ("input_size",      ctypes.c_uint8),
        ("weights",         ctypes.c_uint8 * 100),
        ("n_weights",       ctypes.c_uint8),
    ]


def run(weights_file: str = "weights_method2.json"):
    print("[Method 4 - IPA Demo] | model_cache and fwd_table start EMPTY")
    print("  The model travels in the packet. First packet loads the model (~3 ms).")
    print("  Subsequent packets: TRUE HIT directly from the kernel (<1 ms).")
    print()

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    # model_cache intentionally left EMPTY: the model arrives in the packet
    # populate_model_cache(b, 42, ...) <- NOT called

    # fwd_table intentionally left EMPTY: rules installed on-demand by the CP
    # populate_fwd_and_valid_keys(...)  <- NOT called

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)
    fwd    = b.get_table("fwd_table")
    vk     = b.get_table("valid_keys")

    # Track which model_ids are already loaded in cache (Python-side set)
    loaded_models = set()

    # ------------------------------------------------------------------
    # Callback for MODEL MISS: model_id not found in model_cache.
    # The kernel has copied the raw weights from the packet payload.
    # The CP:
    #   1. Extracts the weights from the event.
    #   2. Loads them into model_cache (this is the ~3 ms step).
    #   3. Computes and installs the forwarding rule immediately.
    # ------------------------------------------------------------------
    def handle_model_miss(cpu, data, size):
        t0 = time.perf_counter()

        raw = ctypes.cast(data, ctypes.POINTER(ctypes.c_byte * size)).contents
        ev  = ModelMissEvent.from_buffer_copy(raw)

        model_id = ev.model_id
        n        = ev.n_weights

        if model_id in loaded_models:
            # Already loaded by a concurrent event — skip
            return

        # Extract raw int8 weights from the event (carried from the packet)
        weights = [ctypes.c_int8(ev.weights[i]).value for i in range(n)]
        print(f"\n[CP] MODEL MISS | model_id={model_id} | "
              f"Extracting {n} weights from packet payload...")

        # Load the model into model_cache
        populate_model_cache(b, model_id, weights, SCALE_FACTOR)
        loaded_models.add(model_id)

        # Compute the forwarding key using pure integer arithmetic
        # (identical to the kernel) and install the rule immediately
        iv = [model_id, ev.ttl, ev.ingress_ifindex, ev.input_size]
        output_raw = sum(iv[i] * weights[i] for i in range(min(4, len(weights))))
        OFFSET = 100000
        key = (output_raw + OFFSET * SCALE_FACTOR) // SCALE_FACTOR

        fwd[ctypes.c_ulonglong(key)] = action
        vk[ctypes.c_uint8(ev.ttl)]   = ctypes.c_ulonglong(key)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"[CP] model_id={model_id} LOADED & rule INSTALLED | "
              f"key={key} | TTL={ev.ttl} | elapsed={elapsed_ms:.2f} ms")
        print(f"[CP] Next packets for model_id={model_id} -> TRUE HIT (<1 ms)")

    # ------------------------------------------------------------------
    # Callback for FWD MISS: model is in cache but forwarding rule missing.
    # This should not happen after handle_model_miss installs the rule,
    # but acts as a safety net for edge cases (e.g. different TTL values).
    # ------------------------------------------------------------------
    def handle_fwd_miss(cpu, data, size):
        raw = ctypes.cast(data, ctypes.POINTER(ctypes.c_byte * size)).contents
        ev  = MissEvent.from_buffer_copy(raw)

        key = ev.key
        already = any(k.value == key for k in fwd.keys())
        if not already:
            fwd[ctypes.c_ulonglong(key)] = action
            vk[ctypes.c_uint8(ev.ttl)]   = ctypes.c_ulonglong(key)
            print(f"\n[CP] FWD MISS (safety net) | TTL={ev.ttl} | key={key} -> INSTALLED")

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
