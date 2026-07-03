"""
Method 3 — OpenFlow-like (reactive rule installation)

fwd_table parte VUOTA. Le regole vengono installate dal CP on-demand
quando arriva un FWD MISS, esattamente come OpenFlow.
Il primo pacchetto per ogni TTL produce un MISS, i successivi TRUE HIT.

File usati:
  /shared/weights_method2.json : pesi int8 (QAT)
"""
import ctypes
import socket
import threading
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, attach_xdp, stats_loop, EGRESS_IFACE
)

SCALE_FACTOR = 128


def run(model_id: int = 42):
    weights_path = "/shared/weights_method2.json"
    print(f"[Method 3 - OpenFlow] | model_id: {model_id}")
    print("  fwd_table starts EMPTY. Rules installed on-demand on MISS.")
    print()

    integer_weights = load_weights(weights_path)
    int8_weights    = [int(w) for w in integer_weights[:4]]
    print(f"  SCALE_FACTOR  = {SCALE_FACTOR}")
    print(f"  Raw int8 weights: {int8_weights}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, model_id, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)
    fwd    = b.get_table("fwd_table")
    vk     = b.get_table("valid_keys")

    import time

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

    def handle_miss(cpu, data, size):
        raw = ctypes.cast(data, ctypes.POINTER(ctypes.c_byte * size)).contents
        ev  = MissEvent.from_buffer_copy(raw)
        already = any(k.value == ev.key for k in fwd.keys())
        if not already:
            fwd[ctypes.c_ulonglong(ev.key)] = action
            vk[ctypes.c_uint8(ev.ttl)]      = ctypes.c_ulonglong(ev.key)
            print(f"\n[CP] FWD MISS | TTL={ev.ttl} | key={ev.key} -> INSTALLED")

    b["miss_events"].open_perf_buffer(handle_miss)

    def perf_loop():
        while True:
            try:
                b.perf_buffer_poll(timeout=100)
            except Exception:
                break

    threading.Thread(target=perf_loop, daemon=True).start()
    print("[Method 3] CP listener active. Waiting for packets...")

    attach_xdp(b, fn)
    stats_loop(b)
