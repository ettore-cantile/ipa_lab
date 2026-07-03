"""
Method 4 — IPA Demo ("Wow Factor")

Il modello viaggia DENTRO il payload del pacchetto.
model_cache e fwd_table partono VUOTE.
Al primo pacchetto per un nuovo model_id:
  1. Il kernel rileva che il modello non e' in cache.
  2. Emette un model_miss_event con i 4 byte di pesi dal payload.
  3. Il CP carica i pesi in model_cache (~1-3 ms).
  4. Il CP installa subito le regole per tutti i TTL 30-64.
Dai pacchetti successivi: TRUE HIT direttamente dal kernel (<1 ms).

File usati:
  /shared/weights_method2.json : usato dal sender per il payload
  (non caricato dal CP al boot — arriva nel pacchetto)

Usage sul router (es. frankfurt):
  python3 /shared/switch_core.py ipa_demo

Usage sul sender:
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
    print("[Method 4 - IPA Demo] | model_cache e fwd_table partono VUOTE")
    print("  Il modello viaggia nel pacchetto. Primo pacchetto carica il modello.")
    print("  Pacchetti successivi: TRUE HIT direttamente dal kernel (<1 ms).")
    print()

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)
    fwd    = b.get_table("fwd_table")
    vk     = b.get_table("valid_keys")
    if_idx = socket.if_nametoindex("eth1")

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
              f"weights from packet: {weights}")

        populate_model_cache(b, ev.model_id, weights, SCALE_FACTOR)
        loaded_models.add(ev.model_id)

        # Installa subito le regole per TUTTI i TTL 30-64
        # cosi' non ci sono FWD MISS successivi
        for ttl in range(30, 65):
            iv = [ev.model_id, ttl, if_idx, 65]
            output_raw = sum(iv[i] * weights[i] for i in range(4))
            key = (output_raw + OFFSET * SCALE_FACTOR) // SCALE_FACTOR
            fwd[ctypes.c_ulonglong(key)] = action
            vk[ctypes.c_uint8(ttl)]      = ctypes.c_ulonglong(key)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"[CP] model_id={ev.model_id} LOADED | "
              f"35 regole TTL 30-64 installate | elapsed={elapsed_ms:.2f} ms")
        print(f"[CP] Pacchetti successivi per model_id={ev.model_id} -> TRUE HIT (<1 ms)")

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
    print("[Method 4] CP listeners attivi. In attesa di pacchetti...")

    attach_xdp(b, fn)
    stats_loop(b)
