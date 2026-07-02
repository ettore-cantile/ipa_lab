"""
Metodo 3 — OpenFlow-like (Control Plane on-demand)

fwd_table e valid_keys partono vuote.
Ad ogni table miss il kernel invia un miss_event al CP via BPF_PERF_OUTPUT.
Il CP installa la regola usando direttamente ev.key (la chiave gia' calcolata
dal kernel) — nessun ricalcolo in user space, zero possibilita' di mismatch.

File pesi: weights.json + weights_float.json
"""
import ctypes
import socket
import threading
import json
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, attach_xdp, stats_loop,
    EGRESS_IFACE
)

# ---------------------------------------------------------------------------
# Struct ctypes che replica byte per byte la miss_event del kernel.
# Layout con padding esplicito (_pack_=1):
#   model_id(1) + ttl(1) + pad(2) + ingress_ifindex(4)
#   + input_size(1) + pad(7) + key(8)  =  24 byte totali
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


def run(weights_file: str = "weights.json"):
    weights_path = f"/shared/{weights_file}"
    float_path   = "/shared/weights_float.json"
    print(f"[Metodo 3 - OpenFlow-like] | File pesi: {weights_file}")

    with open(float_path) as f:
        float_data = json.load(f)
    SCALE_FACTOR = float_data["scale_factor"]
    print(f"  SCALE_FACTOR = {SCALE_FACTOR}")

    integer_weights = load_weights(weights_path)

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, 42, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)
    fwd    = b.get_table("fwd_table")
    vk     = b.get_table("valid_keys")

    print("[Metodo 3] fwd_table e valid_keys vuote: popolate on-demand dal CP.")

    # ------------------------------------------------------------------
    # Callback CP: usa ev.key (chiave gia' calcolata dal kernel).
    # Nessun ricalcolo in user space -> zero rischio di mismatch.
    # ------------------------------------------------------------------
    def handle_miss(cpu, data, size):
        raw = ctypes.cast(data, ctypes.POINTER(ctypes.c_byte * size)).contents
        ev  = MissEvent.from_buffer_copy(raw)

        key = ev.key   # chiave esatta del kernel, nessun ricalcolo

        already = any(k.value == key for k in fwd.keys())
        if not already:
            fwd[ctypes.c_ulonglong(key)] = action
            vk[ctypes.c_uint8(ev.ttl)]   = ctypes.c_ulonglong(key)
            print(f"\n[CP] TTL={ev.ttl} | key={key} -> INSTALLATA")
        else:
            print(f"\n[CP] TTL={ev.ttl} | key={key} -> gia' presente")

    b["miss_events"].open_perf_buffer(handle_miss)

    def perf_loop():
        while True:
            try:
                b.perf_buffer_poll(timeout=100)
            except Exception:
                break

    threading.Thread(target=perf_loop, daemon=True).start()
    print("[Metodo 3] Listener CP attivo.")

    attach_xdp(b, fn)
    stats_loop(b)
