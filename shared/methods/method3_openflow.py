"""
Metodo 3 — OpenFlow-like (Control Plane on-demand)

fwd_table e valid_keys partono vuote.
Ad ogni table miss il kernel invia un miss_event al CP via BPF_PERF_OUTPUT.
Il CP installa la regola on-demand usando aritmetica intera pura,
identica al calcolo kernel, per evitare mismatch da arrotondamento float.

File pesi: weights.json + weights_float.json
"""
import ctypes
import socket
import json
import threading
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, attach_xdp, stats_loop,
    EGRESS_IFACE, OFFSET
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


def compute_key_integer(iv: list, int8_weights: list, scale: int) -> int:
    """
    Replica ESATTA del calcolo kernel in aritmetica intera pura:

      output_raw  = sum(iv[i] * (signed char)weights[i])   <- interi signed
      output_u    = (output_raw + OFFSET * scale)           <- unsigned 64
      key         = output_u // scale                       <- divisione intera

    Nessun float coinvolto: elimina i mismatch da arrotondamento.
    """
    output_raw = sum(v * ctypes.c_int8(w).value
                     for v, w in zip(iv, int8_weights))
    output_u   = output_raw + OFFSET * scale          # replica OFFSET*scale kernel
    key        = output_u // scale                    # divisione intera troncata
    return key


def run(weights_file: str = "weights.json"):
    weights_path = f"/shared/{weights_file}"
    float_path   = "/shared/weights_float.json"
    print(f"[Metodo 3 - OpenFlow-like] | File pesi: {weights_file}")

    with open(float_path) as f:
        float_data = json.load(f)
    SCALE_FACTOR = float_data["scale_factor"]
    print(f"  SCALE_FACTOR = {SCALE_FACTOR}")

    integer_weights = load_weights(weights_path)
    int8_weights    = [int(w) for w in integer_weights[:4]]  # raw int8, no divisione
    print(f"  Pesi int8 raw: {int8_weights}")

    b  = load_bpf(EBPF_PROGRAM)
    fn = b.load_func("ipa_switch", BPF.XDP)

    populate_model_cache(b, 42, integer_weights, SCALE_FACTOR)

    egress_ifindex = socket.if_nametoindex(EGRESS_IFACE)
    action = build_fwd_action(b, egress_ifindex)
    fwd    = b.get_table("fwd_table")
    vk     = b.get_table("valid_keys")

    print("[Metodo 3] fwd_table e valid_keys vuote: popolate on-demand dal CP.")

    # ------------------------------------------------------------------
    # Callback CP: aritmetica intera pura, nessun float
    # ------------------------------------------------------------------
    def handle_miss(cpu, data, size):
        raw = ctypes.cast(data, ctypes.POINTER(ctypes.c_byte * size)).contents
        ev  = MissEvent.from_buffer_copy(raw)

        iv     = [ev.model_id, ev.ttl, ev.ingress_ifindex, ev.input_size]
        cp_key = compute_key_integer(iv, int8_weights, SCALE_FACTOR)
        match  = "OK" if ev.key == cp_key else f"WARN: kernel={ev.key} cp={cp_key}"

        already = any(k.value == cp_key for k in fwd.keys())
        if not already:
            fwd[ctypes.c_ulonglong(cp_key)] = action
            vk[ctypes.c_uint8(ev.ttl)]      = ctypes.c_ulonglong(cp_key)
            print(f"\n[CP] TTL={ev.ttl} | cp_key={cp_key} -> INSTALLATA {match}")
        else:
            print(f"\n[CP] TTL={ev.ttl} | cp_key={cp_key} -> gia' presente")

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
