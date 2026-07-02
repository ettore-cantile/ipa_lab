"""
Metodo 3 — OpenFlow-like (Control Plane on-demand)

fwd_table e valid_keys partono vuote.
Ad ogni table miss il kernel invia un miss_event al CP via BPF_PERF_OUTPUT.
Il CP calcola la chiave corretta con i pesi float, inserisce la regola in
fwd_table E popola valid_keys, cosi' il kernel puo' classificare correttamente
i pacchetti successivi come TRUE HIT o FAKE HIT.

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


def run(weights_file: str = "weights.json"):
    weights_path = f"/shared/{weights_file}"
    float_path   = "/shared/weights_float.json"
    print(f"[Metodo 3 - OpenFlow-like] | File pesi: {weights_file}")

    with open(float_path) as f:
        float_data = json.load(f)
    SCALE_FACTOR = float_data["scale_factor"]
    cp_weights   = float_data["weights"][:4]
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
    # Callback CP: riceve miss_event, installa regola + aggiorna valid_keys
    # ------------------------------------------------------------------
    def handle_miss(cpu, data, size):
        ev     = b["miss_events"].event(data)
        iv     = [ev.model_id, ev.ttl, ev.ingress_ifindex, ev.input_size]
        raw    = sum(v * w for v, w in zip(iv, cp_weights))
        cp_key = int(raw) + OFFSET

        already = any(k.value == cp_key for k in fwd.keys())
        if not already:
            fwd[ctypes.c_ulonglong(cp_key)]  = action
            vk[ctypes.c_uint8(ev.ttl)]       = ctypes.c_ulonglong(cp_key)
            print(f"\n[CP] TTL={ev.ttl} | kernel_key={ev.key} "
                  f"| cp_key={cp_key} -> INSTALLATA")
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
