"""
Metodo 3 — OpenFlow-like (Control Plane on-demand)
La fwd_table parte vuota. Ad ogni miss il kernel notifica il CP
tramite BPF_PERF_OUTPUT; il CP calcola la chiave e installa la regola.
File pesi: weights.json  (stessi del Metodo 1)
"""
import ctypes
import socket
import json
import threading
import time
from bcc import BPF
from ebpf_program import EBPF_PROGRAM
from common import (
    load_bpf, load_weights, build_fwd_action,
    populate_model_cache, attach_xdp, stats_loop,
    INGRESS_IFACE, EGRESS_IFACE, OFFSET
)


def run(weights_file: str = "weights.json"):
    weights_path = f"/shared/{weights_file}"
    float_path   = "/shared/weights_float.json"
    print(f"[Metodo 3 - OpenFlow-like] | File pesi: {weights_file}")

    # Pesi float per il CP (stessa logica PTQ)
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
    action         = build_fwd_action(b, egress_ifindex)
    fwd            = b.get_table("fwd_table")

    print("[Metodo 3] fwd_table vuota: regole installate on-demand dal CP.")

    # ------------------------------------------------------------------
    # Callback: handler miss — installazione on-demand della regola
    # ------------------------------------------------------------------
    def handle_miss(cpu, data, size):
        ev  = b["miss_events"].event(data)
        iv  = [ev.model_id, ev.ttl, ev.ingress_ifindex, ev.input_size]
        raw = sum(v * w for v, w in zip(iv, cp_weights))
        cp_key = int(raw) + OFFSET

        already_installed = any(
            k.value == cp_key for k in fwd.keys()
        )
        if not already_installed:
            fwd[ctypes.c_ulonglong(cp_key)] = action
            print(f"\n[CP] TTL={ev.ttl} | kernel_key={ev.key} "
                  f"| cp_key={cp_key} -> REGOLA INSTALLATA")
        else:
            print(f"\n[CP] TTL={ev.ttl} | cp_key={cp_key} -> gia' presente")

    b["miss_events"].open_perf_buffer(handle_miss)

    # Thread daemon per il polling del perf buffer
    def perf_loop():
        while True:
            try:
                b.perf_buffer_poll(timeout=100)
            except Exception:
                break

    t = threading.Thread(target=perf_loop, daemon=True)
    t.start()
    print("[Metodo 3] Listener CP attivo.")

    attach_xdp(b, fn)

    # extra_poll_fn=None: il polling e' nel thread, stats_loop usa sleep(1)
    stats_loop(b)
