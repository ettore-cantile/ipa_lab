#!/usr/bin/env python3
"""
queue_state_monitor.py  --  seeder for the `queue_occupancy` feature.

`queue_occupancy` is the example of a NEW feature type added to demonstrate
that the sparse-route feature catalog (model_meta.FEATURE_CATALOG) is
extensible: a model can declare it in its descriptor and the switch builds
that slot of the input vector from a dedicated BPF map named `queue_state`
(index i -> queue i occupancy, an int value the model was trained on),
exactly like `link_state` but for a different signal.

Unlike link_state (which reads a real kernel signal, /sys/.../carrier), this
lab has no real per-queue occupancy source, so the values are SYNTHETIC:
either a fixed seed, a constant, or a slow synthetic sweep. This is enough to
exercise the datapath end-to-end (the model reads the map, multiplies by its
compiled-in weights) -- it is not a real telemetry source. In a real
deployment this module would read actual queue depths (e.g. from tc/qdisc
stats) and write them here.

Usage (library, started by method4_hardcoded.py when the model's descriptor
uses queue_occupancy):
    from queue_state_monitor import init_queue_state, start_monitor_thread
    init_queue_state(b, size)                 # seed slots at startup
    stop = start_monitor_thread(b, size)      # background synthetic updates
    ...
    stop.set()                                # on shutdown
"""

import ctypes
import random
import threading
import time

QUEUE_STATE_MAP = "queue_state"


def _write_map(bpf_obj, idx: int, value: int) -> None:
    bpf_obj[QUEUE_STATE_MAP][ctypes.c_int(idx)] = ctypes.c_uint32(int(value) & 0xFFFFFFFF)


def init_queue_state(bpf_obj, size: int, seed: int = 0) -> list:
    """Seed the `queue_state` map with `size` synthetic occupancy values.
    seed=0 -> all zeros (empty queues baseline); otherwise a deterministic
    pseudo-random vector so runs are reproducible. Returns the values written."""
    if seed == 0:
        values = [0] * size
    else:
        rng = random.Random(seed)
        values = [rng.randint(0, 15) for _ in range(size)]
    for i, v in enumerate(values):
        _write_map(bpf_obj, i, v)
    return values


def update_queue_state(bpf_obj, size: int, t: float) -> list:
    """Write a synthetic occupancy vector (a slow deterministic sweep of `t`),
    so a running demo shows the feature actually changing. Returns the values."""
    values = [int(8 + 7 * ((i + t) % 4) / 4.0) for i in range(size)]
    for i, v in enumerate(values):
        _write_map(bpf_obj, i, v)
    return values


def monitor_loop(bpf_obj, size: int, interval: float = 1.0,
                 stop_event: "threading.Event" = None) -> None:
    t = 0.0
    while not (stop_event and stop_event.is_set()):
        update_queue_state(bpf_obj, size, t)
        t += 1.0
        time.sleep(interval)


def start_monitor_thread(bpf_obj, size: int, interval: float = 1.0
                         ) -> "threading.Event":
    """Start monitor_loop in a daemon thread. Returns the stop_event; call
    stop_event.set() to end the loop."""
    stop_event = threading.Event()
    t = threading.Thread(
        target=monitor_loop,
        args=(bpf_obj, size, interval, stop_event),
        daemon=True,
    )
    t.start()
    return stop_event
