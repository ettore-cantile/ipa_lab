#!/usr/bin/env python3
"""queue_state_monitor.py -- fills the `queue_state` map read by the
`queue_occupancy` feature (synthetic values: there is no real queue source).
"""

import random
import threading
import time

QUEUE_STATE_MAP = "queue_state"


def _write_vector(bpf_obj, values) -> None:
    """Write all slots into the single struct-valued queue_state entry (key 0)
    with one map update -- the datapath reads them with one lookup."""
    from common import write_vector_map
    write_vector_map(bpf_obj, QUEUE_STATE_MAP, values)


def update_queue_state(bpf_obj, size: int, t: float) -> list:
    """Write a synthetic occupancy vector (a slow deterministic sweep of `t`),
    so a running demo shows the feature actually changing."""
    values = [int(8 + 7 * ((i + t) % 4) / 4.0) for i in range(size)]
    _write_vector(bpf_obj, values)
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
    """Start monitor_loop in a daemon thread."""
    stop_event = threading.Event()
    t = threading.Thread(
        target=monitor_loop,
        args=(bpf_obj, size, interval, stop_event),
        daemon=True,
    )
    t.start()
    return stop_event
