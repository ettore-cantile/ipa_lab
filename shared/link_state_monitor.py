#!/usr/bin/env python3
"""
link_state_monitor.py  --  egress link up/down monitor for the IPA pipelines.

The trained model (FRR_model.py) takes 6 "output interface states" as its first
6 input features [0..5]: the operational up/down status of the router's egress
interfaces. This is the core fast-reroute signal -- which next-hop link is
currently available. In the eBPF programs those 6 slots are read from a BPF map
named `link_state` (index i -> egress iface i, value 1=up / 0=down).

This module keeps that map truthful. It reads the real carrier state of each
egress interface from the kernel (/sys/class/net/<iface>/carrier, falling back
to operstate) and writes it into the `link_state` map of a loaded BPF object.

All three pipelines share the same map name and semantics:
  - Pipeline 1 (hardcoded): link_state[i] multiplies the compiled-in fc1 weights
  - Pipeline 2 (template) : link_state[i] indexes arch_weights in the fc1 loop
  - Pipeline 3 (modular)  : the dispatcher copies link_state[i] into scratch_acts[i]

Usage:
  as a library (started by execute_pipeline / method*.py):
      from link_state_monitor import init_link_state_up, start_monitor_thread
      init_link_state_up(b, egress_ifaces)          # all links up at startup
      stop = start_monitor_thread(b, egress_ifaces) # background carrier polling
      ...
      stop.set()                                    # on shutdown

  standalone dry-run (no BPF object, just print what would be written):
      python3 link_state_monitor.py --ifaces eth0 eth1 eth2 eth3 eth4 eth5
"""

import os
import ctypes
import threading
import time

DEFAULT_IFACES = ["eth0", "eth1", "eth2", "eth3", "eth4", "eth5"]
LINK_STATE_MAP = "link_state"
N_EGRESS = 6


def carrier_state(iface: str) -> int:
    """
    Return 1 if `iface` has carrier (link up), 0 otherwise.

    Primary source: /sys/class/net/<iface>/carrier (1/0). Reading it can raise
    EINVAL when the interface is administratively down, so fall back to
    /sys/class/net/<iface>/operstate ('up' -> 1). Unknown iface -> 0 (down).
    """
    base = f"/sys/class/net/{iface}"
    carrier = os.path.join(base, "carrier")
    try:
        with open(carrier) as f:
            return 1 if f.read().strip() == "1" else 0
    except (FileNotFoundError, OSError):
        pass
    operstate = os.path.join(base, "operstate")
    try:
        with open(operstate) as f:
            return 1 if f.read().strip() == "up" else 0
    except (FileNotFoundError, OSError):
        return 0


def _write_vector(bpf_obj, values) -> None:
    """Write all 6 slots into the single struct-valued link_state entry (key 0)
    with one map update -- the datapath then reads them with one lookup. (Lazy
    import so this module stays importable without BCC for the dry-run below.)"""
    from common import write_vector_map
    write_vector_map(bpf_obj, LINK_STATE_MAP, values)


def init_link_state_up(bpf_obj, ifaces=None) -> None:
    """Seed all 6 egress slots to 'up' (1). Called once at pipeline startup so
    the model sees the normal all-links-healthy baseline before the first poll."""
    _write_vector(bpf_obj, [1] * N_EGRESS)


def update_link_state(bpf_obj, ifaces=None, verbose: bool = False) -> list:
    """Read the carrier of each egress iface and write it into the map.
    Returns the list of 6 states written (for logging/inspection)."""
    ifaces = (ifaces or DEFAULT_IFACES)[:N_EGRESS]
    states = []
    for i in range(N_EGRESS):
        name = ifaces[i] if i < len(ifaces) else f"eth{i}"
        st = carrier_state(name)
        states.append(st)
        if verbose:
            print(f"  link_state[{i}] {name:6s} = {st}")
    _write_vector(bpf_obj, states)
    return states


def monitor_loop(bpf_obj, ifaces=None, interval: float = 0.5,
                 stop_event: "threading.Event" = None) -> None:
    """Poll carrier state every `interval` seconds until stop_event is set,
    writing changes into the link_state map."""
    ifaces = ifaces or DEFAULT_IFACES
    prev = None
    while not (stop_event and stop_event.is_set()):
        states = update_link_state(bpf_obj, ifaces)
        if states != prev:
            up = [ifaces[i] for i in range(N_EGRESS) if states[i]]
            down = [ifaces[i] for i in range(N_EGRESS) if not states[i]]
            print(f"[link_state] up={up} down={down}")
            prev = states
        time.sleep(interval)


def start_monitor_thread(bpf_obj, ifaces=None, interval: float = 0.5
                         ) -> "threading.Event":
    """Start monitor_loop in a daemon thread. Returns the stop_event; call
    stop_event.set() to end the loop."""
    stop_event = threading.Event()
    t = threading.Thread(
        target=monitor_loop,
        args=(bpf_obj, ifaces, interval, stop_event),
        daemon=True,
    )
    t.start()
    return stop_event


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(
        description="Dry-run: print egress carrier states (no BPF map write)")
    p.add_argument("--ifaces", nargs="+", default=DEFAULT_IFACES,
                   help="egress interfaces, cls 0..5 (default eth0..eth5)")
    args = p.parse_args()
    print("Egress link carrier state (1=up, 0=down):")
    for i, name in enumerate(args.ifaces[:N_EGRESS]):
        print(f"  link_state[{i}] {name:6s} = {carrier_state(name)}")
