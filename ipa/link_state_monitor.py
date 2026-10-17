#!/usr/bin/env python3
"""link_state_monitor.py -- keeps the `link_state` map equal to the real
up/down state of the egress interfaces (read from /sys/class/net).
"""

import os
import threading
import time

LINK_STATE_MAP = "link_state"

def n_egress() -> int:
    """Number of link_state slots."""
    import model_meta as _mm
    return int(_mm.load_topology_config()["n_interfaces"])


def default_ifaces() -> list:
    """The interfaces whose carrier fills link_state[0..n_egress-1]."""
    from node_config import port_map_from_env
    env_map, pattern = port_map_from_env()
    names = [pattern.format(i=i) for i in range(n_egress())]
    if env_map:
        for slot, iface in env_map.items():
            if 0 <= slot < len(names):
                names[slot] = iface
    return names


def iface_exists(iface: str) -> bool:
    """Whether `iface` is a real interface on this node."""
    return os.path.isdir(f"/sys/class/net/{iface}")


def carrier_state(iface: str) -> int:
    """Return 1 if `iface` has carrier (link up), 0 otherwise."""
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
    with one map update -- the datapath then reads them with one lookup."""
    from common import write_vector_map
    write_vector_map(bpf_obj, LINK_STATE_MAP, values)


def _slot_names(ifaces=None) -> list:
    """Resolve the slot -> interface-name mapping, padded to n_egress() with
    the eth<i> convention so a caller passing FEWER names cannot IndexError."""
    n = n_egress()
    ifaces = list(ifaces or default_ifaces())
    return [ifaces[i] if i < len(ifaces) else f"eth{i}" for i in range(n)]


def init_link_state_up(bpf_obj, ifaces=None) -> list:
    """Seed the baseline the model sees before the first carrier poll."""
    names = _slot_names(ifaces)
    states = [1 if iface_exists(n) else 0 for n in names]
    absent = [n for n, s in zip(names, states) if not s]
    _write_vector(bpf_obj, states)
    if absent:
        print(f"[link_state] seeded up={[n for n, s in zip(names, states) if s]}; "
              f"slots with no interface on this node (permanently 0): {absent}")
    return states


def update_link_state(bpf_obj, ifaces=None, verbose: bool = False) -> list:
    """Read the carrier of each egress iface and write it into the map."""
    names = _slot_names(ifaces)
    states = []
    for i, name in enumerate(names):
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
    names = _slot_names(ifaces)
    present = [iface_exists(n) for n in names]
    absent = [n for n, p in zip(names, present) if not p]
    if absent:
        print(f"[link_state] slots with no interface on this node: {absent} "
              f"-- structurally 0, not a link failure")
    prev = None
    while not (stop_event and stop_event.is_set()):
        try:
            states = update_link_state(bpf_obj, ifaces)
            if states != prev:
                up = [n for n, s in zip(names, states) if s]
                down = [n for n, s, p in zip(names, states, present) if p and not s]
                print(f"[link_state] up={up} down={down}")
                prev = states
        except Exception as e:
            print(f"[link_state] poll failed ({e}); retrying in {interval}s")
        time.sleep(interval)


def start_monitor_thread(bpf_obj, ifaces=None, interval: float = 0.5
                         ) -> "threading.Event":
    """Start monitor_loop in a daemon thread."""
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
    _n = n_egress()
    p.add_argument("--ifaces", nargs="+", default=default_ifaces(),
                   help=f"egress interfaces, slot 0..{_n - 1} "
                        f"(default eth0..eth{_n - 1})")
    args = p.parse_args()
    print(f"Egress link carrier state over {n_egress()} model slots "
          f"(1=up, 0=down/absent):")
    for i, name in enumerate(_slot_names(args.ifaces)):
        note = "" if iface_exists(name) else "   <- no such interface on this node"
        print(f"  link_state[{i}] {name:6s} = {carrier_state(name)}{note}")
