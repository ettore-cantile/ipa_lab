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
import threading
import time

LINK_STATE_MAP = "link_state"

# Number of link_state slots in the input vector. This is the MODEL's feature
# width, fixed by the trained checkpoint (the 65-4-4-7 model was trained with
# n_interfaces=6, so fc1 reserves 6 columns for link_state) -- which is the
# degree of the LARGEST node in the network, not the degree of the node this
# runs on. In the generated Germany50 lab that maximum is 6 (karlsruhe, once
# h_src is attached to it), but node degrees range from 2 to 6, so on every
# node except karlsruhe some of these slots have no interface behind them.
# The vector width must stay at the trained value or the fc1 column offsets
# desync from the weights; see model_meta.derive_shape /
# verify_shape_vs_checkpoint.
def n_egress() -> int:
    """Number of link_state slots: the MODEL's feature width.

    Was `N_EGRESS = 6`, a module constant -- the Germany50 lab's largest node
    degree, frozen at import time and then used as the loop bound, the CLI
    default and the map width. Resolved from the scenario now; the value is
    still the network's maximum interface count, not this node's degree, since
    it has to match the columns fc1 was trained with.
    """
    import model_meta as _mm
    return int(_mm.load_topology_config()["n_interfaces"])


def default_ifaces() -> list:
    return [f"eth{i}" for i in range(n_egress())]


def iface_exists(iface: str) -> bool:
    """Whether `iface` is a real interface on this node."""
    return os.path.isdir(f"/sys/class/net/{iface}")


def carrier_state(iface: str) -> int:
    """
    Return 1 if `iface` has carrier (link up), 0 otherwise.

    Primary source: /sys/class/net/<iface>/carrier (1/0). Reading it can raise
    EINVAL when the interface is administratively down, so fall back to
    /sys/class/net/<iface>/operstate ('up' -> 1). Unknown iface -> 0 (down).

    Note the deliberate conflation at the map level: an ABSENT interface and a
    DOWN interface both write 0, because the model has no third state -- a slot
    it cannot forward through is a slot it must not pick. Only the LOGGING
    separates the two (see monitor_loop): reporting a slot the node does not
    physically have as "down" made a structural padding slot look like a live
    link failure, which is exactly the signal this lab is measuring.
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


def _slot_names(ifaces=None) -> list:
    """Resolve the slot -> interface-name mapping, padded to n_egress() with the
    eth<i> convention so a caller passing FEWER names cannot IndexError."""
    n = n_egress()
    ifaces = list(ifaces or default_ifaces())
    return [ifaces[i] if i < len(ifaces) else f"eth{i}" for i in range(n)]


def init_link_state_up(bpf_obj, ifaces=None) -> list:
    """Seed the baseline the model sees before the first carrier poll.

    Slots backed by an interface that exists on this node are seeded 'up' (1);
    slots with no such interface are seeded 0 and stay 0 forever. The `ifaces`
    argument used to be accepted and then silently ignored (this always wrote
    [1]*6), which seeded a confident 'up' into padding slots the node cannot
    forward through. Returns the seeded vector.
    """
    names = _slot_names(ifaces)
    states = [1 if iface_exists(n) else 0 for n in names]
    absent = [n for n, s in zip(names, states) if not s]
    _write_vector(bpf_obj, states)
    if absent:
        print(f"[link_state] seeded up={[n for n, s in zip(names, states) if s]}; "
              f"slots with no interface on this node (permanently 0): {absent}")
    return states


def update_link_state(bpf_obj, ifaces=None, verbose: bool = False) -> list:
    """Read the carrier of each egress iface and write it into the map.
    Returns the list of n_egress() states written (for logging/inspection)."""
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
    # Which slots are backed by a real interface is decided ONCE: interfaces do
    # not appear or vanish over a lab's lifetime, and re-deciding per poll would
    # make the log flap.
    present = [iface_exists(n) for n in names]
    absent = [n for n, p in zip(names, present) if not p]
    if absent:
        # Say this once, up front, instead of listing these slots as "down"
        # every poll. The checkpoint reserves n_egress() link_state columns
        # because the network's largest node has degree 6; this node has fewer
        # interfaces than that, so the extra slots have nothing behind them.
        # They are not links that failed.
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
            # This runs in a daemon thread: an unhandled exception used to kill
            # carrier monitoring silently, freezing link_state at its startup
            # seed with the pipeline still reporting itself healthy. Log and
            # keep polling -- a transient map error must not end the monitor.
            print(f"[link_state] poll failed ({e}); retrying in {interval}s")
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
