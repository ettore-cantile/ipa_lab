"""
common.py - Shared runtime helpers, scenario-independent.

This docstring used to be the wiring table of ONE node of ONE lab:

    darmstadt[0]="l59" <-> frankfurt[1]="l59"
      eth0 = 10.0.0.233/30  -> INGRESS
    darmstadt[1]="l62" <-> mannheim[0]="l62"
      eth1 = 10.0.0.246/30  -> EGRESS

and the module exported INGRESS_IFACE = "eth0" / EGRESS_IFACE = "eth1" /
N_WEIGHTS = 319 to match it. Those are properties of a deployment and of a
checkpoint; this module is neither. Which interface a node ingresses on is a
NODE fact (node_config.py), and the weight count is a MODEL fact
(model_meta.derive_shape).

What is left here is genuinely shared and scenario-free: BPF map helpers, MAC
and ifindex resolution, and XDP attach/detach.
"""
import json
import os
import re
import socket
import ctypes
import threading
import time
from bcc import BPF

# Default ingress interface, overridable by $IPA_IFACE. Not a lab constant:
# every entry point also takes --iface, and this only names the interface a
# bare `run()` attaches to when nothing else says.
INGRESS_IFACE = os.environ.get("IPA_IFACE", "eth0")

# Fallback destination MAC, used only until ARP resolves the real neighbour
# (see start_mac_refresh_thread). Was a specific lab neighbour's address.
DST_MAC = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]


def load_weights(path: str) -> list:
    with open(path, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# dense_vector feature maps (link_state, queue_state): stored as a SINGLE
# struct-valued entry `struct {__u32 v[N];}` at key 0, so the datapath reads
# all N slots with ONE bpf_map_lookup_elem instead of N separate lookups (was
# 6 for link_state + 4 for queue_occupancy = 10 helper calls per packet).
# These helpers write that single entry from userspace (the seeders/monitors).
# ---------------------------------------------------------------------------
def write_vector_map(bpf_obj, map_name: str, values) -> None:
    """Write the per-slot list `values` into the single key-0 entry of a
    struct-valued dense_vector map. Extra values are ignored, missing slots
    stay 0."""
    tbl = bpf_obj[map_name]
    leaf = tbl.Leaf()
    n = len(leaf.v)
    for i, val in enumerate(list(values)[:n]):
        leaf.v[i] = int(val) & 0xFFFFFFFF
    tbl[ctypes.c_int(0)] = leaf


def set_vector_slot(bpf_obj, map_name: str, idx: int, val: int) -> None:
    """Set one slot of a struct-valued dense_vector map (read-modify-write the
    key-0 entry). Used e.g. to flip a single link down in tests."""
    tbl = bpf_obj[map_name]
    leaf = tbl[ctypes.c_int(0)]
    leaf.v[idx] = int(val) & 0xFFFFFFFF
    tbl[ctypes.c_int(0)] = leaf


_LOOKUP_CALL_RE = re.compile(r'(\b\w+)\.lookup\(([^()]*)\)')


def instrument_map_lookups(src: str) -> str:
    """
    Wrap every `<map>.lookup(<key>)` call in `src` with a CTR_INC() counter
    increment, turning `table.lookup(&key)` into
    `({ CTR_INC(); table.lookup(&key); })` (a GNU C statement expression --
    valid wherever the original call was, since its last statement's value
    becomes the expression's value).

    CTR_INC() is a no-op unless IPA_COUNT_LOOKUPS is #defined before the
    source is compiled (see the CTR_INC macro in each pipeline's eBPF
    header) -- so this instrumentation only affects a dedicated measurement
    build, never the production/performance-measured programs whose
    instruction counts and latency are already hardware-verified.

    Used by verify_prog_run.count_lookups() to get a REAL per-packet
    map-lookup count for the design-space metrics table, replacing a
    stale hand estimate.

    Skips `lookup_ctr.lookup(...)` itself -- that call lives inside the
    CTR_INC() macro definition; wrapping it would make CTR_INC call
    itself recursively, which cpp does not expand (leaves a literal
    "undeclared function CTR_INC" call in the compiled output).
    """
    def _wrap(m):
        table = m.group(1)
        if table == "lookup_ctr":
            return m.group(0)
        return "({ CTR_INC(); %s.lookup(%s); })" % (table, m.group(2))
    return _LOOKUP_CALL_RE.sub(_wrap, src)


def count_instrumented_sites(src: str) -> dict:
    """
    How many `.lookup()` call sites instrument_map_lookups() would wrap, broken
    down per eBPF function (`int <name>(struct xdp_md *ctx)`), plus a "<header>"
    bucket for sites outside any function (shared always_inline helpers).

    Diagnostic only: when an instrumented measurement build gets rejected for
    exceeding the kernel's program-size cap, this says WHERE the added
    instrumentation weight lands, instead of leaving a bare "program too large".
    Used by verify_prog_run.count_lookups().
    """
    fn_re = re.compile(r'^\s*int\s+(\w+)\s*\(\s*struct\s+xdp_md', re.M)
    bounds = [(m.start(), m.group(1)) for m in fn_re.finditer(src)]
    out = {}
    for m in _LOOKUP_CALL_RE.finditer(src):
        if m.group(1) == "lookup_ctr":
            continue
        owner = "<header>"
        for pos, name in bounds:
            if m.start() >= pos:
                owner = name
            else:
                break
        out[owner] = out.get(owner, 0) + 1
    return out


def local_mac(iface: str) -> list:
    """Real MAC address of `iface`, read from the kernel (/sys/class/net) --
    always available, unlike the neighbor's MAC which requires a resolved
    ARP/neighbor entry."""
    with open(f"/sys/class/net/{iface}/address") as f:
        hexstr = f.read().strip()
    return [int(b, 16) for b in hexstr.split(":")]


def neighbor_mac(iface: str):
    """Next-hop neighbor MAC on `iface`, resolved from the kernel's ARP
    table (/proc/net/arp). Returns None if the link hasn't seen any
    traffic yet (no ARP exchange -> no entry) -- callers should fall back
    to a default and warn rather than install an unresolved/zero MAC."""
    try:
        with open("/proc/net/arp") as f:
            lines = f.readlines()[1:]
    except OSError:
        return None
    for line in lines:
        cols = line.split()
        if len(cols) < 6:
            continue
        hw_addr, dev = cols[3], cols[5]
        if dev != iface or hw_addr in ("00:00:00:00:00:00", "<incomplete>"):
            continue
        return [int(b, 16) for b in hw_addr.split(":")]
    return None


def resolve_ifindex(name: str, fallback: str = None):
    """
    Resolve `name` -> (resolved_name, ifindex).

    If `name` doesn't exist on this node:
      - fallback given: fall back to it (with a warning), returning
        whichever name actually resolved. Appropriate for a secondary/
        egress lookup (e.g. populating a mac_table entry) where any
        working interface is an acceptable substitute -- this is exactly
        what bit method4_hardcoded.py on a node missing eth4/eth5: the
        ifindex had a fallback already, but the interface NAME used to
        read /sys/class/net/<name>/address for the MAC did not, and
        crashed on a nonexistent interface.
      - fallback is None (default): raise a clear RuntimeError listing
        the interfaces that DO exist. Appropriate for the ingress/attach
        target -- silently substituting a different interface there would
        attach XDP to the wrong link without the caller ever noticing,
        which is worse than a loud, actionable failure.
    """
    try:
        return name, socket.if_nametoindex(name)
    except OSError:
        if fallback is not None:
            try:
                idx = socket.if_nametoindex(fallback)
            except OSError:
                idx = 2
            print(f"[common] WARNING: interface {name} not found on this node -- "
                  f"falling back to {fallback} (ifindex={idx})")
            return fallback, idx
        try:
            available = sorted(os.listdir("/sys/class/net"))
        except OSError:
            available = []
        raise RuntimeError(
            f"interface {name!r} not found on this node. "
            f"Available: {available}. Pass the correct --iface/iface=...")


def resolve_egress_mac(iface: str, fallback_dst: list = None):
    """Real per-interface L2 addressing for a mac_table action:
      src_mac = this host's own MAC on `iface` (always resolvable)
      dst_mac = the next-hop neighbor's MAC, from the kernel ARP table
    Falls back to `fallback_dst` (or the module DST_MAC constant) with a
    warning if the neighbor hasn't been ARP-resolved yet (idle link --
    e.g. before any OSPF/IP traffic has crossed it)."""
    src = local_mac(iface)
    dst = neighbor_mac(iface)
    if dst is None:
        dst = fallback_dst or DST_MAC
        dst_str = ":".join(f"{b:02x}" for b in dst)
        print(f"[mac] WARNING: no ARP entry for {iface} yet -- using fallback dst_mac {dst_str}")
    return src, dst


def install_mac_per_port(b, table_name: str, node_cfg, logical_ports: list = None):
    """Populate `table_name` keyed by LOGICAL PORT, from a resolved NodeConfig.

    mac_table used to be keyed by CLASS, with class k assumed to live on
    `eth{k}`. Both halves were wrong: a class is not a port (the model states
    which port each class selects, see class_semantics.py) and a port is not an
    interface name (the node states that, see node_config.py). This function
    consumes the node's resolution and writes only ports the node can realise;
    a port the model may select but the node lacks is left unmapped, so the
    datapath treats it as unforwardable instead of redirecting somewhere
    arbitrary.

    Returns {"installed": [(port, iface, ifindex)], "pending": [(port, iface)],
             "absent": [(port, iface)]}.
    """
    ports = sorted(node_cfg.bindings) if logical_ports is None else sorted(logical_ports)
    mac = b.get_table(table_name)
    installed, pending, absent = [], [], []
    for port in ports:
        bind = node_cfg.bindings.get(port)
        if bind is None or not bind.present or bind.ifindex is None:
            absent.append((port, bind.iface if bind else "?"))
            continue
        src = bind.src_mac
        dst = bind.dst_mac
        if src is None:
            absent.append((port, bind.iface))
            continue
        if dst is None:
            dst = DST_MAC
            pending.append((port, bind.iface))
        action = mac.Leaf()
        action.ifindex = bind.ifindex
        for i in range(6):
            action.src_mac[i] = src[i]
            action.dst_mac[i] = dst[i]
        mac[ctypes.c_uint32(port)] = action
        installed.append((port, bind.iface, bind.ifindex))
    pend = {p for p, _ in pending}
    for port, ifc, idx in installed:
        st = "ARP pending -> fallback dst_mac" if port in pend else "ARP resolved"
        print(f"[mac] {table_name}: logical_port {port} -> {ifc} "
              f"(ifindex={idx}) [{st}]")
    if absent:
        names = ", ".join(f"port {p} ({n})" for p, n in absent)
        print(f"[mac] {table_name}: {len(absent)} of {len(ports)} logical ports "
              f"have no usable interface on this node -> unforwardable: {names}")
    if not installed:
        print(f"[mac] WARNING: {table_name} -- no logical port resolved; "
              f"every FORWARD class is unforwardable")
    return {"installed": installed, "pending": pending, "absent": absent}


# install_mac_per_class() lived here: it keyed mac_table by CLASS, assuming
# class k == logical port k == eth{k}. All three equalities are false for the
# checked-in model (DROP is class 5, class 6 is untrained, ports are a separate
# index space), it had no callers left after install_mac_per_port() replaced
# it, and keeping a deprecated shim around only invites the assumption back.
# Use install_mac_per_port(b, table, node_cfg, logical_ports).


def install_ingress_port_table(b, map_name: str, node_cfg,
                               logical_ports: list = None) -> dict:
    """Fill `map_name` with kernel ifindex -> LOGICAL PORT, 1-based.

    The mirror of install_mac_per_port. That one answers "the model chose class
    k, which interface do I send out of"; this one answers "the packet arrived
    on interface X, which of my ports is that" -- the question the trained
    ingress_iface one-hot asks.

    It used to be answered by a compile-time table, [2, 3, 4, ...], i.e. the
    assumption eth0 == ifindex 2. Kernel ifindexes are assigned by the kernel:
    2 and 3 on a freshly booted container, 207 and 209 on a box that has
    created a few veths. When they do not match, no bit is set and a trained
    feature contributes nothing -- silently, with every test still green
    because nothing checked that it contributed anything.

    Values are 1-based because the datapath's guard is `>= 1 && <= size`, so a
    missing entry (0) reads as "not one of my ports". Returns what was written.
    """
    ports = list(logical_ports) if logical_ports is not None \
        else sorted(node_cfg.port_to_iface)
    written = {}
    for logical_idx, port in enumerate(sorted(ports), start=1):
        ifx = node_cfg.ifindex_of(port)
        if ifx is None:
            continue
        b[map_name][ctypes.c_uint32(int(ifx))] = ctypes.c_uint32(logical_idx)
        written[int(ifx)] = logical_idx

    if not written:
        print(f"[ingress] WARNING: {map_name} is empty -- no logical port "
              f"resolved to an interface on this node, so the ingress_iface "
              f"feature contributes nothing to any decision")
    else:
        for ifx, li in sorted(written.items()):
            name = next((n for p2, n in node_cfg.port_to_iface.items()
                         if node_cfg.ifindex_of(p2) == ifx), "?")
            print(f"[ingress] {map_name}: ifindex {ifx} ({name}) -> "
                  f"one-hot slot {li}")
    return written


def resolve_node_index(node_cfg=None, n_nodes: int = None):
    """This node's index in the node one-hot, or None if it cannot be known.

    Resolution order, loudest first:

      1. $IPA_NODE_ID                    -- explicit, and what tests use
      2. the topology's name -> index table (node_config.node_index_of)
      3. None

    Returns None rather than 0 when nothing answers. Zero is a valid node, so
    defaulting to it would make every unconfigured node claim to be node 0 --
    which is exactly the defect this replaces: the one-hot used to be indexed
    by ipa->model_id, so with a single registered model every node fired slot 0
    and 52 of the 65 inputs carried no information at all.

    NOTE ON MEANING: the index has to match the ordering the model was TRAINED
    on for the decisions to mean anything about the real network. If the point
    of a run is to measure the pipeline rather than the routing, any index that
    varies per node will do -- but then the decisions are arbitrary, and that
    should be stated wherever the numbers are reported.
    """
    env = os.environ.get("IPA_NODE_ID")
    if env is not None:
        try:
            idx = int(env)
        except ValueError:
            raise ValueError(f"IPA_NODE_ID={env!r} is not an integer")
        if n_nodes is not None and not 0 <= idx < n_nodes:
            raise ValueError(
                f"IPA_NODE_ID={idx} outside [0, {n_nodes}) for this topology")
        return idx

    if node_cfg is not None and getattr(node_cfg, "node_index", None) is not None:
        return int(node_cfg.node_index)

    try:
        from node_config import load_topology, node_index_of
        import socket as _socket
        idx = node_index_of(_socket.gethostname(), load_topology())
        if idx is not None:
            return int(idx)
    except Exception:
        pass
    return None


def install_node_id(b, map_name: str, node_cfg=None, n_nodes: int = None):
    """Write this node's index into the single-entry `map_name`.

    Returns the index written, or None if none could be resolved -- in which
    case the map is left empty and the datapath sets no bit, which is the
    honest representation of "this node does not know which node it is".
    """
    idx = resolve_node_index(node_cfg, n_nodes)
    if idx is not None and not 0 <= idx <= 255:
        # The datapath holds this index in a byte-bounded value, because the
        # verifier needs that bound to reason about the feature loop. Truncating
        # here would make node 300 silently claim to be node 44.
        raise ValueError(
            f"node index {idx} is outside [0, 255], which is what the datapath "
            f"can represent. A topology with more than 256 nodes needs a wider "
            f"bound in the generated C as well.")
    if idx is None:
        print(f"[node] WARNING: {map_name} left empty -- no node index resolved "
              f"($IPA_NODE_ID, or a name->index table in the topology). The "
              f"node one-hot will contribute nothing to any decision.")
        return None
    b[map_name][ctypes.c_uint32(0)] = ctypes.c_uint32(int(idx))
    print(f"[node] {map_name}: this node is index {idx}"
          + (f" of {n_nodes}" if n_nodes else ""))
    return idx

def start_mac_refresh_thread(b, table_name: str, egress_ifaces: list,
                             interval: float = 5.0):
    """Start a daemon thread that periodically re-reads /proc/net/arp and
    updates mac_table BPF entries that still use the fallback MAC with the
    real ARP-resolved neighbor MAC as soon as it becomes available.

    This removes the need for manual ARP warmup before launching the pipeline:
    within `interval` seconds of OSPF/FRR generating the first L3 traffic on
    a link the real neighbor MAC is detected and the BPF map entry corrected.

    egress_ifaces: list of (cls, iface_name) pairs to watch.

    Ifaces that do not exist on this node (/sys/class/net) are silently
    skipped: the model may produce classes pointing to eth4/eth5 on nodes
    that only have eth0-eth3, but those classes already map to MISS in the
    BPF mac_table (install_mac_per_class leaves them unmapped), so there is
    nothing to update and retrying them forever would be wasteful.
    """
    mac_tbl = b.get_table(table_name)
    fallback = DST_MAC

    # Filter out ifaces that don't exist on this node — they are already
    # MISS in the BPF map and will never have an ARP entry to resolve.
    try:
        existing = set(os.listdir("/sys/class/net"))
    except OSError:
        existing = set()
    watchlist = [(cls, iface) for cls, iface in egress_ifaces
                 if iface in existing]

    # Print the actual (post-filter) watchlist so the log reflects only the
    # interfaces that will really be polled (not phantom eth4/eth5 etc.).
    watch_names = [iface for _, iface in watchlist]
    print(f"[mac] MAC refresh thread started for: {watch_names}")

    if not watchlist:
        return None   # nothing to watch

    def _refresh():
        # Keep polling for the whole pipeline lifetime instead of exiting once
        # every class has resolved: an ARP entry can go stale/expire, and the
        # next hop behind a port can change (link flap, neighbour reboot). A
        # thread that stopped at first resolution would leave the BPF map
        # pointing at a dead MAC with no way to notice. Cost is one
        # /proc/net/arp read per interval, so re-polling forever is cheap.
        # Writes happen only when the resolved MAC actually differs from what
        # is already in the map, so the steady state is read-only.
        current = {}          # cls -> last dst_mac written
        while True:
            time.sleep(interval)
            for cls, iface in watchlist:
                dst = neighbor_mac(iface)
                if dst is None or dst == fallback or current.get(cls) == dst:
                    continue
                try:
                    src = local_mac(iface)
                    ifindex = socket.if_nametoindex(iface)
                    action = mac_tbl.Leaf()
                    action.ifindex = ifindex
                    for i in range(6):
                        action.src_mac[i] = src[i]
                        action.dst_mac[i] = dst[i]
                    mac_tbl[ctypes.c_uint32(cls)] = action
                    current[cls] = dst
                    dst_str = ":".join(f"{x:02x}" for x in dst)
                    print(f"[mac_refresh] class {cls} ({iface}): "
                          f"dst_mac updated to {dst_str}")
                except Exception as e:
                    print(f"[mac_refresh] class {cls} ({iface}): update failed ({e})")

    t = threading.Thread(target=_refresh, daemon=True, name="mac_refresh")
    t.start()
    return t


# XDP attach flags, from include/uapi/linux/if_link.h.
XDP_FLAGS_SKB_MODE = 2      # generic: runs in netif_receive_skb, AFTER the skb
XDP_FLAGS_DRV_MODE = 4      # native:  runs in the driver, BEFORE the skb exists
XDP_FLAGS_HW_MODE = 8       # offloaded onto the NIC

_MODE_FLAGS = {"native": XDP_FLAGS_DRV_MODE,
               "generic": XDP_FLAGS_SKB_MODE,
               "auto": 0}

# Default attach mode, overridable per call or by $IPA_XDP_MODE.
#
# This used to be hardcoded to generic (flags=2), and the reason was written
# into the docstring: generic "works on every device regardless of driver
# support, which mattered for veth interfaces inside the stripped
# containers". That justification came from the emulator, not from the design.
# Generic XDP runs inside netif_receive_skb -- after the kernel has already
# allocated the sk_buff -- which is later and slower than native XDP and is NOT
# the path a real deployment takes. Native is the default now; a box that
# cannot do native has to say so out loud.
DEFAULT_XDP_MODE = os.environ.get("IPA_XDP_MODE", "native")


def xdp_mode_in_effect(iface: str):
    """Which XDP mode is actually attached to `iface` right now.

    Returns "native", "generic", "offload", or None if nothing is attached.

    Asking the kernel rather than trusting the flags we passed is the whole
    point: with flags=0 the kernel picks the mode itself and silently falls
    back to generic, which is exactly how a measurement ends up describing a
    path nobody deploys. Reads `ip -details link show`, which prints the mode
    as `xdpgeneric` / `xdpdrv` / `xdpoffload`.
    """
    try:
        import subprocess
        out = subprocess.run(["ip", "-details", "link", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    if "xdpoffload" in out:
        return "offload"
    if "xdpdrv" in out:
        return "native"
    if "xdpgeneric" in out:
        return "generic"
    return "native" if "prog/xdp" in out or " xdp " in out else None


def attach_xdp(b: BPF, fn, iface: str = INGRESS_IFACE, mode: str = None):
    """Attach `fn` to `iface`, defaulting to NATIVE XDP.

    `mode` is "native" (driver mode, the real datapath), "generic" (SKB mode,
    after the skb is allocated), or "auto" (flags=0: let the kernel choose,
    which means it may quietly give you generic). Defaults to
    $IPA_XDP_MODE, else native.

    A native attach that fails does NOT silently become a generic one. Falling
    back by itself is what makes a number unattributable: the program runs, the
    counters move, and nothing in the output says the packet took a different
    path than the one being measured. Ask for "auto" or "generic" explicitly if
    that is what you want.

    Whatever was requested, the mode actually in effect is read back from the
    kernel and printed, and a mismatch is reported loudly.

    Raises on failure instead of printing and returning: a swallowed exception
    let every caller print "Pipeline running" over an interface with nothing
    attached, leaving the HIT/MISS/DROP counters frozen at 0 with no indication
    of why. Callers that want to survive a failed attach must catch it.
    """
    mode = (mode or DEFAULT_XDP_MODE).lower()
    if mode not in _MODE_FLAGS:
        raise ValueError(
            f"unknown XDP mode {mode!r}: expected one of "
            f"{', '.join(sorted(_MODE_FLAGS))} (via the mode= argument or "
            f"$IPA_XDP_MODE)")
    flags = _MODE_FLAGS[mode]

    print(f"[xdp] Attaching XDP to {iface} in {mode} mode (flags={flags})...")
    try:
        b.attach_xdp(iface, fn, flags=flags)
    except Exception as e:
        hint = ""
        if mode == "native":
            hint = (" This interface's driver may not support native XDP "
                    "(emulated NICs such as e1000 do not; veth, virtio_net "
                    "and most physical drivers do). To measure on the generic "
                    "path instead, say so explicitly: "
                    "IPA_XDP_MODE=generic, or mode='generic'.")
        raise RuntimeError(
            f"XDP attach to {iface!r} in {mode} mode failed: {e}. "
            f"Check the interface exists, is up, and has no stale program "
            f"(ip link set dev {iface} xdp off).{hint}"
        ) from e

    actual = xdp_mode_in_effect(iface)
    if actual is None:
        print(f"[xdp] attached to {iface}, but the kernel reports no XDP "
              f"program on it -- cannot confirm the mode")
    elif mode == "auto":
        print(f"[xdp] XDP attached to {iface}: kernel chose {actual} mode")
    elif actual != mode:
        print(f"[xdp] WARNING: asked for {mode} mode, kernel reports {actual}. "
              f"Every measurement from this run describes the {actual} path.")
    else:
        print(f"[xdp] XDP attached to {iface} in {actual} mode")
    return actual


def detach_xdp(b: BPF, iface: str = INGRESS_IFACE, mode: str = None):
    """Detach, using the same flags the attach used.

    The flags must match: removing a native program with SKB flags fails.
    """
    mode = (mode or DEFAULT_XDP_MODE).lower()
    b.remove_xdp(iface, flags=_MODE_FLAGS.get(mode, 0))
    print(f"[xdp] XDP removed from {iface}")
