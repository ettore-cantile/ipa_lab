"""
common.py - Shared helpers used by all methods.

Interface mapping (from lab.conf + darmstadt.startup):
  darmstadt[0]="l59" <-> frankfurt[1]="l59"
    eth0 = 10.0.0.233/30  -> INGRESS: IPA packets arrive from frankfurt here
  darmstadt[1]="l62" <-> mannheim[0]="l62"
    eth1 = 10.0.0.246/30  -> EGRESS:  forwarded packets leave toward mannheim

"""
import json
import os
import re
import ctypes
import threading
import time
from bcc import BPF

INGRESS_IFACE = "eth0"   # darmstadt[0]=l59, link to frankfurt (10.0.0.233/30)
EGRESS_IFACE  = "eth1"   # darmstadt[1]=l62, link to mannheim  (10.0.0.246/30)
DST_MAC       = [0x62, 0x45, 0x3d, 0xec, 0xc9, 0x80]  # resolve_egress_mac() fallback

# Total number of weights: fc1(260+4) + fc2(16+4) + out(28+7) = 319
N_WEIGHTS = 319


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
    import socket
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


def install_mac_per_class(b, table_name: str, n_fwd: int, egress_ifaces: list = None):
    """Populate `table_name` (BPF_HASH class -> fwd_action) with a DISTINCT
    next-hop PER egress class: class i -> egress_ifaces[i], src = that iface's own
    MAC, dst = the ARP-resolved MAC of its neighbour (fallback until ARP resolves).

    This makes the NN's argmax class actually select the physical egress port,
    instead of every class redirecting out the same interface (the old behaviour:
    one iface resolved, the same action written to all classes).

    egress_ifaces: class -> interface name. Default ['eth0','eth1',...], i.e. the
    argmax class index == egress port index (same order as the link_state slots).
    Classes whose interface is absent on this node are left UNMAPPED -> that class
    resolves to MISS at runtime. Pass an explicit list to match a different
    class->port convention.

    Returns {"installed": [(cls, iface, ifindex)],
             "pending":   [(cls, iface)]}
    where `pending` lists exactly the classes whose dst_mac is still the
    fallback because ARP hasn't resolved yet. Callers feed `pending` straight
    into start_mac_refresh_thread() -- they must NOT re-derive it by calling
    neighbor_mac() again: a second /proc/net/arp read can disagree with the one
    used here (ARP may resolve in between), which would either leave a fallback
    MAC unwatched or spawn a refresh thread for an already-correct entry.
    """
    import ctypes
    if egress_ifaces is None:
        egress_ifaces = [f"eth{i}" for i in range(n_fwd)]
    mac = b.get_table(table_name)
    installed, pending = [], []
    for cls in range(n_fwd):
        name = egress_ifaces[cls] if cls < len(egress_ifaces) else None
        if not name:
            continue
        try:
            iface_r, ifindex = resolve_ifindex(name)
            src_mac = local_mac(iface_r)
            dst_mac = neighbor_mac(iface_r)
        except Exception as e:
            print(f"[mac] class {cls}: egress '{name}' unavailable ({e}) -> unmapped (MISS)")
            continue
        if dst_mac is None:
            # No ARP entry yet (idle link). Install a fallback so the class is
            # not a hard MISS, and hand this class to the refresh thread.
            dst_mac = DST_MAC
            pending.append((cls, iface_r))
        action = mac.Leaf()
        action.ifindex = ifindex
        for i in range(6):
            action.src_mac[i] = src_mac[i]
            action.dst_mac[i] = dst_mac[i]
        mac[ctypes.c_uint32(cls)] = action
        installed.append((cls, iface_r, ifindex))
    pending_cls = {c for c, _ in pending}
    for cls, ifc, idx in installed:
        state = "ARP pending -> fallback dst_mac" if cls in pending_cls else "ARP resolved"
        print(f"[mac] {table_name}: class {cls} -> {ifc} (ifindex={idx}) [{state}]")
    if not installed:
        print(f"[mac] WARNING: {table_name} -- no egress interface resolved; every class -> MISS")
    return {"installed": installed, "pending": pending}


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
                    import socket as _socket
                    ifindex = _socket.if_nametoindex(iface)
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


def attach_xdp(b: BPF, fn, iface: str = INGRESS_IFACE):
    print(f"[xdp] Attaching XDP to {iface}...")
    try:
        b.attach_xdp(iface, fn, flags=2)
        print(f"[xdp] XDP attached to {iface}")
    except Exception as e:
        print(f"[xdp] Error: {e}")


def detach_xdp(b: BPF, iface: str = INGRESS_IFACE):
    b.remove_xdp(iface, flags=2)
    print(f"[xdp] XDP removed from {iface}")
