"""common.py -- shared runtime helpers: BPF map helpers, MAC and ifindex
resolution, XDP attach and detach.
"""
import json
import os
import re
import socket
import ctypes
import threading
import time
try:
    from bcc import BPF
except ImportError:
    BPF = None

INGRESS_IFACE = os.environ.get("IPA_IFACE", "eth0")
DST_MAC = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]


def load_weights(path: str) -> list:
    with open(path, "r") as f:
        return json.load(f)


# --- dense_vector feature maps (link_state, queue_state): stored as a SINGLE ---
def write_vector_map(bpf_obj, map_name: str, values) -> None:
    """Write the per-slot list `values` into the single key-0 entry of a
    struct-valued dense_vector map."""
    tbl = bpf_obj[map_name]
    leaf = tbl.Leaf()
    n = len(leaf.v)
    for i, val in enumerate(list(values)[:n]):
        leaf.v[i] = int(val) & 0xFFFFFFFF
    tbl[ctypes.c_int(0)] = leaf


def set_vector_slot(bpf_obj, map_name: str, idx: int, val: int) -> None:
    """Set one slot of a struct-valued dense_vector map (read-modify-write the
    key-0 entry)."""
    tbl = bpf_obj[map_name]
    leaf = tbl[ctypes.c_int(0)]
    leaf.v[idx] = int(val) & 0xFFFFFFFF
    tbl[ctypes.c_int(0)] = leaf


_LOOKUP_CALL_RE = re.compile(r'(\b\w+)\.lookup\(([^()]*)\)')


def instrument_map_lookups(src: str) -> str:
    """Wrap every `<map>.lookup(<key>)` in `src` with a CTR_INC() counter
    increment (active only with IPA_COUNT_LOOKUPS defined)."""
    def _wrap(m):
        table = m.group(1)
        if table == "lookup_ctr":
            return m.group(0)
        return "({ CTR_INC(); %s.lookup(%s); })" % (table, m.group(2))
    return _LOOKUP_CALL_RE.sub(_wrap, src)


def count_instrumented_sites(src: str) -> dict:
    """How many `.lookup()` call sites instrument_map_lookups() would wrap,
    broken down per eBPF function (`int <name>(struct xdp_md *ctx)`), plus a
    "<header>" bucket for sites outside any function (shared always_inline
    helpers)."""
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
    """Next-hop neighbor MAC on `iface`, resolved from the kernel's ARP table
    (/proc/net/arp)."""
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
    """Resolve `name` -> (resolved_name, ifindex)."""
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


def install_mac_per_port(b, table_name: str, node_cfg, logical_ports: list = None):
    """Populate `table_name` keyed by LOGICAL PORT, from a resolved NodeConfig."""
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


def ingress_port_slots(node_cfg, logical_ports: list = None) -> dict:
    """{kernel ifindex: one-hot slot, 1-based}: the slot is the rank of the
    port among the node's ports."""
    ports = list(logical_ports) if logical_ports is not None \
        else sorted(node_cfg.port_to_iface)
    out = {}
    for logical_idx, port in enumerate(sorted(ports), start=1):
        ifx = node_cfg.ifindex_of(port)
        if ifx is not None:
            out[int(ifx)] = logical_idx
    return out


def install_ingress_port_table(b, map_name: str, node_cfg,
                               logical_ports: list = None) -> dict:
    """Fill `map_name` with kernel ifindex -> LOGICAL PORT, 1-based."""
    written = ingress_port_slots(node_cfg, logical_ports)
    for ifx, logical_idx in written.items():
        b[map_name][ctypes.c_uint32(int(ifx))] = ctypes.c_uint32(logical_idx)

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
    """This node's index in the node one-hot, or None if it cannot be known."""
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
    """Write this node's index into the single-entry `map_name`."""
    idx = resolve_node_index(node_cfg, n_nodes)
    if idx is not None and not 0 <= idx <= 254:
        raise ValueError(
            f"node index {idx} is outside [0, 254]. The datapath holds this "
            f"in exactly one byte -- the range the verifier needs to keep "
            f"Pipeline 3's layer_first inside its complexity budget -- and 255 "
            f"is reserved to mean \"unknown\". Truncating here would make node "
            f"300 silently claim to be node 44.")
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
    real ARP-resolved neighbor MAC as soon as it becomes available."""
    mac_tbl = b.get_table(table_name)
    fallback = DST_MAC

    try:
        existing = set(os.listdir("/sys/class/net"))
    except OSError:
        existing = set()
    watchlist = [(cls, iface) for cls, iface in egress_ifaces
                 if iface in existing]

    watch_names = [iface for _, iface in watchlist]
    print(f"[mac] MAC refresh thread started for: {watch_names}")

    if not watchlist:
        return None

    def _refresh():
        current = {}
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


XDP_FLAGS_SKB_MODE = 2
XDP_FLAGS_DRV_MODE = 4
XDP_FLAGS_HW_MODE = 8

_MODE_FLAGS = {"native": XDP_FLAGS_DRV_MODE,
               "generic": XDP_FLAGS_SKB_MODE,
               "auto": 0}

DEFAULT_XDP_MODE = os.environ.get("IPA_XDP_MODE", "native")


def xdp_mode_in_effect(iface: str):
    """Which XDP mode is actually attached to `iface` right now."""
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
    """Attach `fn` to `iface`, defaulting to NATIVE XDP."""
    mode = (mode or DEFAULT_XDP_MODE).lower()
    if mode not in _MODE_FLAGS:
        raise ValueError(
            f"unknown XDP mode {mode!r}: expected one of "
            f"{', '.join(sorted(_MODE_FLAGS))} (via the mode= argument or "
            f"$IPA_XDP_MODE)")
    flags = _MODE_FLAGS[mode]

    print(f"[xdp] Attaching XDP to {iface} in {mode} mode (flags={flags})...")
    try:
        if hasattr(b, "attach_xdp"):
            b.attach_xdp(iface, fn, flags=flags)
        else:
            _attach_pinned(fn, iface, mode)
    except Exception as e:
        hint = ""
        if mode == "native":
            hint = (" This interface's driver may not support native XDP "
                    "(some drivers, such as e1000, do not; veth, virtio_net "
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
    """Detach, using the same flags the attach used."""
    mode = (mode or DEFAULT_XDP_MODE).lower()
    if hasattr(b, "remove_xdp"):
        b.remove_xdp(iface, flags=_MODE_FLAGS.get(mode, 0))
    else:
        import subprocess
        subprocess.run(["ip", "link", "set", "dev", iface,
                        _IP_XDP_KEYWORD.get(mode, "xdp"), "off"],
                       check=True, capture_output=True, text=True)
    print(f"[xdp] XDP removed from {iface}")


_IP_XDP_KEYWORD = {"native": "xdpdrv", "generic": "xdpgeneric", "auto": "xdp"}


def _attach_pinned(fn, iface, mode):
    """Attach a pinned program (fn.pin_path) with iproute2. -force replaces a
    program already there, which is what BCC's attach does too."""
    import subprocess
    path = getattr(fn, "pin_path", None)
    if not path:
        raise RuntimeError("the program has no pin_path: neither a BCC "
                           "function nor a pinned program")
    r = subprocess.run(["ip", "-force", "link", "set", "dev", iface,
                        _IP_XDP_KEYWORD[mode], "pinned", path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()
                           or f"ip link set exited {r.returncode}")
