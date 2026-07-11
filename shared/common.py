"""
common.py - Shared helpers used by all methods.

Interface mapping (from lab.conf + darmstadt.startup):
  darmstadt[0]="l59" <-> frankfurt[1]="l59"
    eth0 = 10.0.0.233/30  -> INGRESS: IPA packets arrive from frankfurt here
  darmstadt[1]="l62" <-> mannheim[0]="l62"
    eth1 = 10.0.0.246/30  -> EGRESS:  forwarded packets leave toward mannheim

"""
import json
import re
from bcc import BPF

INGRESS_IFACE = "eth0"   # darmstadt[0]=l59, link to frankfurt (10.0.0.233/30)
EGRESS_IFACE  = "eth1"   # darmstadt[1]=l62, link to mannheim  (10.0.0.246/30)
DST_MAC       = [0x62, 0x45, 0x3d, 0xec, 0xc9, 0x80]  # resolve_egress_mac() fallback

# Total number of weights: fc1(260+4) + fc2(16+4) + out(28+7) = 319
N_WEIGHTS = 319


def load_weights(path: str) -> list:
    with open(path, "r") as f:
        return json.load(f)


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
