"""
common.py - Shared helpers used by all methods.

Interface mapping (from lab.conf + darmstadt.startup):
  darmstadt[0]="l59" <-> frankfurt[1]="l59"
    eth0 = 10.0.0.233/30  -> INGRESS: IPA packets arrive from frankfurt here
  darmstadt[1]="l62" <-> mannheim[0]="l62"
    eth1 = 10.0.0.246/30  -> EGRESS:  forwarded packets leave toward mannheim

Key note about the input_size field:
  In the new paper-compliant IPA header, input_size=65 (actual value).
  The CP uses iv = [42, ttl, ifindex, 65] to compute fwd_table keys,
  aligned with the XDP kernel code that reads ipa->input_size.
"""
import json
import ctypes
import socket
import time
from bcc import BPF

INGRESS_IFACE = "eth0"   # darmstadt[0]=l59, link to frankfurt (10.0.0.233/30)
EGRESS_IFACE  = "eth1"   # darmstadt[1]=l62, link to mannheim  (10.0.0.246/30)
OFFSET        = 100000
SRC_MAC       = [0x22, 0x8e, 0x26, 0xbb, 0xdf, 0xf5]
DST_MAC       = [0x62, 0x45, 0x3d, 0xec, 0xc9, 0x80]

# Total number of weights: fc1(260+4) + fc2(16+4) + out(28+7) = 319
N_WEIGHTS = 319


def load_bpf(program_str: str) -> BPF:
    return BPF(text=program_str)


def load_weights(path: str) -> list:
    with open(path, "r") as f:
        return json.load(f)


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


def build_fwd_action(b: BPF, egress_ifindex: int,
                     src_mac=None, dst_mac=None):
    src_mac = src_mac or SRC_MAC
    dst_mac = dst_mac or DST_MAC
    fwd    = b.get_table("fwd_table")
    action = fwd.Leaf()
    action.ifindex = egress_ifindex
    for i in range(6):
        action.src_mac[i] = src_mac[i]
        action.dst_mac[i] = dst_mac[i]
    return action


def populate_model_cache(b: BPF, model_id: int,
                         integer_weights: list, scale_factor: int):
    """
    Load weights into the BPF model_cache map (capacity: N_WEIGHTS=319).
    If the list is shorter, the remaining bytes stay 0.
    """
    cache = b.get_table("model_cache")
    entry = cache.Leaf()
    entry.is_valid     = 1
    entry.scale_factor = scale_factor
    for i in range(min(len(integer_weights), N_WEIGHTS)):
        entry.weights[i] = ctypes.c_uint8(integer_weights[i]).value
    cache[cache.Key(model_id)] = entry
    print(f"[cache] Model {model_id} loaded | "
          f"{min(len(integer_weights), N_WEIGHTS)} weights | "
          f"scale_factor={scale_factor}")


def _compute_key_float(iv: list, cp_weights: list) -> int:
    """Method 1 PTQ: key from original floats -> intentional FAKE HIT."""
    return int(sum(v * w for v, w in zip(iv, cp_weights))) + OFFSET


def _compute_key_integer(iv: list, int8_weights: list, scale: int) -> int:
    """Method 2/3 QAT: integer arithmetic matching the kernel -> TRUE HIT."""
    output_raw = sum(v * ctypes.c_int8(w).value
                     for v, w in zip(iv, int8_weights))
    return (output_raw + OFFSET * scale) // scale


def populate_fwd_and_valid_keys(b: BPF, action, cp_weights: list,
                                scale_factor: int,
                                ingress_iface: str = INGRESS_IFACE,
                                integer_arithmetic: bool = False):
    """
    Pre-populate fwd_table and valid_keys for TTL 30-64.
    iv = [model_id=42, ttl, ifindex, input_size=65]
    input_size=65 reflects the actual value in the new IPA header.
    """
    fwd    = b.get_table("fwd_table")
    vk     = b.get_table("valid_keys")
    if_idx = socket.if_nametoindex(ingress_iface)

    for ttl in range(30, 65):
        iv = [42, ttl, if_idx, 65]  # input_size=65 (was 4)
        if integer_arithmetic:
            key = _compute_key_integer(iv, cp_weights, scale_factor)
        else:
            key = _compute_key_float(iv, cp_weights)
        fwd[ctypes.c_ulonglong(key)] = action
        vk[ctypes.c_uint8(ttl)]      = ctypes.c_ulonglong(key)

    mode = "integer/QAT" if integer_arithmetic else "float/PTQ"
    print(f"[fwd] fwd_table and valid_keys loaded for TTL 30-64 [{mode}]")


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


def stats_loop(b: BPF, iface: str = INGRESS_IFACE,
               extra_poll_fn=None):
    stats = b.get_table("pkt_stats")
    print("\nListening for packets... (Ctrl+C to stop)")
    print(f"{'TRUE HIT':<22} | {'FAKE HIT':<22} | {'MISS':<20}")
    print("-" * 70)
    try:
        while True:
            if extra_poll_fn:
                extra_poll_fn()
            else:
                time.sleep(1)
            try:
                true_hits = stats[stats.Key(0)].value
                misses    = stats[stats.Key(1)].value
                fake_hits = stats[stats.Key(2)].value
                print(f"\r{true_hits:<22} | {fake_hits:<22} | {misses:<20}",
                      end="", flush=True)
            except Exception:
                pass
    except KeyboardInterrupt:
        detach_xdp(b, iface)
        print("\n\nXDP removed. Exiting.")
