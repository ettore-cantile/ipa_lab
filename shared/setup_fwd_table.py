#!/usr/bin/env python3
"""
setup_fwd_table.py  —  Populate fwd_table and valid_keys in the BPF maps
========================================================================
Reads the node's real interfaces (via `ip addr`) and populates:
  - fwd_table[model_id] = next-hop interface index towards frankfurt
  - valid_keys[ttl]     = expected key (model_id used as the key)

Usage:
  sudo python3 /shared/setup_fwd_table.py [--model-id 0] [--method hardcoded|template|modular]

darmstadt topology (node_id=10):
  eth0 -> 10.0.0.233/30  (link to frankfurt: 10.0.0.234 is frankfurt's eth1)
  eth1 -> 10.0.0.246/30
  eth2 -> 10.0.0.250/30

The next-hop towards frankfurt (10.255.255.17) is on eth0 (index 0).
"""

import argparse
import subprocess
import sys
import os

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

# --------------------------------------------------------------------------
# Known topology: darmstadt eth0 -> subnet 10.0.0.232/30 -> frankfurt eth1
# Next-hop towards frankfurt = index 0 (eth0)
# --------------------------------------------------------------------------
NEXT_HOP_IFACE_IDX = 0   # darmstadt's eth0 points to frankfurt
FRANKFURT_LOOPBACK = "10.255.255.17"
FRANKFURT_ETH1     = "10.0.0.234"   # frankfurt's IP on eth1 (direct link)


def get_iface_list():
    """Return list of up interface names on this node (exclude lo)."""
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show", "up"],
                                       text=True)
        ifaces = []
        for line in out.splitlines():
            parts = line.split()
            name = parts[1].rstrip(":")
            if name != "lo":
                ifaces.append(name)
        return ifaces
    except Exception as e:
        print(f"[setup_fwd_table] Warning: could not list interfaces: {e}")
        return ["eth0", "eth1", "eth2"]


def verify_next_hop_reachable():
    """Ping frankfurt to confirm direct connectivity."""
    try:
        ret = subprocess.call(
            ["ping", "-c", "1", "-W", "1", FRANKFURT_ETH1],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return ret == 0
    except Exception:
        return False


def populate_maps_hardcoded(bpf, model_id):
    """
    Pipeline 1 (hardcoded): le mappe si chiamano fwd_table e valid_keys.
    fwd_table: u32 model_id -> u32 iface_idx
    valid_keys: u32 ttl     -> u32 model_id  (chiave per TRUE HIT check)
    """
    try:
        fwd_table  = bpf["fwd_table"]
        valid_keys = bpf["valid_keys"]

        # Popola forwarding: model_id 0 -> eth0 (next-hop a frankfurt)
        fwd_table[bpf.Object.ctypes.c_uint32(model_id)] = \
            bpf.Object.ctypes.c_uint32(NEXT_HOP_IFACE_IDX)

        # valid_keys: TTL 64 (tipico) -> model_id
        for ttl in range(1, 129):
            valid_keys[bpf.Object.ctypes.c_uint32(ttl)] = \
                bpf.Object.ctypes.c_uint32(model_id)

        print(f"[setup_fwd_table] fwd_table[{model_id}] = eth{NEXT_HOP_IFACE_IDX} (frankfurt)")
        print(f"[setup_fwd_table] valid_keys[1..128] = {model_id}")
        return True
    except Exception as e:
        print(f"[setup_fwd_table] ERROR populating maps: {e}")
        return False


def populate_maps_via_bpftool(model_id):
    """
    Fallback: use `bpftool map update` to populate fwd_table and valid_keys
    without a reference to the Python BPF object (useful when the program was
    already loaded by another process).
    """
    print("[setup_fwd_table] Using bpftool fallback to update maps...")

    def bpftool_map_update(map_name, key_val, value_val):
        cmd = [
            "bpftool", "map", "update",
            "name", map_name,
            "key", "hex",
            f"{key_val:02x}", "00", "00", "00",
            "value", "hex",
            f"{value_val:02x}", "00", "00", "00"
        ]
        ret = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ret == 0

    ok = bpftool_map_update("fwd_table", model_id, NEXT_HOP_IFACE_IDX)
    if ok:
        print(f"[setup_fwd_table] bpftool: fwd_table[{model_id}] = {NEXT_HOP_IFACE_IDX}")
    else:
        print(f"[setup_fwd_table] WARNING: bpftool fwd_table update failed (program may not be loaded yet)")

    for ttl in [64, 63, 62, 128, 255]:
        bpftool_map_update("valid_keys", ttl, model_id)
    print(f"[setup_fwd_table] bpftool: valid_keys[64,63,62,128,255] = {model_id}")

    return ok


def main():
    parser = argparse.ArgumentParser(
        description="Populate BPF fwd_table and valid_keys for Kathara test"
    )
    parser.add_argument("--model-id", type=int, default=0,
                        help="Model ID to register (default: 0)")
    parser.add_argument("--method",
                        choices=["hardcoded", "template", "modular", "auto"],
                        default="auto",
                        help="Pipeline method (default: auto-detect via bpftool)")
    parser.add_argument("--check-reachability", action="store_true",
                        help="Ping frankfurt to verify next-hop before populating")
    args = parser.parse_args()

    print("[setup_fwd_table] === Kathara BPF map setup ===")
    print(f"[setup_fwd_table] Node: darmstadt (10.255.255.10)")
    print(f"[setup_fwd_table] Next-hop: frankfurt ({FRANKFURT_ETH1}) via eth{NEXT_HOP_IFACE_IDX}")
    print(f"[setup_fwd_table] Model ID: {args.model_id}")

    ifaces = get_iface_list()
    print(f"[setup_fwd_table] Interfaces up: {ifaces}")

    if args.check_reachability:
        reachable = verify_next_hop_reachable()
        if reachable:
            print(f"[setup_fwd_table] Reachability OK: {FRANKFURT_ETH1} responds to ping")
        else:
            print(f"[setup_fwd_table] WARNING: {FRANKFURT_ETH1} not responding — "
                  "FRR/OSPF may still be converging. Maps will be set anyway.")

    # Try bpftool approach (works regardless of how the BPF prog was loaded)
    success = populate_maps_via_bpftool(args.model_id)

    if not success:
        print("[setup_fwd_table] bpftool failed — ensure execute_pipeline.py is running first.")
        print("[setup_fwd_table] Run: sudo python3 /shared/execute_pipeline.py --method hardcoded --iface eth0")
        sys.exit(1)

    print("[setup_fwd_table] Maps populated successfully.")
    print("[setup_fwd_table] Now run on darmstadt:")
    print(f"  python3 /shared/send_ipa.py --dst frankfurt --count 100 --model-id {args.model_id} "
          f"--weights /shared/weights.json")


if __name__ == "__main__":
    main()
