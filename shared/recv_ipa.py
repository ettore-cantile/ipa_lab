#!/usr/bin/env python3
"""
recv_ipa.py  —  IPA listener on frankfurt to verify packet arrival
=========================================================================
Run on frankfurt BEFORE sending from darmstadt.
Listens on UDP port 9999, decodes the IPA header and prints statistics.

Usage:
  python3 /shared/recv_ipa.py [--timeout 30] [--port 9999]

Esempio output:
  [recv_ipa] Listening on UDP :9999 (timeout=30s)
  [recv_ipa] #  1 | src=10.0.0.233 | model_id=0 | iface=1 | ttl=64 | payload=319B
  [recv_ipa] #  2 | src=10.0.0.233 | model_id=0 | iface=1 | ttl=64 | payload=319B
  ...
  [recv_ipa] === Summary ===
  [recv_ipa] Received : 100 packets
  [recv_ipa] Unique model_ids: {0}
  [recv_ipa] TTL distribution: {64: 100}
"""

import argparse
import signal
import sys
from scapy.all import sniff, IP, UDP, Raw


class IPAStats:
    def __init__(self):
        self.count      = 0
        self.model_ids  = {}
        self.ttl_dist   = {}
        self.src_ips    = set()

    def record(self, src, model_id, ttl, payload_len):
        self.count += 1
        self.model_ids[model_id] = self.model_ids.get(model_id, 0) + 1
        self.ttl_dist[ttl]       = self.ttl_dist.get(ttl, 0) + 1
        self.src_ips.add(src)

    def summary(self):
        print("\n[recv_ipa] === Summary ===")
        print(f"[recv_ipa] Received      : {self.count} packet(s)")
        print(f"[recv_ipa] Sources       : {self.src_ips}")
        print(f"[recv_ipa] model_id dist : {self.model_ids}")
        print(f"[recv_ipa] TTL dist      : {self.ttl_dist}")
        if self.count > 0:
            print("[recv_ipa] TEST PASSED — packets arrived at frankfurt")
        else:
            print("[recv_ipa] TEST FAILED — no packets received")


stats = IPAStats()


def parse_ipa_header(raw_bytes):
    """
    Parse 21-byte fixed IPA header.
    Returns dict with model_id, model_type, param_size, scale_factor,
    input_size, output_size, hidden_layers, neurons_per_layer.
    """
    if len(raw_bytes) < 21:
        return None
    return {
        "model_id":          raw_bytes[0],
        "model_type":        raw_bytes[1],
        "param_size":        raw_bytes[2],
        "scale_factor":      (raw_bytes[3] << 8) | raw_bytes[4],
        "input_size":        raw_bytes[5],
        "output_size":       raw_bytes[6],
        "hidden_layers":     raw_bytes[7],
        "neurons_per_layer": raw_bytes[8],
        "n_feature_types":   raw_bytes[9],
        # Output descriptor at offset 18
        "n_output_types":    raw_bytes[18],
    }


def packet_handler(pkt):
    if not (pkt.haslayer(UDP) and pkt[UDP].dport == PORT):
        return
    if not pkt.haslayer(Raw):
        return

    src        = pkt[IP].src if pkt.haslayer(IP) else "?"
    ttl        = pkt[IP].ttl if pkt.haslayer(IP) else 0
    raw        = bytes(pkt[Raw].load)
    hdr        = parse_ipa_header(raw)
    payload_len = len(raw) - 21 if len(raw) >= 21 else len(raw)

    if hdr:
        model_id = hdr["model_id"]
        print(f"[recv_ipa] #{stats.count+1:3d} | src={src:15s} | "
              f"model_id={model_id} | ttl={ttl} | "
              f"arch={hdr['input_size']}x{hdr['neurons_per_layer']}x{hdr['output_size']} | "
              f"payload={payload_len}B")
        stats.record(src, model_id, ttl, payload_len)
    else:
        print(f"[recv_ipa] #{stats.count+1:3d} | src={src} | MALFORMED (len={len(raw)}B)")
        stats.record(src, -1, ttl, len(raw))


def signal_handler(sig, frame):
    stats.summary()
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Listen for IPA packets on UDP port 9999 (run on frankfurt)"
    )
    parser.add_argument("--port",    type=int, default=9999,
                        help="UDP port to listen on (default: 9999)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Stop after N seconds (default: 60, 0=forever)")
    parser.add_argument("--count",   type=int, default=0,
                        help="Stop after N packets (default: 0=unlimited)")
    args = parser.parse_args()

    PORT = args.port
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    timeout_str = f"{args.timeout}s" if args.timeout > 0 else "unlimited"
    count_str   = str(args.count) if args.count > 0 else "unlimited"
    print(f"[recv_ipa] Listening on UDP :{PORT} | timeout={timeout_str} | count={count_str}")
    print(f"[recv_ipa] frankfurt loopback=10.255.255.17 | eth1=10.0.0.234")
    print(f"[recv_ipa] Waiting for packets from darmstadt (10.0.0.233)...")
    print()

    sniff(
        filter=f"udp port {PORT}",
        prn=packet_handler,
        timeout=args.timeout if args.timeout > 0 else None,
        count=args.count if args.count > 0 else 0,
        store=False,
    )

    stats.summary()
