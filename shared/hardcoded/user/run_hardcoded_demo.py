#!/usr/bin/env python3
"""
run_hardcoded_demo.py — Send IPA test packets and verify XDP action.

Usage (inside Kathara, e.g. on node 'sender'):
    python3 /shared/hardcoded/user/run_hardcoded_demo.py --target <IP> --iface eth0

Reuses shared/send_ipa.py for packet construction.
"""

import argparse
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, '..', '..'))

try:
    from send_ipa import send_ipa_packet  # noqa
except ImportError:
    print('[warn] send_ipa.py not found — using scapy fallback')
    send_ipa_packet = None


def send_with_scapy(target_ip: str, iface: str, model_id: int, n: int) -> None:
    """Fallback: send raw UDP/9999 packets with IPA header via scapy."""
    from scapy.all import IP, UDP, Raw, send  # type: ignore
    # IPA header: version=1, num_fields=5, model_id (big-endian 2 bytes)
    ipa_hdr = bytes([0x01, 0x05]) + model_id.to_bytes(2, 'big')
    # 5 dummy INT8 features
    features = bytes([10, 20, 30, 40, 50])
    payload = ipa_hdr + features
    pkt = IP(dst=target_ip) / UDP(dport=9999) / Raw(load=payload)
    print(f'[send] Sending {n} IPA packets to {target_ip}:9999 (model_id={model_id})')
    for i in range(n):
        send(pkt, iface=iface, verbose=False)
        time.sleep(0.01)
    print('[done] Check trace_pipe on the receiver node:')
    print('       cat /sys/kernel/debug/tracing/trace_pipe')


def main():
    parser = argparse.ArgumentParser(description='IPA hardcoded demo traffic generator')
    parser.add_argument('--target', required=True, help='Destination IP address')
    parser.add_argument('--iface', default='eth0', help='Source interface')
    parser.add_argument('--model', type=int, default=42, help='model_id to encode in header')
    parser.add_argument('--count', type=int, default=10, help='Number of packets to send')
    args = parser.parse_args()

    if send_ipa_packet:
        print(f'[send] Using shared/send_ipa.py for {args.count} packets')
        for _ in range(args.count):
            send_ipa_packet(args.target, args.model)
            time.sleep(0.01)
    else:
        send_with_scapy(args.target, args.iface, args.model, args.count)


if __name__ == '__main__':
    main()
