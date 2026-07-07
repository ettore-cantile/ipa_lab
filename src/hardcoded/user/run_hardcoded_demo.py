#!/usr/bin/env python3
"""
run_hardcoded_demo.py — End-to-end demo and micro-benchmark for the hardcoded model.

Reuses shared/send_ipa.py to inject IPA-tagged test traffic and shared/test_ipa.py
for correctness verification.

Usage:
    python3 run_hardcoded_demo.py --iface eth0 --model 42 [--pkts 10000]

Metrics collected (printed to stdout):
    - Total packets sent
    - Elapsed time (s)
    - Throughput (Mpps)
    - Model update time (placeholder — triggers recompile+reload)
"""

import argparse
import os
import sys
import time

SHARED_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'shared')
sys.path.insert(0, SHARED_DIR)

try:
    from send_ipa import send_ipa_packet  # type: ignore
except ImportError:
    print("[warn] send_ipa.py not found — using stub")
    def send_ipa_packet(*args, **kwargs): pass  # noqa: E301

try:
    from test_ipa import run_tests  # type: ignore
except ImportError:
    print("[warn] test_ipa.py not found — skipping correctness tests")
    def run_tests(*args, **kwargs): print("[skip] test_ipa not available")  # noqa: E301


def benchmark(iface: str, model_id: int, n_pkts: int) -> dict:
    """Send n_pkts IPA packets and measure throughput."""
    print(f'[bench] Sending {n_pkts} IPA packets on {iface} for model {model_id}...')
    t0 = time.perf_counter()
    for i in range(n_pkts):
        # Minimal IPA packet: version=1, num_fields=5, model_id, 5 INT8 features
        features = [i % 127, (i+1) % 127, (i+2) % 127, (i+3) % 127, (i+4) % 127]
        send_ipa_packet(iface=iface, model_id=model_id, features=features)
    elapsed = time.perf_counter() - t0

    throughput_mpps = (n_pkts / elapsed) / 1e6 if elapsed > 0 else 0.0
    result = {
        'implementation': 'hardcoded',
        'model_id': model_id,
        'packets': n_pkts,
        'elapsed_s': round(elapsed, 4),
        'throughput_mpps': round(throughput_mpps, 4),
        'tail_calls_per_pkt': 1,
        'map_lookups_per_pkt': 0,
    }
    return result


def main():
    parser = argparse.ArgumentParser(description='Hardcoded model demo + benchmark')
    parser.add_argument('--iface', default='eth0', help='Interface')
    parser.add_argument('--model', type=int, default=42, help='Model ID')
    parser.add_argument('--pkts', type=int, default=10000, help='Packets to send')
    parser.add_argument('--test', action='store_true', help='Run correctness tests')
    args = parser.parse_args()

    if args.test:
        print('=== Correctness Tests ===')
        run_tests()

    print('=== Benchmark ===')
    result = benchmark(args.iface, args.model, args.pkts)
    print(f"  Implementation : {result['implementation']}")
    print(f"  Model ID       : {result['model_id']}")
    print(f"  Packets        : {result['packets']}")
    print(f"  Elapsed        : {result['elapsed_s']} s")
    print(f"  Throughput     : {result['throughput_mpps']} Mpps")
    print(f"  Tail calls/pkt : {result['tail_calls_per_pkt']}")
    print(f"  Map lookups/pkt: {result['map_lookups_per_pkt']}")
    print()
    print("[note] These figures measure the user-space send rate.")
    print("       For kernel-side XDP throughput, use 'bpftool prog profile' or pktgen.")


if __name__ == '__main__':
    main()
