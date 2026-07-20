#!/usr/bin/env python3
"""
bench_live_throughput.py -- REAL end-to-end throughput cross-check (sender).

Why this exists: test_suite.py / bench_depth_vs_width.py / bench_tailcall_
overhead.py all measure cost via BPF_PROG_TEST_RUN -- the program runs in
complete isolation, no real NIC interrupt, no driver, no cache contention
from other traffic. That is exactly the kind of gap "Benchmarking Crimes"
(Heiser, arXiv:1801.02381) and the Verizon LISA21 XDP talk warn about: a
synthetic in-kernel timer can silently diverge from what happens when
packets actually arrive through the wire. This script generates REAL
traffic -- as many packets/sec as this Python process can push through a
real UDP socket -- so the RECEIVING node's pkt_stats counter (HIT/MISS/DROP,
printed live by method4/5/6, or read via `bpf_introspect.py` -- NOT bpftool,
which is not installed in this lab's Kathara node images)
gives a genuinely independent throughput number to compare against the
BPF_PROG_TEST_RUN-derived one in docs/testing.md.

Caveats -- be honest about what this is NOT:
  - This is a Python sender: expect low tens of thousands of pkt/s at best,
    nowhere near line rate or the Mpps figures BPF_PROG_TEST_RUN reports.
    The comparison that matters is RELATIVE (does the P1/P2/P3 ranking
    survive under real delivery?), not the absolute pkt/s number.
  - test_ipa.py uses scapy's send() per packet (~30-200 pkt/s observed in
    this project -- each call re-resolves routing/L2 from scratch). This
    script uses a single connected UDP socket in a tight sendto() loop
    instead, which is orders of magnitude faster and is what actually makes
    this a meaningful throughput test rather than a correctness smoke test.
  - Kathara's fabric does not route UDP:9999 to a node's LOOPBACK IP
    end-to-end (see docs/testing.md sec. 5) -- --dest-ip MUST be the real
    IP of the receiving node's directly-connected interface (its neighbor
    on that link), not its hostname or loopback address. Find it with:
        kathara exec <receiver> -- ip -o -4 addr show

Usage (from the sender node, e.g. darmstadt):
    python3 shared/test/bench_live_throughput.py --dest-ip 10.0.0.234 --duration 10
    python3 shared/test/bench_live_throughput.py --dest-ip 10.0.0.234 --duration 10 --workers 4

On the receiver (e.g. frankfurt), in a separate shell, either watch the
running pipeline's live HIT/MISS/DROP printout (started via
execute_pipeline.py) or read the counter directly before/after (bpftool is
NOT installed in this lab's Kathara images -- use bpf_introspect.py instead):
    kathara exec frankfurt -- python3 /shared/bpf_introspect.py pkt_stats 3
"""
import argparse
import multiprocessing
import re
import socket
import struct
import sys
import time

# Matches shared/test/test_ipa.py's IPA_HDR layout exactly (21 bytes):
# 3 single-byte fields, scale_factor (2 bytes), then 16 more single-byte
# fields (input/output/hidden/neurons, feature descriptor, output descriptor).
IPA_HDR = struct.Struct("!BBBH16B")


def _build_header(model_id: int, scale_factor: int) -> bytes:
    return IPA_HDR.pack(
        model_id, 0x00, 7, scale_factor,          # model_id, model_type, param_size, scale_factor
        65, 7, 2, 4,                                # input_size, output_size, hidden_layers, neurons_per_layer
        4,                                           # n_feature_types
        0x01, 6,  0x02, 6,  0x03, 1,  0x04, 52,      # feat0..feat3 (code, count) -- link_state/iface/ttl/node
        1, 0x05, 7,                                  # n_output_types, out0_code, out0_count
    )


def _flood(dest_ip, port, duration, model_id, scale_factor, ttl, result_queue, worker_id):
    payload = _build_header(model_id, scale_factor)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    s.connect((dest_ip, port))   # resolve route/ARP ONCE, not per packet
    sent = 0
    t_end = time.perf_counter() + duration
    while time.perf_counter() < t_end:
        s.send(payload)
        sent += 1
    result_queue.put((worker_id, sent))


def main():
    ap = argparse.ArgumentParser(description="Real UDP flood throughput cross-check (sender side)")
    ap.add_argument("--dest-ip", required=True,
                    help="Real IP of the receiving node's directly-connected interface "
                         "(NOT hostname/loopback -- see module docstring)")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--model-id", type=int, default=0)
    ap.add_argument("--scale-factor", type=int, default=128)
    ap.add_argument("--ttl", type=int, default=42)
    ap.add_argument("--workers", type=int, default=1,
                    help="Parallel sender processes. Python's GIL caps a single "
                         "process well under what the kernel/NIC can sustain; "
                         "use several processes (not threads) to push closer to "
                         "the real ceiling.")
    args = ap.parse_args()

    # REFUSE a non-numeric destination. socket.connect() silently resolves
    # hostnames via the system resolver -- if that resolves to something that
    # doesn't actually cross the fabric (e.g. a loopback/self address), the
    # send() loop still "succeeds" (UDP is fire-and-forget) and reports a
    # huge, MEANINGLESS pkt/s number with nothing ever reaching the receiver.
    # This happened in testing: --dest-ip frankfurt (a hostname) reported
    # 1.27M pkt/s, ~40-100x this script's own documented expectation for a
    # Python sender -- the tell that packets never left the local stack.
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", args.dest_ip):
        sys.exit(f"[flood] REFUSING: --dest-ip {args.dest_ip!r} is not a dotted IPv4 address. "
                 f"A hostname resolves silently and can give a fake high pkt/s with zero "
                 f"packets actually delivered (see module docstring). Find the real IP with:\n"
                 f"    kathara exec <receiver> -- ip -o -4 addr show dev <ingress-iface>")

    print(f"[flood] -> {args.dest_ip}:{args.port}  model_id={args.model_id}  "
          f"workers={args.workers}  duration={args.duration}s")

    q = multiprocessing.Queue()
    procs = [multiprocessing.Process(
                target=_flood, args=(args.dest_ip, args.port, args.duration,
                                     args.model_id, args.scale_factor, args.ttl,
                                     q, i))
             for i in range(args.workers)]
    t0 = time.perf_counter()
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    elapsed = time.perf_counter() - t0

    total_sent = 0
    for _ in procs:
        wid, sent = q.get()
        print(f"  worker {wid}: {sent} pkt")
        total_sent += sent

    pps = total_sent / elapsed
    print(f"\n[flood] TOTAL: {total_sent} pkt in {elapsed:.2f}s  =  {pps:,.0f} pkt/s")
    print(f"[flood] Now read the RECEIVER's pkt_stats delta over this same window")
    print(f"[flood] (replace RECEIVER_NODE below with the actual node name, e.g. frankfurt):")
    print(f"    kathara exec RECEIVER_NODE -- python3 /shared/bpf_introspect.py pkt_stats 3")
    print(f"[flood] Compare {pps:,.0f} pkt/s (this sender's REAL ceiling) against the "
          f"BPF_PROG_TEST_RUN-derived Mpps in docs/testing.md -- the isolated number is "
          f"an upper bound on the DATAPATH's own cost, not a promise about real delivered "
          f"throughput end-to-end (Heiser's benchmarking-crimes point: don't conflate the two).")


if __name__ == "__main__":
    main()
