#!/usr/bin/env python3
"""
test_ipa.py  -  Performance & correctness test for the IPA XDP switch.

Run this on DARMSTADT (or any node that can reach Frankfurt):
    python3 /shared/test_ipa.py [--count N] [--delay MS] [--dest IP]

What it measures:
  - throughput      : packets/sec sent from this node
  - redirect_rate   : read from Frankfurt's [TRACE] output
  - latency         : ICMP RTT as lower-bound baseline

Usage examples:
    python3 /shared/test_ipa.py                        # 10 pkt, 50ms delay
    python3 /shared/test_ipa.py --count 1000 --delay 0 # stress test
    python3 /shared/test_ipa.py --dest 10.255.255.17   # custom IP
"""

import argparse
import time
import subprocess
import re
from scapy.all import send, IP, UDP, Packet
from scapy.fields import ByteField, ShortField


class IPA_HDR(Packet):
    name = "IPAHeader"
    fields_desc = [
        ByteField("model_id",          42),
        ByteField("type_and_param_sz",  0),
        ShortField("scaling",          100),
        ByteField("input_size",          4),
        ByteField("output_size",         1),
        ByteField("hidden_layers",       4),
        ByteField("neurons_per_layer",   2),
    ]


parser = argparse.ArgumentParser(description="IPA switch performance tester")
parser.add_argument("--count",  type=int,   default=10,          help="Numero di pacchetti (default: 10)")
parser.add_argument("--delay",  type=float, default=50,          help="Delay tra pacchetti in ms (default: 50)")
parser.add_argument("--dest",   type=str,   default="frankfurt", help="Destinazione host o IP (default: frankfurt)")
parser.add_argument("--model",  type=int,   default=42,          help="model_id (default: 42)")
args = parser.parse_args()

N     = args.count
DELAY = args.delay / 1000.0
DEST  = args.dest
MODEL = args.model

SEP = "=" * 55
print(f"\n{SEP}")
print(f"  IPA XDP Switch  -  Performance Test")
print(SEP)
print(f"  Destinazione : {DEST}")
print(f"  model_id     : {MODEL}")
print(f"  Pacchetti    : {N}")
print(f"  Delay        : {args.delay} ms")
print(f"{SEP}\n")

# ---- Measure ICMP RTT baseline before sending ---------------------------
print("[1/3] Misuro RTT ICMP verso Frankfurt come baseline latenza...")
try:
    result = subprocess.check_output(["ping", "-c", "5", "-q", DEST], text=True)
    m = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", result)
    if m:
        rtt_min, rtt_avg, rtt_max, rtt_mdev = [float(x) for x in m.groups()]
        print(f"  ICMP RTT  min={rtt_min:.3f}ms  avg={rtt_avg:.3f}ms  "
              f"max={rtt_max:.3f}ms  mdev={rtt_mdev:.3f}ms")
        print(f"  XDP redirect latency e' tipicamente < 0.1ms (< ICMP min RTT)")
except Exception as e:
    print(f"  ping fallito: {e}")
    rtt_avg = None

# ---- Send IPA packets ---------------------------------------------------
print(f"\n[2/3] Invio {N} pacchetti IPA a '{DEST}' (model_id={MODEL})...")
packet = IP(dst=DEST) / UDP(dport=9999) / IPA_HDR(model_id=MODEL)

t_start = time.perf_counter()
for i in range(N):
    send(packet, verbose=False)
    if DELAY > 0:
        time.sleep(DELAY)
t_end = time.perf_counter()
elapsed = t_end - t_start

throughput = N / elapsed
print(f"  Completato in {elapsed:.3f}s  |  Throughput: {throughput:.1f} pkt/s")

# ---- Summary ------------------------------------------------------------
print(f"\n[3/3] Riepilogo risultati")
print(SEP)
print(f"  Pacchetti inviati    : {N}")
print(f"  Tempo totale         : {elapsed:.3f} s")
print(f"  Throughput (send)    : {throughput:.1f} pkt/s")
if rtt_avg:
    print(f"  ICMP RTT avg         : {rtt_avg:.3f} ms")
    print(f"  XDP latency stimata  : << {rtt_avg:.3f} ms  (kernel bypass)")
print(SEP)
print()
print("  Ora controlla il terminale di Frankfurt (switch_core.py).")
print("  Dovresti vedere esattamente {N} righe [TRACE] con:")
print(f"    -> REDIRECT ifindex=215(eth2)    <- tutto ok")
print(f"    -> PASS (nessuna regola fwd)     <- MYSTERY_NUMBER mismatch")
print(f"    -> PASS (modello non trovato)    <- modello non caricato")
print(f"    (nessun output)                  <- pacchetto non arriva (OSPF?)")
print()
print(f"  redirect_rate = (righe REDIRECT / {N}) * 100")
print(SEP)
print()
