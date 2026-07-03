#!/usr/bin/env python3
"""
test_ipa.py — Performance tester per IPA switch.

Usa lo stesso IPA_HDR paper-compliant di send_ipa.py (21 byte fissi).
Invia N pacchetti con TTL casuale (30-64) e model_id configurabile.

Per il Method 4, usare --weights-file: il PRIMO pacchetto embeds i pesi,
i successivi vengono inviati senza payload (modello gia' in cache).

Usage:
  python3 test_ipa.py [--dest HOST] [--count N] [--delay SEC]
                      [--model-id ID] [--weights-file PATH]
Esempi:
  python3 test_ipa.py --dest frankfurt --count 100
  python3 test_ipa.py --dest frankfurt --count 50 --model-id 99
  python3 test_ipa.py --dest frankfurt --count 50 --model-id 99 \
                      --weights-file /shared/weights.json
"""
import argparse
import time
import random
import json
from scapy.all import send, IP, UDP, Packet, Raw
from scapy.fields import ByteField, ShortField

FEAT_LINK_STATE = 0x01
FEAT_INGRESS_IF = 0x02
FEAT_TTL        = 0x03
FEAT_NODE_ID    = 0x04
OUT_NEXT_HOP    = 0x05


class IPA_HDR(Packet):
    name = "IPA_HDR"
    fields_desc = [
        # --- Model Description (5 byte) ---
        ByteField("model_id",         42),
        ByteField("model_type",       0x00),
        ByteField("param_size",       7),
        ShortField("scale_factor",    128),
        # --- Model Specifications (4 byte) ---
        ByteField("input_size",       65),
        ByteField("output_size",       7),
        ByteField("hidden_layers",     2),
        ByteField("neurons_per_layer", 4),
        # --- Input Descriptor (9 byte) ---
        ByteField("n_feature_types",  4),
        ByteField("feat0_code",  FEAT_LINK_STATE), ByteField("feat0_count",  6),
        ByteField("feat1_code",  FEAT_INGRESS_IF), ByteField("feat1_count",  6),
        ByteField("feat2_code",  FEAT_TTL),        ByteField("feat2_count",  1),
        ByteField("feat3_code",  FEAT_NODE_ID),    ByteField("feat3_count", 52),
        # --- Output Descriptor (3 byte) ---
        ByteField("n_output_types", 1),
        ByteField("out0_code",  OUT_NEXT_HOP), ByteField("out0_count", 7),
    ]


parser = argparse.ArgumentParser(description="IPA switch performance tester")
parser.add_argument("--dest",         type=str,   default="frankfurt")
parser.add_argument("--count",        type=int,   default=10)
parser.add_argument("--delay",        type=float, default=0.0)
parser.add_argument("--model-id",     type=int,   default=42)
parser.add_argument("--weights-file", type=str,   default=None,
                    help="Se fornito, il 1° pacchetto embeds i pesi (Method 4)")
args = parser.parse_args()

N        = args.count
DELAY    = args.delay
DEST     = args.dest
MODEL_ID = args.model_id

weights_payload = b""
scale_factor    = 128
if args.weights_file:
    try:
        with open(args.weights_file) as f:
            weights = json.load(f)
        weights_payload = bytes([w & 0xFF for w in weights])
        print(f"[test_ipa] Loaded {len(weights_payload)} weights from {args.weights_file}")
    except Exception as e:
        print(f"[test_ipa] Warning: {e}")

try:
    with open("/shared/weights_float.json") as f:
        scale_factor = json.load(f)["scale_factor"]
except Exception:
    pass

print(f"\n[test_ipa] Sending {N} packets to '{DEST}'")
print(f"  model_id={MODEL_ID} | scale_factor={scale_factor} | "
      f"header=21 byte | weights={'1st pkt only' if weights_payload else 'none'}")
print()

t_start = time.perf_counter()
for i in range(N):
    ttl = random.randint(30, 64)
    ipa_hdr = IPA_HDR(model_id=MODEL_ID, scale_factor=scale_factor)
    packet  = IP(dst=DEST, ttl=ttl) / UDP(dport=9999) / ipa_hdr

    if i == 0 and weights_payload:
        packet = packet / Raw(load=weights_payload)
        print(f"  pkt #{i+1:>4} | TTL={ttl} | +weights ({len(weights_payload)} byte)")
    else:
        if i < 3 or i == N - 1:
            print(f"  pkt #{i+1:>4} | TTL={ttl}")
        elif i == 3:
            print(f"  ... ({N - 4} more)")

    send(packet, verbose=False)
    if DELAY > 0:
        time.sleep(DELAY)

t_end = time.perf_counter()
elapsed = t_end - t_start
print(f"\n[test_ipa] Done. {N} pkts in {elapsed:.3f}s "
      f"({N/elapsed:.1f} pkt/s)")
print("[!] Controlla i contatori TRUE HIT / FAKE HIT / MISS sul router.")
