#!/usr/bin/env python3
"""
test_ipa.py - Performance tester for the IPA switch.

Uses the same paper-compliant IPA_HDR as send_ipa.py (21 fixed bytes).
Sends N packets with random TTL values (30-64) and configurable model_id.

scale_factor note in the IPA header:
  The kernel does NOT use scale_factor from the header for inference -
  it always uses the one from model_cache loaded by the CP.
  The field is still populated correctly (default 128) for paper-format
  completeness and for Method 4 (used by the CP).

For Method 4, use --weights-file: the FIRST packet embeds the weights,
and the following packets are sent without payload (model already in cache).

Usage:
  python3 shared/test/test_ipa.py [--dest HOST] [--count N] [--delay SEC]
                      [--model-id ID] [--model-ids ID1 ID2 ...] [--weights-file PATH]
                      [--scale-factor N]
Examples:
  python3 shared/test/test_ipa.py --dest frankfurt --count 100
  python3 shared/test/test_ipa.py --dest frankfurt --count 50 --model-id 42
  python3 shared/test/test_ipa.py --dest frankfurt --count 50 --model-ids 42 43 44
  python3 shared/test/test_ipa.py --dest frankfurt --count 50 --model-id 42 \
                      --weights-file /shared/weights_method2.json
"""
import argparse
import os
import sys
import time
import random
import json
from scapy.all import send, IP, UDP, Packet, Raw
from scapy.fields import ByteField, ShortField

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

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
parser.add_argument("--model-ids",    type=int,   nargs="+", default=None,
                    help="Cycle packets across several model_id's (round-robin) "
                         "to exercise a multi-model template/modular registry. "
                         "Overrides --model-id when given.")
parser.add_argument("--scale-factor", type=int,   default=128,
                    help="scale_factor in the IPA header (default 128). "
                         "It does not affect kernel inference (which uses the cache), "
                         "but it must match the one used by the CP in Method 4.")
parser.add_argument("--weights-file", type=str,   default=None,
                    help="If provided, the 1st packet embeds the weights (Method 4)")
parser.add_argument("--scenario", choices=["sparse", "dense"], default="sparse",
                    help="'sparse' (default): today's behavior (header only, optional "
                         "1st-packet weight blob). 'dense': every packet carries a real "
                         "quantized feature vector, read directly by the dense eBPF "
                         "route (generate_ebpf_hardcoded_dense) -- see --model-meta.")
parser.add_argument("--model-meta", type=str, default=None,
                    help="dense only: path to model_meta.json declaring n_in/n_out "
                         "(default: shared/test/fixtures/dense_10_4_4_4/model_meta.json)")
parser.add_argument("--features", type=str, default=None,
                    help="dense only: comma-separated int8 feature values, reused for "
                         "every packet (default: one random vector, reused for all packets)")
args = parser.parse_args()

N            = args.count
DELAY        = args.delay
DEST         = args.dest
MODEL_IDS    = args.model_ids if args.model_ids else [args.model_id]
SCALE_FACTOR = args.scale_factor

weights_payload = b""
if args.weights_file:
    try:
        with open(args.weights_file) as f:
            weights = json.load(f)
        weights_payload = bytes([w & 0xFF for w in weights])
        print(f"[test_ipa] Loaded {len(weights_payload)} weights from {args.weights_file}")
    except Exception as e:
        print(f"[test_ipa] Warning: {e}")

dense_payload = b""
dense_n_in = dense_n_out = None
if args.scenario == "dense":
    import model_meta as _mm
    meta_path = args.model_meta or os.path.join(
        SHARED_DIR, "test", "fixtures", "dense_10_4_4_4", "model_meta.json")
    with open(meta_path) as f:
        _meta = json.load(f)
    dense_n_in, dense_n_out = _meta["n_in"], _meta["n_out"]
    if args.features:
        features = [int(x) for x in args.features.split(",")]
        if len(features) != dense_n_in:
            raise SystemExit(f"--features has {len(features)} values, expected {dense_n_in}")
    else:
        features = [random.randint(-30, 30) for _ in range(dense_n_in)]
    dense_payload = bytes(f & 0xFF for f in features)
    print(f"[test_ipa] dense scenario: n_in={dense_n_in} n_out={dense_n_out} "
          f"features={features}")

print(f"\n[test_ipa] Sending {N} packets to '{DEST}'")
print(f"  model_ids={MODEL_IDS} (round-robin) | scale_factor={SCALE_FACTOR} | "
      f"header=21 byte | scenario={args.scenario} | "
      f"weights={'1st pkt only' if weights_payload else 'none'}")
print()

t_start = time.perf_counter()
for i in range(N):
    ttl = random.randint(30, 64)
    mid = MODEL_IDS[i % len(MODEL_IDS)]
    if args.scenario == "dense":
        ipa_hdr = IPA_HDR(model_id=mid, scale_factor=SCALE_FACTOR,
                          input_size=dense_n_in, output_size=dense_n_out)
    else:
        ipa_hdr = IPA_HDR(model_id=mid, scale_factor=SCALE_FACTOR)
    packet  = IP(dst=DEST, ttl=ttl) / UDP(dport=9999) / ipa_hdr

    if args.scenario == "dense":
        packet = packet / Raw(load=dense_payload)
        if i < 3 or i == N - 1:
            print(f"  pkt #{i+1:>4} | TTL={ttl} | model_id={mid} | features ({len(dense_payload)} byte)")
        elif i == 3:
            print(f"  ... ({N - 4} more)")
    elif i == 0 and weights_payload:
        packet = packet / Raw(load=weights_payload)
        print(f"  pkt #{i+1:>4} | TTL={ttl} | model_id={mid} | +weights ({len(weights_payload)} byte)")
    else:
        if i < 3 or i == N - 1:
            print(f"  pkt #{i+1:>4} | TTL={ttl} | model_id={mid}")
        elif i == 3:
            print(f"  ... ({N - 4} more)")

    send(packet, verbose=False)
    if DELAY > 0:
        time.sleep(DELAY)

t_end = time.perf_counter()
elapsed = t_end - t_start
print(f"\n[test_ipa] Done. {N} pkts in {elapsed:.3f}s "
      f"({N/elapsed:.1f} pkt/s)")
print("[!] Check the TRUE HIT / FAKE HIT / MISS counters on the router.")
