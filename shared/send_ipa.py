#!/usr/bin/env python3
"""
send_ipa.py — Invia un pacchetto IPA con header paper-compliant.

Struttura header IPA (Section III del paper):

  [Model Description]     5 byte
    model_id        : u8
    model_type      : u8   (0x00 = fully-connected NN)
    param_size      : u8   (7 = int8 / 7-bit quantization)
    scale_factor    : u16  (big-endian)

  [Model Specifications]  4 byte
    input_size      : u8   (65)
    output_size     : u8   (7 = 6 iface + DROP)
    hidden_layers   : u8   (2)
    neurons_per_layer: u8  (4)

  [Input Descriptor]      9 byte
    n_feature_types : u8   (4)
    feat0_code/count: u8,u8  (0x01, 6)   link_state_interfaces
    feat1_code/count: u8,u8  (0x02, 6)   ingress_interface one-hot
    feat2_code/count: u8,u8  (0x03, 1)   normalized_ttl
    feat3_code/count: u8,u8  (0x04, 52)  node_id one-hot

  [Output Descriptor]     3 byte
    n_output_types  : u8   (1)
    out0_code/count : u8,u8  (0x05, 7)   next_hop_or_drop

  [Model Parameters]    319 byte  (payload Raw, int8 serializzati row-by-row)

Totale: 21 byte header fisso + 319 byte pesi = 340 byte (~22.7% di MTU 1500)

Usage:
  python3 send_ipa.py <dst> [model_id] [weights_json]
Esempi:
  python3 send_ipa.py frankfurt
  python3 send_ipa.py frankfurt 42
  python3 send_ipa.py frankfurt 99 /shared/weights.json
"""
import sys
import json
from scapy.all import send, IP, UDP, Packet, Raw
from scapy.fields import ByteField, ShortField

# Feature type codes (Input Descriptor)
FEAT_LINK_STATE = 0x01
FEAT_INGRESS_IF = 0x02
FEAT_TTL        = 0x03
FEAT_NODE_ID    = 0x04
OUT_NEXT_HOP    = 0x05


class IPA_HDR(Packet):
    """
    Header IPA paper-compliant — 21 byte fissi.
    Sezioni: Model Description + Model Specifications +
             Input Descriptor (4 feature) + Output Descriptor.
    """
    name = "IPA_HDR"
    fields_desc = [
        # --- Model Description (5 byte) ---
        ByteField("model_id",         42),
        ByteField("model_type",       0x00),  # 0x00 = fully-connected NN
        ByteField("param_size",       7),     # 7-bit / int8
        ShortField("scale_factor",    128),   # u16 big-endian

        # --- Model Specifications (4 byte) ---
        ByteField("input_size",          65), # 6+6+1+52
        ByteField("output_size",          7), # 6 iface + DROP
        ByteField("hidden_layers",        2),
        ByteField("neurons_per_layer",    4),

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


if len(sys.argv) < 2:
    print("Usage: python3 send_ipa.py <dst> [model_id] [weights_json]")
    sys.exit(1)

destination = sys.argv[1]

model_id = 42
if len(sys.argv) >= 3:
    try:
        model_id = int(sys.argv[2])
    except ValueError:
        print("Error: model_id must be an integer.")
        sys.exit(1)

# Pesi opzionali nel payload (Method 4)
weights_payload = b""
scale_factor    = 128
if len(sys.argv) >= 4:
    weights_file = sys.argv[3]
    try:
        with open(weights_file, "r") as f:
            weights = json.load(f)
        weights_payload = bytes([w & 0xFF for w in weights])
        print(f"[send_ipa] Embedding {len(weights_payload)} weight bytes from {weights_file}")
    except Exception as e:
        print(f"[send_ipa] Warning: could not load weights: {e}")

# Legge scale_factor da weights_float.json se disponibile
try:
    with open("/shared/weights_float.json") as f:
        scale_factor = json.load(f)["scale_factor"]
except Exception:
    pass

ipa_hdr = IPA_HDR(model_id=model_id, scale_factor=scale_factor)
packet  = IP(dst=destination) / UDP(dport=9999) / ipa_hdr
if weights_payload:
    packet = packet / Raw(load=weights_payload)

print(f"[send_ipa] -> '{destination}' | model_id={model_id} | "
      f"header=21 byte | payload={len(weights_payload)} byte")
send(packet, verbose=False)
print("[send_ipa] Packet sent successfully!")
