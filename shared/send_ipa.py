#!/usr/bin/env python3
"""
send_ipa.py - Send IPA packet(s) with paper-compliant header.

Usage (originale, single packet):
  python3 send_ipa.py <dst> [model_id] [weights_json]

Usage (Kathara test, multi-packet):
  python3 send_ipa.py --dst frankfurt --count 100 --model-id 0 --weights /shared/weights.json
  python3 send_ipa.py --dst frankfurt --count 500 --interval 0.002

IPA header structure (Section III of the paper):

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

  [Model Parameters]    319 byte  (Raw payload, int8 serialized row-by-row)

Total: 21-byte fixed header + 319 bytes of weights = 340 bytes
"""
import sys
import json
import time
import argparse
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
    Paper-compliant IPA header - 21 fixed bytes.
    Sections: Model Description + Model Specifications +
              Input Descriptor (4 features) + Output Descriptor.
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


def load_weights(weights_file):
    """Load quantized weights from JSON file, return bytes."""
    with open(weights_file, "r") as f:
        weights = json.load(f)
    if isinstance(weights, dict) and "weights" in weights:
        weights = weights["weights"]
    return bytes([w & 0xFF for w in weights])


def load_scale_factor(default=128):
    """Try to read scale_factor from weights_float.json."""
    try:
        with open("/shared/weights_float.json") as f:
            data = json.load(f)
            return data.get("scale_factor", default)
    except Exception:
        return default


def send_packets(dst, model_id=42, weights_file=None, count=1, interval=0.001):
    """Send `count` IPA packets to destination."""
    scale_factor = load_scale_factor()

    weights_payload = b""
    if weights_file:
        try:
            weights_payload = load_weights(weights_file)
            print(f"[send_ipa] Embedding {len(weights_payload)} weight bytes from {weights_file}")
        except Exception as e:
            print(f"[send_ipa] Warning: could not load weights: {e}")

    ipa_hdr = IPA_HDR(model_id=model_id, scale_factor=scale_factor)
    base_pkt = IP(dst=dst) / UDP(dport=9999) / ipa_hdr
    if weights_payload:
        base_pkt = base_pkt / Raw(load=weights_payload)

    print(f"[send_ipa] dst='{dst}' model_id={model_id} scale={scale_factor} "
          f"hdr=21B payload={len(weights_payload)}B count={count} interval={interval}s")

    for i in range(count):
        send(base_pkt, verbose=False)
        if interval > 0 and i < count - 1:
            time.sleep(interval)

    print(f"[send_ipa] Done — sent {count} packet(s) to {dst}")


# ---------------------------------------------------------------------------
# CLI — backward-compatible: se il primo argomento non inizia con '--'
# si usa la vecchia interfaccia positionale.
# ---------------------------------------------------------------------------
def _legacy_mode():
    """Original positional-argument interface for backward compatibility."""
    destination = sys.argv[1]
    model_id = 42
    if len(sys.argv) >= 3:
        try:
            model_id = int(sys.argv[2])
        except ValueError:
            print("Error: model_id must be an integer.")
            sys.exit(1)
    weights_file = sys.argv[3] if len(sys.argv) >= 4 else None
    send_packets(dst=destination, model_id=model_id,
                 weights_file=weights_file, count=1, interval=0)


if __name__ == "__main__":
    # Detect legacy mode: first arg exists and does not start with '--'
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        _legacy_mode()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="Send IPA packet(s) with paper-compliant header.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples (Kathara test):
  # Single packet (legacy):
  python3 send_ipa.py frankfurt
  python3 send_ipa.py frankfurt 42 /shared/weights.json

  # Multi-packet with --method args (new):
  python3 send_ipa.py --dst frankfurt --count 200 --model-id 0
  python3 send_ipa.py --dst frankfurt --count 500 --weights /shared/weights.json --interval 0.002
        """
    )
    parser.add_argument("--dst", required=True,
                        help="Destination hostname or IP (e.g. 'frankfurt' or '10.0.0.234')")
    parser.add_argument("--model-id", type=int, default=0,
                        help="Model ID field in IPA header (default: 0)")
    parser.add_argument("--weights", default=None,
                        help="Path to quantized weights JSON (e.g. /shared/weights.json)")
    parser.add_argument("--count", type=int, default=1,
                        help="Number of packets to send (default: 1)")
    parser.add_argument("--interval", type=float, default=0.001,
                        help="Inter-packet interval in seconds (default: 0.001)")
    args = parser.parse_args()

    send_packets(
        dst=args.dst,
        model_id=args.model_id,
        weights_file=args.weights,
        count=args.count,
        interval=args.interval,
    )
