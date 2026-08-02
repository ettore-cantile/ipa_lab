#!/usr/bin/env python3
"""
send_ipa.py - Send IPA packet(s) with paper-compliant header.

Usage (originale, single packet):
  python3 send_ipa.py <dst> [model_id] [weights_json]

Usage (Kathara test, multi-packet with variable TTL):
  python3 send_ipa.py --dst frankfurt --count 100 --model-id 0 --weights /shared/weights.json
  python3 send_ipa.py --dst frankfurt --count 100 --ttl-min 30 --ttl-max 64
  python3 send_ipa.py --dst frankfurt --count 500 --interval 0.002

IPA header structure (Section III of the paper):

  [Model Description]     5 byte
    model_id        : u8
    model_type      : u8   (0x00 = fully-connected NN)
    param_size      : u8   (7 = int8 / 7-bit quantization)
    scale_factor    : u16  (big-endian)

  [Input Descriptor]      5 byte
    input_size      : u8   (65)
    output_size     : u8   (7)
    hidden_layers   : u8   (2)
    neurons_per_layer: u8  (4)
    n_feature_types : u8   (4)

  [Feature Types]         8 byte
    Codes per model_meta.FEATURE_CODE (the single source of truth):
      0x01 link_state   0x02 ingress_iface   0x03 ttl
      0x04 node         0x05 queue_occupancy
    Default descriptor, in the order the 65-4-4-7 model was trained on:
    feat0: code=0x01 count=6   (link_state, one slot per egress interface)
    feat1: code=0x02 count=6   (ingress iface one-hot)
    feat2: code=0x03 count=1   (TTL)
    feat3: code=0x04 count=52  (node one-hot)

  [Output Descriptor]     3 byte
    n_output_types  : u8  (1)
    out0_code       : u8  (0x01 = next-hop index)
    out0_count      : u8  (7)

  Total fixed header: 21 byte
  Payload: N_WEIGHTS=319 quantized int8 weights (1 byte each)
"""

import argparse
import os
import random
import socket
import struct
import sys
import time

# IPA fixed header size
IPA_HEADER_SIZE = 21
N_WEIGHTS       = 319


def build_ipa_header(
    model_id: int,
    scale_factor: int,
    input_size: int = 65,
    output_size: int = 7,
    hidden_layers: int = 2,
    neurons_per_layer: int = 4,
    link_state_count: int = 6,
    ingress_iface_count: int = 6,
    ttl_count: int = 1,
    node_count: int = 52,
) -> bytes:
    """
    Build the 21-byte IPA header as specified in the paper.

    The four (code, count) pairs describe the model's input vector and now
    match model_meta.FEATURE_CODE and the default descriptor order
    [link_state, ingress_iface, ttl, node] -- which is what the pipelines
    actually build and what test/test_ipa.py already emitted. They previously
    declared (model_id,1), (ttl,1), (ingress_iface,6), (node,52): wrong codes
    AND wrong widths, so the two senders in this repo produced different
    header bytes for the same model. No datapath behaviour depended on it --
    the eBPF programs read only model_id -- but the header is documentation on
    the wire, so it should not contradict the descriptor registry.

    Sizes default to the checked-in 65-4-4-7 model's shape; pass a different
    model's resolved shape (see shared/model_meta.py derive_shape) instead.
    """
    return struct.pack(
        ">BBBHBBBBB" "BBBBBBBB" "BBB",
        # Model Description (5 bytes)
        model_id & 0xFF,   # model_id
        0x00,              # model_type: fully-connected NN
        7,                 # param_size: int8 / 7-bit quantization
        scale_factor & 0xFFFF,  # scale_factor (big-endian u16)
        # Input Descriptor (5 bytes)
        input_size,
        output_size,
        hidden_layers,
        neurons_per_layer,
        4,    # n_feature_types
        # Feature Types (8 bytes: 4 x (code, count)), descriptor order
        0x01, link_state_count,      # feat0: link_state
        0x02, ingress_iface_count,   # feat1: ingress iface one-hot
        0x03, ttl_count,             # feat2: ttl
        0x04, node_count,            # feat3: node one-hot
        # Output Descriptor (3 bytes)
        1,             # n_output_types
        0x01,          # out0_code: next-hop index (output codes are their own
                       # namespace, unrelated to FEATURE_CODE; unused by the datapath)
        output_size,   # out0_count
    )


def build_payload(weights_path: str, model_id: int) -> bytes:
    """
    Build the IPA payload: 21-byte header + 319-byte weight blob.
    If weights_path is provided and valid, use real weights;
    otherwise fall back to zero-filled weights.

    The datapath never reads this payload (weights are loaded out-of-band at
    control-plane time; the input vector is built locally on the node). It
    exists here only to produce a realistic packet size for testing.
    """
    # Try to load real weights
    weights = None
    scale   = 128

    if weights_path and os.path.exists(weights_path):
        try:
            import json
            with open(weights_path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                scale   = int(data.get("scale_factor", 128))
                weights = [int(w) & 0xFF for w in data.get("weights", [])]
            elif isinstance(data, list):
                weights = [int(w) & 0xFF for w in data]
        except Exception as e:
            print(f"[send_ipa] Warning: could not load {weights_path}: {e}")

    if weights is None or len(weights) < N_WEIGHTS:
        weights = [0] * N_WEIGHTS

    header  = build_ipa_header(model_id, scale)
    payload = bytes(weights[:N_WEIGHTS])
    return header + payload


def send_packets(
    dst: str,
    count: int,
    model_id: int,
    weights_path: str,
    port: int,
    interval: float,
    ttl_min: int,
    ttl_max: int,
) -> None:
    """
    Send `count` IPA UDP packets to `dst`:`port`.
    Each packet has a random TTL drawn from [ttl_min, ttl_max].
    """
    payload = build_payload(weights_path, model_id)

    # Resolve destination
    try:
        dst_ip = socket.gethostbyname(dst)
    except socket.gaierror:
        dst_ip = dst

    print(f"[send_ipa] Destination : {dst} ({dst_ip}):{port}")
    print(f"[send_ipa] Packets     : {count}")
    print(f"[send_ipa] Model ID    : {model_id}")
    print(f"[send_ipa] TTL range   : {ttl_min}-{ttl_max} (random per packet)")
    print(f"[send_ipa] Payload     : {len(payload)}B  "
          f"({IPA_HEADER_SIZE}B header + {len(payload)-IPA_HEADER_SIZE}B weights)")
    print(f"[send_ipa] Interval    : {interval}s")
    print()

    # Use raw IP socket to set TTL per-packet
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl_max)

        sent = 0
        for i in range(count):
            ttl = random.randint(ttl_min, ttl_max)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.sendto(payload, (dst_ip, port))
            sent += 1
            if (i + 1) % 10 == 0 or i == count - 1:
                print(f"[send_ipa] Sent {sent:>5}/{count}  last_ttl={ttl}",
                      end="\r", flush=True)
            if interval > 0 and i < count - 1:
                time.sleep(interval)

        print(f"\n[send_ipa] Done — sent {sent}/{count} packets to {dst_ip}:{port}")

    except PermissionError:
        print("[send_ipa] PermissionError: try running with sudo")
        sys.exit(1)
    finally:
        # socket() itself can raise (e.g. PermissionError), in which case `sock`
        # was never bound -- closing it unconditionally masked the real error
        # with a NameError.
        if sock is not None:
            sock.close()


def main():
    # Legacy positional-arg mode: python3 send_ipa.py <dst> [model_id] [weights]
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        dst        = sys.argv[1]
        model_id   = int(sys.argv[2])   if len(sys.argv) > 2 else 0
        weights    = sys.argv[3]        if len(sys.argv) > 3 else None
        send_packets(dst, 1, model_id, weights, 9999, 0.0, 64, 64)
        return

    parser = argparse.ArgumentParser(
        description="Send IPA packets to a destination (run on darmstadt)"
    )
    parser.add_argument("--dst",      required=True,
                        help="Destination IP or hostname (e.g. frankfurt, 10.0.0.234)")
    parser.add_argument("--count",    type=int,   default=1,
                        help="Number of packets to send (default: 1)")
    parser.add_argument("--model-id", type=int,   default=0,
                        help="Model ID embedded in IPA header (default: 0)")
    parser.add_argument("--weights",  default=None,
                        help="Path to weights JSON file (default: zero weights)")
    parser.add_argument("--port",     type=int,   default=9999,
                        help="UDP destination port (default: 9999)")
    parser.add_argument("--interval", type=float, default=0.01,
                        help="Delay between packets in seconds (default: 0.01)")
    parser.add_argument("--ttl-min",  type=int,   default=64,
                        help="Minimum IP TTL (default: 64)")
    parser.add_argument("--ttl-max",  type=int,   default=64,
                        help="Maximum IP TTL (default: 64)")
    args = parser.parse_args()

    if args.ttl_min > args.ttl_max:
        parser.error("--ttl-min must be <= --ttl-max")

    send_packets(
        dst=args.dst,
        count=args.count,
        model_id=args.model_id,
        weights_path=args.weights,
        port=args.port,
        interval=args.interval,
        ttl_min=args.ttl_min,
        ttl_max=args.ttl_max,
    )


if __name__ == "__main__":
    main()
