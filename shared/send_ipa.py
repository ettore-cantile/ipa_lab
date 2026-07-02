import sys
from scapy.all import send, IP, UDP, Packet, Raw
from scapy.fields import ByteField, ShortField
import json

# Define the custom IPA header structure using Scapy
class IPA_HDR(Packet):
    name = "IPAHeader"
    fields_desc = [
        ByteField("model_id", 42),
        ByteField("type_and_param_sz", 0),
        ShortField("scaling", 100),
        ByteField("input_size", 4),
        ByteField("output_size", 1),
        ByteField("hidden_layers", 4),
        ByteField("neurons_per_layer", 2)
    ]

if len(sys.argv) < 2:
    print("Usage: python3 send_ipa.py <destination_host_or_ip> [model_id] [weights_json]")
    print("Example: python3 send_ipa.py frankfurt")
    print("Example: python3 send_ipa.py frankfurt 42")
    print("Example: python3 send_ipa.py frankfurt 99 /shared/weights_method2.json")
    sys.exit(1)

destination = sys.argv[1]

model_id = 42
if len(sys.argv) >= 3:
    try:
        model_id = int(sys.argv[2])
    except ValueError:
        print("Error: model_id must be an integer.")
        sys.exit(1)

# Optional weights file: if provided, embed raw int8 weights in the packet payload
# This is required for Method 4 (IPA Demo) where the model travels in the packet.
weights_payload = b""
if len(sys.argv) >= 4:
    weights_file = sys.argv[3]
    try:
        with open(weights_file, "r") as f:
            weights = json.load(f)
        # Encode as signed bytes (int8)
        weights_payload = bytes([w & 0xFF for w in weights[:100]])
        print(f"Embedding {len(weights_payload)} weight bytes from {weights_file} in packet payload.")
    except Exception as e:
        print(f"Warning: could not load weights file: {e}")

# input_size carries the number of weights embedded (used by the kernel to copy them)
n_weights = len(weights_payload) if weights_payload else 4

# Construct the network packet
packet = IP(dst=destination) / UDP(dport=9999) / IPA_HDR(
    model_id=model_id,
    input_size=n_weights
)
if weights_payload:
    packet = packet / Raw(load=weights_payload)

print(f"Sending IPA Packet to '{destination}' with Model ID {model_id}...")
send(packet, verbose=False)
print("Packet sent successfully!")
