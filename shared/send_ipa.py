import sys
from scapy.all import send, IP, UDP, Packet
from scapy.fields import ByteField, ShortField

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

# Check if the user provided the required destination argument
if len(sys.argv) < 2:
    print("Usage: python3 send_ipa.py <destination_host_or_ip> [model_id]")
    print("Example: python3 send_ipa.py frankfurt")
    print("Example: python3 send_ipa.py frankfurt 42")
    sys.exit(1)

# Get the destination from the first command line argument
destination = sys.argv[1]

# Optional: Get the model_id from the second command line argument, default to 42
model_id = 42
if len(sys.argv) >= 3:
    try:
        model_id = int(sys.argv[2])
    except ValueError:
        print("Error: model_id must be an integer.")
        sys.exit(1)

# Construct the network packet
# Note: Scapy will automatically resolve the hostname to an IP address using /etc/hosts
packet = IP(dst=destination) / UDP(dport=9999) / IPA_HDR(model_id=model_id)

print(f"Sending IPA Packet to '{destination}' with Model ID {model_id}...")

# Send the packet at Layer 3 (IP layer)
send(packet, verbose=False)

print("Packet sent successfully!")