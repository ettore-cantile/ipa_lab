# Start from the official Kathara base image
FROM kathara/base

# Install both FRR (for routing) and eBPF tools (BCC)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y frr python3-bpfcc bpfcc-tools linux-headers-generic && \
    rm -rf /var/lib/apt/lists/*