FROM kathara/base

# Install BCC and kernel header utilities
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        frr \
        python3-bpfcc \
        bpfcc-tools \
        linux-headers-generic \
        kmod \
        iproute2 \
        && rm -rf /var/lib/apt/lists/*

# Copy the header install helper script
COPY install_headers.sh /usr/local/bin/install_headers.sh
RUN chmod +x /usr/local/bin/install_headers.sh
