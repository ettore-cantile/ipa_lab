FROM kathara/base

# Install BCC, FRR, and explicitly versioned kernel headers
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        frr \
        python3-bpfcc \
        bpfcc-tools \
        linux-headers-6.1.0-49-amd64 \
        linux-headers-6.1.0-49-common \
        linux-kbuild-6.1 \
        linux-compiler-gcc-12-x86 \
        kmod \
        iproute2 \
        && rm -rf /var/lib/apt/lists/*

# Pre-create the BPF symlink that BCC looks for at /lib/modules/<host-kernel>/build.
# At container startup the host kernel version (e.g. 7.0.0-22-generic) differs
# from the Debian headers installed above (6.1.0-49-amd64). We pre-create the
# directory and symlink using the Debian headers so BCC can compile eBPF programs.
# The real kernel version is resolved at runtime by fix_bpf.sh in the startup.
RUN HDRDIR=$(ls /usr/src/ | grep 'linux-headers-.*-amd64$' | grep -v 'generic' | head -1) && \
    HDRCOMMON=$(ls /usr/src/ | grep 'linux-headers-.*-common$' | head -1) && \
    if [ -n "${HDRDIR}" ]; then \
        KVER=${HDRDIR#linux-headers-} && \
        mkdir -p /lib/modules/${KVER} && \
        ln -sf /usr/src/${HDRDIR} /lib/modules/${KVER}/build && \
        echo "Dockerfile BPF symlink: /lib/modules/${KVER}/build -> /usr/src/${HDRDIR}" && \
        if [ -n "${HDRCOMMON}" ]; then \
            cp -rn /usr/src/${HDRCOMMON}/include /usr/src/${HDRDIR}/include 2>/dev/null || true; \
        fi; \
    fi

# Copy the header install helper script
COPY install_headers.sh /usr/local/bin/install_headers.sh
RUN chmod +x /usr/local/bin/install_headers.sh
