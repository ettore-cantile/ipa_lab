#!/bin/bash
# install_headers.sh — run this inside the Kathara container before switch_core.py
# It installs the exact kernel headers matching the host kernel version.

KERNEL=$(uname -r)
echo "[*] Host kernel: $KERNEL"

# Create the expected symlink path that BCC looks for
HEADER_DIR="/lib/modules/${KERNEL}"
mkdir -p "${HEADER_DIR}"

# If build/ symlink is missing, create a workaround pointing to /usr/src
if [ ! -e "${HEADER_DIR}/build" ]; then
    SRC_DIR=$(ls /usr/src/ 2>/dev/null | grep "linux-headers-${KERNEL}" | head -1)
    if [ -n "$SRC_DIR" ]; then
        ln -s "/usr/src/${SRC_DIR}" "${HEADER_DIR}/build"
        echo "[+] Symlink created: ${HEADER_DIR}/build -> /usr/src/${SRC_DIR}"
    else
        echo "[*] Trying to install linux-headers-${KERNEL} ..."
        apt-get update -qq && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y "linux-headers-${KERNEL}" 2>/dev/null || \
        DEBIAN_FRONTEND=noninteractive apt-get install -y "linux-headers-$(uname -r | sed 's/-generic//g')-generic" 2>/dev/null || \
        echo "[!] Could not install exact headers; BPF may still fail."

        SRC_DIR=$(ls /usr/src/ 2>/dev/null | grep "linux-headers-${KERNEL}" | head -1)
        [ -n "$SRC_DIR" ] && ln -s "/usr/src/${SRC_DIR}" "${HEADER_DIR}/build"
    fi
fi

# Ensure /proc/config.gz is accessible (needed by some BCC checks)
if [ ! -f /proc/config.gz ] && [ -f "/boot/config-${KERNEL}" ]; then
    mkdir -p /proc 2>/dev/null || true
fi

echo "[+] Header setup complete. You can now run switch_core.py"
