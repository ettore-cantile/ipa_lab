#!/bin/bash
# install_headers.sh — compatibility helper for a host kernel different from the container.
# Creates the symlink /lib/modules/$(uname -r)/build pointing to available headers.
# Used as a manual fallback; normally fix_bpf.sh is called from startup.

KERNEL=$(uname -r)
echo "[*] Host kernel: $KERNEL"

HEADER_DIR="/lib/modules/${KERNEL}"
mkdir -p "${HEADER_DIR}"

if [ -e "${HEADER_DIR}/build" ]; then
    echo "[+] ${HEADER_DIR}/build already present."
    exit 0
fi

# 1) Exact matching headers
SRC_DIR=$(ls /usr/src/ 2>/dev/null | grep -E "linux-headers-${KERNEL}$" | head -1)
if [ -n "$SRC_DIR" ]; then
    ln -sf "/usr/src/${SRC_DIR}" "${HEADER_DIR}/build"
    echo "[+] Exact symlink: ${HEADER_DIR}/build -> /usr/src/${SRC_DIR}"
    exit 0
fi

# 2) First available header set (cross-version fallback)
SRC_DIR=$(ls /usr/src/ 2>/dev/null | grep 'linux-headers-' | grep -v '\-common$' | head -1)
if [ -n "$SRC_DIR" ]; then
    ln -sf "/usr/src/${SRC_DIR}" "${HEADER_DIR}/build"
    echo "[+] Fallback symlink: ${HEADER_DIR}/build -> /usr/src/${SRC_DIR}"
    exit 0
fi

# 3) Prova apt
echo "[*] Trying apt install..."
apt-get update -qq && \
DEBIAN_FRONTEND=noninteractive apt-get install -y linux-headers-amd64 2>/dev/null || true

SRC_DIR=$(ls /usr/src/ 2>/dev/null | grep 'linux-headers-' | grep -v '\-common$' | head -1)
if [ -n "$SRC_DIR" ]; then
    ln -sf "/usr/src/${SRC_DIR}" "${HEADER_DIR}/build"
    echo "[+] apt fallback symlink: ${HEADER_DIR}/build -> /usr/src/${SRC_DIR}"
    exit 0
fi

echo "[!] Could not set up kernel headers. BPF may fail."
exit 1
