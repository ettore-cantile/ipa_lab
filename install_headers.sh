#!/bin/bash
# install_headers.sh — compatibilità con kernel host diverso dal container
# Crea il symlink /lib/modules/$(uname -r)/build verso gli header disponibili.
# Usato come fallback manuale; di norma viene chiamato fix_bpf.sh dallo startup.

KERNEL=$(uname -r)
echo "[*] Host kernel: $KERNEL"

HEADER_DIR="/lib/modules/${KERNEL}"
mkdir -p "${HEADER_DIR}"

if [ -e "${HEADER_DIR}/build" ]; then
    echo "[+] ${HEADER_DIR}/build already present."
    exit 0
fi

# 1) Header esatti
SRC_DIR=$(ls /usr/src/ 2>/dev/null | grep -E "linux-headers-${KERNEL}$" | head -1)
if [ -n "$SRC_DIR" ]; then
    ln -sf "/usr/src/${SRC_DIR}" "${HEADER_DIR}/build"
    echo "[+] Exact symlink: ${HEADER_DIR}/build -> /usr/src/${SRC_DIR}"
    exit 0
fi

# 2) Primo header disponibile (fallback cross-version)
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
