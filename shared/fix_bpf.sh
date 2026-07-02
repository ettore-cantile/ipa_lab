#!/bin/bash
# fix_bpf.sh — Mounts the host headers provided through /shared

KERNEL=$(uname -r)
echo "[fix_bpf] Preparing headers for eBPF (Kernel $KERNEL)..."

# 1. Recreate the symlinks in /usr/src inside the container
mkdir -p /usr/src
ln -sfn /shared/host_headers/linux-headers-${KERNEL} /usr/src/linux-headers-${KERNEL}
ln -sfn /shared/host_headers/linux-headers-${KERNEL%-generic} /usr/src/linux-headers-${KERNEL%-generic}

# 2. Create the /lib/modules/.../build symlink that BCC expects by default
HEADER_DIR="/lib/modules/${KERNEL}"
mkdir -p "${HEADER_DIR}"
ln -sfn "/usr/src/linux-headers-${KERNEL}" "${HEADER_DIR}/build"

if [ -f "${HEADER_DIR}/build/include/linux/kconfig.h" ]; then
    echo "[fix_bpf] OK: kconfig.h found! BCC is ready to compile."
else
    echo "[fix_bpf] WARNING: kconfig.h not found."
fi