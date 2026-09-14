#!/bin/bash
# fix_bpf.sh — Mounts the host headers provided through /shared

KERNEL=$(uname -r)
echo "[fix_bpf] Preparing headers for eBPF (Kernel $KERNEL)..."

HH=/shared/host_headers

# Pick the header tree to use. Exact match on $(uname -r) first, then the
# version-stripped base (Debian ships linux-headers-7.0.0-22 for a
# 7.0.0-22-generic kernel), then whatever single tree is present.
# The last fallback matters: the repo carries ONE pinned tree, so on any host
# whose kernel name does not match it byte-for-byte the first two candidates
# are dangling symlinks and BCC used to fail with a bare missing-kconfig.h
# warning and no hint about which directory it actually wanted.
SRC=""
for cand in "linux-headers-${KERNEL}" "linux-headers-${KERNEL%-generic}"; do
    if [ -d "${HH}/${cand}" ]; then SRC="${cand}"; break; fi
done
if [ -z "${SRC}" ]; then
    SRC=$(ls "${HH}" 2>/dev/null | grep '^linux-headers-' | grep -v -- '-common$' | head -1)
    if [ -n "${SRC}" ]; then
        echo "[fix_bpf] NOTE: no header tree named for kernel ${KERNEL};"
        echo "[fix_bpf]       falling back to the only one available: ${SRC}"
    fi
fi

if [ -z "${SRC}" ]; then
    echo "[fix_bpf] ERROR: no kernel headers under ${HH}."
    echo "[fix_bpf]   They are not tracked in git. On the Kathara HOST run:"
    echo "[fix_bpf]     bash shared/fetch_host_headers.sh"
    echo "[fix_bpf]   BCC cannot compile eBPF programs until then."
    exit 1
fi

# 1. Recreate the symlinks in /usr/src inside the container
mkdir -p /usr/src
ln -sfn "${HH}/${SRC}" "/usr/src/linux-headers-${KERNEL}"
ln -sfn "${HH}/${SRC}" "/usr/src/linux-headers-${KERNEL%-generic}"

# 2. Create the /lib/modules/.../build symlink that BCC expects by default
HEADER_DIR="/lib/modules/${KERNEL}"
mkdir -p "${HEADER_DIR}"
ln -sfn "/usr/src/linux-headers-${KERNEL}" "${HEADER_DIR}/build"

if [ -f "${HEADER_DIR}/build/include/linux/kconfig.h" ]; then
    echo "[fix_bpf] OK: kconfig.h found (${SRC})! BCC is ready to compile."
else
    echo "[fix_bpf] WARNING: kconfig.h not found under ${HH}/${SRC}."
    echo "[fix_bpf]   The tree may be incomplete or built for a different kernel."
    echo "[fix_bpf]   Re-run 'bash shared/fetch_host_headers.sh' on the host."
fi
