#!/bin/bash
# fetch_host_headers.sh — populate shared/host_headers/ from THIS host's kernel.
#
# shared/ is bind-mounted into every Kathara node, and fix_bpf.sh symlinks
# /usr/src/linux-headers-$(uname -r) inside each container to what it finds
# here. BCC compiles eBPF programs against those headers, so without them
# every pipeline fails at BPF(text=...) with a missing kconfig.h.
#
# These headers are a build dependency of the host kernel, not project source:
# they are ~114 MB of generated files, pinned to one exact kernel version, and
# are deliberately NOT tracked in git (see .gitignore). Run this once after
# cloning, and again after a kernel upgrade.
#
# Usage:  bash shared/fetch_host_headers.sh
set -euo pipefail

KERNEL="$(uname -r)"
DEST="$(cd "$(dirname "$0")" && pwd)/host_headers"

echo "[fetch_host_headers] host kernel: ${KERNEL}"
echo "[fetch_host_headers] destination: ${DEST}"

if [ ! -d /usr/src ]; then
    echo "[fetch_host_headers] ERROR: /usr/src does not exist. Run this on the"
    echo "  Linux host that runs Kathara, not inside a container."
    exit 1
fi

# Both the exact name and the version-stripped base: fix_bpf.sh tries
# linux-headers-$(uname -r) first and linux-headers-${KERNEL%-generic} second,
# so copy whichever of the two the host actually provides.
CANDIDATES="linux-headers-${KERNEL} linux-headers-${KERNEL%-generic}"
found=0
mkdir -p "${DEST}"

for name in ${CANDIDATES}; do
    src="/usr/src/${name}"
    [ -d "${src}" ] || continue
    [ -e "${DEST}/${name}" ] && { echo "[fetch_host_headers] ${name} already present, skipping"; found=1; continue; }
    echo "[fetch_host_headers] copying ${src} ..."
    cp -a "${src}" "${DEST}/${name}"
    found=1
done

if [ "${found}" -eq 0 ]; then
    echo "[fetch_host_headers] ERROR: no kernel headers found in /usr/src for ${KERNEL}."
    echo "  Install them first, e.g.:"
    echo "    sudo apt-get install -y linux-headers-\$(uname -r)"
    ls /usr/src 2>/dev/null | sed 's/^/    available: /'
    exit 1
fi

# A '-common' tree holds the arch-independent include/ that the arch-specific
# tree references; without it kconfig.h resolves but many includes do not.
COMMON="$(ls /usr/src 2>/dev/null | grep -- '-common$' | head -1 || true)"
if [ -n "${COMMON}" ] && [ ! -e "${DEST}/${COMMON}" ]; then
    echo "[fetch_host_headers] copying /usr/src/${COMMON} ..."
    cp -a "/usr/src/${COMMON}" "${DEST}/${COMMON}"
fi

echo "[fetch_host_headers] done:"
du -sh "${DEST}" 2>/dev/null || true
ls -1 "${DEST}"
