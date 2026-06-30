#!/bin/bash
# fix_bpf.sh — eseguito automaticamente da frankfurt.startup
# Risolve il mismatch tra kernel host (es. 7.0.0-22-generic Ubuntu)
# e gli header Debian installati nell'immagine (es. 6.1.0-49-amd64).
# BCC ha bisogno di trovare /lib/modules/$(uname -r)/build per compilare;
# questo script crea quel symlink puntando agli header già presenti.

KERNEL=$(uname -r)
echo "[fix_bpf] Host kernel: ${KERNEL}"

HEADER_DIR="/lib/modules/${KERNEL}"
mkdir -p "${HEADER_DIR}"

if [ -e "${HEADER_DIR}/build" ]; then
    echo "[fix_bpf] ${HEADER_DIR}/build already exists, nothing to do."
    exit 0
fi

# 1) Cerca headers ESATTI per questo kernel
EXACT=$(ls /usr/src/ 2>/dev/null | grep -E "linux-headers-${KERNEL}$" | head -1)
if [ -n "${EXACT}" ]; then
    ln -sf "/usr/src/${EXACT}" "${HEADER_DIR}/build"
    echo "[fix_bpf] Exact match: ${HEADER_DIR}/build -> /usr/src/${EXACT}"
    exit 0
fi

# 2) Fallback: usa il primo header disponibile in /usr/src (es. 6.1.0-49-amd64)
# BCC compila bytecode eBPF che non dipende dalla versione esatta del kernel
# quando si usano feature standard (tc, XDP di base, socket filters).
FALLBACK=$(ls /usr/src/ 2>/dev/null | grep 'linux-headers-' | grep -v '\-common$' | head -1)
if [ -n "${FALLBACK}" ]; then
    ln -sf "/usr/src/${FALLBACK}" "${HEADER_DIR}/build"
    echo "[fix_bpf] Fallback symlink: ${HEADER_DIR}/build -> /usr/src/${FALLBACK}"
    # Assicura anche che esista il percorso che gcc cerca
    ALT_DIR="/lib/modules/${FALLBACK#linux-headers-}"
    if [ ! -e "${ALT_DIR}/build" ] && [ "${ALT_DIR}" != "${HEADER_DIR}" ]; then
        mkdir -p "${ALT_DIR}"
        ln -sf "/usr/src/${FALLBACK}" "${ALT_DIR}/build"
    fi
    exit 0
fi

# 3) Ultimo resort: prova apt
echo "[fix_bpf] No headers found in /usr/src, trying apt..."
apt-get update -qq 2>/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    linux-headers-amd64 linux-kbuild-6.1 2>/dev/null || true

FALLBACK2=$(ls /usr/src/ 2>/dev/null | grep 'linux-headers-' | grep -v '\-common$' | head -1)
if [ -n "${FALLBACK2}" ]; then
    ln -sf "/usr/src/${FALLBACK2}" "${HEADER_DIR}/build"
    echo "[fix_bpf] apt fallback: ${HEADER_DIR}/build -> /usr/src/${FALLBACK2}"
    exit 0
fi

echo "[fix_bpf] ERROR: could not set up kernel headers. BPF compilation may fail."
exit 1
