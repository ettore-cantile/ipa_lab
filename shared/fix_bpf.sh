#!/bin/bash
# fix_bpf.sh — Associa gli header dell'host passati tramite /shared

KERNEL=$(uname -r)
echo "[fix_bpf] Preparazione headers per eBPF (Kernel $KERNEL)..."

# 1. Ricrea i link in /usr/src nel container
mkdir -p /usr/src
ln -sfn /shared/host_headers/linux-headers-${KERNEL} /usr/src/linux-headers-${KERNEL}
ln -sfn /shared/host_headers/linux-headers-${KERNEL%-generic} /usr/src/linux-headers-${KERNEL%-generic}

# 2. Crea il link /lib/modules/.../build che BCC cerca di default
HEADER_DIR="/lib/modules/${KERNEL}"
mkdir -p "${HEADER_DIR}"
ln -sfn "/usr/src/linux-headers-${KERNEL}" "${HEADER_DIR}/build"

if [ -f "${HEADER_DIR}/build/include/linux/kconfig.h" ]; then
    echo "[fix_bpf] OK: kconfig.h trovato! BCC e' pronto per compilare."
else
    echo "[fix_bpf] ATTENZIONE: kconfig.h non trovato."
fi