#!/bin/bash
# fix_bpf.sh — eseguito da frankfurt.startup ad ogni avvio del container.
# Risolve il mismatch tra kernel host (es. 7.0.0-22-generic Ubuntu)
# e gli header Debian nell'immagine (es. 6.1.0-49-amd64).
# BCC cerca /lib/modules/$(uname -r)/build con include/linux/kconfig.h dentro.

KERNEL=$(uname -r)
echo "[fix_bpf] Host kernel: ${KERNEL}"

HEADER_DIR="/lib/modules/${KERNEL}"
mkdir -p "${HEADER_DIR}"

if [ -e "${HEADER_DIR}/build" ] && [ -f "${HEADER_DIR}/build/include/linux/kconfig.h" ]; then
    echo "[fix_bpf] Headers already OK at ${HEADER_DIR}/build"
    exit 0
fi

# Trova il miglior header disponibile: preferisci versione -amd64 (non meta)
# con include/linux/kconfig.h presente (merged da -common nel Dockerfile)
BEST=""
for d in $(ls /usr/src/ 2>/dev/null | grep 'linux-headers-' | grep -v 'common$' | sort -r); do
    if [ -f "/usr/src/${d}/include/linux/kconfig.h" ]; then
        BEST="${d}"
        break
    fi
done

# Se kconfig.h non c'è ancora, prova a copiarlo dal pacchetto -common
if [ -z "${BEST}" ]; then
    for d in $(ls /usr/src/ 2>/dev/null | grep 'linux-headers-' | grep -v 'common$' | sort -r); do
        COMMON=$(ls /usr/src/ 2>/dev/null | grep 'linux-headers-' | grep 'common$' | head -1)
        if [ -n "${COMMON}" ]; then
            cp -rn "/usr/src/${COMMON}/include" "/usr/src/${d}/include" 2>/dev/null || true
            if [ -f "/usr/src/${d}/include/linux/kconfig.h" ]; then
                BEST="${d}"
                break
            fi
        fi
    done
fi

# Ultimo fallback: qualsiasi header in /usr/src
if [ -z "${BEST}" ]; then
    BEST=$(ls /usr/src/ 2>/dev/null | grep 'linux-headers-' | grep -v 'common$' | head -1)
fi

if [ -n "${BEST}" ]; then
    # Rimuovi symlink vecchio se esiste ma era rotto
    rm -f "${HEADER_DIR}/build"
    ln -sf "/usr/src/${BEST}" "${HEADER_DIR}/build"
    echo "[fix_bpf] Symlink: ${HEADER_DIR}/build -> /usr/src/${BEST}"
    # Verifica finale
    if [ -f "${HEADER_DIR}/build/include/linux/kconfig.h" ]; then
        echo "[fix_bpf] OK: kconfig.h found, BCC should compile successfully."
    else
        echo "[fix_bpf] WARNING: kconfig.h still missing. BPF may fail."
    fi
    exit 0
fi

echo "[fix_bpf] ERROR: no usable kernel headers found in /usr/src/"
exit 1
