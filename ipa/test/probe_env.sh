#!/usr/bin/env bash
# probe_env.sh -- what can THIS Linux box actually run?
#
# Why this exists
# ---------------
# Every performance number in this repository comes from BPF_PROG_TEST_RUN,
# which has no NIC, no driver and no packet rate. Moving to a real datapath
# means attaching XDP in NATIVE mode to a real interface and driving it with
# real traffic. Three things decide whether that is possible here, and none of
# them can be assumed:
#
#   1. is this bare metal, or a VM/WSL kernel that may lack native XDP at all
#   2. does XDP_REDIRECT *into* a veth work on this kernel version
#   3. is pktgen (the in-kernel generator) available, or are we stuck with a
#      userspace sender an order of magnitude slower
#
# Read-only except for one throwaway netns + veth pair, both named with the
# ipaprobe prefix and removed by the EXIT trap even on failure.
#
# Usage:  sudo bash ipa/test/probe_env.sh

NS="ipaprobe-ns"
V0="ipaprobe0"
V1="ipaprobe1"

G="\033[0;32m"; R="\033[0;31m"; Y="\033[1;33m"; N="\033[0m"
ok()   { printf "  ${G}yes${N}  %s\n" "$1"; }
no()   { printf "  ${R}NO${N}   %s\n" "$1"; }
warn() { printf "  ${Y}??${N}   %s\n" "$1"; }
hdr()  { printf "\n${Y}== %s ==${N}\n" "$1"; }

cleanup() {
    ip link del "$V0" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "needs root: sudo bash $0" >&2
    exit 1
fi

# ---------------------------------------------------------------- 1. kernel
hdr "kernel and virtualisation"
echo "  uname   : $(uname -r)"
echo "  arch    : $(uname -m)"
echo "  cpus    : $(nproc)"

virt="unknown"
command -v systemd-detect-virt >/dev/null 2>&1 && virt=$(systemd-detect-virt 2>/dev/null || echo none)
echo "  virt    : $virt"
if grep -qi microsoft /proc/version 2>/dev/null; then
    no "WSL detected -- native XDP and pktgen are usually absent here"
elif [ "$virt" = "none" ]; then
    ok "bare metal"
else
    warn "virtualised ($virt) -- native XDP depends on the virtual NIC driver"
fi

# ------------------------------------------------------------- 2. kconfig
hdr "kernel config"
CFG=""
[ -r "/boot/config-$(uname -r)" ] && CFG="/boot/config-$(uname -r)"
if [ -z "$CFG" ] && [ -r /proc/config.gz ]; then
    CFG="/tmp/ipaprobe-config"
    zcat /proc/config.gz > "$CFG" 2>/dev/null || CFG=""
fi
if [ -z "$CFG" ]; then
    warn "no kernel config readable -- skipping (not fatal, the live tests below decide)"
else
    for opt in CONFIG_BPF_SYSCALL CONFIG_XDP_SOCKETS CONFIG_VETH CONFIG_NET_PKTGEN CONFIG_DEBUG_INFO_BTF; do
        v=$(grep -E "^${opt}=" "$CFG" | cut -d= -f2)
        case "$v" in
            y) ok "$opt=y" ;;
            m) ok "$opt=m  (module)" ;;
            *) no "$opt is not set" ;;
        esac
    done
fi

# ------------------------------------------------------------- 3. toolchain
hdr "toolchain"
for t in ip bpftool clang llvm-strip python3; do
    if command -v "$t" >/dev/null 2>&1; then
        ok "$t  ($(command -v $t))"
    else
        no "$t missing"
    fi
done
python3 -c "import bcc" 2>/dev/null && ok "python3 bcc module" || no "python3 bcc module missing"
python3 -c "import torch" 2>/dev/null && ok "python3 torch module" || warn "python3 torch missing (host-side only: extract_weights)"
[ -f /usr/include/bpf/libbpf.h ] && ok "libbpf headers (libbpf-dev)" || no "libbpf headers missing -- the AOT loader will not build"
[ -f /sys/kernel/btf/vmlinux ] && ok "/sys/kernel/btf/vmlinux (CO-RE possible)" || no "no kernel BTF -- CO-RE not possible"

# ------------------------------------------------------------- 4. physical
hdr "physical interfaces and their drivers"
for d in /sys/class/net/*; do
    i=$(basename "$d")
    [ "$i" = "lo" ] && continue
    [ -e "$d/device" ] || continue          # skip virtual devices
    drv=$(basename "$(readlink -f "$d/device/driver" 2>/dev/null)" 2>/dev/null)
    echo "  $i  driver=$drv"
done

# ------------------------------------------------------- 5. veth + native XDP
hdr "veth pair and NATIVE XDP attach  (the decisive test)"
cleanup
if ! ip netns add "$NS" 2>/dev/null; then
    no "cannot create a network namespace -- L1 fabric is impossible here"
    exit 1
fi
ok "network namespace"

if ! ip link add "$V0" type veth peer name "$V1" 2>/dev/null; then
    no "cannot create a veth pair -- L1 fabric is impossible here"
    exit 1
fi
ok "veth pair"
ip link set "$V1" netns "$NS"
ip link set "$V0" up
ip netns exec "$NS" ip link set "$V1" up

# Minimal XDP_PASS program, built with bpftool's own loader so this probe does
# not depend on BCC being importable.
if command -v clang >/dev/null 2>&1; then
    cat > /tmp/ipaprobe.bpf.c <<'C'
#include <linux/bpf.h>
#define SEC(N) __attribute__((section(N), used))
SEC("xdp")
int probe_pass(struct xdp_md *ctx) { return 2; /* XDP_PASS */ }
char _license[] SEC("license") = "GPL";
C
    if clang -O2 -g -target bpf -c /tmp/ipaprobe.bpf.c -o /tmp/ipaprobe.bpf.o 2>/tmp/ipaprobe.cc.log; then
        ok "clang builds a BPF object"
        if ip link set dev "$V0" xdpdrv obj /tmp/ipaprobe.bpf.o sec xdp 2>/tmp/ipaprobe.drv.log; then
            ok "NATIVE XDP (xdpdrv) attaches to veth  <- L1 and L2-single are on"
            ip link set dev "$V0" xdpdrv off 2>/dev/null
        else
            no "native XDP refused on veth: $(tr -d '\n' < /tmp/ipaprobe.drv.log | tail -c 160)"
            if ip link set dev "$V0" xdpgeneric obj /tmp/ipaprobe.bpf.o sec xdp 2>/dev/null; then
                warn "generic XDP works, native does not -- measurements here describe the post-skb path"
                ip link set dev "$V0" xdpgeneric off 2>/dev/null
            else
                no "generic XDP also refused -- no XDP on veth at all here"
            fi
        fi
    else
        no "clang cannot build a BPF object: $(tail -1 /tmp/ipaprobe.cc.log)"
    fi
else
    warn "clang missing -- cannot test the attach modes"
fi

# ------------------------------------------------------------- 6. pktgen
hdr "traffic generation"
if modprobe pktgen 2>/dev/null; then
    ok "pktgen module loads  <- in-kernel generator, millions of pps"
    [ -d /proc/net/pktgen ] && ok "/proc/net/pktgen present" || warn "module loaded but /proc/net/pktgen absent"
else
    no "pktgen unavailable -- fall back to a userspace sender (~10x slower)"
fi
for t in trafgen mausezahn iperf3; do
    command -v "$t" >/dev/null 2>&1 && ok "$t available"
done

hdr "verdict"
echo "  Report the whole output. The decisive lines are:"
echo "    - virt / WSL          -> whether native XDP is possible at all"
echo "    - NATIVE XDP attach   -> whether L1 is real or just generic again"
echo "    - pktgen              -> whether L2-single gets real rates"
echo
