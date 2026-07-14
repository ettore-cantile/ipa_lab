#!/usr/bin/env python3
"""
bench_veth_pps.py  --  REAL packets-per-second throughput of the 3 IPA/eBPF
pipelines, driven through the actual XDP hook on a veth pair.

Why this exists (vs verify_prog_run.py's BPF_PROG_TEST_RUN):
  BPF_PROG_TEST_RUN executes just the BPF bytecode in isolation -- great for
  a deterministic per-packet cost (instructions, latency) but it does NOT
  push packets through the real RX path (stack -> XDP hook -> program). This
  script instead:
    1. creates a veth pair (veth_ipa0 <-> veth_ipa1),
    2. attaches a pipeline's XDP dispatcher to veth_ipa1,
    3. floods veth_ipa0 with in-kernel pktgen at max rate,
    4. reads the pipeline's own pkt_stats counters before/after,
  so the measured pps is the rate the program ACTUALLY sustains under load,
  including softirq/NAPI/RX-path overhead pktgen drives through the veth.

Honest limits (state these in the thesis):
  - veth is a VIRTUAL link: no physical NIC, no DMA, no driver -- still
    software, NOT line-rate on real hardware. Absolute pps is optimistic vs
    a physical 10/100G NIC.
  - pktgen and the XDP program share the host CPUs, so they compete; the
    number is a lower bound on the program's own capacity.
  - RELATIVE comparison across P1/P2/P3 is valid (same rig, same generator),
    which is what the design-space trade-off needs. Report it alongside the
    BPF_PROG_TEST_RUN per-packet cost, not instead of it.

Needs Linux + BCC + root + the pktgen module (modprobe pktgen). pktgen fills
the UDP payload with zero bytes, so the IPA model_id (first payload byte) is
0 -- register model_id 0 (the default here). If your pktgen build does not
zero-fill, pass --model-id to match its pattern's first byte.

Usage:
    sudo modprobe pktgen
    sudo python3 shared/test/bench_veth_pps.py                 # all 3 pipelines
    sudo python3 shared/test/bench_veth_pps.py --method hardcoded --count 20000000
    sudo python3 shared/test/bench_veth_pps.py --mode skb      # force SKB (generic) XDP
"""
import argparse
import os
import subprocess
import sys
import time
import ctypes as ct

_TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _dir in (SHARED_DIR, _TEST_DIR):
    if _dir not in sys.path:
        sys.path.insert(0, _dir)
os.chdir(SHARED_DIR)

VETH_SRC = "veth_ipa0"   # pktgen transmits here
VETH_DST = "veth_ipa1"   # XDP program attached here (RX side)

# XDP attach flags
XDP_FLAGS_DRV_MODE = 4   # native (driver) -- faster, needs veth XDP support
XDP_FLAGS_SKB_MODE = 2   # generic/SKB    -- always works, slower

PKTGEN_CTRL = "/proc/net/pktgen/pgctrl"
PKTGEN_THREAD0 = "/proc/net/pktgen/kpktgend_0"


def _sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _write(path, line):
    with open(path, "w") as f:
        f.write(line + "\n")


def veth_up():
    _sh(f"ip link del {VETH_SRC}", check=False)   # clean any stale pair
    _sh(f"ip link add {VETH_SRC} type veth peer name {VETH_DST}")
    _sh(f"ip link set {VETH_SRC} up")
    _sh(f"ip link set {VETH_DST} up")


def veth_down():
    _sh(f"ip link del {VETH_SRC}", check=False)


def iface_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()


def pktgen_available():
    return os.path.exists(PKTGEN_CTRL)


def pktgen_setup(dst_mac, count, pkt_size, model_id):
    """Configure pktgen on VETH_SRC: UDP dport 9999 so the dispatcher accepts
    the frame; payload is pktgen's default fill (zero on most builds -> IPA
    model_id 0)."""
    _write(PKTGEN_THREAD0, "rem_device_all")
    _write(PKTGEN_THREAD0, f"add_device {VETH_SRC}")
    dev = f"/proc/net/pktgen/{VETH_SRC}"
    _write(dev, f"count {count}")
    _write(dev, "clone_skb 0")
    _write(dev, f"pkt_size {pkt_size}")
    _write(dev, "delay 0")
    _write(dev, f"dst_mac {dst_mac}")
    _write(dev, "dst 10.0.0.2")
    _write(dev, "udp_dst_min 9999")
    _write(dev, "udp_dst_max 9999")
    _write(dev, "udp_src_min 12345")
    _write(dev, "udp_src_max 12345")


def pktgen_run():
    """Blocking: fires all configured packets. Returns wall seconds."""
    t0 = time.perf_counter()
    _write(PKTGEN_CTRL, "start")
    return time.perf_counter() - t0


def _pkt_stats_sum(setup):
    ps = setup["pkt_stats"]
    total = 0
    for i in range(3):
        try:
            total += int(ps[ct.c_int(i)].value)
        except Exception:
            pass
    return total


def bench_one(name, setup_fn, model_path, model_id, count, pkt_size, mode):
    from bcc import BPF
    setup = setup_fn(model_id, model_path)
    b, disp = setup["b"], setup["disp"]

    flags = XDP_FLAGS_SKB_MODE if mode == "skb" else XDP_FLAGS_DRV_MODE
    attached_mode = mode
    try:
        b.attach_xdp(VETH_DST, disp, flags=flags)
    except Exception as e:
        if mode != "skb":
            print(f"  [{name}] native XDP attach failed ({e}); falling back to SKB")
            flags = XDP_FLAGS_SKB_MODE
            attached_mode = "skb"
            b.attach_xdp(VETH_DST, disp, flags=flags)
        else:
            raise

    dst_mac = iface_mac(VETH_DST)
    pktgen_setup(dst_mac, count, pkt_size, model_id)

    before = _pkt_stats_sum(setup)
    wall = pktgen_run()
    after = _pkt_stats_sum(setup)

    b.remove_xdp(VETH_DST, flags=flags)

    processed = after - before
    pps = processed / wall if wall > 0 else 0.0
    # per-program xlated instruction count (same as the other bench)
    from verify_prog_run import prog_insn_count
    insn = 0
    for pfd in setup.get("progs", {}).values():
        ic, _ = prog_insn_count(pfd)
        insn += ic or 0
    return {
        "name": name, "mode": attached_mode, "pps": pps,
        "processed": processed, "sent": count, "wall": wall, "insn": insn,
    }


def main():
    p = argparse.ArgumentParser(description="Real-packet pps of the 3 IPA/eBPF pipelines via veth+pktgen")
    p.add_argument("--method", choices=["hardcoded", "template", "modular", "all"], default="all")
    p.add_argument("--model", default=os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt"))
    p.add_argument("--model-id", type=int, default=0,
                   help="IPA model_id; must match pktgen's first payload byte (default 0 = zero-fill)")
    p.add_argument("--count", type=int, default=10_000_000, help="packets to send per pipeline")
    p.add_argument("--pkt-size", type=int, default=64, help="frame bytes (>=63 to hold eth+ip+udp+ipa_hdr)")
    p.add_argument("--mode", choices=["native", "skb"], default="native",
                   help="XDP attach mode on veth (native falls back to skb if unsupported)")
    args = p.parse_args()

    if not sys.platform.startswith("linux"):
        print("[bench] Needs Linux + BCC + root + pktgen. Run on the Linux host / Kathara.")
        sys.exit(1)
    if os.geteuid() != 0:
        print("[bench] Needs root (veth create + XDP attach + pktgen).")
        sys.exit(1)
    if not pktgen_available():
        print("[bench] pktgen not loaded. Run:  sudo modprobe pktgen")
        sys.exit(1)

    from verify_prog_run import setup_hardcoded, setup_template, setup_modular
    methods = {
        "hardcoded": setup_hardcoded,
        "template":  setup_template,
        "modular":   setup_modular,
    }
    chosen = list(methods.items()) if args.method == "all" else [(args.method, methods[args.method])]

    print(f"[bench] veth {VETH_SRC}<->{VETH_DST} | model={os.path.basename(args.model)} "
          f"| count={args.count} | pkt_size={args.pkt_size} | mode={args.mode}")
    print(f"[bench] measuring pps the XDP program actually processes under pktgen flood")
    print()

    rows = []
    veth_up()
    try:
        for name, fn in chosen:
            print(f"[bench] running {name} ...")
            try:
                rows.append(bench_one(name, fn, args.model, args.model_id,
                                      args.count, args.pkt_size, args.mode))
            except Exception as e:
                print(f"  [{name}] FAILED: {e}")
    finally:
        veth_down()

    if not rows:
        sys.exit(1)

    print()
    print("=" * 78)
    print(" Real-packet throughput via veth + pktgen (XDP hook exercised)")
    print("=" * 78)
    print(f"  {'pipeline':<12}{'mode':>8}{'xlated insn':>14}{'processed':>14}{'wall (s)':>12}{'Mpps':>12}")
    print("  " + "-" * 72)
    for r in rows:
        print(f"  {r['name']:<12}{r['mode']:>8}{r['insn']:>14}{r['processed']:>14}"
              f"{r['wall']:>12.3f}{r['pps']/1e6:>12.3f}")
    print("  " + "-" * 72)
    print()
    print("  NOTE: veth is virtual (no physical NIC/DMA) -- absolute Mpps is software,")
    print("  not hardware line-rate. RELATIVE P1/P2/P3 comparison is valid (same rig).")
    print("  Pair with verify_prog_run.py's per-packet cost (instructions, latency).")
    if len(rows) > 1 and rows[0]["pps"] > 0:
        base = rows[0]
        for r in rows[1:]:
            if r["pps"] > 0:
                print(f"  {base['name']} sustains ~{base['pps']/r['pps']:.1f}x the pps of {r['name']}.")


if __name__ == "__main__":
    main()
