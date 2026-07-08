#!/usr/bin/env python3
"""
method4_hardcoded.py  —  Pipeline 1: Hardcoded Model

Design space position:
  Massime prestazioni, minima flessibilità.
  Ogni modello → un programma eBPF dedicato con pesi hardcoded come
  letterali signed char nel sorgente C. Inferenza completamente unrolled,
  nessuna BPF map lookup per i pesi, una sola tail call.

Usage (via switch_core.py / execute_pipeline.py):
    python3 execute_pipeline.py --method hardcoded
    python3 execute_pipeline.py --method hardcoded --model-id 0 --iface eth0

Direct run (dev/test):
    sudo python3 shared/methods/method4_hardcoded.py --iface veth0 --model-id 0
"""

import os
import sys
import time
import ctypes
import argparse

SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)
os.chdir(SHARED_DIR)

from bcc import BPF
from ebpf_program import load_and_generate
from extract_weights import extract_weights_int8


def run(
    model_id: int = 0,
    iface: str = "eth0",
    model_path: str = None,
    fwd_rules: dict = None,
) -> None:
    """
    Load Pipeline 1 (hardcoded) on `iface`.

    Args:
        model_id   : model identifier (embeds in the eBPF comment, used for
                     model_miss_events matching)
        iface      : network interface to attach XDP to
        model_path : path to .pt checkpoint; defaults to the shared one
        fwd_rules  : dict { ttl_int : (ifindex, src_mac_bytes, dst_mac_bytes) }
                     for populating fwd_table and valid_keys.  If None, maps
                     are left empty (useful for verifier-only tests).
    """
    if model_path is None:
        model_path = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")

    # ------------------------------------------------------------------
    # Step 1: generate hardcoded eBPF source from real model weights
    # ------------------------------------------------------------------
    print(f"[P1-hardcoded] Generating eBPF source from {model_path} …")
    ebpf_src, weights_int8, scale = load_and_generate(model_path, model_id)
    print(f"[P1-hardcoded] scale={scale}, weights={len(weights_int8)}, "
          f"source={len(ebpf_src)} chars")

    # ------------------------------------------------------------------
    # Step 2: compile + load via BCC (this is where the verifier runs)
    # ------------------------------------------------------------------
    print(f"[P1-hardcoded] Loading eBPF program (verifier check) …")
    b = BPF(text=ebpf_src)
    fn = b.load_func("ipa_switch", BPF.XDP)
    print(f"[P1-hardcoded] Verifier: OK — program fd={fn.fd}")

    # ------------------------------------------------------------------
    # Step 3: populate model_cache (kept for Method-4 model-miss CP logic)
    # ------------------------------------------------------------------
    class ModelData(ctypes.Structure):
        _fields_ = [
            ("weights",      ctypes.c_uint8 * 319),
            ("is_valid",     ctypes.c_uint8),
            ("scale_factor", ctypes.c_uint16),
        ]

    entry = ModelData()
    for i, w in enumerate(weights_int8[:319]):
        entry.weights[i] = ctypes.c_uint8(w & 0xFF).value
    entry.is_valid     = 1
    entry.scale_factor = scale

    b["model_cache"][ctypes.c_uint8(model_id)] = entry
    print(f"[P1-hardcoded] model_cache[{model_id}] populated (is_valid=1, scale={scale})")

    # ------------------------------------------------------------------
    # Step 4: populate forwarding maps (optional)
    # ------------------------------------------------------------------
    if fwd_rules:
        class FwdAction(ctypes.Structure):
            _fields_ = [
                ("ifindex",  ctypes.c_uint32),
                ("src_mac",  ctypes.c_uint8 * 6),
                ("dst_mac",  ctypes.c_uint8 * 6),
            ]

        for ttl, (ifindex, src_mac, dst_mac) in fwd_rules.items():
            # key derivation must match the kernel formula
            # (placeholder: use ttl as key directly for test rules)
            key = ctypes.c_uint64(int(ttl))
            act = FwdAction()
            act.ifindex = ifindex
            for i, b_ in enumerate(src_mac): act.src_mac[i] = b_
            for i, b_ in enumerate(dst_mac): act.dst_mac[i] = b_
            b["fwd_table"][key]    = act
            b["valid_keys"][ctypes.c_uint8(ttl)] = key
            print(f"[P1-hardcoded] fwd_rule: ttl={ttl} -> ifindex={ifindex}")

    # ------------------------------------------------------------------
    # Step 5: attach XDP
    # ------------------------------------------------------------------
    b.attach_xdp(iface, fn)
    print(f"[P1-hardcoded] XDP attached to {iface} — running (Ctrl-C to stop)")
    print(f"[P1-hardcoded] Pipeline 1: 1 tail call, 0 weight map lookups, ~780 insns")
    print()

    # ------------------------------------------------------------------
    # Step 6: stats loop
    # ------------------------------------------------------------------
    prev = [0, 0, 0]
    try:
        while True:
            time.sleep(1)
            stats = b["pkt_stats"]
            cur   = [stats[i].value for i in range(3)]
            delta = [cur[i] - prev[i] for i in range(3)]
            print(
                f"[P1] hit={cur[0]:>8}  miss={cur[1]:>8}  fake={cur[2]:>8}  "
                f"(Δhit={delta[0]:+5}  Δmiss={delta[1]:+5}  Δfake={delta[2]:+5})",
                end="\r",
            )
            prev = cur
    except KeyboardInterrupt:
        pass
    finally:
        b.remove_xdp(iface)
        print(f"\n[P1-hardcoded] XDP removed from {iface}")
        _print_final_stats(b)


def _print_final_stats(b):
    stats = b["pkt_stats"]
    hit, miss, fake = (stats[i].value for i in range(3))
    total = hit + miss + fake
    print()
    print("=" * 50)
    print("Pipeline 1 — Hardcoded — final stats")
    print(f"  TRUE HIT  : {hit:>10}  ({100*hit/max(total,1):.1f}%)")
    print(f"  MISS      : {miss:>10}  ({100*miss/max(total,1):.1f}%)")
    print(f"  FAKE HIT  : {fake:>10}  ({100*fake/max(total,1):.1f}%)")
    print(f"  TOTAL     : {total:>10}")
    print("=" * 50)


# ---------------------------------------------------------------------------
# Direct CLI run (for dev / verifier testing without the full switch stack)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pipeline 1: Hardcoded eBPF XDP")
    parser.add_argument("--iface",    default="eth0",   help="Network interface")
    parser.add_argument("--model-id", type=int, default=0, help="Model ID")
    parser.add_argument("--model",    default=None,     help="Path to .pt checkpoint")
    parser.add_argument("--verify-only", action="store_true",
                        help="Load+verify eBPF program but do NOT attach XDP")
    args = parser.parse_args()

    if args.verify_only:
        model_path = args.model or os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
        print(f"[verify-only] Generating source from {model_path} …")
        src, w, s = load_and_generate(model_path, args.model_id)
        print(f"[verify-only] scale={s}, weights={len(w)}, source_chars={len(src)}")
        b = BPF(text=src)
        fn = b.load_func("ipa_switch", BPF.XDP)
        print(f"[verify-only] Verifier PASSED — fd={fn.fd}")
        import subprocess, tempfile
        with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
            f.write(src)
            tmp = f.name
        result = subprocess.run(
            ["clang", "-O2", "-target", "bpf", "-I/usr/include",
             "-c", tmp, "-o", tmp.replace(".c", ".o")],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            out = subprocess.run(
                ["llvm-objdump", "-d", tmp.replace(".c", ".o")],
                capture_output=True, text=True
            )
            insns = sum(1 for l in out.stdout.splitlines() if l.strip() and l[0] != '<')
            print(f"[verify-only] Compiled OK — ~{insns} objdump lines")
        else:
            print(f"[verify-only] clang error: {result.stderr[:400]}")
        sys.exit(0)

    run(
        model_id=args.model_id,
        iface=args.iface,
        model_path=args.model,
    )
