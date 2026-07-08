"""
pipeline_benchmark.py  (design-space-docs branch)
==================================================
Comparative benchmark for Pipeline 2 (Arch Template) and Pipeline 3 (Modular).
Pipeline 1 (Hardcoded) is shown in the summary table as a static reference
baseline (no live run: it lives in the main branch).

Measures the experimental metrics from docs/design-space.md:
  Datapath:   throughput (Mpps), CPU%, eBPF instruction count
  Control:    model update latency per pipeline

Combined compilation strategy for Pipeline 2:
  We prepend '#define IPA_ARCH_COMBINED 1' to EBPF_ARCH_65_4_4_7 before
  concatenating it with EBPF_TEMPLATE_ARCH_DISPATCHER.  The #ifndef guard
  in EBPF_ARCH_65_4_4_7 skips the shared struct/map declarations, leaving
  only the arch-specific #defines and the int arch_65_4_4_7() function.
  This gives BCC a single compilation unit -> single arch_weights map
  instance -> load_arch_weights works without KeyError.
"""

import argparse
import json
import os
import sys
import time
import subprocess
import ctypes
import socket
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from bcc import BPF
except ImportError:
    print("ERROR: BCC not found. Install: apt-get install python3-bpfcc")
    sys.exit(1)

from ebpf_template_arch import (
    EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_65_4_4_7,
    load_arch_weights,
)
from ebpf_modular import (
    EBPF_MODULAR_FULL, load_modular_weights,
)
from common import (
    INGRESS_IFACE, EGRESS_IFACE, OFFSET,
    SRC_MAC, DST_MAC,
)

# ---------------------------------------------------------------------------
# Pipeline 2 combined source
# Prepend the guard define so EBPF_ARCH_65_4_4_7's #ifndef block is skipped.
# ---------------------------------------------------------------------------
EBPF_TEMPLATE_COMBINED = (
    EBPF_TEMPLATE_ARCH_DISPATCHER
    + "\n#define IPA_ARCH_COMBINED 1\n"
    + EBPF_ARCH_65_4_4_7
)


def _get_ebpf_insn_count(prog_name: str) -> int:
    try:
        out = subprocess.check_output(
            ["bpftool", "prog", "show", "name", prog_name, "--json"],
            stderr=subprocess.DEVNULL)
        data = json.loads(out)
        if data and "insns_cnt" in data[0]:
            return data[0]["insns_cnt"]
    except Exception:
        pass
    return -1


def _read_pkt_stats(bpf_obj, map_name: str) -> dict:
    s = {"hit": 0, "miss": 0, "fake": 0}
    try:
        m = bpf_obj[map_name]
        s["hit"]  = int(m[0].value)
        s["miss"] = int(m[1].value)
        s["fake"] = int(m[2].value)
    except Exception:
        pass
    return s


def _populate_fwd(bpf_obj, fwd_map: str, vk_map: str,
                  cp_weights: list, scale: int):
    fwd    = bpf_obj[fwd_map]
    vk     = bpf_obj[vk_map]
    action = fwd.Leaf()
    action.ifindex = socket.if_nametoindex(EGRESS_IFACE)
    for i in range(6):
        action.src_mac[i] = SRC_MAC[i]
        action.dst_mac[i] = DST_MAC[i]

    if_idx = socket.if_nametoindex(INGRESS_IFACE)
    for ttl in range(30, 65):
        iv  = [42, ttl, if_idx, 65]
        raw = sum(v * ctypes.c_int8(int(w)).value
                  for v, w in zip(iv, cp_weights))
        key = (raw + OFFSET * scale) // scale
        fwd[ctypes.c_ulonglong(key)] = action
        vk[ctypes.c_uint8(ttl)]      = ctypes.c_ulonglong(key)


def benchmark_pipeline(
    pipeline_id: int, iface: str, duration: int,
    weights: list, cp_weights_4: list, scale: int
) -> dict:
    results = {"pipeline": pipeline_id, "duration_s": duration, "iface": iface}
    print(f"\n=== Benchmarking Pipeline {pipeline_id} ===")

    if pipeline_id == 2:
        entry_fn   = "ipa_switch_template"
        arch_fn    = "arch_65_4_4_7"
        stats_map  = "pkt_stats_t2"
        fwd_map    = "fwd_table_t2"
        vk_map     = "valid_keys_t2"

        t0_load = time.perf_counter()
        b = BPF(text=EBPF_TEMPLATE_COMBINED)
        results["load_time_s"] = round(time.perf_counter() - t0_load, 4)
        print(f"  Load time: {results['load_time_s']*1000:.1f} ms")

        # Single combined object -> single arch_weights map -> no KeyError
        load_arch_weights(b, weights, model_id=42, scale=scale)

        # Wire arch function into the tail-call map
        fn_arch = b.load_func(arch_fn, BPF.XDP)
        b["arch_progs"][ctypes.c_int(0)] = ctypes.c_int(fn_arch.fd)

    elif pipeline_id == 3:
        entry_fn   = "modular_dispatcher"
        stats_map  = "pkt_stats_t3"
        fwd_map    = "fwd_table_t3"
        vk_map     = "valid_keys_t3"

        t0_load = time.perf_counter()
        b = BPF(text=EBPF_MODULAR_FULL)
        results["load_time_s"] = round(time.perf_counter() - t0_load, 4)
        print(f"  Load time: {results['load_time_s']*1000:.1f} ms")

        load_modular_weights(b, weights, model_id=42, scale=scale)
        fn_l0 = b.load_func("layer_65_4",       BPF.XDP)
        fn_l1 = b.load_func("layer_4_4",        BPF.XDP)
        fn_l2 = b.load_func("layer_4_7_argmax", BPF.XDP)
        chain = b["layer_chain"]
        chain[ctypes.c_int(0)] = ctypes.c_int(fn_l0.fd)
        chain[ctypes.c_int(1)] = ctypes.c_int(fn_l1.fd)
        chain[ctypes.c_int(2)] = ctypes.c_int(fn_l2.fd)

    else:
        print(f"  Unknown pipeline id {pipeline_id}, skipping.")
        return results

    _populate_fwd(b, fwd_map, vk_map, cp_weights_4, scale)

    try:
        fn = b.load_func(entry_fn, BPF.XDP)
        b.attach_xdp(iface, fn, 0)
        results["xdp_attached"] = True
    except Exception as e:
        print(f"  WARNING: XDP attach failed ({e}). Dry-run mode.")
        results["xdp_attached"] = False
        results["note"] = str(e)
        del b
        return results

    insns = _get_ebpf_insn_count(entry_fn)
    results["ebpf_insn_count"] = insns
    if insns > 0:
        print(f"  eBPF instructions ({entry_fn}): {insns}")

    s0      = _read_pkt_stats(b, stats_map)
    t_start = time.perf_counter()
    cpu0    = time.process_time()
    print(f"  Running for {duration}s...")
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    elapsed     = time.perf_counter() - t_start
    cpu_elapsed = time.process_time() - cpu0
    s1 = _read_pkt_stats(b, stats_map)

    total   = (
        (s1["hit"] + s1["miss"] + s1["fake"])
        - (s0["hit"] + s0["miss"] + s0["fake"])
    )
    tp_mpps = (total / elapsed) / 1e6 if elapsed > 0 else 0
    cpu_pct = (cpu_elapsed / elapsed) * 100 if elapsed > 0 else 0

    results["throughput_mpps"] = round(tp_mpps, 4)
    results["cpu_pct"]         = round(cpu_pct, 2)
    results["pkt_stats"]       = {
        "hit":  s1["hit"]  - s0["hit"],
        "miss": s1["miss"] - s0["miss"],
        "fake": s1["fake"] - s0["fake"],
    }
    print(f"  Throughput: {tp_mpps:.4f} Mpps")
    print(f"  CPU:        {cpu_pct:.1f}%")

    # Measure model update latency (map write only, no recompile)
    t_upd = time.perf_counter()
    if pipeline_id == 2:
        load_arch_weights(b, weights, model_id=42, scale=scale)
    else:
        load_modular_weights(b, weights, model_id=42, scale=scale)
    results["model_update_latency_s"] = round(
        time.perf_counter() - t_upd, 6)
    print(f"  Model update latency: "
          f"{results['model_update_latency_s']*1000:.2f} ms")

    b.remove_xdp(iface, 0)
    del b
    return results


DESIGN_SPACE_TABLE = """
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551 Pipeline             \u2551 eBPF code    \u2551 Weights  \u2551 Tail calls\u2551 Interm. state     \u2551 Flexibility \u2551 Exp. performance  \u2551
\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u256c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u256c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u256c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u256c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u256c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u256c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
\u2551 1. Hardcoded         \u2551 1/model      \u2551 hardcoded\u2551 1         \u2551 none              \u2551 low         \u2551 maximum  [ref]    \u2551
\u2551 2. Arch template     \u2551 1/arch shape \u2551 BPF map  \u2551 1         \u2551 local frame       \u2551 medium      \u2551 high/intermediate \u2551
\u2551 3. Modular pipeline  \u2551 1/layer      \u2551 BPF map  \u2551 N(layers) \u2551 scratch PERCPU    \u2551 maximum     \u2551 lower             \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2569\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2569\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2569\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2569\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2569\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2569\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
"""


def print_summary(results: list) -> None:
    print("\n" + "=" * 70)
    print("IPA/eBPF Design Space \u2014 Benchmark Results")
    print("=" * 70)
    print(DESIGN_SPACE_TABLE)
    print(f"{'Pipeline':<25} {'Throughput (Mpps)':<20} "
          f"{'CPU%':<8} {'Update (ms)':<14} {'eBPF insns'}")
    print("-" * 78)
    print(f"{'1. Hardcoded [ref]':<25} {'N/A (main branch)':<20} "
          f"{'N/A':<8} {'recompile':<14} {'N/A'}")
    for r in results:
        p      = r.get("pipeline", "?")
        tp     = r.get("throughput_mpps", "N/A")
        cpu    = r.get("cpu_pct", "N/A")
        upd    = r.get("model_update_latency_s")
        upd_ms = f"{upd*1000:.2f}" if upd is not None else "N/A"
        insns  = r.get("ebpf_insn_count", "N/A")
        name   = {2: "2. Arch template",
                  3: "3. Modular pipeline"}.get(p, f"P{p}")
        print(f"{name:<25} {str(tp):<20} {str(cpu):<8} "
              f"{upd_ms:<14} {insns}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark Pipeline 2 (Arch Template) "
                    "and Pipeline 3 (Modular).")
    parser.add_argument(
        "--iface", default=INGRESS_IFACE,
        help=f"XDP interface (default: {INGRESS_IFACE})")
    parser.add_argument(
        "--duration", type=int, default=10,
        help="Measurement window in seconds (default: 10)")
    parser.add_argument(
        "--pipeline", default="all",
        help="2, 3, or all (default: all)")
    parser.add_argument(
        "--model",
        default="frr_germany50_5_model_4x2.pt",
        help="Path to .pt model file (requires torch)")
    parser.add_argument(
        "--weights-json", default=None,
        help="Path to precomputed weights.json (skips torch/model load)")
    parser.add_argument("--output", default="benchmark_results.json")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: must run as root for XDP.")
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # Weight loading
    # ------------------------------------------------------------------ #
    if args.weights_json:
        print(f"Loading precomputed weights from {args.weights_json} ...")
        with open(args.weights_json) as f:
            weights_data = json.load(f)
        if isinstance(weights_data, dict):
            floats = weights_data["weights"]
            scale  = weights_data["scale_factor"]
            weights = [
                max(-128, min(127, int(round(wf * scale))))
                for wf in floats
            ]
            cp4 = floats[:4]
        else:
            scale   = 128
            weights = weights_data
            cp4     = [w / 127.0 for w in weights[:4]]
        print(f"  {len(weights)} int8 weights loaded.")
    else:
        import warnings
        try:
            import torch
            torch_ok = True
        except ImportError:
            torch_ok = False
            warnings.warn(
                "torch not available — auto-loading from /shared/weights.json",
                RuntimeWarning)

        if torch_ok:
            from extract_weights import extract_weights_int8
            print(f"Loading weights from {args.model} (torch)...")
            weights = extract_weights_int8(args.model)
            try:
                from FRR_model import FastRerouteMLP
                m = FastRerouteMLP(n_interfaces=6, n_nodes=52, hidden_dim=4)
                m.load_state_dict(torch.load(args.model, map_location="cpu"))
                floats  = [w for p in m.parameters()
                           for w in p.data.view(-1).tolist()]
                max_abs = max(abs(w) for w in floats)
                scale   = int(127 / max_abs)
                cp4     = floats[:4]
            except Exception:
                scale = 128
                cp4   = [w / 127.0 for w in weights[:4]]
        else:
            # Auto-fallback: try /shared/weights.json then local weights.json
            for candidate in ["/shared/weights.json",
                               str(Path(__file__).parent / "weights.json")]:
                if os.path.exists(candidate):
                    with open(candidate) as f:
                        wdata = json.load(f)
                    if isinstance(wdata, dict):
                        floats  = wdata["weights"]
                        scale   = wdata["scale_factor"]
                        weights = [
                            max(-128, min(127, int(round(wf * scale))))
                            for wf in floats
                        ]
                        cp4 = floats[:4]
                    else:
                        scale   = 128
                        weights = wdata
                        cp4     = [w / 127.0 for w in weights[:4]]
                    print(f"  {len(weights)} int8 weights from {candidate}")
                    break
            else:
                print("ERROR: no weights.json found. "
                      "Use --weights-json <path>.")
                sys.exit(1)

    pipelines = (
        [2, 3]
        if args.pipeline == "all"
        else [int(x) for x in args.pipeline.split(",")]
    )

    all_results = []
    for pid in pipelines:
        r = benchmark_pipeline(
            pid, args.iface, args.duration, weights, cp4, scale)
        all_results.append(r)

    with open(args.output, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to {args.output}")
    print_summary(all_results)

    summary_path = args.output.replace(".json", "_summary.txt")
    with open(summary_path, "w") as f:
        f.write(DESIGN_SPACE_TABLE)
        for r in all_results:
            f.write(json.dumps(r, indent=2) + "\n")
    print(f"Summary saved to {summary_path}")


if __name__ == "__main__":
    main()
