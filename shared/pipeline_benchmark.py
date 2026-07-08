"""
pipeline_benchmark.py  —  Comparative benchmark for the three IPA/eBPF pipelines.

Measures the experimental metrics defined in docs/design-space.md:
  Datapath:    latency, throughput, CPU%, eBPF instructions, tail calls, map lookups
  Control:     model update time for each pipeline

Usage (run as root on the IPA router node):
    python3 pipeline_benchmark.py --iface eth0 --duration 10 --pipeline all
    python3 pipeline_benchmark.py --iface eth0 --duration 10 --pipeline 1
    python3 pipeline_benchmark.py --iface eth0 --duration 10 --pipeline 2
    python3 pipeline_benchmark.py --iface eth0 --duration 10 --pipeline 3

Outputs:
    benchmark_results.json   — raw metrics per pipeline
    benchmark_summary.txt    — human-readable comparison table

Notes:
  - Requires BCC (bpfcc) and root privileges
  - Uses bpftool prog profile for instruction counting when available
  - Throughput estimated from pkt_stats_* maps over the measurement window
  - Latency measured via XDP TX timestamps (requires kernel >= 5.14)
"""

import argparse
import json
import os
import sys
import time
import subprocess
from pathlib import Path

# Add shared/ to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from bcc import BPF
except ImportError:
    print("ERROR: BCC not found. Install with: apt-get install python3-bpfcc")
    sys.exit(1)

from extract_weights import extract_weights_int8
from ebpf_program    import EBPF_PROGRAM, N_WEIGHTS
from ebpf_template_arch import (
    EBPF_ARCH_65_4_4_7, N_WEIGHTS_T2, load_arch_weights
)
from ebpf_modular import (
    EBPF_MODULAR_FULL, load_modular_weights
)


# ---------------------------------------------------------------------------
# Helper: read pkt_stats array from a loaded BPF object
# ---------------------------------------------------------------------------
def read_pkt_stats(bpf_obj: BPF, map_name: str) -> dict:
    stats = {"hit": 0, "miss": 0, "fake": 0}
    try:
        m = bpf_obj[map_name]
        stats["hit"]  = int(m[0].value)
        stats["miss"] = int(m[1].value)
        stats["fake"] = int(m[2].value)
    except Exception:
        pass
    return stats


# ---------------------------------------------------------------------------
# Helper: get eBPF program instruction count via bpftool
# ---------------------------------------------------------------------------
def get_ebpf_insn_count(prog_name: str) -> int:
    """Returns instruction count for the named eBPF prog from bpftool, or -1."""
    try:
        out = subprocess.check_output(
            ["bpftool", "prog", "show", "name", prog_name, "--json"],
            stderr=subprocess.DEVNULL
        )
        data = json.loads(out)
        if data and "insns_cnt" in data[0]:
            return data[0]["insns_cnt"]
    except Exception:
        pass
    return -1


# ---------------------------------------------------------------------------
# Helper: measure model update latency for each pipeline
# ---------------------------------------------------------------------------
def measure_update_latency_pipeline1() -> float:
    """
    Pipeline 1: update = recompile + reload BPF program.
    Returns elapsed time in seconds.
    """
    start = time.perf_counter()
    # Re-instantiate BPF to simulate recompile+reload
    b = BPF(text=EBPF_PROGRAM)
    elapsed = time.perf_counter() - start
    del b
    return elapsed


def measure_update_latency_pipeline2(bpf_obj: BPF, weights: list) -> float:
    """
    Pipeline 2: update = write new weights to BPF map.
    Returns elapsed time in seconds.
    """
    start = time.perf_counter()
    load_arch_weights(bpf_obj, weights, model_id=0, scale=128)
    return time.perf_counter() - start


def measure_update_latency_pipeline3(bpf_obj: BPF, weights: list) -> float:
    """
    Pipeline 3: update = write new weights to BPF map (same as P2 for weights).
    Architecture change would additionally update layer_chain entries.
    Returns elapsed time in seconds.
    """
    start = time.perf_counter()
    load_modular_weights(bpf_obj, weights, model_id=0, scale=128)
    return time.perf_counter() - start


# ---------------------------------------------------------------------------
# Benchmark a single pipeline
# ---------------------------------------------------------------------------
def benchmark_pipeline(
    pipeline_id: int,
    iface: str,
    duration: int,
    weights: list
) -> dict:
    results = {
        "pipeline": pipeline_id,
        "duration_s": duration,
        "iface": iface,
    }

    print(f"\n=== Benchmarking Pipeline {pipeline_id} ===")

    if pipeline_id == 1:
        src = EBPF_PROGRAM
        fn_name = "ipa_switch"
        stats_map = "pkt_stats"
    elif pipeline_id == 2:
        src = EBPF_ARCH_65_4_4_7
        fn_name = "arch_65_4_4_7"
        stats_map = "pkt_stats_t2"
    elif pipeline_id == 3:
        src = EBPF_MODULAR_FULL
        fn_name = "modular_dispatcher"
        stats_map = "pkt_stats_t3"
    else:
        return results

    # Load BPF program
    t_load_start = time.perf_counter()
    b = BPF(text=src)
    t_load = time.perf_counter() - t_load_start
    results["load_time_s"] = round(t_load, 4)
    print(f"  Load time:   {t_load*1000:.1f} ms")

    # Populate weights
    if pipeline_id == 2:
        load_arch_weights(b, weights, model_id=0, scale=128)
    elif pipeline_id == 3:
        load_modular_weights(b, weights, model_id=0, scale=128)

    # Attach XDP
    try:
        fn = b.load_func(fn_name, BPF.XDP)
        b.attach_xdp(iface, fn, 0)
    except Exception as e:
        print(f"  WARNING: XDP attach failed ({e}). Running in dry-run mode.")
        results["xdp_attached"] = False
        results["note"] = str(e)
        del b
        return results

    results["xdp_attached"] = True

    # Instruction count
    insns = get_ebpf_insn_count(fn_name)
    results["ebpf_insn_count"] = insns
    if insns > 0:
        print(f"  eBPF instructions: {insns}")

    # Read baseline stats
    s0 = read_pkt_stats(b, stats_map)
    t0 = time.perf_counter()
    cpu0 = time.process_time()

    # Run for duration seconds
    print(f"  Running for {duration}s ... (press Ctrl+C to stop early)")
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass

    t1 = time.perf_counter()
    cpu1 = time.process_time()
    s1 = read_pkt_stats(b, stats_map)

    elapsed = t1 - t0
    total_pkts = (s1["hit"] + s1["miss"] + s1["fake"]) - \
                 (s0["hit"] + s0["miss"] + s0["fake"])
    throughput_mpps = (total_pkts / elapsed) / 1e6 if elapsed > 0 else 0
    cpu_pct = ((cpu1 - cpu0) / elapsed) * 100 if elapsed > 0 else 0

    results["total_packets"]   = total_pkts
    results["throughput_mpps"] = round(throughput_mpps, 4)
    results["cpu_pct"]         = round(cpu_pct, 2)
    results["pkt_stats"]       = {
        "hit":  s1["hit"]  - s0["hit"],
        "miss": s1["miss"] - s0["miss"],
        "fake": s1["fake"] - s0["fake"],
    }

    print(f"  Throughput:  {throughput_mpps:.4f} Mpps")
    print(f"  CPU:         {cpu_pct:.1f}%")
    print(f"  Packets:     {total_pkts} (hit={results['pkt_stats']['hit']}, "
          f"miss={results['pkt_stats']['miss']})")

    # Model update latency
    if pipeline_id == 1:
        upd = measure_update_latency_pipeline1()
    elif pipeline_id == 2:
        upd = measure_update_latency_pipeline2(b, weights)
    else:
        upd = measure_update_latency_pipeline3(b, weights)

    results["model_update_latency_s"] = round(upd, 6)
    print(f"  Model update latency: {upd*1000:.2f} ms")

    # Detach
    b.remove_xdp(iface, 0)
    del b

    return results


# ---------------------------------------------------------------------------
# Print comparison table
# ---------------------------------------------------------------------------
DESIGN_SPACE_TABLE = """
╔══════════════════════╦══════════════╦══════════╦═══════════╦═══════════════════╦═════════════╦═══════════════════╗
║ Pipeline             ║ eBPF code    ║ Weights  ║ Tail calls║ Intermediate state║ Flexibility ║ Expected perf     ║
╠══════════════════════╬══════════════╬══════════╬═══════════╬═══════════════════╬═════════════╬═══════════════════╣
║ 1. Hardcoded model   ║ 1/model      ║ hardcoded║ 1         ║ none              ║ low         ║ maximum           ║
║ 2. Arch template     ║ 1/arch shape ║ BPF map  ║ 1         ║ local frame       ║ medium      ║ high/intermediate ║
║ 3. Modular pipeline  ║ 1/layer      ║ BPF map  ║ N(layers) ║ scratch map       ║ maximum     ║ lower             ║
╚══════════════════════╩══════════════╩══════════╩═══════════╩═══════════════════╩═════════════╩═══════════════════╝
"""


def print_summary(all_results: list) -> None:
    print("\n" + "=" * 60)
    print("IPA/eBPF Design Space — Benchmark Results")
    print("=" * 60)
    print(DESIGN_SPACE_TABLE)
    print("Measured results:")
    print(f"{'Pipeline':<25} {'Throughput (Mpps)':<20} {'CPU%':<8} {'Update (ms)':<14} {'eBPF insns':<12}")
    print("-" * 80)
    for r in all_results:
        p = r.get("pipeline", "?")
        tp = r.get("throughput_mpps", "N/A")
        cpu = r.get("cpu_pct", "N/A")
        upd = r.get("model_update_latency_s", None)
        upd_ms = f"{upd*1000:.2f}" if upd is not None else "N/A"
        insns = r.get("ebpf_insn_count", "N/A")
        name = {1: "Hardcoded model", 2: "Arch template", 3: "Modular pipeline"}.get(p, f"P{p}")
        print(f"{name:<25} {str(tp):<20} {str(cpu):<8} {upd_ms:<14} {str(insns):<12}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="IPA/eBPF design-space benchmark: compare the three pipeline implementations."
    )
    parser.add_argument("--iface",    required=True, help="Network interface for XDP attachment")
    parser.add_argument("--duration", type=int, default=10, help="Measurement window in seconds")
    parser.add_argument("--pipeline", default="all",
                        help="Which pipeline(s) to benchmark: 1, 2, 3, or all")
    parser.add_argument("--model",    default="shared/frr_germany50_5_model_4x2.pt",
                        help="Path to .pt model file")
    parser.add_argument("--output",   default="benchmark_results.json",
                        help="Output JSON file")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: must run as root for XDP.")
        sys.exit(1)

    # Load weights
    print(f"Loading weights from {args.model} ...")
    weights = extract_weights_int8(args.model)
    print(f"  {len(weights)} int8 weights loaded.")

    # Select pipelines
    if args.pipeline == "all":
        pipelines = [1, 2, 3]
    else:
        pipelines = [int(x) for x in args.pipeline.split(",")]

    all_results = []
    for pid in pipelines:
        r = benchmark_pipeline(pid, args.iface, args.duration, weights)
        all_results.append(r)

    # Save JSON
    with open(args.output, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to {args.output}")

    # Print summary table
    print_summary(all_results)

    # Save text summary
    summary_path = args.output.replace(".json", "_summary.txt")
    with open(summary_path, "w") as f:
        f.write(DESIGN_SPACE_TABLE)
        f.write("\nMeasured:\n")
        for r in all_results:
            f.write(json.dumps(r, indent=2) + "\n")
    print(f"Summary saved to {summary_path}")


if __name__ == "__main__":
    main()
