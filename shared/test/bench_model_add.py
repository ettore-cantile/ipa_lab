#!/usr/bin/env python3
"""
bench_model_add.py  --  measures the "add a model at runtime" cost for the
three IPA/eBPF design-space pipelines. This is the control-plane flexibility
metric the design-space doc asks for, next to the datapath metrics already
covered by verify_prog_run.py / test_suite.py --only kernel:

    hardcoded : model update = regenerate C source + BPF compile + load_func
                (no incremental path exists -- every "add" is a full reload)
    template  : one-time program compile+load, then model update =
                load_arch_weights() -- bpf_map_update_elem writes only
    modular   : one-time program compile+load, then model update =
                load_modular_weights() -- bpf_map_update_elem writes only

Needs Linux + BCC + root (loads real XDP programs, never attaches them).

Usage:
    sudo python3 shared/bench_model_add.py
    sudo python3 shared/bench_model_add.py --n-models 3 --model /shared/frr_germany50_5_model_4x2.pt
    kathara exec frankfurt -- python3 /shared/bench_model_add.py
"""
import os
import sys
import time
import argparse
import statistics
import ctypes as ct

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)
os.chdir(SHARED_DIR)

MODEL_PT = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")


def _stats(times):
    times_ms = [t * 1000.0 for t in times]
    return {
        "n": len(times_ms),
        "mean_ms": statistics.mean(times_ms),
        "median_ms": statistics.median(times_ms),
        "min_ms": min(times_ms),
        "max_ms": max(times_ms),
        "stdev_ms": statistics.pstdev(times_ms) if len(times_ms) > 1 else 0.0,
    }


def bench_hardcoded(weights, scale, n_models):
    """Every model add = full C source regen + BPF compile + load_func.
    Pipeline 1 has no cheaper path by design (weights are literals)."""
    from bcc import BPF
    from ebpf_program import generate_ebpf_hardcoded

    times = []
    for i in range(n_models):
        t0 = time.perf_counter()
        src = generate_ebpf_hardcoded(weights, scale, model_id=i)
        b = BPF(text=src)
        b.load_func("ipa_switch", BPF.XDP)
        times.append(time.perf_counter() - t0)
    return None, times  # no separable one-time setup


def bench_template(weights, scale, n_models):
    """One-time compile+load, then N incremental load_arch_weights() calls."""
    from bcc import BPF
    from ebpf_template_arch import (
        EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_65_4_4_7,
        load_arch_weights, N_WEIGHTS_T2,
    )

    max_models = 1024 // N_WEIGHTS_T2  # MAX_WEIGHT_ENTRIES bound
    if n_models > max_models:
        print(f"[bench] template: capping n_models {n_models} -> {max_models} "
              f"(MAX_WEIGHT_ENTRIES=1024 / N_WEIGHTS_T2={N_WEIGHTS_T2})")
        n_models = max_models

    src = "#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_65_4_4_7
    t0 = time.perf_counter()
    b = BPF(text=src)
    b.load_func("ipa_switch_template", BPF.XDP)
    leaf_fn = b.load_func("arch_65_4_4_7", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
    setup_s = time.perf_counter() - t0

    times = []
    for i in range(n_models):
        t0 = time.perf_counter()
        load_arch_weights(b, weights, model_id=i, scale=scale,
                          weight_offset=i * N_WEIGHTS_T2)
        times.append(time.perf_counter() - t0)
    return setup_s, times


def bench_modular(weights, scale, n_models):
    """One-time compile+load, then N incremental load_modular_weights() calls."""
    from bcc import BPF
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights

    model_size = len(weights)
    max_models = 2048 // model_size  # MAX_LAYER_WEIGHT_ENTRIES bound
    if n_models > max_models:
        print(f"[bench] modular: capping n_models {n_models} -> {max_models} "
              f"(MAX_LAYER_WEIGHT_ENTRIES=2048 / model_size={model_size})")
        n_models = max_models

    t0 = time.perf_counter()
    b = BPF(text=EBPF_MODULAR_FULL)
    disp_fn = b.load_func("modular_dispatcher", BPF.XDP)
    lf0 = b.load_func("layer_65_4", BPF.XDP)
    lf1 = b.load_func("layer_4_4", BPF.XDP)
    lf2 = b.load_func("layer_4_7_argmax", BPF.XDP)
    b["layer_chain"][ct.c_int(0)] = ct.c_int(lf0.fd)
    b["layer_chain"][ct.c_int(1)] = ct.c_int(lf1.fd)
    b["layer_chain"][ct.c_int(2)] = ct.c_int(lf2.fd)
    setup_s = time.perf_counter() - t0

    times = []
    for i in range(n_models):
        t0 = time.perf_counter()
        load_modular_weights(b, weights, model_id=i, scale=scale,
                             base_offset=i * model_size)
        times.append(time.perf_counter() - t0)
    return setup_s, times


def main():
    parser = argparse.ArgumentParser(description="Bench: cost of adding a model to each IPA/eBPF pipeline")
    parser.add_argument("--model", default=MODEL_PT, help="Path to .pt checkpoint")
    parser.add_argument("--n-models", type=int, default=3,
                        help="How many successive model-add operations to time per pipeline (default 3)")
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        print(f"[bench] Needs Linux + BCC + root. Run inside Kathara, e.g.:")
        print(f"  kathara exec frankfurt -- python3 /shared/bench_model_add.py")
        sys.exit(1)

    from verify_prog_run import load_weights
    weights, scale = load_weights(args.model)
    print(f"[bench] weights={len(weights)} scale={scale} n_models={args.n_models}")
    print()

    results = {}
    for name, fn in [("hardcoded", bench_hardcoded),
                      ("template",  bench_template),
                      ("modular",   bench_modular)]:
        print(f"[bench] running {name} ...")
        setup_s, times = fn(weights, scale, args.n_models)
        results[name] = (setup_s, times)

    print()
    print("=" * 78)
    print(" Model-add cost per pipeline (aggiornamento modello a runtime)")
    print("=" * 78)
    print(f"  {'pipeline':<12}{'one-time setup (ms)':>22}{'mean add (ms)':>18}"
          f"{'min':>10}{'max':>10}{'stdev':>10}")
    print("  " + "-" * 74)
    for name in ("hardcoded", "template", "modular"):
        setup_s, times = results[name]
        s = _stats(times)
        setup_str = f"{setup_s*1000:.3f}" if setup_s is not None else "n/a (baked into add)"
        print(f"  {name:<12}{setup_str:>22}{s['mean_ms']:>18.3f}"
              f"{s['min_ms']:>10.3f}{s['max_ms']:>10.3f}{s['stdev_ms']:>10.3f}")
    print("  " + "-" * 74)
    print()
    print("  hardcoded : no incremental path -- 'add' == full BPF compile+load_func")
    print("              every time (weights are hardcoded C literals).")
    print("  template  : one-time program load, then 'add' == load_arch_weights()")
    print("              (bpf_map_update_elem writes only, program stays loaded).")
    print("  modular   : one-time program load, then 'add' == load_modular_weights()")
    print("              (bpf_map_update_elem writes only, program stays loaded).")
    print()
    hc = _stats(results["hardcoded"][1])["mean_ms"]
    tp = _stats(results["template"][1])["mean_ms"]
    md = _stats(results["modular"][1])["mean_ms"]
    if tp > 0:
        print(f"  hardcoded add is ~{hc/tp:.0f}x slower than template add "
              f"(recompile vs. map write).")
    if md > 0:
        print(f"  hardcoded add is ~{hc/md:.0f}x slower than modular add "
              f"(recompile vs. map write).")


if __name__ == "__main__":
    main()
