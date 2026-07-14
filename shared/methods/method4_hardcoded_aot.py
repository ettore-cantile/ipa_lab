#!/usr/bin/env python3
"""
method4_hardcoded_aot.py  --  Pipeline 1 ALTERNATIVE loader: AOT-literal (libbpf).

This is a SEPARATE, optional variant of Pipeline 1. It does NOT replace
method4_hardcoded.py (the BCC literal path stays byte-identical and is the
guaranteed fallback). It exists to answer one question the professor may ask:
can we keep the maximum hardcoded performance AND remove the ~1660 ms of
clang-at-runtime that BCC pays on every (re)load?

The problem (measured, method4 BCC path):
    [M1 update timing] redirect/reload (BPF compile+load): ~1660 ms
    -> 99.8% of that is clang compiling the weights-literal C at runtime, on the
       datapath node, for EVERY new/modified model.

The alternative, for the "models known a priori" case (exactly the hardcoded
assumption): compile the weights-literal program OFFLINE, once, on a build box,
into a plain BPF .o (clang, libbpf dialect, weights as C literals). At runtime
the datapath node only does bpf_object__open_file + bpf_object__load -> a few ms,
NO clang. Because the weights are still C literals compiled by clang -O2, the
per-weight strength reduction (x*0 folded away, x*8 -> shift) is preserved, so
performance stays at the literal maximum -- identical to BCC at the same
architecture (measured: ~69 vs ~66 ns/pkt).

What this script does (bench only -- it does NOT attach XDP to a real iface;
that is method4's job):
    1. load node_config.json from the node (authoritative for n_interfaces /
       n_nodes / n_queues), verify N_IN consistency with the checkpoint,
    2. generate the weights-literal libbpf C for the model (real int8 weights),
    3. clang-compile it to a .o OFFLINE and TIME that build (the cost you pay
       once, on the build box, NOT on the hot path),
    4. build the libbpf loader (loader_aot) if needed,
    5. run it: it TIMES the runtime open+load (the real deploy cost) and
       BPF_PROG_TEST_RUNs the program (full path, same methodology as
       test_suite --kernel) to confirm the literal performance is preserved.

Bound: this variant currently targets the DEFAULT FRR descriptor (65-4-4-7,
node config 6/52). Sparse/heterogeneous per-model descriptors are supported by
the BCC path (ebpf_program.py) but not yet by this offline generator -- porting
the descriptor-driven IV codegen to libbpf dialect is future work. The script
refuses a non-default descriptor with a clear message rather than silently
producing a wrong program.

Requires (on the VM/build box): clang, llvm, libbpf-dev, linux headers. BCC
already pulls clang/llvm; libbpf-dev is the only likely-missing one:
    sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)

Run:
    sudo python3 shared/methods/method4_hardcoded_aot.py
    sudo python3 shared/methods/method4_hardcoded_aot.py --model shared/frr_germany50_5_model_4x2.pt
    sudo python3 shared/methods/method4_hardcoded_aot.py \\
        --node-config /etc/ipa/node_config.json
"""

import os
import sys
import time
import argparse
import subprocess

SHARED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POC_DIR    = os.path.join(SHARED_DIR, "poc_aot")
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)
if POC_DIR not in sys.path:
    sys.path.insert(0, POC_DIR)
_ORIGINAL_CWD = os.getcwd()

# Default path for the per-node feature-dimension configuration.
_DEFAULT_NODE_CONFIG_PATH = "/etc/ipa/node_config.json"

from model_meta import (
    load_model_meta,
    load_node_config,
    derive_shape,
    verify_shape_vs_checkpoint,
)

# What the offline generator (gen_full_c.py) currently hardcodes. A model whose
# resolved descriptor differs cannot be built by this AOT path yet.
_SUPPORTED = {
    "n_in": 65, "n_out": 7, "hidden_dims": [4, 4],
    "features": [("link_state", 6), ("ingress_iface", 6), ("ttl", 1), ("node", 52)],
}


def _resolve_cli_path(path):
    if path is None or os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(_ORIGINAL_CWD, path))


def _check_supported(shape):
    feats = [(f["type"], f["size"]) for f in shape["features"]]
    if (shape["n_in"], shape["n_out"], list(shape["hidden_dims"]), feats) != (
        _SUPPORTED["n_in"], _SUPPORTED["n_out"], _SUPPORTED["hidden_dims"],
        _SUPPORTED["features"]):
        sys.exit(
            "[AOT] this offline variant only supports the default FRR descriptor "
            f"(65-4-4-7, features {_SUPPORTED['features']}).\n"
            f"      got n_in={shape['n_in']} n_out={shape['n_out']} "
            f"hidden={shape['hidden_dims']} features={feats}.\n"
            "      Use the BCC path (method4_hardcoded.py) for custom descriptors; "
            "porting the descriptor-driven IV codegen to libbpf dialect is future work.")


def _run(cmd, **kw):
    """Run a command, streaming failures. Returns (rc, stdout, stderr)."""
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return p.returncode, p.stdout, p.stderr


def main():
    ap = argparse.ArgumentParser(description="Pipeline 1 AOT-literal deploy bench (libbpf)")
    ap.add_argument("--model", default=None, help="Path to .pt checkpoint (default: checked-in FRR)")
    ap.add_argument(
        "--node-config",
        default=_DEFAULT_NODE_CONFIG_PATH,
        help=(
            f"Path to node_config.json (default: {_DEFAULT_NODE_CONFIG_PATH}). "
            "Provides authoritative n_interfaces / n_nodes / n_queues for the "
            "node. Falls back to built-in defaults if the file doesn't exist."
        ),
    )
    ap.add_argument("--clang", default="clang", help="clang binary")
    ap.add_argument("--cc", default="cc", help="C compiler for the loader")
    ap.add_argument("--keep", action="store_true", help="keep generated .bpf.c/.o")
    args = ap.parse_args()
    args.model = _resolve_cli_path(args.model)

    model_path = args.model or os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")

    # ------------------------------------------------------------------
    # Step 0: load node_config (per-node dims) and model_meta (per-model
    # descriptor), then derive the concrete shape.
    # node_config is the authoritative source for n_interfaces/n_nodes/
    # n_queues; any such keys in model_meta.json are ignored.
    # ------------------------------------------------------------------
    node_cfg = load_node_config(args.node_config)
    meta     = load_model_meta(model_path)
    shape    = derive_shape(meta, node_config=node_cfg)

    # ------------------------------------------------------------------
    # Step 0.5: verify that the checkpoint was trained with the same N_IN
    # that node_config + feature types produce.  Raises a clear ValueError
    # if they differ -- prevents silent wrong-inference.
    # ------------------------------------------------------------------
    verify_shape_vs_checkpoint(shape, model_path)

    # ------------------------------------------------------------------
    # Step 0.6: AOT-specific guard -- this offline generator only supports
    # the default FRR descriptor (65-4-4-7, node config 6/52).  Must run
    # AFTER the two checks above so N_IN errors surface before this one.
    # ------------------------------------------------------------------
    _check_supported(shape)

    print(f"[AOT] model={model_path}")
    print(f"[AOT] shape={shape['n_in']}-{'-'.join(map(str, shape['hidden_dims']))}-{shape['n_out']} (default FRR descriptor)")

    # 1) generate the weights-literal libbpf C from the real model weights.
    #    ARCH-FAITHFUL: dispatcher + PROG_ARRAY tail-call + model that re-parses
    #    (double parse) == the BCC hardcoded topology, so the bench is
    #    apples-to-apples with test_suite --kernel hardcoded.
    from gen_full_c import generate_arch_literal_c
    c_src = generate_arch_literal_c(model_path if args.model else None)
    c_path = os.path.join(POC_DIR, "nn_aot_arch.bpf.c")
    o_path = os.path.join(POC_DIR, "nn_aot_arch.o")
    with open(c_path, "w") as f:
        f.write(c_src)
    print(f"[AOT] generated {os.path.relpath(c_path, _ORIGINAL_CWD)} ({len(c_src)} chars)")

    # 2) OFFLINE build: clang-compile the literal C to a .o, TIMED. This is the
    #    "recompile" cost -- but it happens once, on a build box, off the hot path.
    bpf_cflags = ["-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86"]
    t0 = time.perf_counter()
    rc, out, err = _run([args.clang, *bpf_cflags, "-c", c_path, "-o", o_path], cwd=POC_DIR)
    build_ms = (time.perf_counter() - t0) * 1000.0
    if rc != 0:
        sys.exit(f"[AOT] clang failed (rc={rc}):\n{err}")
    print(f"[AOT] OFFLINE build (clang -> .o): {build_ms:.1f} ms  [paid once, on the build box]")

    # 3) build the libbpf loader if missing (or stale)
    loader_c   = os.path.join(POC_DIR, "loader_aot.c")
    loader_bin = os.path.join(POC_DIR, "loader_aot")
    if (not os.path.exists(loader_bin)
            or os.path.getmtime(loader_bin) < os.path.getmtime(loader_c)):
        rc, out, err = _run([args.cc, "-O2", loader_c, "-o", loader_bin, "-lbpf"], cwd=POC_DIR)
        if rc != 0:
            sys.exit(f"[AOT] loader build failed (rc={rc}):\n{err}\n"
                     "      Need libbpf-dev: sudo apt-get install libbpf-dev")
        print(f"[AOT] built loader_aot")

    # 4) run the loader: it TIMES runtime open+load and BPF_PROG_TEST_RUNs
    print(f"[AOT] running loader_aot on the prebuilt .o ...\n")
    rc, out, err = _run([loader_bin, o_path], cwd=POC_DIR)
    sys.stdout.write(out)
    if err.strip():
        sys.stderr.write(err)
    if rc != 0:
        sys.exit(f"[AOT] loader_aot failed (rc={rc})")

    print("\n" + "=" * 64)
    print(" SUMMARY: BCC (runtime clang) vs AOT-literal (offline .o)")
    print("=" * 64)
    print(f"  BCC method4 (re)load    : ~1660 ms  (clang at runtime, every model)")
    print(f"  AOT offline build       : {build_ms:>7.1f} ms  (clang once, on build box)")
    print(f"  AOT runtime deploy      : ~few ms   (open+load only -- see [deploy] above)")
    print(f"  performance             : literal maximum preserved (see [perf] above)")
    print("=" * 64)

    if not args.keep:
        for p in (c_path, o_path):
            try:
                os.remove(p)
            except OSError:
                pass


if __name__ == "__main__":
    main()
