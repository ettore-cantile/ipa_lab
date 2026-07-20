#!/usr/bin/env python3
"""
method4_hardcoded_aot.py  --  Pipeline 1 ALTERNATIVE loader: AOT-literal (libbpf).

This is a SEPARATE, optional variant of Pipeline 1. It does NOT replace
method4_hardcoded.py (the BCC literal path stays byte-identical and is the
guaranteed fallback). It exists to answer one question the professor may ask:
can we keep the maximum hardcoded performance AND remove the ~1660 ms of
clang-at-runtime that BCC pays on every (re)load?

Topology dimensions (n_interfaces, n_nodes, n_queues) come from
topology_config.json — a file that describes the NETWORK TOPOLOGY shared
by all nodes in the same deployment. If absent, DEFAULT_TOPOLOGY_CONFIG
(historical 6/52) is used.

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
    1. load topology_config.json (authoritative network dimensions), verify
       N_IN consistency with the checkpoint,
    2. generate the weights-literal libbpf C for the model (real int8 weights),
    3. clang-compile it to a .o OFFLINE and TIME that build (the cost you pay
       once, on the build box, NOT on the hot path),
    4. build the libbpf loader (loader_aot) if needed,
    5. run it: it TIMES the runtime open+load (the real deploy cost) and
       BPF_PROG_TEST_RUNs the program (full path, same methodology as
       test_suite --kernel) to confirm the literal performance is preserved.

Descriptor support: the offline generator (gen_full_c.py) is descriptor-driven
— it ports the three feature kinds (scalar / dense_vector_map / onehot) to the
libbpf dialect, so ANY descriptor the BCC path (ebpf_program.py) accepts is now
AOT-compilable too. The default [link_state, ingress_iface, ttl, node] / n_out=7
still produces the byte-identical 65-4-4-7 program.

Requires (on the VM/build box): clang, llvm, libbpf-dev, linux headers.
    sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)

Run:
    sudo python3 shared/methods/method4_hardcoded_aot.py
    sudo python3 shared/methods/method4_hardcoded_aot.py \\
        --model shared/frr_germany50_5_model_4x2.pt
    sudo python3 shared/methods/method4_hardcoded_aot.py \\
        --topology-config /etc/ipa/topology_config.json
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

_DEFAULT_TOPOLOGY_CONFIG_PATH = "/etc/ipa/topology_config.json"

from model_meta import (
    load_model_meta,
    load_topology_config,
    derive_shape,
    verify_shape_vs_checkpoint,
)

def _resolve_cli_path(path):
    if path is None or os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(_ORIGINAL_CWD, path))


def _run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return p.returncode, p.stdout, p.stderr


def main():
    ap = argparse.ArgumentParser(description="Pipeline 1 AOT-literal deploy bench (libbpf)")
    ap.add_argument("--model", default=None, help="Path to .pt checkpoint (default: checked-in FRR)")
    ap.add_argument(
        "--topology-config",
        default=_DEFAULT_TOPOLOGY_CONFIG_PATH,
        dest="topology_config",
        help=(
            f"Path to topology_config.json (default: {_DEFAULT_TOPOLOGY_CONFIG_PATH}). "
            "Describes the network topology shared by all nodes (n_interfaces, "
            "n_nodes, n_queues). Falls back to built-in defaults if absent."
        ),
    )
    ap.add_argument("--clang", default="clang", help="clang binary")
    ap.add_argument("--cc", default="cc", help="C compiler for the loader")
    ap.add_argument("--keep", action="store_true", help="keep generated .bpf.c/.o")
    ap.add_argument(
        "--iface", default=None,
        help="LIVE DEPLOY: attach the prebuilt .o to this interface (real XDP "
             "attach, stays resident until Ctrl-C) instead of the TEST_RUN bench. "
             "This is the AOT alternative to method4_hardcoded's BCC live attach.")
    args = ap.parse_args()
    args.model = _resolve_cli_path(args.model)

    model_path = args.model or os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")

    # ------------------------------------------------------------------
    # Step 0: load topology_config (authoritative network dimensions) and
    # model_meta (per-model feature descriptor), then derive the shape.
    # topology_config is the authoritative source for n_interfaces /
    # n_nodes / n_queues; any such keys in model_meta.json are ignored.
    # ------------------------------------------------------------------
    topo_cfg = load_topology_config(args.topology_config)
    meta     = load_model_meta(model_path)
    shape    = derive_shape(meta, topology_config=topo_cfg)

    # ------------------------------------------------------------------
    # Step 0.5: verify that the checkpoint was trained with the same N_IN
    # that topology_config + feature types produce. Raises a clear
    # ValueError if they differ — prevents silent wrong-inference.
    # ------------------------------------------------------------------
    verify_shape_vs_checkpoint(shape, model_path)

    feats_str = ", ".join(f"{f['type']}[{f['size']}]" for f in shape["features"])
    print(f"[AOT] model={model_path}")
    print(f"[AOT] shape={shape['n_in']}-{'-'.join(map(str, shape['hidden_dims']))}-{shape['n_out']}  "
          f"descriptor=[{feats_str}]")

    # Descriptor-driven generator: pass the resolved meta + topology so a custom
    # descriptor produces the matching program (default -> byte-identical 65-4-4-7).
    from gen_full_c import generate_arch_literal_c
    c_src = generate_arch_literal_c(
        model_path if args.model else None, meta=meta, topology_config=topo_cfg)
    c_path = os.path.join(POC_DIR, "nn_aot_arch.bpf.c")
    o_path = os.path.join(POC_DIR, "nn_aot_arch.o")
    with open(c_path, "w") as f:
        f.write(c_src)
    print(f"[AOT] generated {os.path.relpath(c_path, _ORIGINAL_CWD)} ({len(c_src)} chars)")

    bpf_cflags = ["-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86"]
    t0 = time.perf_counter()
    rc, out, err = _run([args.clang, *bpf_cflags, "-c", c_path, "-o", o_path], cwd=POC_DIR)
    build_ms = (time.perf_counter() - t0) * 1000.0
    if rc != 0:
        sys.exit(f"[AOT] clang failed (rc={rc}):\n{err}")
    print(f"[AOT] OFFLINE build (clang -> .o): {build_ms:.1f} ms  [paid once, on the build box]")

    loader_c   = os.path.join(POC_DIR, "loader_aot.c")
    loader_bin = os.path.join(POC_DIR, "loader_aot")
    if (not os.path.exists(loader_bin)
            or os.path.getmtime(loader_bin) < os.path.getmtime(loader_c)):
        rc, out, err = _run([args.cc, "-O2", loader_c, "-o", loader_bin, "-lbpf"], cwd=POC_DIR)
        if rc != 0:
            sys.exit(f"[AOT] loader build failed (rc={rc}):\n{err}\n"
                     "      Need libbpf-dev: sudo apt-get install libbpf-dev")
        print(f"[AOT] built loader_aot")

    if args.iface:
        # LIVE DEPLOY: attach the prebuilt .o to a real interface and stay
        # resident (no clang on this node). Runs the loader in --attach mode
        # with inherited stdio so output streams and Ctrl-C detaches.
        import socket
        try:
            ifindex = socket.if_nametoindex(args.iface)
        except OSError:
            sys.exit(f"[AOT] interface {args.iface!r} not found")
        print(f"[AOT] LIVE deploy: attaching prebuilt .o to {args.iface} "
              f"(ifindex={ifindex}); no clang on this node. Ctrl-C to detach.\n")
        rc = subprocess.run([loader_bin, o_path, "--attach", str(ifindex)],
                            cwd=POC_DIR).returncode
        if rc != 0:
            sys.exit(f"[AOT] loader_aot live attach failed (rc={rc})")
        return

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
