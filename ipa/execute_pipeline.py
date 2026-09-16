#!/usr/bin/env python3
"""
execute_pipeline.py  —  Design-space pipeline launcher
=======================================================
Single entry point for all three design-space pipelines:

  --method hardcoded   Pipeline 1: Hardcoded model
                       (weights as C literals, unrolled inference,
                        1 tail call, 0 weight map lookups)

  --method template    Pipeline 2: Pre-built architectural template
                       (weights in BPF_ARRAY, 1 tail call,
                        model update = bpf_map_update_elem)

  --method modular     Pipeline 3: Modular neural pipeline
                       (BPF_PERCPU_ARRAY scratch, N tail calls,
                        maximum runtime flexibility)

Usage:
    sudo python3 ipa/execute_pipeline.py --method hardcoded [--iface eth0] [--model-id 0]
    sudo python3 ipa/execute_pipeline.py --method template  [--iface eth0] [--model-id 0]
    sudo python3 ipa/execute_pipeline.py --method modular   [--iface eth0] [--model-id 0]

Notes:
    - Requires root (XDP attach).
    - The .pt model is resolved by model_meta.default_checkpoint()
      ($IPA_CHECKPOINT, then model_meta.json's `checkpoint` key)
    - extract_weights.py requires torch; it is skipped if weights.json exists.
"""

import argparse
import os
import sys
import runpy

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)


def main():
    # chdir into shared/ so the pipeline modules resolve their relative data
    # paths (weights.json, the .pt checkpoint) the way they expect. Done here
    # rather than at module level: importing this module should not silently
    # change the caller's working directory.
    os.chdir(SHARED_DIR)

    parser = argparse.ArgumentParser(
        description="IPA/eBPF design-space pipeline launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Pipeline trade-off summary:
  hardcoded : maximum performance | minimum flexibility | 0 weight lookups
  template  : medium performance  | medium flexibility  | BPF_ARRAY lookup
  modular   : lower performance   | maximum flexibility | PERCPU_ARRAY + N tail calls

For the full metric comparison across pipelines:
  sudo python3 ipa/test/test_suite.py --only kernel
        """
    )
    parser.add_argument(
        "--method",
        choices=["hardcoded", "template", "modular"],
        default="hardcoded",
        help="Pipeline to run (default: hardcoded)"
    )
    parser.add_argument(
        "--iface",
        default="eth0",
        help="Network interface for XDP attach (default: eth0)"
    )
    parser.add_argument(
        "--model-id",
        type=int,
        default=0,
        help="Model ID to register (default: 0)"
    )
    parser.add_argument(
        "--model-ids",
        type=int,
        nargs="+",
        default=None,
        help="Register several model_id's concurrently (template/modular only; "
             "ignored by hardcoded, which is single-model by design). "
             "Overrides --model-id when given."
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Path to .pt checkpoint (default: model_meta.default_checkpoint())"
    )
    parser.add_argument(
        "--xdp-mode",
        choices=["native", "generic", "auto"],
        default=None,
        help="XDP attach mode. native (default) runs in the driver, before the "
             "sk_buff exists -- the path a real deployment takes. generic runs "
             "in netif_receive_skb, after it. auto lets the kernel pick, which "
             "means it may silently give you generic. Overrides $IPA_XDP_MODE."
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Load and verify eBPF program without attaching XDP (safe for testing)"
    )
    args = parser.parse_args()

    from model_meta import default_checkpoint
    model_path = args.model or default_checkpoint()

    # ------------------------------------------------------------------
    # Step 1: extract weights (produces weights.json + weights_float.json)
    # Skip if both files already exist — extract_weights.py requires torch
    # which is NOT available inside a stripped container image.  The pre-built JSON
    # files checked into the repo are sufficient for all three pipelines.
    # ------------------------------------------------------------------
    weights_path = os.path.join(SHARED_DIR, "weights.json")
    float_path   = os.path.join(SHARED_DIR, "weights_float.json")

    print("=" * 60)
    ids_desc = args.model_ids if args.model_ids else args.model_id
    print(f"[pipeline] method={args.method}  iface={args.iface}  model_id(s)={ids_desc}")
    print("=" * 60)

    if os.path.exists(weights_path) and os.path.exists(float_path):
        print("[pipeline] Step 1 — weights already present, skipping extract_weights.py")
        print(f"[pipeline]   {weights_path} ({os.path.getsize(weights_path)} bytes)")
        print(f"[pipeline]   {float_path} ({os.path.getsize(float_path)} bytes)")
    else:
        if not os.path.exists(model_path):
            print(f"[ERROR] Model not found: {model_path}")
            print("[ERROR] And weights.json / weights_float.json are also missing.")
            print("[ERROR] Run extract_weights.py on a machine with torch, then commit the JSON files.")
            sys.exit(1)
        print(f"[pipeline] Step 1 — extracting weights from {model_path}")
        runpy.run_path(
            os.path.join(SHARED_DIR, "extract_weights.py"),
            run_name="__main__"
        )
        if not os.path.exists(weights_path):
            print("[ERROR] weights.json not generated — exiting.")
            sys.exit(1)

    print("[pipeline] weights.json OK")

    # ------------------------------------------------------------------
    # Step 2: launch the chosen pipeline
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    pnum = {'hardcoded': '1', 'template': '2', 'modular': '3'}[args.method]
    print(f"[pipeline] Step 2 — launching Pipeline {pnum} ({args.method})")
    print("=" * 60)

    if args.method == "hardcoded":
        # Pipeline 1 — weights hardcoded as C literals, unrolled inference.
        if args.verify_only:
            # Verifier smoke test via the BCC generator (no attach, no offline clang).
            # Forward the RESOLVED model_path, not args.model: this process has
            # already os.chdir'd into SHARED_DIR, so method4_hardcoded.py's own
            # default ("shared/frr_...pt", relative) would resolve to
            # ipa/ipa/frr_...pt and fail to load.
            sys.argv = ["method4_hardcoded.py", "--verify-only",
                        "--iface", args.iface,
                        "--model-id", str(args.model_id),
                        "--model", model_path]
            runpy.run_path(
                os.path.join(SHARED_DIR, "methods", "method4_hardcoded.py"),
                run_name="__main__"
            )
        else:
            # AOT-literal deploy — the ONLY hardcoded deploy backend. Prebuilt
            # .o attached live, NO clang/libbpf-dev needed on this node (see
            # method4_hardcoded_aot.py and shared/poc_aot/loader_aot.c, now
            # statically linked against libbpf for exactly this reason).
            # BCC is no longer used to deploy hardcoded; it is still used
            # internally by the test suite (verify_prog_run.py etc.) to
            # compile-and-verify offline, which is a different concern from
            # what actually runs on the datapath node.
            # Same reason as above: pass the already-resolved absolute path.
            sys.argv = ["method4_hardcoded_aot.py", "--iface", args.iface,
                        "--xdp-mode", args.xdp_mode or "native",
                        "--model", model_path]
            runpy.run_path(
                os.path.join(SHARED_DIR, "methods", "method4_hardcoded_aot.py"),
                run_name="__main__"
            )

    elif args.method == "template":
        # Pipeline 2 — architectural template, weights in BPF_ARRAY
        from methods.method5_template import run
        run(model_id=args.model_id, iface=args.iface, model_ids=args.model_ids,
            xdp_mode=args.xdp_mode)

    else:
        # Pipeline 3 — modular layers, scratch map, N tail calls
        from methods.method6_modular import run
        run(model_id=args.model_id, iface=args.iface, model_ids=args.model_ids,
            xdp_mode=args.xdp_mode)


if __name__ == "__main__":
    main()
