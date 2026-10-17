#!/usr/bin/env python3
"""method4_hardcoded_aot.py -- deploy loader of Pipeline 1: the object compiled
offline (AOT) is loaded on the node with libbpf, no compiler needed.
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
    load_class_semantics,
)

def _resolve_cli_path(path):
    if path is None or os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(_ORIGINAL_CWD, path))


def _run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return p.returncode, p.stdout, p.stderr


class AotDeploy:
    """The loader in deploy mode, with this process as its control plane."""

    def __init__(self, cmd, pin_dir, semantics, n_nodes=None, monitor=True,
                 echo=True):
        self.cmd, self.pin_dir, self.semantics = cmd, pin_dir, semantics
        self.n_nodes, self.monitor, self.echo = n_nodes, monitor, echo
        self.proc = None
        self.b = None
        self.node_cfg = None
        self.mac_info = None
        self.lines = []
        self._stop_monitor = None
        self._rc = None

    def _expect(self, word):
        """Read the loader's stdout up to the line that starts with `word`."""
        for line in self.proc.stdout:
            self.lines.append(line)
            if self.echo:
                sys.stdout.write(line)
            if line.startswith(word):
                return line.split()[1:]
        raise RuntimeError(f"loader_aot exited (rc={self.proc.wait()}) before "
                           f"printing {word}; last output: "
                           f"{''.join(self.lines[-5:]).strip()!r}")

    def start(self):
        import threading
        from pinned_maps import PinnedObject, FwdAction
        from common import (install_mac_per_port, install_ingress_port_table,
                            install_node_id, start_mac_refresh_thread)
        from link_state_monitor import init_link_state_up, start_monitor_thread
        from node_config import NodeConfig

        self.proc = subprocess.Popen(self.cmd, cwd=POC_DIR,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True,
                                     bufsize=1)
        try:
            self._expect("READY")
            b = PinnedObject(self.pin_dir,
                             leaf_types={"mac_table": FwdAction,
                                         "link_state": "u32vec",
                                         "queue_state": "u32vec"})
            sem = self.semantics
            print("[AOT] class semantics:")
            print(sem.summary())
            self.node_cfg = NodeConfig.resolve(sem.logical_ports)
            print(self.node_cfg.summary())
            for _p in self.node_cfg.validate(sem.logical_ports, strict=False):
                print(f"[AOT] NOTE: {_p}")
            self.mac_info = install_mac_per_port(b, "mac_table", self.node_cfg,
                                                 sem.logical_ports)
            if "ingress_port" in b:
                install_ingress_port_table(b, "ingress_port", self.node_cfg,
                                           sem.logical_ports)
            if "node_id" in b:
                install_node_id(b, "node_id", self.node_cfg,
                                n_nodes=self.n_nodes)
            if "link_state" in b:
                init_link_state_up(b)
                if self.monitor:
                    self._stop_monitor = start_monitor_thread(b, interval=0.5)
                    print("[AOT] link_state seeded (present interfaces up, "
                          "absent slots 0); carrier monitor running")
            if "queue_state" in b:
                print("[AOT] NOTE: queue_state is left to "
                      "queue_state_monitor.py, as in the P2/P3 deploys")
            if self.mac_info["pending"]:
                start_mac_refresh_thread(b, "mac_table",
                                         self.mac_info["pending"], interval=5.0)

            self.proc.stdin.write("ATTACH\n")
            self.proc.stdin.flush()
            self._expect("ATTACHED")

            def _drain():
                for line in self.proc.stdout:
                    self.lines.append(line)
                    if self.echo:
                        sys.stdout.write(line)
            threading.Thread(target=_drain, daemon=True).start()
            self.b = b
            return b
        except BaseException:
            self.stop()
            raise

    def stop(self):
        """Detach and wait. Idempotent; returns the loader's exit code."""
        if self.proc is None:
            return None
        if self._rc is not None:
            return self._rc
        if self._stop_monitor is not None:
            self._stop_monitor.set()
        try:
            self.proc.stdin.write("DETACH\n")
            self.proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass
        try:
            self._rc = self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            self._rc = self.proc.wait()
        return self._rc

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


def _live_deploy(cmd, pin_dir, semantics, n_nodes=None):
    """Deploy until Ctrl-C, printing HIT | MISS | DROP once a second."""
    import ctypes
    dep = AotDeploy(cmd, pin_dir, semantics, n_nodes=n_nodes)
    rc = None
    try:
        b = dep.start()
        stats = b["pkt_stats"]
        print(f"\n{'TRUE HIT':<22} | {'MISS':<22} | {'DROP':<20}")
        print("-" * 70)
        while dep.proc.poll() is None:
            time.sleep(1)
            try:
                from stats_maps import read_counter
                v = [read_counter(stats, i) for i in range(3)]
                print(f"\r{v[0]:<22} | {v[1]:<22} | {v[2]:<20}",
                      end="", flush=True)
            except Exception:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        rc = dep.stop()
    if rc != 0:
        sys.exit(f"\n[AOT] loader_aot exited with rc={rc}")
    print("\n[AOT] detached, pins removed.")


def ensure_loader(cc="cc"):
    """Build poc_aot/loader_aot if it is missing or older than its source;"""
    import shutil
    loader_c   = os.path.join(POC_DIR, "loader_aot.c")
    loader_bin = os.path.join(POC_DIR, "loader_aot")
    needs_build = (not os.path.exists(loader_bin)
                  or os.path.getmtime(loader_bin) < os.path.getmtime(loader_c))
    if needs_build and not shutil.which(cc):
        raise RuntimeError(
            f"[AOT] '{cc}' not found on this node and no prebuilt "
            f"{os.path.relpath(loader_bin, _ORIGINAL_CWD)}.\n"
            f"      Build it ONCE on a box with a C compiler + libbpf-dev/libelf-dev/"
            f"zlib1g-dev\n      (e.g. a build host):\n"
            f"          python3 ipa/methods/method4_hardcoded_aot.py\n"
            f"      The binary is statically linked (no runtime libbpf.so needed), and "
            f"since\n      the directory is shared with every node, building it once "
            f"on the\n      host makes it immediately available on every node -- no copy step.")
    if needs_build:
        base3 = ["-l:libbpf.a", "-l:libelf.a", "-l:libz.a"]
        base5 = base3 + ["-l:libzstd.a", "-l:liblzma.a"]
        base6 = base5 + ["-l:libbz2.a"]
        static_attempts = [
            ["-static", *base6],
            ["-static", *base5],
            ["-static", *base3],
            base5,
            base3,
        ]
        built = False
        won_fully_static = False
        last_err = ""
        for extra in static_attempts:
            rc, out, err = _run([cc, "-O2", loader_c, "-o", loader_bin, *extra], cwd=POC_DIR)
            if rc == 0:
                won_fully_static = ("-static" in extra)
                kind = "fully static" if won_fully_static else "libbpf-static, glibc-DYNAMIC"
                print(f"[AOT] built loader_aot ({kind}: {' '.join(extra)})")
                built = True
                break
            last_err = err
        if built and not won_fully_static:
            print("[AOT] WARNING: the fully-static (-static) link did not succeed, so this")
            print("      loader links glibc DYNAMICALLY and may fail on a node with an OLDER")
            print("      glibc than this host (symptom: 'GLIBC_x.yy not found'). To get a")
            print("      portable fully-static binary, install the static libs it still needs:")
            print("      sudo apt-get install libc6-dev libbz2-dev libzstd-dev liblzma-dev")
            print("      then rebuild: rm ipa/poc_aot/loader_aot && python3 <this script>")
        if not built:
            print("[AOT] static link failed on all attempts. Full ld error:")
            print("      " + "\n      ".join(last_err.strip().splitlines()[-8:]))
            print("[AOT] To fix the STATIC link (needed on nodes without libbpf.so):")
            print("      sudo apt-get install libbpf-dev libelf-dev zlib1g-dev libzstd-dev liblzma-dev")
            print("[AOT] Falling back to DYNAMIC -lbpf. WARNING: this binary needs libbpf.so at")
            print("      runtime -- it will NOT run on a node that lacks it (check with:")
            print("      ldconfig -p | grep bpf on the node).")
            rc, out, err = _run([cc, "-O2", loader_c, "-o", loader_bin, "-lbpf"], cwd=POC_DIR)
            if rc != 0:
                raise RuntimeError(f"[AOT] loader build failed even dynamically (rc={rc}):\n{err}\n"
                         "      Need at least libbpf-dev: sudo apt-get install libbpf-dev")
            print("[AOT] built loader_aot (DYNAMIC -- libbpf.so required at runtime)")
    return loader_bin


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
             "The only way Pipeline 1 is deployed.")
    ap.add_argument(
        "--xdp-mode", choices=["native", "generic", "auto"], default="native",
        help="XDP attach mode for --iface. native (default) runs in the driver, "
             "before the sk_buff exists -- the path a real deployment takes. "
             "generic runs in netif_receive_skb, after it. auto lets the kernel "
             "pick, which means it may silently give you generic.")
    ap.add_argument(
        "--build-only", action="store_true",
        help="generate + compile the .o and build the loader, then stop: no "
             "bench, no attach. Used by the kernel benches (check_pipelines."
             "setup_hardcoded, via p1_aot) and test_forwarding, which drive the object themselves")
    ap.add_argument(
        "--pin-root", default="/sys/fs/bpf",
        help="bpffs directory under which the live deploy pins its maps "
             "(ipa_p1_<iface>), for the control plane to fill before attach")
    args = ap.parse_args()
    args.model = _resolve_cli_path(args.model)

    from model_meta import default_checkpoint
    model_path = args.model or default_checkpoint()

    # --- Step 0: load topology_config (authoritative network dimensions) and ---
    topo_cfg = load_topology_config(args.topology_config)
    meta     = load_model_meta(model_path)
    shape    = derive_shape(meta, topology_config=topo_cfg)

    # --- Step 0.5: verify that the checkpoint was trained with the same N_IN ---
    verify_shape_vs_checkpoint(shape, model_path)

    feats_str = ", ".join(f"{f['type']}[{f['size']}]" for f in shape["features"])
    print(f"[AOT] model={model_path}")
    print(f"[AOT] shape={shape['n_in']}-{'-'.join(map(str, shape['hidden_dims']))}-{shape['n_out']}  "
          f"descriptor=[{feats_str}]")

    semantics = load_class_semantics(model_path, shape["n_out"])

    from gen_full_c import generate_arch_literal_c
    c_src = generate_arch_literal_c(
        model_path if args.model else None, meta=meta, topology_config=topo_cfg,
        semantics=semantics)
    c_path = os.path.join(POC_DIR, "nn_aot_arch.bpf.c")
    o_path = os.path.join(POC_DIR, "nn_aot_arch.o")
    with open(c_path, "w") as f:
        f.write(c_src)
    print(f"[AOT] generated {os.path.relpath(c_path, _ORIGINAL_CWD)} ({len(c_src)} chars)")

    import shutil
    build_ms = None
    if shutil.which(args.clang):
        bpf_cflags = ["-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86"]
        import platform
        _ma = f"/usr/include/{platform.machine()}-linux-gnu"
        if os.path.isdir(os.path.join(_ma, "asm")):
            bpf_cflags.append(f"-I{_ma}")
        t0 = time.perf_counter()
        rc, out, err = _run([args.clang, *bpf_cflags, "-c", c_path, "-o", o_path], cwd=POC_DIR)
        build_ms = (time.perf_counter() - t0) * 1000.0
        if rc != 0:
            sys.exit(f"[AOT] clang failed (rc={rc}):\n{err}")
        print(f"[AOT] OFFLINE build (clang -> .o): {build_ms:.1f} ms  [paid once, on the build box]")
    elif os.path.exists(o_path):
        print(f"[AOT] '{args.clang}' not found -- reusing prebuilt "
              f"{os.path.relpath(o_path, _ORIGINAL_CWD)} (AOT deploy, no clang on this node).")
    else:
        sys.exit(
            f"[AOT] '{args.clang}' not found and no prebuilt "
            f"{os.path.relpath(o_path, _ORIGINAL_CWD)}.\n"
            f"      AOT-literal is the only hardcoded deploy backend. Build the .o OFFLINE on a\n"
            f"      box with clang (python3 ipa/methods/method4_hardcoded_aot.py),\n"
            f"      then copy nn_aot_arch.o onto this node.")

    try:
        loader_bin = ensure_loader(args.cc)
    except RuntimeError as e:
        sys.exit(str(e))

    if args.build_only:
        print(f"[AOT] build complete: {o_path} {loader_bin}")
        return

    if args.iface:
        import socket
        try:
            ifindex = socket.if_nametoindex(args.iface)
        except OSError:
            sys.exit(f"[AOT] interface {args.iface!r} not found")
        pin_dir = os.path.join(args.pin_root,
                               "ipa_p1_" + args.iface.replace(".", "_"))
        print(f"[AOT] LIVE deploy: prebuilt .o on {args.iface} "
              f"(ifindex={ifindex}), maps pinned under {pin_dir}; no clang on "
              f"this node. Ctrl-C to detach.\n")
        cmd = [loader_bin, o_path, "--attach", str(ifindex),
               "--xdp-mode", args.xdp_mode, "--pin-dir", pin_dir]
        _live_deploy(cmd, pin_dir, semantics, n_nodes=topo_cfg.get("n_nodes"))
        return

    print("[AOT] running loader_aot on the prebuilt .o ...\n")
    rc, out, err = _run([loader_bin, o_path], cwd=POC_DIR)
    sys.stdout.write(out)
    if err.strip():
        sys.stderr.write(err)
    if rc != 0:
        sys.exit(f"[AOT] loader_aot failed (rc={rc})")

    build_str = (f"{build_ms:.1f} ms" if build_ms is not None
                 else "reused prebuilt .o (no clang on this node)")
    print(f"\n[AOT] offline build: {build_str}; verifier + JIT and one "
          f"BPF_PROG_TEST_RUN passed (see [deploy] and [perf] above).")

    if not args.keep:
        try:
            os.remove(c_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
