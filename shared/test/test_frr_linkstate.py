#!/usr/bin/env python3
"""
test_frr_linkstate.py -- REAL link-failure reroute test, driven by an actual
carrier flap (not a synthetic map write).

Why this exists: verify_prog_run.probe_link_down() (wired into
test_suite.py --only kernel as the "link_state reroute" check) proves the
MODEL reroutes when link_state[k] is flipped directly in the BPF map -- but
it never touches a real interface, real carrier detection, or the
link_state_monitor polling thread that is supposed to keep the map in sync
with reality. This script closes that gap: it brings a REAL interface down
on a REAL Kathara node while a pipeline is live-attached and real traffic is
flowing, and checks that egress traffic actually moves away from the failed
link -- exercising the full chain (carrier change -> link_state_monitor
thread -> BPF map -> inference -> argmax -> mac_table -> redirect), the
thing an FRR/OSPF reconvergence event would trigger in the real topology.

Runs from the HOST (or wherever `kathara` is on PATH), orchestrating via
`kathara exec` -- NOT meant to run inside a Kathara node.

Requires: the lab already started (`kathara lstart`), FRR/OSPF converged.

Usage:
    python3 shared/test/test_frr_linkstate.py \\
        --switch frankfurt --ingress-iface eth1 --fail-iface eth2 \\
        --sender darmstadt --method template --model-id 0

If any single step's automation doesn't match your kathara version, every
step is also printable/runnable BY HAND -- pass --dry-run to print the exact
command sequence without executing it. Map reads use bpf_introspect.py (a
raw bpf() syscall reader), NOT bpftool -- bpftool is not installed in this
lab's Kathara node images.

Honesty about what this proves and what it doesn't (same spirit as
docs/testing.md's benchmarking notes): this is a Kathara/VM lab, not
production hardware -- the interesting result is qualitative (does the
switch actually stop using the dead link within one polling interval?), not
an absolute failover-time SLA number.
"""
import argparse
import json
import re
import subprocess
import sys
import time

_SUFFIX = {"hardcoded": "", "template": "_t2", "modular": "_t3"}


def _run(cmd, **kw):
    print(f"    $ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _kexec(node, *args):
    return ["kathara", "exec", node, "--"] + list(args)


def get_iface_ip(node, iface):
    r = _run(_kexec(node, "ip", "-o", "-4", "addr", "show", "dev", iface))
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", r.stdout)
    if not m:
        sys.exit(f"[frr-test] Could not read an IPv4 address for {iface} on {node}:\n{r.stdout}{r.stderr}")
    return m.group(1)


def bpf_map_dump(node, map_name, max_entries):
    """Reads a live BPF array map by name from `node` via bpf_introspect.py
    (raw bpf() syscall, no bpftool -- bpftool is NOT installed in this lab's
    Kathara images, confirmed: 'executable file not found in $PATH'). Runs
    the reader script INSIDE the node (kathara exec) since the map lives in
    that node's kernel/namespace. Returns {key_int: value_int}."""
    r = _run(_kexec(node, "python3", "/shared/bpf_introspect.py", map_name, str(max_entries)))
    if r.returncode != 0:
        print(f"[frr-test] WARNING: bpf_introspect failed on {node} for {map_name}: "
              f"{r.stdout.strip()} {r.stderr.strip()}")
        return {}
    try:
        return {int(k): v for k, v in json.loads(r.stdout.strip()).items()}
    except (json.JSONDecodeError, ValueError):
        print(f"[frr-test] WARNING: could not parse bpf_introspect output: {r.stdout!r}")
        return {}


def main():
    ap = argparse.ArgumentParser(description="Real carrier-flap reroute test (orchestrated via kathara exec)")
    ap.add_argument("--switch", required=True, help="Node running the pipeline (e.g. frankfurt)")
    ap.add_argument("--ingress-iface", required=True, help="Iface where test traffic ENTERS the switch (e.g. eth1)")
    ap.add_argument("--fail-iface", required=True, help="Egress iface to bring down mid-test (e.g. eth2)")
    ap.add_argument("--sender", required=True, help="Node that floods traffic toward --switch (e.g. darmstadt)")
    ap.add_argument("--method", choices=["hardcoded", "template", "modular"], default="template")
    ap.add_argument("--model-id", type=int, default=0)
    ap.add_argument("--n-classes", type=int, default=7,
                    help="Size of cls_stats (n_out of the registered model; default 7 = 6 egress + drop)")
    ap.add_argument("--pre-seconds", type=float, default=5.0, help="Flood time before the flap")
    ap.add_argument("--post-seconds", type=float, default=5.0, help="Flood time after the flap")
    ap.add_argument("--dry-run", action="store_true", help="Print the command sequence, execute nothing")
    args = ap.parse_args()

    suffix = _SUFFIX[args.method]
    cls_map, mac_table = f"cls_stats{suffix}", f"mac_table{suffix}"
    total_duration = args.pre_seconds + args.post_seconds + 5

    print(f"[frr-test] switch={args.switch} ingress={args.ingress_iface} "
          f"fail_iface={args.fail_iface} sender={args.sender} method={args.method}")

    if args.dry_run:
        print("\n[frr-test] --dry-run: sequence that would run --\n")
        print(f"  1. kathara exec {args.switch} -- ip link set dev {args.ingress_iface} xdp off")
        print(f"  2. kathara exec {args.switch} -- python3 /shared/execute_pipeline.py "
              f"--method {args.method} --iface {args.ingress_iface} --model-id {args.model_id}  (background)")
        print(f"  3. kathara exec {args.sender} -- python3 /shared/test/bench_live_throughput.py "
              f"--dest-ip <ip of {args.ingress_iface}> --duration {total_duration} --model-id {args.model_id}  (background)")
        print(f"  4. sleep {args.pre_seconds}; dump {cls_map} (snapshot A)")
        print(f"  5. kathara exec {args.switch} -- ip link set dev {args.fail_iface} down")
        print(f"  6. sleep {args.post_seconds}; dump {cls_map} (snapshot B)")
        print(f"  7. compare deltas; kathara exec {args.switch} -- ip link set dev {args.fail_iface} up")
        print(f"  8. kill pipeline + sender, detach XDP")
        return

    dest_ip = get_iface_ip(args.switch, args.ingress_iface)
    print(f"[frr-test] {args.ingress_iface} on {args.switch} = {dest_ip}")

    _run(_kexec(args.switch, "ip", "link", "set", "dev", args.ingress_iface, "xdp", "off"))

    print(f"\n[frr-test] Starting pipeline on {args.switch} (background)...")
    pipeline_proc = subprocess.Popen(
        _kexec(args.switch, "python3", "/shared/execute_pipeline.py",
               "--method", args.method, "--iface", args.ingress_iface,
               "--model-id", str(args.model_id)),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    class_to_iface = {}
    t_wait = time.time() + 15
    while time.time() < t_wait:
        line = pipeline_proc.stdout.readline()
        if not line:
            break
        print(f"    [pipeline] {line.rstrip()}")
        m = re.search(rf"{mac_table}: class (\d+) -> (eth\d+)", line)
        if m:
            class_to_iface[int(m.group(1))] = m.group(2)
        if "Stats:" in line or len(class_to_iface) >= 1 and "TRUE HIT" in line:
            break

    fail_class = next((c for c, ifc in class_to_iface.items() if ifc == args.fail_iface), None)
    if fail_class is None:
        print(f"[frr-test] WARNING: could not determine which class maps to {args.fail_iface} "
              f"from startup output ({class_to_iface}). Proceeding anyway -- "
              f"inspect cls_stats manually if the verdict below looks wrong.")
    else:
        print(f"[frr-test] {args.fail_iface} = class {fail_class}")

    try:
        print(f"\n[frr-test] Starting flood from {args.sender} -> {dest_ip} for {total_duration:.0f}s...")
        sender_proc = subprocess.Popen(
            _kexec(args.sender, "python3", "/shared/test/bench_live_throughput.py",
                   "--dest-ip", dest_ip, "--duration", str(total_duration),
                   "--model-id", str(args.model_id)),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        time.sleep(args.pre_seconds)
        snap_a = bpf_map_dump(args.switch, cls_map, args.n_classes)
        print(f"[frr-test] snapshot A (pre-flap) cls_stats: {snap_a}")

        print(f"\n[frr-test] Flapping {args.fail_iface} DOWN on {args.switch}...")
        _run(_kexec(args.switch, "ip", "link", "set", "dev", args.fail_iface, "down"))

        time.sleep(args.post_seconds)
        snap_b = bpf_map_dump(args.switch, cls_map, args.n_classes)
        print(f"[frr-test] snapshot B (post-flap) cls_stats: {snap_b}")

        try:
            sender_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            sender_proc.terminate()

        deltas = {k: snap_b.get(k, 0) - snap_a.get(k, 0) for k in set(snap_a) | set(snap_b)}
        print(f"\n[frr-test] per-class delta (post-flap window): {deltas}")

        if fail_class is not None:
            failed_delta = deltas.get(fail_class, 0)
            other_growth = sum(v for k, v in deltas.items() if k != fail_class)
            verdict = (failed_delta == 0 and other_growth > 0)
            print(f"\n[frr-test] class {fail_class} ({args.fail_iface}) delta after flap: {failed_delta} "
                  f"(expect 0 -- traffic must stop going there)")
            print(f"[frr-test] other classes' combined delta: {other_growth} "
                  f"(expect > 0 -- traffic must reroute somewhere)")
            print(f"\n{'PASS' if verdict else 'FAIL'}: reroute {'confirmed' if verdict else 'NOT confirmed'} "
                  f"within {args.post_seconds:.0f}s of the real carrier flap")
            sys.exit(0 if verdict else 1)
        else:
            print("\n[frr-test] INCONCLUSIVE: fail_iface's class unknown, inspect the deltas above manually.")
            sys.exit(2)

    finally:
        print("\n[frr-test] Cleaning up...")
        _run(_kexec(args.switch, "ip", "link", "set", "dev", args.fail_iface, "up"))
        pipeline_proc.terminate()
        _run(_kexec(args.switch, "pkill", "-f", "execute_pipeline.py"))
        _run(_kexec(args.switch, "ip", "link", "set", "dev", args.ingress_iface, "xdp", "off"))


if __name__ == "__main__":
    main()
