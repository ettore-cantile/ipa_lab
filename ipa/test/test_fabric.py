#!/usr/bin/env python3
"""
test_fabric.py -- do the packets actually come out of the right port?

What this asks that nothing else does
-------------------------------------
The kernel suite runs each pipeline under BPF_PROG_TEST_RUN and checks that the
return code and the chosen class match an independent reference. That proves
the arithmetic. It cannot prove delivery: TEST_RUN never redirects anything,
because there is no interface to redirect to.

Here the program is attached in NATIVE XDP mode to a real interface, a real
frame is injected, and the test reads which interface it came out of:

    ref_infer(...)            -> class k
    semantics.port_of(k)      -> logical port p
    fabric.ifindex_of[p]      -> the veth the datapath should have picked
    capture                   -> the veth it ACTUALLY left by

A DROP class is checked the same way, by its absence: nothing must arrive
anywhere before the timeout.

Usage
-----
    sudo python3 ipa/test/test_fabric.py                  # all three pipelines
    sudo python3 ipa/test/test_fabric.py --method template
    sudo python3 ipa/test/test_fabric.py --ttl-max 60      # widen the search
    sudo python3 ipa/test/test_fabric.py --xdp-mode generic   # compare paths

Needs Linux + BCC + root.
"""
import argparse
import ctypes as ct
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(HERE)
for _p in (SHARED_DIR, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
NC = "\033[0m"

_results = {"pass": 0, "fail": 0}


def ok(msg):
    _results["pass"] += 1
    print(f"  {GREEN}[PASS]{NC} {msg}")


def fail(msg):
    _results["fail"] += 1
    print(f"  {RED}[FAIL]{NC} {msg}")


def info(msg):
    print(f"  {YELLOW}[INFO]{NC} {msg}")


def _install_fabric_mac_table(b, name, fab, ports):
    """logical port -> {ifindex, MACs}, with the FABRIC's real ifindexes.

    verify_prog_run's _install_mac_table writes the same ifindex for every
    port, which is fine when nothing is ever delivered. Here the ifindex is the
    whole point: a wrong one sends the packet out the wrong veth, and that is
    exactly the failure this test exists to catch.
    """
    import verify_prog_run as V
    installed = {}
    for port in ports:
        ifx = fab.ifindex_of.get(port)
        if ifx is None:
            continue
        b[name][ct.c_uint32(port)] = V._FwdAction(
            ifindex=ifx,
            src_mac=(ct.c_uint8 * 6)(0x02, 0, 0, 0, 0, 0x01),
            dst_mac=(ct.c_uint8 * 6)(0x02, 0, 0, 0, 0, 0x02),
        )
        installed[port] = ifx
    return installed


def _is_probe_frame(data: bytes) -> bool:
    """Is this the frame the test injected, or the kernel talking to itself?

    The datapath rewrites the MACs but leaves L3/L4 alone, so the injected
    frame is still IPv4/UDP to port 9999 when it comes out the other side.
    """
    if len(data) < 38:
        return False
    if int.from_bytes(data[12:14], "big") != 0x0800:      # IPv4
        return False
    if data[23] != 17:                                     # UDP
        return False
    return int.from_bytes(data[36:38], "big") == 9999      # the IPA port


def _cases_covering_classes(V, weights, scale, model_id, n_out, max_ttl=30):
    """One (link_state, ttl) per output class the model can actually reach.

    Sweeping TTL alone is not a test: for the checked-in checkpoint every TTL
    from 2 to 30 returns class 2, so a seven-TTL run exercises one class seven
    times and reports 7/7. link_state is the feature that moves this argmax, so
    the cases are searched rather than listed -- which also keeps this working
    for a different model, where the reachable set will differ.

    Classes with no input that reaches them (an untrained one, typically) are
    simply absent, and the caller reports them as not covered rather than
    failing: unreachable is a property of the model, not a defect of the
    datapath.
    """
    import itertools
    found = {}
    for bits in itertools.product([0, 1], repeat=6):
        for ttl in range(1, max_ttl + 1):
            cls = V.ref_infer(weights, scale, ttl, model_id,
                              ifindex=0, link_state=list(bits))[0]
            if cls not in found:
                found[cls] = (list(bits), ttl)
            if len(found) == n_out:
                return found
    return found

_MAC_NAME = {1: "mac_table", 2: "mac_table_t2", 3: "mac_table_t3"}
_SETUP = {"hardcoded": "setup_hardcoded",
          "template": "setup_template",
          "modular": "setup_modular"}


def run_one(method, model_path, ttl_range, xdp_mode, timeout, verbose):
    import verify_prog_run as V
    from netns_fabric import NetnsFabric
    from common import attach_xdp, detach_xdp
    import model_meta as mm

    n_out = mm.derive_shape(mm.load_model_meta(
        os.path.join(SHARED_DIR, "weights.json")),
        topology_config=mm.load_topology_config())["n_out"]
    sem = mm.load_class_semantics(os.path.join(SHARED_DIR, "weights.json"), n_out)
    _ = n_out
    ports = sem.logical_ports

    print(f"\n{YELLOW}=== {method} on a real datapath "
          f"({len(ports)} ports, {xdp_mode} XDP) ==={NC}")

    with NetnsFabric(n_ports=len(ports), verbose=verbose) as fab:
        if len(fab.pass_attached) < len(ports):
            missing = [p for p in range(len(ports)) if p not in fab.pass_attached]
            info(f"peers without the XDP_PASS stub: {missing} -- a redirect to "
                 f"those ports cannot be delivered, so a miss there is the "
                 f"fabric's fault, not the pipeline's")

        setup = getattr(V, _SETUP[method])(0, model_path)
        b = setup["b"]
        weights, scale = setup["weights"], setup["scale"]

        installed = _install_fabric_mac_table(b, _MAC_NAME[setup["pipeline"]],
                                              fab, ports)
        if verbose:
            info(f"mac_table: {installed}")

        ingress_ifx = fab.ifindex_of[fab.ingress_port]
        if not 1 <= ingress_ifx <= 6:
            info(f"ingress ifindex is {ingress_ifx}, outside the [1,6] the "
                 f"ingress_iface one-hot covers: that feature contributes "
                 f"nothing here. Real kernel ifindexes are arbitrary -- see "
                 f"the note at the end.")

        # --ttl-max now bounds the SEARCH for per-class inputs, not a blind
        # sweep: the sweep was what made 7/7 mean one class seven times.
        cases = _cases_covering_classes(V, weights, scale, 0, n_out,
                                        max_ttl=max(ttl_range))
        missing = [c for c in range(n_out) if c not in cases]
        info(f"classes reachable by varying link_state and ttl: "
             f"{sorted(cases)}" + (f"; unreachable: {missing}" if missing else ""))

        from common import write_vector_map
        attach_xdp(b, setup["disp"], iface=fab.ingress, mode=xdp_mode)
        try:
            delivered = 0
            for exp_cls in sorted(cases):
                ls, ttl = cases[exp_cls]
                # The map and the reference must be told the same thing, or
                # they are answering different questions.
                write_vector_map(b, "link_state", ls)
                got_cls = V.ref_infer(weights, scale, ttl, 0,
                                      ifindex=ingress_ifx, link_state=ls)[0]
                if got_cls != exp_cls:
                    info(f"ingress ifindex {ingress_ifx} moved the reference "
                         f"from class {exp_cls} to {got_cls}; using {got_cls}")
                    exp_cls = got_cls
                action = sem.action_of(exp_cls)
                exp_port = sem.port_of(exp_cls) if action == "FORWARD" else None
                lsd = "".join(map(str, ls))

                frame = V.build_frame(0, ttl, scale)
                got_port, data = fab.send_and_capture(frame, timeout=timeout,
                                                      match=_is_probe_frame)

                if action != "FORWARD":
                    if got_port is None:
                        ok(f"link_state={lsd} ttl={ttl}: class {exp_cls} is {action}"
                           f" -- nothing left the node, as it should not")
                    else:
                        fail(f"link_state={lsd} ttl={ttl}: class {exp_cls} is {action}"
                             f" but a packet came out of port {got_port}")
                    continue

                if got_port is None:
                    fail(f"link_state={lsd} ttl={ttl}: expected class {exp_cls} -> "
                         f"port {exp_port} (ifindex {fab.ifindex_of[exp_port]}), "
                         f"but nothing arrived within {timeout}s")
                elif got_port != exp_port:
                    fail(f"link_state={lsd} ttl={ttl}: expected class {exp_cls} -> "
                         f"port {exp_port}, packet left by port {got_port}")
                else:
                    delivered += 1
                    dst = data[0:6].hex(":") if data else "?"
                    ok(f"link_state={lsd} ttl={ttl}: class {exp_cls} -> port "
                       f"{exp_port} (ifindex {fab.ifindex_of[exp_port]}), "
                       f"dst_mac={dst}")

            if delivered:
                info(f"{delivered} packet(s) redirected and captured on a real "
                     f"interface -- delivery, not just arithmetic")
        finally:
            try:
                detach_xdp(b, iface=fab.ingress, mode=xdp_mode)
            except Exception as e:
                info(f"detach: {e}")


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("Usage")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--method", choices=list(_SETUP) + ["all"], default="all")
    p.add_argument("--model", default=None,
                   help="checkpoint (default: model_meta.default_checkpoint())")
    p.add_argument("--ttl-max", type=int, default=30,
                   help="upper bound of the TTL search for per-class inputs")
    p.add_argument("--xdp-mode", choices=["native", "generic", "auto"],
                   default="native",
                   help="native is the deployment path; generic is here so the "
                        "two can be compared on the same fabric")
    p.add_argument("--timeout", type=float, default=0.5,
                   help="how long to wait for a redirected frame (default 0.5s)")
    p.add_argument("-q", "--quiet", action="store_true")
    a = p.parse_args()

    if sys.platform != "linux":
        sys.exit(f"needs Linux, not {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("needs root: sudo python3 ipa/test/test_fabric.py")

    from model_meta import default_checkpoint
    model_path = a.model or default_checkpoint()
    methods = list(_SETUP) if a.method == "all" else [a.method]
    ttl_range = range(1, a.ttl_max + 1)

    print(f"{YELLOW}{'=' * 64}{NC}")
    print(f"{YELLOW} fabric test -- real attach, real redirect, real capture{NC}")
    print(f"{YELLOW}{'=' * 64}{NC}")
    print(f"  model   : {model_path}")
    print(f"  ttl     : search 1..{a.ttl_max}")
    print(f"  xdp     : {a.xdp_mode}")

    for m in methods:
        try:
            run_one(m, model_path, ttl_range, a.xdp_mode, a.timeout,
                    verbose=not a.quiet)
        except Exception as e:
            fail(f"{m}: {type(e).__name__}: {e}")

    total = _results["pass"] + _results["fail"]
    print(f"\n{YELLOW}{'=' * 64}{NC}")
    if _results["fail"]:
        print(f"{RED} {_results['pass']}/{total} checks passed, "
              f"{_results['fail']} FAILED{NC}")
    else:
        print(f"{GREEN} {_results['pass']}/{total} checks passed{NC}")
    print(f"{YELLOW}{'=' * 64}{NC}")

    print("\nNote on the ingress_iface feature: the datapath reads "
          "ctx->ingress_ifindex, a KERNEL ifindex, and uses it directly as the "
          "one-hot index. On a real box those are arbitrary (15, 17, 19...), "
          "so the feature is dead unless the ifindex is translated into a "
          "logical port first -- the mirror of the egress mapping that already "
          "exists. Pipeline 1 does translate; Pipelines 2 and 3 do not.")

    return 1 if _results["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
