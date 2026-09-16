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


def _cases_covering_classes(V, weights, scale, model_id, n_out, max_ttl=30,
                            ingress_port=0):
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
        # From 2: ttl<=1 is never forwarded (a hop must not send a packet
        # whose TTL would reach 0), so those inputs cannot be delivered
        # whatever class the model picks.
        for ttl in range(2, max_ttl + 1):
            cls = V.ref_infer(weights, scale, ttl, model_id,
                              ingress_port=ingress_port,
                              link_state=list(bits))[0]
            if cls not in found:
                found[cls] = (list(bits), ttl)
            if len(found) == n_out:
                return found
    return found

def _counter_snapshot(m, n):
    """Current values of a BPF_ARRAY, as a plain list."""
    out = []
    for i in range(n):
        try:
            v = m[ct.c_int(i)]
        except Exception:
            out.append(0)
            continue
        out.append(int(getattr(v, "value", v)))
    return out


def _delta(before, after):
    """Indices whose counter moved, with how much."""
    return {i: after[i] - before[i]
            for i in range(min(len(before), len(after)))
            if after[i] != before[i]}

_MAC_NAME = {1: "mac_table", 2: "mac_table_t2", 3: "mac_table_t3"}
_INGRESS_NAME = {1: "ingress_port", 2: "ingress_port_t2", 3: "ingress_port_t3"}

# The one-hot slot the fabric's ingress interface occupies. On a real node the
# ingress is one of the node's own ports; the fabric keeps it on a separate
# interface so a redirect back to port 0 stays observable, and then declares it
# as this slot so the ingress_iface feature is actually exercised rather than
# left contributing nothing.
FABRIC_INGRESS_SLOT = 1
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

        # Kernel ifindex -> logical port, the ingress-side mirror of mac_table.
        # Without it the ingress_iface one-hot is empty on any real box, because
        # the kernel ifindex (205, 217, ...) never falls inside [1, n_interfaces].
        ing_name = _INGRESS_NAME[setup["pipeline"]]
        ingress_port = FABRIC_INGRESS_SLOT
        try:
            b[ing_name][ct.c_uint32(fab.ingress_ifindex)] = \
                ct.c_uint32(ingress_port)
            if verbose:
                info(f"{ing_name}: ifindex {fab.ingress_ifindex} "
                     f"({fab.ingress}) -> one-hot slot {ingress_port}")
        except Exception as e:
            ingress_port = 0
            info(f"{ing_name} unavailable ({e}); the ingress_iface feature "
                 f"contributes nothing in this run")

        # --ttl-max now bounds the SEARCH for per-class inputs, not a blind
        # sweep: the sweep was what made 7/7 mean one class seven times.
        cases = _cases_covering_classes(V, weights, scale, 0, n_out,
                                        max_ttl=max(ttl_range),
                                        ingress_port=ingress_port)
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
                                      ingress_port=ingress_port, link_state=ls)[0]
                assert got_cls == exp_cls, (
                    f"the case search and the per-case reference disagree "
                    f"({exp_cls} vs {got_cls}) on the same input -- they are "
                    f"not being given the same ingress_port")
                action = sem.action_of(exp_cls)
                exp_port = sem.port_of(exp_cls) if action == "FORWARD" else None
                lsd = "".join(map(str, ls))

                cls_before = _counter_snapshot(setup["cls_stats"], n_out)
                pkt_before = _counter_snapshot(setup["pkt_stats"], 3)

                frame = V.build_frame(0, ttl, scale)
                got_port, data = fab.send_and_capture(frame, timeout=timeout,
                                                      match=_is_probe_frame)

                cls_d = _delta(cls_before,
                               _counter_snapshot(setup["cls_stats"], n_out))
                pkt_d = _delta(pkt_before,
                               _counter_snapshot(setup["pkt_stats"], 3))
                chosen = max(cls_d, key=cls_d.get) if cls_d else None
                pkt_names = {0: "HIT", 1: "MISS", 2: "DROP"}
                why = ", ".join(f"{pkt_names.get(i, i)}+{v}"
                                for i, v in sorted(pkt_d.items())) or "no counter moved"

                # Question one, and the only one the class semantics answer:
                # did the datapath DECIDE what the reference decided?
                if chosen is not None and chosen != exp_cls:
                    fail(f"link_state={lsd} ttl={ttl}: reference says class "
                         f"{exp_cls}, datapath chose class {chosen} ({why})")
                    continue
                if chosen is None:
                    fail(f"link_state={lsd} ttl={ttl}: expected class "
                         f"{exp_cls}, but the datapath recorded no class at "
                         f"all ({why}) -- the program did not reach argmax, or "
                         f"took a path that does not record one")
                    continue

                if action != "FORWARD":
                    # "nothing arrived" is NOT evidence of a DROP: a lost
                    # redirect, a filtered frame and a program that never ran
                    # all look identical from out here. The counter is.
                    if got_port is not None:
                        fail(f"link_state={lsd} ttl={ttl}: class {exp_cls} is "
                             f"{action} but a packet came out of port {got_port}")
                    elif chosen == exp_cls:
                        ok(f"link_state={lsd} ttl={ttl}: class {exp_cls} "
                           f"{action} recorded ({why}), nothing left the node")
                    else:
                        fail(f"link_state={lsd} ttl={ttl}: expected class "
                             f"{exp_cls} ({action}), nothing left the node but "
                             f"the datapath recorded {chosen} ({why})")
                    continue

                if got_port is None:
                    fail(f"link_state={lsd} ttl={ttl}: datapath chose class "
                         f"{exp_cls} -> port {exp_port} (ifindex "
                         f"{fab.ifindex_of[exp_port]}) and counted {why}, but "
                         f"nothing arrived within {timeout}s -- decided "
                         f"correctly, did not deliver")
                elif got_port != exp_port:
                    fail(f"link_state={lsd} ttl={ttl}: expected class {exp_cls} -> "
                         f"port {exp_port}, packet left by port {got_port}")
                else:
                    delivered += 1
                    dst = data[0:6].hex(":") if data else "?"
                    ok(f"link_state={lsd} ttl={ttl}: class {exp_cls} -> port "
                       f"{exp_port} (ifindex {fab.ifindex_of[exp_port]}), "
                       f"dst_mac={dst}, {why}")

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
    ttl_range = range(2, a.ttl_max + 1)

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

    print("\nThe ingress_iface one-hot is fed from the `ingress_port` map: "
          "kernel ifindex -> logical port, installed above from the fabric's "
          "own interfaces. It used to be indexed by the raw "
          "ctx->ingress_ifindex (P2/P3) or by a switch over a compile-time "
          "[2, 3, ...] table (P1), both of which resolve to nothing on a box "
          "whose ifindexes are 205 and 217 -- a trained feature contributing "
          "zero, with every test still green because none checked that it "
          "contributed anything.")

    return 1 if _results["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
