#!/usr/bin/env python3
"""test_forwarding.py -- do packets come out of the port the model chose?

The program is attached to a real veth interface, a frame is injected, and the
test reads which interface it left by (or that it was dropped). Needs root.

Usage:
    sudo python3 ipa/test/test_forwarding.py
    sudo python3 ipa/test/test_forwarding.py --method aot
    sudo python3 ipa/test/test_forwarding.py --sweep
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
    """logical port -> {ifindex, MACs}, with the FABRIC's real ifindexes."""
    import check_pipelines as V
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
    """Is this the frame the test injected, or the kernel talking to itself?"""
    if len(data) < 38:
        return False
    if int.from_bytes(data[12:14], "big") != 0x0800:
        return False
    if data[23] != 17:
        return False
    return int.from_bytes(data[36:38], "big") == 9999


def _cases_covering_classes(V, weights, scale, model_id, n_out, max_ttl=30,
                            ingress_port=0, node_index=None):
    """One (link_state, ttl) per output class the model can actually reach."""
    import itertools
    found = {}
    n_ls = 6
    m = V._mut()
    if m is not None:
        n_ls = (m.feature("link_state") or {"size": 0})["size"]
    for bits in itertools.product([0, 1], repeat=n_ls):
        for ttl in range(2, max_ttl + 1):
            cls = V.ref_infer(weights, scale, ttl, model_id,
                              ingress_port=ingress_port,
                              node_index=node_index,
                              link_state=list(bits))[0]
            if cls not in found:
                found[cls] = (list(bits), ttl)
            if len(found) == n_out:
                return found
    return found

def _cases_widened(model, cases, n_out, max_ttl, ingress_port, node_index,
                   budget=20000, seed=20260929):
    """The classes the link_state x TTL search left out, searched again over
    EVERY input the node controls."""
    import random
    import pipeline_setup as PS
    size = {f["type"]: f["size"] for f in model.features}
    out = {c: (ls, ttl, {"port": ingress_port, "node": node_index,
                         "queues": None})
           for c, (ls, ttl) in cases.items()}
    rng = random.Random(seed)
    for _ in range(budget):
        if len(out) == n_out:
            break
        ls = [rng.randint(0, 1) for _ in range(size.get("link_state", 0))]
        q = [rng.randint(0, 15) for _ in range(size.get("queue_occupancy", 0))]
        ttl = rng.randint(2, max(2, max_ttl))
        port = rng.randint(0, size["ingress_iface"]) if "ingress_iface" in size else 0
        node = rng.randrange(size["node"]) if "node" in size else None
        cls, _ = PS.reference(model, ttl, link_state=ls or None,
                              ingress_port=port, node_index=node,
                              queues=q or None)
        if cls not in out:
            out[cls] = (ls, ttl, {"port": port, "node": node,
                                  "queues": q or None})
    return out


def _counter_snapshot(m, n):
    """Current values of a counter array, summed over CPUs, as a list."""
    from stats_maps import read_counter
    return [read_counter(m, i) for i in range(n)]


def _delta(before, after):
    """Indices whose counter moved, with how much."""
    return {i: after[i] - before[i]
            for i in range(min(len(before), len(after)))
            if after[i] != before[i]}

_MAC_NAME = {1: "mac_table", 2: "mac_table_t2", 3: "mac_table_t3"}
_INGRESS_NAME = {1: "ingress_port", 2: "ingress_port_t2", 3: "ingress_port_t3"}
_NODEID_NAME = {1: "node_id", 2: "node_id_t2", 3: "node_id_t3"}
FABRIC_NODE_INDEX = 7
FABRIC_INGRESS_SLOT = 1
_SETUP = {"hardcoded": "setup_hardcoded",
          "template": "setup_template",
          "modular": "setup_modular"}


def _deliver_cases(fab, b, sem, n_out, cases, V, weights, scale,
                   ingress_port, node_index, cls_map, pkt_map, timeout,
                   wire=None):
    """Inject one frame per class case and check where it came out."""
    from common import write_vector_map
    delivered = 0
    for exp_cls in sorted(cases):
        ls, ttl = cases[exp_cls][:2]
        extra = cases[exp_cls][2] if len(cases[exp_cls]) > 2 else None
        write_vector_map(b, "link_state", ls)
        if extra is not None:
            import pipeline_setup as PS
            ingress_port, node_index = wire(extra)
            got_cls = PS.reference(V._mut(), ttl, link_state=ls or None,
                                   ingress_port=ingress_port,
                                   node_index=node_index,
                                   queues=extra["queues"])[0]
        else:
            got_cls = V.ref_infer(weights, scale, ttl, 0,
                                  ingress_port=ingress_port,
                                  node_index=node_index, link_state=ls)[0]
        assert got_cls == exp_cls, (
            f"the case search and the per-case reference disagree "
            f"({exp_cls} vs {got_cls}) on the same input -- they are "
            f"not being given the same ingress_port")
        action = sem.action_of(exp_cls)
        exp_port = sem.port_of(exp_cls) if action == "FORWARD" else None
        lsd = "".join(map(str, ls))
        if extra is not None:
            lsd += (f" port={ingress_port} node={node_index}"
                    + (f" queues={''.join(map(str, extra['queues']))}"
                       if extra["queues"] else ""))

        cls_before = _counter_snapshot(cls_map, n_out)
        pkt_before = _counter_snapshot(pkt_map, 3)

        frame = V.build_frame(0, ttl, scale)
        got_port, data = fab.send_and_capture(frame, timeout=timeout,
                                              match=_is_probe_frame)

        cls_d = _delta(cls_before,
                       _counter_snapshot(cls_map, n_out))
        pkt_d = _delta(pkt_before,
                       _counter_snapshot(pkt_map, 3))
        chosen = max(cls_d, key=cls_d.get) if cls_d else None
        pkt_names = {0: "HIT", 1: "MISS", 2: "DROP"}
        why = ", ".join(f"{pkt_names.get(i, i)}+{v}"
                        for i, v in sorted(pkt_d.items())) or "no counter moved"

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
    return delivered


def run_one(method, model_path, ttl_range, xdp_mode, timeout, verbose):
    import check_pipelines as V
    from netns_fabric import NetnsFabric
    from common import attach_xdp, detach_xdp
    import model_meta as mm

    mut = V._mut()
    if mut is not None:
        import pipeline_setup as PS
        n_out, sem = mut.n_out, mut.semantics
    else:
        n_out = mm.derive_shape(mm.load_model_meta(
            os.path.join(SHARED_DIR, "weights.json")),
            topology_config=mm.load_topology_config())["n_out"]
        sem = mm.load_class_semantics(os.path.join(SHARED_DIR, "weights.json"), n_out)
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

        ing_name = _INGRESS_NAME[setup["pipeline"]]
        ingress_port = FABRIC_INGRESS_SLOT
        if mut is not None:
            ingress_port = PS.ingress_slot_for(mut, FABRIC_INGRESS_SLOT) or 0
        try:
            if not ingress_port:
                raise KeyError("the model has no ingress_iface feature")
            b[ing_name][ct.c_uint32(fab.ingress_ifindex)] = \
                ct.c_uint32(ingress_port)
            if verbose:
                info(f"{ing_name}: ifindex {fab.ingress_ifindex} "
                     f"({fab.ingress}) -> one-hot slot {ingress_port}")
        except Exception as e:
            ingress_port = 0
            info(f"{ing_name} unavailable ({e}); the ingress_iface feature "
                 f"contributes nothing in this run")

        nid_name = _NODEID_NAME[setup["pipeline"]]
        node_index = FABRIC_NODE_INDEX
        if mut is not None:
            node_index = PS.node_index_for(mut, FABRIC_NODE_INDEX)
        try:
            if node_index is None:
                raise KeyError("the model has no node feature")
            b[nid_name][ct.c_uint32(0)] = ct.c_uint32(node_index)
            if verbose:
                info(f"{nid_name}: this node is index {node_index}")
        except Exception as e:
            node_index = None
            info(f"{nid_name} unavailable ({e}); the node feature contributes "
                 f"nothing in this run")

        max_ttl = max(ttl_range)
        if mut is not None:
            import model_under_test as MUT
            max_ttl = min(max_ttl, max(2, MUT.initial_ttl(mut)))
        cases = _cases_covering_classes(V, weights, scale, 0, n_out,
                                        max_ttl=max_ttl,
                                        ingress_port=ingress_port,
                                        node_index=node_index)
        missing = [c for c in range(n_out) if c not in cases]
        info(f"classes reachable by varying link_state and ttl: "
             f"{sorted(cases)}" + (f"; unreachable: {missing}" if missing else ""))
        wire = None
        if mut is not None:
            first = set(cases)
            cases = _cases_widened(mut, cases, n_out, max_ttl,
                                   ingress_port, node_index)
            missing = [c for c in range(n_out) if c not in cases]
            info(f"classes reachable varying also ingress port, node and "
                 f"queues: {sorted(cases)} (new: "
                 f"{sorted(set(cases) - first) or 'none'})"
                 + (f"; unreachable: {missing}" if missing else ""))
            from common import write_vector_map

            def wire(extra):
                """This case's ingress port, node and queues, into the maps."""
                PS.set_ingress(setup, fab.ingress_ifindex, extra["port"])
                PS.set_node(setup, extra["node"])
                qf = mut.feature("queue_occupancy")
                if qf is not None:
                    write_vector_map(b, "queue_state",
                                     extra["queues"] or [0] * qf["size"])
                return extra["port"], extra["node"]

        attach_xdp(b, setup["disp"], iface=fab.ingress, mode=xdp_mode)
        try:
            _deliver_cases(fab, b, sem, n_out, cases, V, weights, scale,
                           ingress_port, node_index, setup["cls_stats"],
                           setup["pkt_stats"], timeout, wire=wire)
        finally:
            try:
                detach_xdp(b, iface=fab.ingress, mode=xdp_mode)
            except Exception as e:
                info(f"detach: {e}")


def run_aot(model_path, ttl_range, xdp_mode, timeout, verbose):
    """P1 as it is DEPLOYED, on the same fabric and with the same checks."""
    import subprocess
    import check_pipelines as V
    from netns_fabric import NetnsFabric
    import model_meta as mm
    from common import ingress_port_slots
    from ebpf_program import load_and_generate
    sys.path.insert(0, os.path.join(SHARED_DIR, "methods"))
    import method4_hardcoded_aot as M4

    print(f"\n{YELLOW}=== aot (P1 as deployed) on a real datapath "
          f"({xdp_mode} XDP) ==={NC}")

    r = subprocess.run([sys.executable,
                        os.path.join(SHARED_DIR, "methods",
                                     "method4_hardcoded_aot.py"),
                        "--build-only", "--model", model_path],
                       capture_output=True, text=True)
    o_path = os.path.join(M4.POC_DIR, "nn_aot_arch.o")
    loader = os.path.join(M4.POC_DIR, "loader_aot")
    built = "[AOT] build complete:" in r.stdout
    if not (built and os.path.exists(o_path) and os.path.exists(loader)):
        fail(f"aot: build failed (rc={r.returncode}): "
             f"{(r.stderr or r.stdout).strip()[-400:]}")
        return
    ok("aot: object and loader built by method4_hardcoded_aot.py")

    meta = mm.load_model_meta(model_path)
    topo = mm.load_topology_config()
    shape = mm.derive_shape(meta, topology_config=topo)
    n_out = shape["n_out"]
    sem = mm.load_class_semantics(model_path, n_out)
    ports = sem.logical_ports
    _, weights, scale = load_and_generate(model_path, meta=meta,
                                          topology_config=topo)

    saved_env = {k: os.environ.get(k) for k in ("IPA_PORT_MAP", "IPA_NODE_ID")}
    with NetnsFabric(n_ports=len(ports), verbose=verbose) as fab:
        os.environ["IPA_PORT_MAP"] = ",".join(
            f"{p}={fab.port_to_iface[p]}" for p in ports
            if p in fab.port_to_iface)
        os.environ["IPA_NODE_ID"] = str(FABRIC_NODE_INDEX)
        pin_dir = "/sys/fs/bpf/ipa_p1_fabric_test"
        cmd = [loader, o_path, "--attach", str(fab.ingress_ifindex),
               "--xdp-mode", xdp_mode, "--pin-dir", pin_dir]
        dep = M4.AotDeploy(cmd, pin_dir, sem, n_nodes=topo.get("n_nodes"),
                           monitor=False, echo=verbose)
        try:
            b = dep.start()
            ok(f"aot: loader READY -> control plane -> ATTACHED "
               f"({xdp_mode}), maps pinned under {pin_dir}")

            wrong = []
            for p in ports:
                e = b["mac_table"][ct.c_uint32(p)]
                if e.ifindex != fab.ifindex_of.get(p):
                    wrong.append((p, e.ifindex, fab.ifindex_of.get(p)))
            good = not wrong
            (ok if good else fail)(
                "aot: mac_table installed by the deploy's control plane: "
                + ("every port -> its fabric ifindex "
                   f"{[fab.ifindex_of[p] for p in ports]}, none -> 1 (lo)"
                   if good else f"wrong entries (port, got, want): {wrong}"))

            slots = ingress_port_slots(dep.node_cfg, ports)
            ingress_port = slots.get(fab.ingress_ifindex, 0)
            node_index = FABRIC_NODE_INDEX
            cases = _cases_covering_classes(V, weights, scale, 0, n_out,
                                            max_ttl=max(ttl_range),
                                            ingress_port=ingress_port,
                                            node_index=node_index)
            missing = [c for c in range(n_out) if c not in cases]
            info(f"classes reachable by varying link_state and ttl: "
                 f"{sorted(cases)}" + (f"; unreachable: {missing}"
                                       if missing else ""))
            _deliver_cases(fab, b, sem, n_out, cases, V, weights, scale,
                           ingress_port, node_index, b["cls_stats"],
                           b["pkt_stats"], timeout)
        finally:
            rc = dep.stop()
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            (ok if rc == 0 else fail)(
                f"aot: loader detached and exited (rc={rc})")
            (ok if not os.path.exists(pin_dir) else fail)(
                f"aot: pins removed ({pin_dir} "
                f"{'gone' if not os.path.exists(pin_dir) else 'STILL THERE'})")


# --- N topologies x N models ---

SWEEP_CASES = [
    (3, 8, (4, 4), 101),
    (4, 16, (6,), 202),
    (5, 24, (4, 4, 4), 303),
    (2, 6, (3, 3), 404),
    (6, 52, (4, 4), 505),
]


def _weight_count(n_in, dims, n_out):
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))


def run_sweep(timeout, xdp_mode, verbose):
    """One (topology, model) pair per case, each on its own fabric."""
    import json
    import random as _random
    import tempfile
    import model_meta as mm
    import check_pipelines as V
    import p1_aot
    from class_semantics import ClassSemantics
    from common import write_vector_map, attach_xdp, detach_xdp
    from netns_fabric import NetnsFabric

    saved_env = os.environ.get("IPA_TOPOLOGY_CONFIG")
    tmpdir = tempfile.mkdtemp(prefix="ipa-sweep-")

    for n_if, n_nodes, dims, seed in SWEEP_CASES:
        name = f"{n_if}if/{n_nodes}n/{'-'.join(map(str, dims))}"
        print(f"\n{YELLOW}=== topology {name} ==={NC}")

        cfg_path = os.path.join(tmpdir, f"topo_{n_if}_{n_nodes}.json")
        with open(cfg_path, "w") as f:
            json.dump({"topology": f"sweep-{n_if}x{n_nodes}",
                       "n_interfaces": n_if, "n_nodes": n_nodes}, f)
        os.environ["IPA_TOPOLOGY_CONFIG"] = cfg_path
        mm.reset_topology_announcements()

        n_out = n_if + 1
        shape = mm.derive_shape({"n_out": n_out, "hidden_dims": list(dims)},
                                topology_config=mm.load_topology_config())
        n_in = shape["n_in"]
        features = shape["features"]
        sem = ClassSemantics.forward_then_drop(n_if, drop_class=n_if,
                                               n_out=n_out)
        ports = sem.logical_ports
        ls_size = next((f["size"] for f in features
                        if f["type"] == "link_state"), 0)

        rng = _random.Random(seed)
        weights = [rng.randint(-30, 30)
                   for _ in range(_weight_count(n_in, dims, n_out))]
        scale = 24

        if verbose:
            info(f"n_in={n_in} n_out={n_out} ports={ports} "
                 f"weights={len(weights)}")

        try:
            aot = p1_aot.load_p1([(0, weights, scale)], features=features,
                                 n_out=n_out, hidden_dims=dims, semantics=sem)
        except Exception as e:
            fail(f"{name}: compile/verifier failed ({e})")
            continue
        b, disp_fn = aot["b"], aot["disp"]

        with NetnsFabric(n_ports=len(ports), verbose=False) as fab:
            for port in ports:
                ifx = fab.ifindex_of.get(port)
                if ifx is None:
                    continue
                b["mac_table"][ct.c_uint32(port)] = V._FwdAction(
                    ifindex=ifx,
                    src_mac=(ct.c_uint8 * 6)(0x02, 0, 0, 0, 0, 0x01),
                    dst_mac=(ct.c_uint8 * 6)(0x02, 0, 0, 0, 0, 0x02))
            try:
                b["ingress_port"][ct.c_uint32(fab.ingress_ifindex)] = \
                    ct.c_uint32(FABRIC_INGRESS_SLOT)
                ingress_port = FABRIC_INGRESS_SLOT
            except Exception:
                ingress_port = 0
            node_index = min(FABRIC_NODE_INDEX, n_nodes - 1)
            try:
                b["node_id"][ct.c_uint32(0)] = ct.c_uint32(node_index)
            except Exception:
                node_index = None

            ls_all_up = [1] * ls_size
            write_vector_map(b, "link_state", ls_all_up)

            attach_xdp(b, disp_fn, iface=fab.ingress, mode=xdp_mode)
            try:
                seen = {}
                for ttl in range(2, 31):
                    cls, _ = V.ref_infer_sparse(
                        weights, features, dims, n_out, ttl, model_id=0,
                        map_values={"link_state": ls_all_up},
                        ingress_port=ingress_port, node_index=node_index,
                        scale=scale)
                    seen.setdefault(cls, ttl)
                info(f"classes reachable by ttl alone: {sorted(seen)}")

                for cls in sorted(seen):
                    ttl = seen[cls]
                    action = sem.action_of(cls)
                    exp_port = sem.port_of(cls) if action == "FORWARD" else None
                    frame = V.build_frame_sparse(0, ttl, scale, n_in, n_out)
                    got_port, data = fab.send_and_capture(
                        frame, timeout=timeout, match=_is_probe_frame)

                    if action != "FORWARD":
                        if got_port is None:
                            ok(f"{name} ttl={ttl}: class {cls} {action}, "
                               f"nothing left the node")
                        else:
                            fail(f"{name} ttl={ttl}: class {cls} is {action} "
                                 f"but a packet left by port {got_port}")
                    elif got_port == exp_port:
                        ok(f"{name} ttl={ttl}: class {cls} -> port {exp_port} "
                           f"(ifindex {fab.ifindex_of[exp_port]})")
                    elif got_port is None:
                        fail(f"{name} ttl={ttl}: class {cls} -> port "
                             f"{exp_port}, nothing arrived in {timeout}s")
                    else:
                        fail(f"{name} ttl={ttl}: class {cls} -> port "
                             f"{exp_port}, packet left by port {got_port}")
            finally:
                try:
                    detach_xdp(b, iface=fab.ingress, mode=xdp_mode)
                except Exception:
                    pass

    if saved_env is None:
        os.environ.pop("IPA_TOPOLOGY_CONFIG", None)
    else:
        os.environ["IPA_TOPOLOGY_CONFIG"] = saved_env
    mm.reset_topology_announcements()


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("Usage")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--method", choices=list(_SETUP) + ["aot", "all"],
                   default="all",
                   help="hardcoded/template/modular are the BCC builds; aot is "
                        "P1 as it is DEPLOYED -- the prebuilt object, attached "
                        "by loader_aot, maps filled by the deploy's own "
                        "control plane")
    p.add_argument("--model", default=None,
                   help="model: checkpoint, synth:<preset>, a directory or a "
                        ".pt (see model_under_test.py). Without it: the "
                        "configured checkpoint")
    p.add_argument("--topology", default=None,
                   help="scenario in topologies/ (without it: the compatible one)")
    p.add_argument("--ttl-max", type=int, default=30,
                   help="upper bound of the TTL search for per-class inputs")
    p.add_argument("--xdp-mode", choices=["native", "generic", "auto"],
                   default="native",
                   help="native is the deployment path; generic is here so the "
                        "two can be compared on the same fabric")
    p.add_argument("--timeout", type=float, default=0.5,
                   help="how long to wait for a redirected frame (default 0.5s)")
    p.add_argument("--sweep", action="store_true",
                   help="also run N topologies x N models: each case is a "
                        "different interface count, node count and hidden "
                        "shape, on its own fabric, with nothing in common with "
                        "the checked-in checkpoint")
    p.add_argument("--only-sweep", action="store_true",
                   help="run only the sweep")
    p.add_argument("-q", "--quiet", action="store_true")
    a = p.parse_args()

    if sys.platform != "linux":
        sys.exit(f"needs Linux, not {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("needs root: sudo python3 ipa/test/test_forwarding.py")

    from model_meta import default_checkpoint
    import model_under_test as MUT
    mut = MUT.select(a.model, a.topology)
    model_path = default_checkpoint()
    methods = list(_SETUP) + ["aot"] if a.method == "all" else [a.method]
    if mut is not None and not mut.reference and "aot" in methods:
        info(f"aot: the deploy builds the object from a checkpoint; with "
             f"{mut.name} P1 is covered by `hardcoded` (same generator)")
        methods.remove("aot")
    ttl_range = range(2, a.ttl_max + 1)

    print(f"{YELLOW}{'=' * 64}{NC}")
    print(f"{YELLOW} fabric test -- real attach, real redirect, real capture{NC}")
    print(f"{YELLOW}{'=' * 64}{NC}")
    print(f"  model   : {mut.name + ' (' + mut.shape + ')' if mut else model_path}")
    print(f"  ttl     : search 1..{a.ttl_max}")
    print(f"  xdp     : {a.xdp_mode}")

    if not a.only_sweep:
        for m in methods:
            try:
                if m == "aot":
                    run_aot(model_path, ttl_range, a.xdp_mode, a.timeout,
                            verbose=not a.quiet)
                else:
                    run_one(m, model_path, ttl_range, a.xdp_mode, a.timeout,
                            verbose=not a.quiet)
            except Exception as e:
                import pipeline_setup as PS
                if isinstance(e, PS.NotApplicable):
                    info(f"{m}: NOT APPLICABLE to this model ({e})")
                else:
                    fail(f"{m}: {type(e).__name__}: {e}")

    if a.sweep or a.only_sweep:
        try:
            run_sweep(a.timeout, a.xdp_mode, verbose=not a.quiet)
        except Exception as e:
            fail(f"sweep: {type(e).__name__}: {e}")

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
          "own interfaces, so the feature works whatever ifindexes the "
          "kernel assigned.")

    return 1 if _results["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
