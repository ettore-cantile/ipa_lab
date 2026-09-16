#!/usr/bin/env python3
"""
test_class_semantics.py -- the class -> action -> port -> ifindex chain.

Userspace by default; `--kernel` additionally compiles the generated P1/AOT
sources and runs the pipelines (needs Linux + BCC + root).

The five configurations the datapath must handle, none of them Germany50:

  A  n_out=4, DROP=1, FORWARD on ports 0 and 3, class 2 UNUSED
  B  n_out=7, DROP=5, FORWARD on ports 0..4, class 6 UNUSED
  C  n_out=3, no DROP class at all
  D  n_out=5, DROP=0, FORWARD on non-consecutive ports
  E  n_out different from the node's interface count

Case B is the checked-in model's REAL semantics: its trained DROP class is 5
(dataset.py maps label -1 to max(label)+1 = 5) while the datapath used to
hardcode 6. Case B therefore doubles as a regression test for that bug.

    python3 shared/test/test_class_semantics.py
    sudo python3 shared/test/test_class_semantics.py --kernel
"""

import argparse
import os
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

from class_semantics import (ClassSemantics, ClassSpec, SemanticsError,   # noqa: E402
                             format_decision, MAX_N_OUT, ACT_INVALID,
                             ACT_FORWARD, ACT_DROP, ACT_UNUSED)
from label_mapping import identity_ports_with_drop                        # noqa: E402
import node_config as NC                                                  # noqa: E402

GREEN, RED, YELLOW, NC_ = "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0m"
_p = _f = 0


def ok(m):
    global _p
    _p += 1
    print(f"  {GREEN}[PASS]{NC_} {m}")


def bad(m):
    global _f
    _f += 1
    print(f"  {RED}[FAIL]{NC_} {m}")


def info(m):
    print(f"  {YELLOW}[INFO]{NC_} {m}")


def check(c, m):
    ok(m) if c else bad(m)
    return c


# ---------------------------------------------------------------------------
def cases():
    """The five required configurations."""
    A = ClassSemantics(4, {0: ClassSpec("FORWARD", 0), 1: ClassSpec("DROP"),
                           2: ClassSpec("UNUSED"), 3: ClassSpec("FORWARD", 3)},
                       drop_class=1)
    B = ClassSemantics.forward_then_drop(5, drop_class=5, n_out=7)
    C = ClassSemantics.forward_then_drop(3, drop_class=None)
    D = ClassSemantics(5, {0: ClassSpec("DROP"), 1: ClassSpec("FORWARD", 3),
                           2: ClassSpec("FORWARD", 7), 3: ClassSpec("UNUSED"),
                           4: ClassSpec("FORWARD", 1)}, drop_class=0)
    E = ClassSemantics.forward_then_drop(2, drop_class=2, n_out=3)
    return [("A", A), ("B", B), ("C", C), ("D", D), ("E", E)]


def t_descriptor():
    print(f"\n{YELLOW}[1] Descriptor validation{NC_}")
    for name, sem in cases():
        try:
            sem.validate()
            ok(f"case {name}: n_out={sem.n_out} drop={sem.drop_class} "
               f"ports={sem.logical_ports} unused={sem.unused_classes}")
        except SemanticsError as e:
            bad(f"case {name}: {e}")

    # every class in range, none missing, none duplicated
    for name, sem in cases():
        c1 = all(0 <= c < sem.n_out for c in sem.classes)
        c2 = set(sem.classes) == set(range(sem.n_out))
        c3 = sem.drop_class is None or sem.classes[sem.drop_class].action == "DROP"
        c4 = all(sem.classes[c].port is not None for c in sem.forward_classes)
        c5 = all(sem.port_of(c) is None for c in sem.unused_classes)
        check(c1 and c2 and c3 and c4 and c5,
              f"case {name}: in range / complete / drop agrees / FORWARD has "
              f"port / UNUSED has none")

    # round trip through JSON
    for name, sem in cases():
        back = ClassSemantics.from_json(sem.to_json())
        check(back.to_json() == sem.to_json(), f"case {name}: JSON round trip")


def t_rejections():
    print(f"\n{YELLOW}[2] Incoherences must be refused, not guessed{NC_}")
    bads = [
        ("class missing semantics", lambda: ClassSemantics(3, {0: ClassSpec("FORWARD", 0)})),
        ("class out of range", lambda: ClassSemantics(
            2, {0: ClassSpec("FORWARD", 0), 1: ClassSpec("UNUSED"), 5: ClassSpec("DROP")})),
        ("two DROP classes", lambda: ClassSemantics(
            3, {0: ClassSpec("DROP"), 1: ClassSpec("DROP"), 2: ClassSpec("FORWARD", 0)},
            drop_class=0)),
        ("drop_class points at non-DROP", lambda: ClassSemantics(
            2, {0: ClassSpec("FORWARD", 0), 1: ClassSpec("UNUSED")}, drop_class=1)),
        ("DROP class but drop_class null", lambda: ClassSemantics(
            2, {0: ClassSpec("FORWARD", 0), 1: ClassSpec("DROP")})),
        ("two classes claim one port", lambda: ClassSemantics(
            2, {0: ClassSpec("FORWARD", 1), 1: ClassSpec("FORWARD", 1)})),
        ("FORWARD without a port", lambda: ClassSpec("FORWARD")),
        ("DROP with a port", lambda: ClassSpec("DROP", 2)),
        ("n_out above MAX_N_OUT", lambda: ClassSemantics.forward_then_drop(MAX_N_OUT + 4)),
        ("semantics inferred from n_out", lambda: ClassSemantics.from_json({"n_out": 7})),
        ("no FORWARD class at all", lambda: ClassSemantics(
            2, {0: ClassSpec("DROP"), 1: ClassSpec("UNUSED")}, drop_class=0)),
    ]
    for desc, fn in bads:
        try:
            fn()
            bad(f"{desc}: accepted (should have been refused)")
        except SemanticsError:
            ok(f"{desc}: refused")


def t_action_table():
    print(f"\n{YELLOW}[3] The datapath's view (class_action map contents){NC_}")
    for name, sem in cases():
        tbl = sem.action_table()
        c1 = len(tbl) == MAX_N_OUT
        c2 = all(tbl[c][0] == ACT_INVALID for c in range(sem.n_out, MAX_N_OUT))
        c3 = all(tbl[c][0] == ACT_FORWARD and tbl[c][1] == sem.port_of(c)
                 for c in sem.forward_classes)
        c4 = sem.drop_class is None or tbl[sem.drop_class][0] == ACT_DROP
        c5 = all(tbl[c][0] == ACT_UNUSED for c in sem.unused_classes)
        check(c1 and c2 and c3 and c4 and c5,
              f"case {name}: table sized to the ceiling, past-n_out entries "
              f"INVALID, FORWARD carries its port, DROP/UNUSED tagged")


def t_chain_and_logging():
    print(f"\n{YELLOW}[4] class -> action -> logical_port, and the log line{NC_}")
    _, D = cases()[3]
    exp = {0: ("DROP", None), 1: ("FORWARD", 3), 2: ("FORWARD", 7),
           3: ("UNUSED", None), 4: ("FORWARD", 1)}
    allok = True
    for c, (a, p) in exp.items():
        got = (D.action_of(c), D.port_of(c))
        if got != (a, p):
            allok = False
            bad(f"case D class {c}: got {got}, expected {(a, p)}")
    check(allok, "case D: non-consecutive ports resolved correctly "
                 "(class 1->port 3, class 2->port 7, class 4->port 1)")
    check(D.action_of(9) == "INVALID" and D.action_of(-1) == "INVALID",
          "out-of-range classes report INVALID rather than a guessed action")

    check(format_decision(1, D, ifindex=207, iface="eth3")
          == "class=1 action=FORWARD logical_port=3 ifindex=207 iface=eth3",
          "log line keeps class / action / logical_port / ifindex distinct")
    check(format_decision(0, D) == "class=0 action=DROP",
          "DROP line carries no port or interface")
    check(format_decision(3, D) == "class=3 action=UNUSED",
          "UNUSED line carries no port or interface")

    # the old decode_nexthop convention must be gone
    from test_suite import decode_nexthop
    s = decode_nexthop(2, semantics=D)
    check("eth1" not in s and "logical_port=7" in s,
          f"decode_nexthop no longer prints eth(class-1): {s!r}")


def t_node_resolution():
    print(f"\n{YELLOW}[5] logical_port -> ifindex (node layer){NC_}")
    _, D = cases()[3]
    cfg = NC.NodeConfig.resolve(D.logical_ports, hostname="testnode")
    check(set(cfg.bindings) == set(D.logical_ports),
          f"only the ports the model can select are resolved: {sorted(cfg.bindings)}")
    check(cfg.port_to_iface[7] == "eth7",
          "default node convention maps logical port 7 to eth7 (a NODE default, "
          "not a datapath assumption)")

    # case E: model asks for fewer ports than the node has, and vice versa
    _, E = cases()[4]
    cfg2 = NC.NodeConfig.resolve(E.logical_ports, hostname="testnode")
    check(len(cfg2.bindings) == E.n_logical_ports == 2,
          f"case E: n_out={E.n_out} but only {E.n_logical_ports} logical ports "
          f"-- n_out != interface count")

    # an explicit non-identity mapping
    cfg3 = NC.NodeConfig.resolve([0, 3], port_to_iface={0: "wanA", 3: "wanB"},
                                 hostname="testnode")
    check(cfg3.port_to_iface == {0: "wanA", 3: "wanB"},
          "node may map logical ports onto arbitrary interface names")

    try:
        NC.NodeConfig.resolve([0, 9], port_to_iface={0: "eth0"}, hostname="t")
        bad("a port with no interface mapping was accepted")
    except NC.NodeConfigError:
        ok("a model port the node cannot map is refused at resolution time")

    probs = cfg.validate(D.logical_ports, strict=False)
    info(f"on this host none of eth1/3/7 exist, so validate() reports "
         f"{len(probs)} unrealisable port(s) -- expected off-node")
    try:
        cfg.validate(D.logical_ports, strict=True)
        info("strict validate() passed (interfaces happen to exist here)")
    except NC.NodeConfigError:
        ok("strict validate() fails before a run rather than redirecting blind")

    # topology must not be able to override class semantics
    import json as _json
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        _json.dump({"n_nodes": 52, "drop_class": 3}, f)
        path = f.name
    try:
        NC.load_topology(path)
        bad("a topology declaring drop_class was accepted")
    except NC.NodeConfigError:
        ok("topology declaring drop_class is refused (semantics belong to the model)")
    finally:
        os.unlink(path)


def t_label_mapping():
    print(f"\n{YELLOW}[6] Dataset label -> class, declared not derived{NC_}")
    m = identity_ports_with_drop([0, 1, 2, 3, 4], drop_label=-1, drop_class=5)
    check(m.n_out == 6, f"n_out follows the mapping ({m.n_out}), no spare class")
    check(m.verify([-1, 0, 1, 2, 3, 4], strict=False) == [],
          "declared mapping matches the germany50 label set")
    sem = m.to_class_semantics()
    check(sem.drop_class == 5 and sem.action_of(5) == "DROP",
          "the trained DROP class is 5 -- what the data says, not n_out-1")

    probs = m.verify([0, 1, 2, 3, 4], strict=False)
    check(any("no label -1" in p or "label -1" in p for p in probs),
          "a declared DROP class with no DROP rows is reported")
    probs = m.verify([-1, 0, 1, 2, 3, 4, 9], strict=False)
    check(any("9" in p for p in probs), "an unmapped label is reported")

    try:
        identity_ports_with_drop([0, 1], drop_label=-1, drop_class=None)
        bad("drop_label without drop_class accepted")
    except SemanticsError:
        ok("drop_label without drop_class refused (no automatic derivation)")

    m7 = identity_ports_with_drop([0, 1, 2, 3, 4], -1, 5, n_out=7)
    check(m7.unused_classes == [6],
          "keeping the checkpoint's n_out=7 makes class 6 an explicit UNUSED, "
          "not a repurposed DROP")


def t_codegen():
    print(f"\n{YELLOW}[7] P1 / AOT generate the declared semantics{NC_}")
    import json
    from ebpf_program import generate_ebpf_hardcoded
    with open(os.path.join(SHARED_DIR, "weights.json")) as f:
        w = json.load(f)

    for name, sem in cases():
        if sem.n_out != 7:
            continue                      # weights.json is a 7-output model
        src = generate_ebpf_hardcoded(w, 24, 0, semantics=sem)
        c1 = f"case {sem.drop_class}: {{" in src and "return XDP_DROP;" in src
        c2 = all(f"case {c}: _port = {sem.port_of(c)}U;" in src
                 for c in sem.forward_classes)
        c3 = all(f"case {c}: {{" in src for c in sem.unused_classes)
        c4 = "best_cls >= 6" not in src and "best_cls >= 5" not in src
        check(c1 and c2 and c3 and c4,
              f"case {name}: P1 emits DROP on class {sem.drop_class}, ports "
              f"{sem.logical_ports}, UNUSED {sem.unused_classes}, and no "
              f"index comparison")

    # a descriptor whose n_out disagrees with the model must be refused
    try:
        generate_ebpf_hardcoded(w, 24, 0,
                                semantics=ClassSemantics.forward_then_drop(2, 2, n_out=3))
        bad("P1 accepted semantics whose n_out contradicts the model")
    except ValueError:
        ok("P1 refuses semantics whose n_out contradicts the model")


def t_kernel():
    print(f"\n{YELLOW}[8] In-kernel: DROP drops, FORWARD redirects, UNUSED passes{NC_}")
    try:
        from bcc import BPF
        import json
    except Exception as e:
        info(f"BCC unavailable ({e}) -- kernel section skipped")
        return
    from ebpf_program import build_combined_hardcoded_source
    with open(os.path.join(SHARED_DIR, "weights.json")) as f:
        w = json.load(f)
    _, B = cases()[1]
    try:
        src = build_combined_hardcoded_source([(0, w, 24, None)], semantics=B)
        b = BPF(text=src)
        b.load_func("model_0", BPF.XDP)
        b.load_func("ipa_switch_hardcoded", BPF.XDP)
        ok("P1 with the real semantics (DROP=5, class 6 UNUSED) passes the verifier")
    except Exception as e:
        bad(f"P1 verifier: {e}")
    for lbl, mod in (("P2", "ebpf_template_arch"), ("P3", "ebpf_modular")):
        try:
            __import__(mod)
            ok(f"{lbl} control plane importable with the class_action map")
        except Exception as e:
            bad(f"{lbl}: {e}")
    info("full per-class runtime behaviour: run test_suite.py --only kernel")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kernel", action="store_true")
    a = ap.parse_args()
    print(f"{YELLOW}=== class -> action -> port -> ifindex: verification ==={NC_}")
    t_descriptor()
    t_rejections()
    t_action_table()
    t_chain_and_logging()
    t_node_resolution()
    t_label_mapping()
    t_codegen()
    if a.kernel:
        t_kernel()
    tot = _p + _f
    col = GREEN if _f == 0 else RED
    print(f"\n{YELLOW}{'=' * 60}{NC_}")
    print(f"{col} {_p}/{tot} checks passed{NC_}")
    print(f"{YELLOW}{'=' * 60}{NC_}")
    return 0 if _f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
