#!/usr/bin/env python3
"""
verify_per_model_semantics.py -- class -> action is a property of the MODEL.

P2 and P3 used to translate the argmax class through ONE class_action table
shared by every model_id, so two models could not give the same class
different meanings, and the control plane refused the second one. The table
is now keyed by (model_id, bank, class): each model owns its rows, and the
bank that is live is committed in the model's registry entry (arch_registry
on P2, layer_registry on P3) together with its n_out / n_layers.

This file checks that claim on the real programs, through the real dispatcher
(BPF_PROG_TEST_RUN, full tail-call path), with ONE program loaded per pipeline
and every model registered into it as data:

  A  single model: every class yields the declared action
  B  two models, same semantics: both correct
  C  two models, different semantics, packets alternating between them
  D  no contamination: A, then B, then A again, also after B is re-registered
  E  unknown model_id, and a removed one: not processed, never another
     model's semantics
  F  different n_out per model: each argmax is bounded by its OWN n_out
  R  re-registering the same model_id replaces n_out + semantics together
     (new bank written, then one registry update flips it), and leaves every
     other model untouched

How the class is controlled. The models are built so that the TTL selects the
class: the only non-zero input weight reads ttl (scale 30, weight 30, so
h1 = ttl exactly), it passes through one unit, and output k gets weight 2k and
bias -(4k + k^2). With scale_factor 1 the logit of class k is then
c^2 - (c - k)^2 for ttl = c + 2, which peaks at k = c alone. Every class of
every model is reachable, the argmax is cross-checked against the independent
Python reference, and a class beyond a model's n_out cannot be produced.

What is observed. FORWARD -> XDP_REDIRECT and the destination MAC the program
wrote, whose last byte is the logical port (mac_table has a distinct next hop
per port); DROP -> XDP_DROP; UNUSED -> XDP_PASS with the class counted;
not processed -> XDP_PASS with no counter moved.

Needs Linux + BCC + root:
    sudo python3 ipa/test/verify_per_model_semantics.py [--pipeline p2|p3]
"""
import argparse
import ctypes as ct
import os
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _dir in (SHARED_DIR, _TEST_DIR):
    if _dir not in sys.path:
        sys.path.insert(0, _dir)
os.chdir(SHARED_DIR)

from class_semantics import ClassSemantics, ClassSpec          # noqa: E402

GREEN, RED, YELLOW, NC = "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0m"
_n_pass = _n_fail = 0

XDP_DROP, XDP_PASS, XDP_REDIRECT = 1, 2, 4
MAC_PREFIX = (0x02, 0x00, 0x00, 0x00, 0x00)   # dst MAC = prefix + logical port
N_PORTS = 5
SCALE = 1          # registry scale_factor: bias multipliers scale**L == 1
TTL_WEIGHT = 30    # == the ttl feature's descriptor scale: h1 = ttl exactly
MISSING_ID = 9


def ok(msg):
    global _n_pass
    _n_pass += 1
    print(f"  {GREEN}[PASS]{NC} {msg}")


def fail(msg):
    global _n_fail
    _n_fail += 1
    print(f"  {RED}[FAIL]{NC} {msg}")


def check(cond, msg):
    ok(msg) if cond else fail(msg)
    return cond


# ---------------------------------------------------------------------------
# Semantics under test
# ---------------------------------------------------------------------------
def _sem(n_out, spec):
    classes = {c: (ClassSpec("FORWARD", a[1]) if a[0] == "F" else
                   ClassSpec("DROP") if a == "D" else ClassSpec("UNUSED"))
               for c, a in enumerate(spec)}
    drops = [c for c, a in enumerate(spec) if a == "D"]
    return ClassSemantics(n_out=n_out, classes=classes,
                          drop_class=drops[0] if drops else None)


# A and B disagree on EVERY class; the user-facing example (0 FORWARD / 1 DROP
# against 0 DROP / 1 FORWARD) is their first two classes.
SEM_A = _sem(4, [("F", 0), "D", ("F", 2), "U"])
SEM_B = _sem(4, ["D", ("F", 1), ("F", 3), ("F", 0)])
# Wider model, the checked-in model's layout: 5 ports, DROP 5, class 6 unused.
SEM_C = ClassSemantics.forward_then_drop(5, drop_class=5, n_out=7)


def expected(sem, cls):
    act = sem.action_of(cls)
    return (act, sem.port_of(cls) if act == "FORWARD" else None, cls)


# ---------------------------------------------------------------------------
# Models whose argmax is chosen by the TTL
# ---------------------------------------------------------------------------
def layer_dims(n_out):
    return [(65, 1), (1, 1), (1, n_out)]


def ttl_for(cls):
    return cls + 2


def ttl_weights(n_out, ttl_col=12):
    """Flat int8 block for 65-1-1-n_out in the layout both loaders write."""
    w = [0] * (65 * 1 + 1 + 1 * 1 + 1 + 1 * n_out + n_out)
    w[ttl_col] = TTL_WEIGHT                     # fc1 row 0, ttl column
    w[65 + 1] = 1                               # fc2 weight [0][0]
    o = 65 + 1 + 1 + 1
    for k in range(n_out):
        w[o + k] = 2 * k                        # out weight [k][0]
        w[o + n_out + k] = -(4 * k + k * k)     # out bias [k]
    return [v & 0xFF for v in w]


def ref_class(n_out, ttl):
    from verify_multi_model import ref_infer_shape
    return ref_infer_shape(ttl_weights(n_out), layer_dims(n_out), ttl, 0,
                           scale=SCALE)[0]


# Every model gets a slice sized for the widest one, so a model_id can be
# re-registered with another n_out without overlapping its neighbour.
SLICE = len(ttl_weights(8))


# ---------------------------------------------------------------------------
# One loaded program per pipeline; models are map entries
# ---------------------------------------------------------------------------
class Harness:
    def __init__(self, pipeline):
        from bcc import BPF
        from verify_prog_run import _seed_link_state, _FwdAction
        self.pipeline = pipeline
        if pipeline == "p2":
            from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                            EBPF_ARCH_GENERIC_2LAYER)
            src = ("#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
                   + "\n" + EBPF_ARCH_GENERIC_2LAYER)
            self.b = BPF(text=src)
            self.disp = self.b.load_func("ipa_switch_template", BPF.XDP)
            leaf = self.b.load_func("arch_generic_2layer", BPF.XDP)
            self.b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
            self.progs = [self.disp.fd, leaf.fd]
            self.registry, sfx = "arch_registry", "t2"
        else:
            from ebpf_modular import EBPF_MODULAR_FULL, LAYER_CHAIN_SIZE
            self.b = BPF(text=EBPF_MODULAR_FULL)
            self.disp = self.b.load_func("modular_dispatcher", BPF.XDP)
            first = self.b.load_func("layer_first", BPF.XDP)
            hidden = self.b.load_func("layer_hidden", BPF.XDP)
            self.b["layer_chain"][ct.c_int(0)] = ct.c_int(first.fd)
            for i in range(1, LAYER_CHAIN_SIZE):
                self.b["layer_chain"][ct.c_int(i)] = ct.c_int(hidden.fd)
            self.progs = [self.disp.fd, first.fd, hidden.fd]
            self.registry, sfx = "layer_registry", "t3"
        self.actions = f"class_action_{sfx}"
        self.ps = self.b[f"pkt_stats_{sfx}"]
        self.cs = self.b[f"cls_stats_{sfx}"]
        _seed_link_state(self.b, 1)
        for port in range(N_PORTS):
            self.b[f"mac_table_{sfx}"][ct.c_uint32(port)] = _FwdAction(
                ifindex=2,
                src_mac=(ct.c_uint8 * 6)(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
                dst_mac=(ct.c_uint8 * 6)(*MAC_PREFIX, port))

    def register(self, model_id, sem, slot):
        w = ttl_weights(sem.n_out)
        if self.pipeline == "p2":
            from ebpf_template_arch import load_arch_weights
            load_arch_weights(self.b, w, model_id=model_id, scale=SCALE,
                              weight_offset=slot * SLICE, n_h1=1, n_h2=1,
                              semantics=sem)
        else:
            from ebpf_modular import load_modular_weights
            load_modular_weights(self.b, w, model_id=model_id, scale=SCALE,
                                 layer_dims=layer_dims(sem.n_out),
                                 base_offset=slot * SLICE, semantics=sem)

    def remove(self, model_id):
        del self.b[self.registry][ct.c_uint8(model_id)]

    def entry(self, model_id):
        """(n_out, [(action, port)] * 32) as the datapath will read it: the
        rows of the bank the registry entry currently commits."""
        from ebpf_template_arch import class_act_key
        e = self.b[self.registry][ct.c_uint8(model_id)]
        n_out = (e.n_out if self.pipeline == "p2" else None)
        tbl = self.b[self.actions]
        rows = []
        for c in range(32):
            r = tbl[ct.c_uint32(class_act_key(model_id, e.sem_bank, c))]
            rows.append((int(r.action), int(r.port)))
        return n_out, rows

    def _u64(self, t, k):
        try:
            return int(t[ct.c_uint32(k)].value)
        except Exception:
            return 0

    def observe(self, model_id, ttl):
        """(action, port, class) the program actually produced."""
        from verify_prog_run import build_frame, prog_test_run_data
        ps0 = [self._u64(self.ps, i) for i in range(3)]
        cs0 = [self._u64(self.cs, i) for i in range(32)]
        rv, _, out = prog_test_run_data(self.disp.fd,
                                        build_frame(model_id, ttl, SCALE))
        dps = [self._u64(self.ps, i) - ps0[i] for i in range(3)]
        fired = [i for i in range(32) if self._u64(self.cs, i) != cs0[i]]
        cls = fired[0] if len(fired) == 1 else None
        if rv == XDP_DROP:
            return ("DROP", None, cls)
        if rv in (0, XDP_REDIRECT):
            dst = tuple(out[0:6])
            port = dst[5] if dst[:5] == MAC_PREFIX else ("mac", dst)
            return ("FORWARD", port, cls)
        if rv == XDP_PASS and cls is not None:
            return ("UNUSED", None, cls)
        if rv == XDP_PASS and dps == [0, 0, 0] and not fired:
            return ("NOT_PROCESSED", None, None)
        return ("OTHER", rv, (dps, fired))


# ---------------------------------------------------------------------------
def sweep(h, model_id, sem, n_classes=None, label=""):
    """Every class of `sem`, through model_id. True if all as declared."""
    bad = []
    for c in range(n_classes or sem.n_out):
        t = ttl_for(c)
        want_cls = min(c, sem.n_out - 1)
        got = h.observe(model_id, t)
        if got != expected(sem, want_cls):
            bad.append((c, got, expected(sem, want_cls)))
    check(not bad, f"{label}model_id={model_id}: "
                   f"{(n_classes or sem.n_out) - len(bad)}/{n_classes or sem.n_out}"
                   f" classes as declared" + (f"  bad={bad[:3]}" if bad else ""))
    return not bad


def run_pipeline(pl):
    print(f"\n{YELLOW}=== {pl.upper()}: per-model class semantics ==={NC}")
    # The class construction itself, against the independent reference.
    refs = {n: [ref_class(n, ttl_for(c)) for c in range(8)] for n in (4, 7)}
    check(refs[4] == [0, 1, 2, 3, 3, 3, 3, 3]
          and refs[7] == [0, 1, 2, 3, 4, 5, 6, 6],
          f"reference: ttl=c+2 selects class c, clamped to n_out-1 "
          f"(n_out=4 {refs[4]}, n_out=7 {refs[7]})")

    h = Harness(pl)
    A, B, A2, C = 1, 2, 3, 4
    n_prog = len(h.progs)

    print(f"{YELLOW}[A] single model{NC}")
    h.register(A, SEM_A, 0)
    sweep(h, A, SEM_A, label="A: ")

    print(f"{YELLOW}[B] two models, same semantics{NC}")
    h.register(A2, SEM_A, 2)
    sweep(h, A, SEM_A, label="B: ")
    sweep(h, A2, SEM_A, label="B: ")

    print(f"{YELLOW}[C] two models, different semantics, alternating{NC}")
    h.register(B, SEM_B, 1)
    bad = []
    for c in range(4):
        for mid, sem in ((A, SEM_A), (B, SEM_B)):
            got = h.observe(mid, ttl_for(c))
            if got != expected(sem, c):
                bad.append((mid, c, got))
    check(not bad, f"C: A and B interleaved, 8/8 decisions follow each "
                   f"model's own table" + (f"  bad={bad}" if bad else ""))
    check(h.observe(A, ttl_for(0)) == ("FORWARD", 0, 0)
          and h.observe(B, ttl_for(0)) == ("DROP", None, 0),
          "C: class 0 -> FORWARD for A, DROP for B")
    check(h.observe(A, ttl_for(1)) == ("DROP", None, 1)
          and h.observe(B, ttl_for(1)) == ("FORWARD", 1, 1),
          "C: class 1 -> DROP for A, FORWARD for B")

    print(f"{YELLOW}[D] no contamination{NC}")
    sweep(h, A, SEM_A, label="D: A before B runs: ")
    sweep(h, B, SEM_B, label="D: B: ")
    sweep(h, A, SEM_A, label="D: A after B ran: ")
    h.register(B, SEM_B, 1)                    # second load of B
    sweep(h, A, SEM_A, label="D: A after B re-registered: ")
    check(h.entry(A)[1] == SEM_A.action_table(),
          "D: A's registry table is still exactly SEM_A")

    print(f"{YELLOW}[E] unknown and removed model_id{NC}")
    got = [h.observe(MISSING_ID, ttl_for(c)) for c in range(4)]
    check(all(g == ("NOT_PROCESSED", None, None) for g in got),
          f"E: model_id={MISSING_ID} never registered -> XDP_PASS, no counter, "
          f"no other model's action ({got[0]})")
    h.remove(A2)
    got = [h.observe(A2, ttl_for(c)) for c in range(4)]
    check(all(g == ("NOT_PROCESSED", None, None) for g in got),
          "E: removed model_id -> not processed (its semantics left with it)")
    sweep(h, A, SEM_A, label="E: A after removing A2: ")
    sweep(h, B, SEM_B, label="E: B after removing A2: ")

    print(f"{YELLOW}[F] different n_out per model{NC}")
    h.register(C, SEM_C, 3)
    sweep(h, C, SEM_C, label="F: C (n_out=7): ")
    # the same TTLs through A: its argmax cannot leave [0, 4)
    sweep(h, A, SEM_A, n_classes=7, label="F: A (n_out=4) on C's 7 TTLs: ")
    if pl == "p2":
        check(h.entry(A)[0] == 4 and h.entry(C)[0] == 7,
              "F: arch_registry keeps n_out=4 for A and n_out=7 for C")
    check([a for a, _ in h.entry(A)[1][4:]] == [0] * 28
          and [a for a, _ in h.entry(C)[1][7:]] == [0] * 25,
          "F: classes past each model's own n_out are ACT_INVALID in its table")

    print(f"{YELLOW}[R] re-registering the same model_id{NC}")
    h.register(A, SEM_B, 0)                    # same n_out, new meanings
    sweep(h, A, SEM_B, label="R: A now carries SEM_B: ")
    sweep(h, B, SEM_B, label="R: B untouched: ")
    sweep(h, C, SEM_C, label="R: C untouched: ")
    h.register(A, SEM_C, 0)                    # new n_out AND new meanings
    n_out_a, tbl_a = h.entry(A)
    check(tbl_a == SEM_C.action_table() and n_out_a in (None, 7),
          "R: one registry entry holds the new n_out and the new table together")
    sweep(h, A, SEM_C, label="R: A as a 7-class model: ")
    sweep(h, B, SEM_B, label="R: B still untouched: ")

    check(len(h.progs) == n_prog,
          f"one {pl.upper()} program set ({n_prog} programs) served "
          f"every model; no model loaded a program")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pipeline", choices=["p2", "p3", "all"], default="all")
    args = p.parse_args()
    if not sys.platform.startswith("linux"):
        print("Needs Linux + BCC + root.")
        return 1
    for pl in (("p2", "p3") if args.pipeline == "all" else (args.pipeline,)):
        run_pipeline(pl)
    total = _n_pass + _n_fail
    colour = GREEN if _n_fail == 0 else RED
    print(f"\n{colour} {_n_pass}/{total} checks passed{NC}")
    return 0 if _n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
