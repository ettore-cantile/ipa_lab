#!/usr/bin/env python3
"""
diag_fabric_divergence.py -- where do the datapath and the reference disagree?

The fabric test found two inputs on which all three pipelines agree with each
other and disagree with ref_infer:

    link_state=100001 ttl=28   reference class 0, datapath class 4
    link_state=000000 ttl=2    reference class 2, datapath DROP (class 5)

Three independent implementations do not make the same mistake, so the
reference is the thing to doubt. But "doubt" is not a diagnosis: the
disagreement could be in layer 1, in layer 2, in the output layer, or in how
the TTL column is divided. This script finds out which, by running the SAME
input through both and comparing the intermediate activations.

Pipeline 3 is used because it is the only one whose intermediates are
observable: it keeps activations in `scratch_acts`, a per-CPU struct-valued
map, between tail-called layer programs. P1 and P2 hold theirs in registers.

    sudo python3 ipa/test/diag_fabric_divergence.py
    sudo python3 ipa/test/diag_fabric_divergence.py --link-state 100001 --ttl 28

Needs Linux + BCC + root. Nothing is attached to any interface: this runs
under BPF_PROG_TEST_RUN, because the question is arithmetic, not delivery.
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

# The cases the fabric test reported. Kept here so the script has something to
# run with no arguments, and so the record of what failed survives the run.
CASES = [("100001", 28), ("000000", 2), ("000001", 24), ("000010", 24),
         ("010000", 2), ("000001", 28)]


def _read_acts(b, width):
    """Activation vector as the kernel left it, folded across CPUs.

    scratch_acts is per-CPU and only the CPU that ran the program wrote
    anything, so the non-zero row is the one that matters.
    """
    try:
        leaf = b["scratch_acts"][ct.c_int(0)]
    except Exception as e:
        return None, f"scratch_acts unreadable ({e})"
    rows = []
    for cpu in range(len(leaf)):
        row = [int(leaf[cpu].v[i]) for i in range(width)]
        if any(row):
            rows.append((cpu, row))
    if not rows:
        return [0] * width, "all CPUs zero"
    if len(rows) > 1:
        return rows[0][1], f"{len(rows)} CPUs non-zero, showing cpu{rows[0][0]}"
    return rows[0][1], f"cpu{rows[0][0]}"


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("    sudo")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--link-state", default=None,
                   help="six 0/1 characters, e.g. 100001 (default: every case "
                        "the fabric test exercises)")
    p.add_argument("--ttl", type=int, default=None)
    p.add_argument("--model", default=None)
    a = p.parse_args()

    if sys.platform != "linux":
        sys.exit(f"needs Linux, not {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("needs root: sudo python3 ipa/test/diag_fabric_divergence.py")

    import verify_prog_run as V
    from common import write_vector_map
    from model_meta import default_checkpoint

    model_path = a.model or default_checkpoint()
    if a.link_state:
        if len(a.link_state) != 6 or set(a.link_state) - set("01"):
            sys.exit("--link-state wants six 0/1 characters, e.g. 100001")
        cases = [(a.link_state, a.ttl if a.ttl is not None else 28)]
    else:
        cases = CASES

    print(f"{YELLOW}{'=' * 70}{NC}")
    print(f"{YELLOW} datapath vs reference, layer by layer (Pipeline 3){NC}")
    print(f"{YELLOW}{'=' * 70}{NC}")
    print(f"  model: {model_path}\n")

    setup = V.setup_modular(0, model_path)
    b, weights, scale = setup["b"], setup["weights"], setup["scale"]
    n_out = 7

    for ls_s, ttl in cases:
        ls = [int(c) for c in ls_s]
        write_vector_map(b, "link_state", ls)

        # Reference: class plus both hidden layers.
        ref_cls, ref_val, ref_h1, ref_h2 = V.ref_infer(
            weights, scale, ttl, 0, ifindex=0, link_state=ls)

        # Datapath: same input, through the real program.
        cls_before = [int(setup["cls_stats"][ct.c_int(i)].value
                          if hasattr(setup["cls_stats"][ct.c_int(i)], "value")
                          else setup["cls_stats"][ct.c_int(i)])
                      for i in range(n_out)]
        frame = V.build_frame(0, ttl, scale)
        retval, _ = V.prog_test_run(setup["disp"].fd, frame, repeat=1)
        cls_after = [int(setup["cls_stats"][ct.c_int(i)].value
                         if hasattr(setup["cls_stats"][ct.c_int(i)], "value")
                         else setup["cls_stats"][ct.c_int(i)])
                     for i in range(n_out)]
        moved = [i for i in range(n_out) if cls_after[i] != cls_before[i]]
        dp_cls = moved[0] if moved else None

        acts, where = _read_acts(b, 4)

        agree = (dp_cls == ref_cls)
        tag = f"{GREEN}agree{NC}" if agree else f"{RED}DISAGREE{NC}"
        print(f"link_state={ls_s} ttl={ttl:2d}  [{tag}]")
        print(f"  reference : class {ref_cls}  (value {ref_val})")
        print(f"  datapath  : class {dp_cls}  (XDP retval {retval})")
        print(f"  ref  h1={ref_h1}")
        print(f"  ref  h2={ref_h2}")
        print(f"  kernel acts after the last layer = {acts}   [{where}]")
        if acts is not None and ref_h2 is not None:
            if list(acts) == list(ref_h2[:len(acts)]):
                print("  -> layer 2 activations MATCH: the divergence is in "
                      "the output layer or in argmax")
            elif acts == [0] * len(acts):
                print("  -> kernel activations are all zero: scratch_acts was "
                      "not left populated by this path, so this comparison "
                      "says nothing")
            else:
                print("  -> layer 2 activations DIFFER: the divergence is at "
                      "or before layer 2")
        print()

    print("Read it this way: matching h2 with a different class means the "
          "output layer or argmax; differing h2 means layer 1 or 2, and the "
          "reference's own h1/h2 say which. The reference is the suspect -- "
          "three independent pipelines agreed with each other.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
