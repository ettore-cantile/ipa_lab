#!/usr/bin/env python3
"""
diag_p3_bisect.py -- which change stopped Pipeline 3 from loading?

Pipeline 3's `layer_first` is refused by the verifier, and BCC reports it as
"Program too large (N insns), at most 4096 insns" -- a stale constant in BCC's
own error string: Pipeline 2 loads at 15 383 instructions in the same run. The
real cause is verification complexity, and complexity is not monotone in
program size: every refused version so far has been SMALLER than the last one
that loaded.

Five hypotheses were tried and all five were wrong, so this stops guessing.
It takes each historical version of ebpf_modular.py, builds Pipeline 3 from it,
and tries to load `layer_first`. What comes back is which commit it stops at --
a fact, not a deduction.

Worth stating plainly: the assumption under all five attempts was that the node
index was the only thing that changed between "loads" and "does not". Between
those two runs there were also the cls_stats instrumentation on the DROP and
UNUSED paths, and the ingress_port map. This checks that assumption instead of
resting on it.

    sudo python3 ipa/test/diag_p3_bisect.py
    sudo python3 ipa/test/diag_p3_bisect.py --rev b4f50b7b --rev HEAD

Needs Linux + BCC + root, and a git checkout.
"""
import argparse
import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)
REPO = os.path.dirname(CORE)
for _p in (CORE, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def revisions_touching(path, limit=12):
    """Commits that changed `path`, newest first."""
    out = subprocess.run(["git", "-C", REPO, "log", f"-{limit}",
                          "--format=%h %ad %s", "--date=short", "--", path],
                         capture_output=True, text=True).stdout
    revs = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2:
            revs.append((parts[0], parts[1]))
    return revs


def source_at(rev, path):
    r = subprocess.run(["git", "-C", REPO, "show", f"{rev}:{path}"],
                       capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def load_module_from_source(src, name):
    """Import a module from source text, in a throwaway file."""
    tmp = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                      encoding="utf-8")
    tmp.write(src)
    tmp.close()
    try:
        spec = importlib.util.spec_from_file_location(name, tmp.name)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def try_load(src_text, label):
    """Build Pipeline 3 from this source and try to load layer_first.

    Returns (ok, detail). Each attempt uses a fresh module name so one version
    cannot leave state behind for the next.
    """
    from bcc import BPF
    try:
        mod = load_module_from_source(src_text, f"_p3_{abs(hash(label)) % 10**8}")
    except Exception as e:
        return False, f"import failed: {type(e).__name__}: {e}"
    try:
        full = mod.EBPF_MODULAR_FULL
    except AttributeError:
        return False, "EBPF_MODULAR_FULL missing"
    try:
        b = BPF(text=full)
    except Exception as e:
        return False, f"compile failed: {str(e).strip().splitlines()[-1][:90]}"
    try:
        fn = b.load_func("layer_first", BPF.XDP)
    except Exception as e:
        return False, f"load refused: {str(e).strip().splitlines()[-1][:90]}"
    try:
        import verify_prog_run as V
        n = V.prog_insn_count(fn.fd)
    except Exception:
        n = None
    return True, f"loaded, {n} instructions" if n else "loaded"


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("    sudo")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rev", action="append", default=[],
                   help="test only these revisions (repeatable); default: the "
                        "last commits that touched ebpf_modular.py, plus the "
                        "working tree")
    p.add_argument("--limit", type=int, default=12)
    a = p.parse_args()

    if sys.platform != "linux":
        sys.exit(f"needs Linux, not {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("needs root: sudo python3 ipa/test/diag_p3_bisect.py")

    rel = "ipa/ebpf_modular.py"
    print(f"{YELLOW}{'=' * 74}{NC}")
    print(f"{YELLOW} Pipeline 3: which version of {rel} loads?{NC}")
    print(f"{YELLOW}{'=' * 74}{NC}\n")

    cases = []
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        cases.append(("working tree", "(uncommitted)", f.read()))
    if a.rev:
        for r in a.rev:
            src = source_at(r, rel)
            cases.append((r, "", src))
    else:
        for rev, date in revisions_touching(rel, a.limit):
            cases.append((rev, date, source_at(rev, rel)))

    first_ok = None
    for label, date, src in cases:
        if src is None:
            print(f"  {label:14s} {date:11s} {RED}source unavailable{NC}")
            continue
        ok, detail = try_load(src, label)
        mark = f"{GREEN}LOADS {NC}" if ok else f"{RED}refused{NC}"
        print(f"  {label:14s} {date:11s} {mark} {detail}")
        if ok and first_ok is None:
            first_ok = label

    print()
    if first_ok is None:
        print("  No version loads, including ones that loaded before. The cause "
              "is then NOT in this file: look at kernel state, at the other "
              "sources compiled into the same object, or at what else the "
              "suite has already loaded when it gets here.")
    elif first_ok == "working tree":
        print("  The working tree loads. Whatever was failing is fixed.")
    else:
        print(f"  First version that loads: {first_ok}. Everything newer than "
              f"it is refused, so the change that broke it is between that "
              f"commit and the next one listed above it.")
        print("  `git -C . diff <that rev> <the next one> -- " + rel + "`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
