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


# --------------------------------------------------------------------------
# Variants of the CURRENT source
# --------------------------------------------------------------------------
# The bisect narrowed the break to one commit, which added two things at once:
# the node_id_t3 map DECLARATION, and a lookup of it inside layer_first. The
# lookup has since moved to the dispatcher and layer_first no longer has one --
# and the program is still refused. So the declaration and the use have to be
# tested separately, which is what these do: each is a textual edit of the
# working tree, loaded in isolation.

def _drop_block(src, start_marker, end_marker):
    """Remove src[start..end], markers included. Returns (src, removed?)."""
    i = src.find(start_marker)
    if i < 0:
        return src, False
    j = src.find(end_marker, i)
    if j < 0:
        return src, False
    return src[:i] + src[j + len(end_marker):], True


def variants(src):
    """(label, source, note) for each thing worth isolating."""
    out = [("as-is", src, "the working tree, unchanged")]

    # no use: the dispatcher stops reading node_id_t3, so the node half of the
    # packed slot is always the unknown sentinel. The map is still declared.
    no_use, ok = _drop_block(
        src,
        "      __u32 _nz = 0;",
        "__u32 _nd = (_nid && *_nid < 0xffU) ? *_nid : 0xffU;")
    if ok:
        no_use = no_use.replace(
            "      long long v = (long long)((_nd << 16) | _port);",
            "      long long v = (long long)((0xffU << 16) | _port);")
        out.append(("no use", no_use,
                    "map declared, never read -- isolates the DECLARATION"))

    # no map at all: declaration gone too.
    no_map = (no_use if ok else src)
    for decl in ("BPF_HASH(node_id_t3, __u32, __u32, 1);",
                 "BPF_ARRAY(node_id_t3, __u32, 1);"):
        no_map = no_map.replace(decl, "")
    if no_map != (no_use if ok else src):
        out.append(("no map", no_map,
                    "declaration removed as well -- isolates the MAP itself"))

    # the node index back where it came from, everything else kept.
    from_model = src
    i = from_model.find("    int mctx = META_NODE_CTX;")
    if i >= 0:
        j = from_model.find("__u32 _node      = (_ctx >> 16) & 0xffU;", i)
        if j >= 0:
            j += len("__u32 _node      = (_ctx >> 16) & 0xffU;")
            from_model = (from_model[:i] +
                          "    int mif = META_NODE_CTX;\n"
                          "    long long *ifp = scratch_meta.lookup(&mif);\n"
                          "    __u32 _raw_iface = ifp ? ((__u32)(*ifp) & 0xffffU) : 0;\n"
                          "    __u32 _node = (__u32)model_id;" +
                          from_model[j:])
            out.append(("node=model_id", from_model,
                        "the original node source, everything else kept"))
    return out


def run_variants():
    src = open(os.path.join(REPO, "ipa/ebpf_modular.py"), encoding="utf-8").read()
    print(f"{YELLOW}{'=' * 74}{NC}")
    print(f"{YELLOW} Variants of the working tree: what exactly does it not tolerate?{NC}")
    print(f"{YELLOW}{'=' * 74}{NC}\n")
    for label, text, note in variants(src):
        ok, detail = try_load(text, "var_" + label)
        mark = f"{GREEN}LOADS  {NC}" if ok else f"{RED}refused{NC}"
        print(f"  {label:14s} {mark} {detail}")
        print(f"                 {note}")
    print()
    print("  Read it as: the first variant that loads names the thing that "
          "does not fit. If none load, nothing in this file is the cause.")
    return 0


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("    sudo")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rev", action="append", default=[],
                   help="test only these revisions (repeatable); default: the "
                        "last commits that touched ebpf_modular.py, plus the "
                        "working tree")
    p.add_argument("--limit", type=int, default=12)
    p.add_argument("--variants", action="store_true",
                   help="instead of walking history, try edits of the CURRENT "
                        "source that each remove one suspect")
    a = p.parse_args()

    if sys.platform != "linux":
        sys.exit(f"needs Linux, not {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("needs root: sudo python3 ipa/test/diag_p3_bisect.py")

    if a.variants:
        return run_variants()

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
