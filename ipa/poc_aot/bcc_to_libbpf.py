#!/usr/bin/env python3
"""
bcc_to_libbpf.py -- compile the SAME datapath source with libbpf instead of BCC.

Why translate instead of rewriting
----------------------------------
BCC is clang-at-runtime: deploying a model means shipping a compiler and a set
of kernel headers to the forwarding node, and compiling there. That is not how
anything goes to production. The libbpf path compiles once, offline, and the
node loads a `.o` -- which is what `poc_aot/` already does for Pipeline 1.

Pipelines 2 and 3 do not need per-model codegen at all: their C is a fixed
template and the model arrives through maps. So the only thing between them and
a libbpf deploy is the DIALECT:

    BCC                                 libbpf
    BPF_ARRAY(m, T, n);                 struct { __uint(type, ...) } m SEC(".maps");
    m.lookup(&k)                        bpf_map_lookup_elem(&m, &k)
    m.update(&k, &v)                    bpf_map_update_elem(&m, &k, &v, BPF_ANY)
    m.delete(&k)                        bpf_map_delete_elem(&m, &k)
    progs.call(ctx, i)                  bpf_tail_call(ctx, &progs, i)
    int fn(struct xdp_md *ctx)          SEC("xdp") int fn(struct xdp_md *ctx)

Hand-porting 1450 lines would create a second copy of the datapath that drifts
from the first, and the whole argument of this work is that the three pipelines
compute the same thing. One source, two backends, and the fabric test can run
both and compare.

What this does NOT do
---------------------
It is a translator for THIS repository's C, not a general BCC frontend. It
handles the constructs these sources actually use (counted, not guessed: 38 map
declarations, 37 lookups, 7 updates, 4 tail calls, 6 XDP functions) and raises
on anything it does not recognise rather than emitting C that looks plausible
and behaves differently.

    python3 ipa/poc_aot/bcc_to_libbpf.py --pipeline template --out ipa/poc_aot/
    python3 ipa/poc_aot/bcc_to_libbpf.py --pipeline modular  --out ipa/poc_aot/
    python3 ipa/poc_aot/bcc_to_libbpf.py --check      # translate, emit nothing
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)
if CORE not in sys.path:
    sys.path.insert(0, CORE)


class TranslationError(RuntimeError):
    """A BCC construct this translator does not handle.

    Raised rather than passed through: C that still contains `m.lookup(&k)`
    would fail to compile, but a construct silently dropped would compile and
    run differently, which is worse.
    """


# --------------------------------------------------------------------------
# Map declarations
# --------------------------------------------------------------------------
_MAP_KINDS = {
    "BPF_ARRAY":        ("BPF_MAP_TYPE_ARRAY", "__u32"),
    "BPF_PERCPU_ARRAY": ("BPF_MAP_TYPE_PERCPU_ARRAY", "__u32"),
    "BPF_HASH":         ("BPF_MAP_TYPE_HASH", None),     # key type is explicit
    "BPF_PROG_ARRAY":   ("BPF_MAP_TYPE_PROG_ARRAY", "__u32"),
}

_MAP_RE = re.compile(
    r"^[ \t]*(BPF_ARRAY|BPF_PERCPU_ARRAY|BPF_HASH|BPF_PROG_ARRAY)\s*\((.*?)\)\s*;",
    re.M)


def _split_args(arg_string):
    """Split a C argument list on commas that are not inside brackets."""
    out, depth, cur = [], 0, ""
    for ch in arg_string:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _emit_map(kind, args):
    map_type, implicit_key = _MAP_KINDS[kind]
    if kind == "BPF_PROG_ARRAY":
        if len(args) != 2:
            raise TranslationError(f"BPF_PROG_ARRAY wants (name, size), got {args}")
        name, size = args
        return (f"struct {{\n"
                f"    __uint(type, {map_type});\n"
                f"    __uint(key_size, sizeof(__u32));\n"
                f"    __uint(value_size, sizeof(__u32));\n"
                f"    __uint(max_entries, {size});\n"
                f"}} {name} SEC(\".maps\");")
    if kind == "BPF_HASH":
        if len(args) != 4:
            raise TranslationError(
                f"BPF_HASH wants (name, key_t, val_t, size), got {args}. The "
                f"2- and 3-argument BCC forms default the sizes; spell them "
                f"out in the source rather than guessing here.")
        name, kt, vt, size = args
    else:
        if len(args) != 3:
            raise TranslationError(f"{kind} wants (name, val_t, size), got {args}")
        name, vt, size = args
        kt = implicit_key
    return (f"struct {{\n"
            f"    __uint(type, {map_type});\n"
            f"    __type(key, {kt});\n"
            f"    __type(value, {vt});\n"
            f"    __uint(max_entries, {size});\n"
            f"}} {name} SEC(\".maps\");")


# --------------------------------------------------------------------------
# Method-call syntax
# --------------------------------------------------------------------------
_LOOKUP_RE = re.compile(r"\b([A-Za-z_]\w*)\.lookup\s*\(")
_UPDATE_RE = re.compile(r"\b([A-Za-z_]\w*)\.update\s*\(")
_DELETE_RE = re.compile(r"\b([A-Za-z_]\w*)\.delete\s*\(")
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\.call\s*\(")
_ANY_METHOD_RE = re.compile(r"\b([A-Za-z_]\w*)\.([a-z_]+)\s*\(")

_KNOWN_METHODS = {"lookup", "update", "delete", "call",
                  "lookup_or_try_init", "increment", "perf_submit"}
_HANDLED = {"lookup", "update", "delete", "call"}


def _code_mask(src):
    """True at every offset that is real code, False inside a comment or a
    string literal.

    Needed because these sources discuss their own BCC constructs in prose:
    one comment reads "BCC's rewriter refuses table.lookup() calls that appear
    textually inside ...", and a translator that rewrites text without knowing
    where the code is turns that sentence into a call to a map named `table`.
    """
    mask = bytearray(b"\x01") * len(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                mask[k] = 0
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                mask[k] = 0
            i = j
        elif c in "\"'":
            q, j = c, i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            for k in range(i, j):
                mask[k] = 0
            i = j
        else:
            i += 1
    return mask


def _balanced_args(src, open_paren):
    """Return (args_string, index_after_closing_paren) for the call at `open_paren`."""
    depth, i = 0, open_paren
    while i < len(src):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return src[open_paren + 1:i], i + 1
        i += 1
    raise TranslationError("unbalanced parentheses in a map call")


def _rewrite_calls(src):
    """One pass per call, left to right, rebuilding the string as we go."""
    for rx, arity, build in (
        (_LOOKUP_RE, 1, lambda m, a: f"bpf_map_lookup_elem(&{m}, {a[0]})"),
        (_UPDATE_RE, 2, lambda m, a: f"bpf_map_update_elem(&{m}, {a[0]}, {a[1]}, BPF_ANY)"),
        (_DELETE_RE, 1, lambda m, a: f"bpf_map_delete_elem(&{m}, {a[0]})"),
        (_CALL_RE,   2, lambda m, a: f"bpf_tail_call({a[0]}, &{m}, {a[1]})"),
    ):
        pos = 0
        while True:
            mask = _code_mask(src)
            m = rx.search(src, pos)
            if not m:
                break
            if not mask[m.start()]:
                pos = m.end()          # prose, not code -- leave it alone
                continue
            name = m.group(1)
            args_s, after = _balanced_args(src, m.end() - 1)
            args = _split_args(args_s)
            if len(args) != arity:
                line = src[:m.start()].count("\n") + 1
                raise TranslationError(
                    f"line {line}: {name}.{rx.pattern.split('.')[1][:6]}() "
                    f"takes {arity} argument(s), found {len(args)}: {args}")
            src = src[:m.start()] + build(name, args) + src[after:]
            pos = m.start()
    return src


# --------------------------------------------------------------------------
# Whole-source translation
# --------------------------------------------------------------------------
PROLOGUE = '''/* GENERATED by ipa/poc_aot/bcc_to_libbpf.py -- do not edit.
 *
 * The SAME datapath as the BCC build, in libbpf dialect: compiled once,
 * offline, and loaded on the node with no clang and no Python. Edit the BCC
 * source in %s and regenerate.
 *
 * vmlinux.h rather than the kernel's own headers: those are exactly what the
 * BCC path needs shipped to it, and the types here come from the running
 * kernel's own BTF instead. Regenerate with:
 *     bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* BCC provides these implicitly. */
#ifndef memcpy
#define memcpy(d, s, n) __builtin_memcpy((d), (s), (n))
#endif

'''

EPILOGUE = '''

char _license[] SEC("license") = "GPL";
'''

# BCC pulls kernel headers in by itself; under libbpf they clash with vmlinux.h.
_DROP_INCLUDE_RE = re.compile(
    r"^[ \t]*#include\s*<(uapi/)?linux/[^>]+>\s*$", re.M)


def translate(src: str, origin: str = "the BCC source") -> str:
    """BCC-dialect C in, libbpf-dialect C out.

    Raises TranslationError on any BCC construct not handled, so an
    unsupported source fails here rather than compiling into something that
    behaves differently from the BCC build.
    """
    # 1. kernel includes: vmlinux.h supplies these types
    src = _DROP_INCLUDE_RE.sub("", src)

    # 2. map declarations
    def _map_sub(m):
        return _emit_map(m.group(1), _split_args(m.group(2)))
    src = _MAP_RE.sub(_map_sub, src)

    # 3. refuse anything we do not translate, BEFORE rewriting, so the error
    #    names the construct as the author wrote it
    mask = _code_mask(src)
    for m in _ANY_METHOD_RE.finditer(src):
        name, meth = m.group(1), m.group(2)
        if not mask[m.start()]:
            continue
        if meth in _KNOWN_METHODS and meth not in _HANDLED:
            raise TranslationError(
                f"{name}.{meth}() is a BCC map method this translator does not "
                f"handle. Add it to _rewrite_calls, or express it with the "
                f"helpers directly in the shared source.")

    # 4. the calls themselves
    src = _rewrite_calls(src)

    # 5. XDP entry points need a section annotation
    mask = _code_mask(src)
    out, last = [], 0
    for m in re.finditer(r"^int\s+(\w+)\s*\(struct xdp_md\s*\*", src, re.M):
        if not mask[m.start()]:
            continue
        out.append(src[last:m.start()])
        out.append(f'SEC("xdp")\nint {m.group(1)}(struct xdp_md *')
        last = m.end()
    out.append(src[last:])
    src = "".join(out)

    mask = _code_mask(src)
    for leftover in _ANY_METHOD_RE.finditer(src):
        if mask[leftover.start()] and leftover.group(2) in _KNOWN_METHODS:
            line = src[:leftover.start()].count("\n") + 1
            raise TranslationError(
                f"line {line}: {leftover.group(0)} survived translation")

    return (PROLOGUE % origin) + src + EPILOGUE


# --------------------------------------------------------------------------
def pipeline_source(which: str):
    """(source, origin) for a pipeline, assembled exactly as the BCC path does."""
    if which == "template":
        import ebpf_template_arch as T
        src = ("#define IPA_ARCH_COMBINED 1\n"
               + T.EBPF_TEMPLATE_ARCH_DISPATCHER + "\n"
               + T.EBPF_ARCH_GENERIC_2LAYER)
        return src, "ipa/ebpf_template_arch.py"
    if which == "modular":
        import ebpf_modular as M
        return M.EBPF_MODULAR_FULL, "ipa/ebpf_modular.py"
    raise ValueError(f"unknown pipeline {which!r}: expected template or modular")


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("    python3")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pipeline", choices=["template", "modular", "all"],
                   default="all")
    p.add_argument("--out", default=HERE,
                   help="directory for the generated .bpf.c (default: poc_aot/)")
    p.add_argument("--check", action="store_true",
                   help="translate and report, write nothing")
    a = p.parse_args()

    names = ["template", "modular"] if a.pipeline == "all" else [a.pipeline]
    rc = 0
    for which in names:
        try:
            src, origin = pipeline_source(which)
        except Exception as e:
            print(f"[bcc2libbpf] {which}: cannot assemble source ({e})")
            rc = 1
            continue
        try:
            out = translate(src, origin)
        except TranslationError as e:
            print(f"[bcc2libbpf] {which}: {e}")
            rc = 1
            continue
        maps = out.count('SEC(".maps")')
        progs = out.count('SEC("xdp")')
        print(f"[bcc2libbpf] {which}: {src.count(chr(10))} lines in -> "
              f"{out.count(chr(10))} out, {maps} maps, {progs} XDP programs")
        if not a.check:
            path = os.path.join(a.out, f"ipa_{which}.bpf.c")
            with open(path, "w", newline="\n") as f:
                f.write(out)
            print(f"[bcc2libbpf] wrote {path}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
