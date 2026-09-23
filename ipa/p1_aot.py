#!/usr/bin/env python3
"""
p1_aot.py -- Pipeline 1 for the tests and benches: the AOT object, not BCC.

Why
---
P1 is deployed ONLY as an AOT object: gen_full_c generates libbpf C, clang
compiles it offline, loader_aot loads it on the node. Until 2026-09-23 every
P1 test and bench compiled a different program instead -- ebpf_program's BCC
source, another generator in another dialect -- so every P1 number described
something no node ever ran. The two were measured side by side and agree
within noise (claims.md B3), and from then on P1 is tested on the real thing:
this module is the one way the tests build and load P1.

What it gives
-------------
  p1_source(...)      libbpf C, same arguments as
                      ebpf_program.build_combined_hardcoded_source
  compile_object(src) clang -> .o, cached by content
  AotObject(o_path)   loader_aot in PIN-ONLY mode: maps AND programs pinned in
                      bpffs, driven from Python (pinned_maps.PinnedObject);
                      the pins vanish when this process -- or the loader --
                      goes away
  load_p1(...)        all three, returning the same dictionary as
                      verify_prog_run.setup_hardcoded used to
  instrument_lookups  the lookup-counting build, in the libbpf dialect

Needs Linux, root, clang, libbpf (the loader is built by
method4_hardcoded_aot.ensure_loader, like the deploy).
"""
import atexit
import hashlib
import itertools
import os
import re
import subprocess
import sys
import tempfile
import time
import weakref

SHARED_DIR = os.path.dirname(os.path.abspath(__file__))
POC_DIR = os.path.join(SHARED_DIR, "poc_aot")
for _p in (SHARED_DIR, POC_DIR, os.path.join(SHARED_DIR, "methods")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# The same flags the deploy build uses (method4_hardcoded_aot.py).
BPF_CFLAGS = ["-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86"]
CACHE_DIR = os.environ.get("IPA_AOT_CACHE",
                           os.path.join(tempfile.gettempdir(), "ipa_aot_cache"))
_PROG_RE = re.compile(r"^int (xdp_\w+)\(struct xdp_md \*ctx\)", re.M)


class FdProg:
    """What a BCC load_func returns, as far as the tests use it: an fd --
    plus the bpffs path, which common.attach_xdp uses to attach it."""

    def __init__(self, fd, pin_path=None):
        self.fd = fd
        self.pin_path = pin_path


# ---------------------------------------------------------------------------
def p1_source(models, n_interfaces=None, n_nodes=None, hidden_dims=(4, 4),
              features=None, n_out=None, semantics=None, static_node=None,
              static_ports=None):
    """libbpf C of P1. `models` = [(model_id, weights_int8, scale), ...] --
    the arguments of build_combined_hardcoded_source, resolved the same way
    (features None -> the configured model's descriptor)."""
    import model_meta as mm
    from gen_full_c import _emit_arch

    if features is None:
        meta = dict(mm.load_model_meta(os.path.join(SHARED_DIR, "weights.json")))
        if n_interfaces is not None:
            meta["n_interfaces"] = n_interfaces
        if n_nodes is not None:
            meta["n_nodes"] = n_nodes
        shape = mm.derive_shape(meta, topology_config=mm.topology_config_for(meta))
        features, n_out = shape["features"], shape["n_out"]
    if n_out is None:
        raise ValueError("p1_source: n_out is required when 'features' is given")
    if semantics is None:
        semantics = mm.descriptor_semantics_or_reference(n_out, "Pipeline1/AOT")
    semantics.validate()
    if semantics.n_out != n_out:
        raise ValueError(f"class semantics declare n_out={semantics.n_out} "
                         f"but the model outputs {n_out}")
    entries = []
    for e in models:
        if len(e) == 4:
            if e[3] is not None:
                raise ValueError("no compile-time ifindex_table: the ingress "
                                 "port mapping is the ingress_port map")
            e = e[:3]
        entries.append((int(e[0]), list(e[1]), int(e[2])))
    shape = {"features": features, "n_out": n_out,
             "hidden_dims": [int(h) for h in hidden_dims],
             "n_in": sum(int(f["size"]) for f in features)}
    if len(entries) == 1 and entries[0][0] == 0:
        return _emit_arch(shape, entries[0][1], entries[0][2], semantics,
                          static_node=static_node, static_ports=static_ports)
    return _emit_arch(shape, None, None, semantics, static_node=static_node,
                      static_ports=static_ports, models=entries)


# ---------------------------------------------------------------------------
_LOOKUP_RE = re.compile(r"bpf_map_lookup_elem\(([^()]*)\)")
_CTR_DECL = """
/* lookup counter -- measurement build only (p1_aot.instrument_lookups). An
 * ARRAY with an atomic add, not a per-CPU one: pinned_maps reads plain maps,
 * and this build is never the one whose latency is reported. */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, __u32); __type(value, __u64); } lookup_ctr SEC(".maps");
static __always_inline void ipa_ctr_inc(void) {
    __u32 _lk = 0; __u64 *_lv = bpf_map_lookup_elem(&lookup_ctr, &_lk);
    if (_lv) __sync_fetch_and_add(_lv, 1);
}
"""


def instrument_lookups(src):
    """Count every bpf_map_lookup_elem the program makes: each call becomes
    `({ ipa_ctr_inc(); bpf_map_lookup_elem(...); })`. The libbpf counterpart
    of common.instrument_map_lookups (BCC's `.lookup(`); the counter's own
    lookup is added after the rewrite, so it is not counted."""
    n = len(_LOOKUP_RE.findall(src))
    out = _LOOKUP_RE.sub(
        lambda m: f"({{ ipa_ctr_inc(); bpf_map_lookup_elem({m.group(1)}); }})",
        src)
    at = out.index('SEC("xdp")')
    return out[:at] + _CTR_DECL + "\n" + out[at:], n


# ---------------------------------------------------------------------------
_UNCACHED = itertools.count()


def compile_object(src, clang="clang", cache=True):
    """clang -> .o, cached by content (same source, same flags -> same object,
    compiled once). Returns (o_path, compile_seconds; 0.0 when cached).
    cache=False always runs clang, for the benches that TIME the build."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    key = hashlib.sha256((src + "\0" + " ".join(BPF_CFLAGS)).encode()).hexdigest()[:24]
    if not cache:
        key += f"_{os.getpid()}_{next(_UNCACHED)}"
    c_path = os.path.join(CACHE_DIR, f"p1_{key}.bpf.c")
    o_path = os.path.join(CACHE_DIR, f"p1_{key}.o")
    if cache and os.path.exists(o_path):
        return o_path, 0.0
    with open(c_path, "w") as f:
        f.write(src)
    t0 = time.perf_counter()
    r = subprocess.run([clang, *BPF_CFLAGS, "-c", c_path, "-o", o_path + ".tmp"],
                       capture_output=True, text=True)
    dt = time.perf_counter() - t0
    if r.returncode != 0:
        raise RuntimeError(f"clang failed on {c_path} (rc={r.returncode}):\n"
                           f"{r.stderr.strip()[-2000:]}")
    os.replace(o_path + ".tmp", o_path)
    return o_path, dt


_PIN_SEQ = [0]


class AotObject:
    """One AOT object, loaded and pinned by loader_aot (PIN-ONLY mode).

    .b         pinned_maps.PinnedObject over its maps
    .progs     {program name: FdProg}
    .load_s    the loader's open + load (verifier + JIT), seconds
    stop()     DETACH -> the loader unpins and exits; also run at exit
    """

    def __init__(self, o_path, prog_names):
        from pinned_maps import PinnedObject, FwdAction
        from method4_hardcoded_aot import ensure_loader

        loader = ensure_loader()
        _PIN_SEQ[0] += 1
        self.pin_dir = f"/sys/fs/bpf/ipa_p1_test_{os.getpid()}_{_PIN_SEQ[0]}"
        self.proc = subprocess.Popen([loader, o_path, "--pin-dir", self.pin_dir],
                                     cwd=POC_DIR, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True,
                                     bufsize=1)   # stderr: the terminal
        self.load_s = None
        seen = []
        for line in self.proc.stdout:
            seen.append(line)
            m = re.match(r"\[aot\] open\+load \(verify\+JIT\): ([\d.]+) ms", line)
            if m:
                self.load_s = float(m.group(1)) / 1000.0
            if line.startswith("READY"):
                break
        else:
            raise RuntimeError(f"loader_aot exited (rc={self.proc.wait()}) "
                               f"before READY; its error is printed above. "
                               f"stdout: {''.join(seen).strip()[-800:]!r}")
        # Stopped at exit, or as soon as nothing refers to it any more (the
        # benches load dozens of objects; each is a loader process, pins and
        # fds). atexit holds a WEAK reference, or it would keep them all.
        ref = weakref.ref(self)
        atexit.register(lambda: ref() is not None and ref().stop())
        self._closed = False
        self.b = PinnedObject(self.pin_dir,
                              leaf_types={"mac_table": FwdAction,
                                          "link_state": "u32vec",
                                          "queue_state": "u32vec"})
        self.progs = {n: FdProg(self.b.prog_fd(n), os.path.join(self.pin_dir, n))
                      for n in prog_names}

    def stop(self):
        if not getattr(self, "_closed", True):
            self._closed = True
            for p in getattr(self, "progs", {}).values():
                try:
                    os.close(p.fd)
                except OSError:
                    pass
            b = getattr(self, "b", None)
            if b is not None:
                b.close()
        if self.proc.poll() is not None:
            return self.proc.returncode
        try:
            self.proc.stdin.write("DETACH\n")
            self.proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass
        try:
            return self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            return self.proc.wait()

    def __del__(self):
        try:
            self.stop()
        except Exception:
            pass


def load_p1(models, instrument=False, cache=True, **kw):
    """Generate, compile and load P1; the dictionary setup_hardcoded returns.

    kw: the p1_source arguments (features, n_out, hidden_dims, semantics,
    static_node, static_ports, n_interfaces, n_nodes). instrument=True builds
    the lookup-counting object (lookup_ctr) instead of the measured one."""
    src = p1_source(models, **kw)
    n_sites = None
    if instrument:
        src, n_sites = instrument_lookups(src)
    o_path, compile_s = compile_object(src, cache=cache)
    names = _PROG_RE.findall(src)
    obj = AotObject(o_path, names)
    # The maps keep their object alive: whoever still holds `b` (a bench
    # that returned it, a test that stored it) keeps the loader and the pins.
    obj.b._owner = obj
    model_fns = {}
    for n in names:
        if n == "xdp_model":
            model_fns[0] = obj.progs[n]
        elif n.startswith("xdp_model_"):
            model_fns[int(n[len("xdp_model_"):])] = obj.progs[n]
    first = model_fns[min(model_fns)]
    return {
        "b": obj.b, "disp": obj.progs["xdp_dispatch"], "fn": first,
        "model_fns": model_fns,
        "progs": {n: p.fd for n, p in obj.progs.items()},
        "cls_stats": obj.b["cls_stats"], "pkt_stats": obj.b["pkt_stats"],
        "pipeline": 1, "owner": obj, "src": src, "o_path": o_path,
        # Model update on the node = load the prebuilt object (verify + JIT);
        # clang ran offline, reported separately (0 when the object was cached).
        "t_redirect_s": obj.load_s or 0.0, "t_compile_s": compile_s,
        "t_insert_s": 0.0, "lookup_sites": n_sites,
    }
