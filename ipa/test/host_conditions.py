#!/usr/bin/env python3
"""host_conditions.py -- the machine conditions while a bench measures.

Pins the bench to chosen cores, fixes their frequency, disables deep idle
states, moves everything else to other cores, records throttling and
frequency during every window, and restores the machine at the end.

    sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/<bench>.py ...
"""
import argparse
import atexit
import csv
import glob
import json
import os
import re
import signal
import subprocess
import sys
import time

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")


def _say(line):
    """print that never raises."""
    try:
        print(line, flush=True)
    except (OSError, ValueError):
        pass


def ok(m):
    _say(f"  {GREEN}[PASS]{NC} {m}")


def info(m):
    _say(f"  {YELLOW}[INFO]{NC} {m}")


def warn(m):
    _say(f"  {RED}[WARN]{NC} {m}")


def note(m):
    _say(f"  {GREY}{m}{NC}")


STATE_REL = ("run", "ipa-bench", "host_state.json")
SCOPE_SLICE = "ipa-bench.slice"
CONFINED_UNITS = ("init.scope", "system.slice", "user.slice", "machine.slice")
DEFAULT_FREQ = "3500"
DEFAULT_SYSTEM_MAX_MHZ = 2500
DEFAULT_UNCORE = "max"
DEFAULT_CSTATE_MAX_US = 1
DEFAULT_PROFILE = "performance"
DEFAULT_GEN_THREADS = 3
MIN_GEN_THREADS = 2
FREQ_TOLERANCE = 0.05
FREQ_CHECK_MIN_BUSY_PCT = 20.0
MEASURE_S = 0.3
MSR_TSC, MSR_MPERF, MSR_APERF, MSR_SMI_COUNT = 0x10, 0xE7, 0xE8, 0x34
PF_KTHREAD = 0x00200000
PF_NO_SETAFFINITY = 0x04000000
KIND_RANK = {"P": 0, "-": 0, "E": 1, "?": 1, "LPE": 2}
KIND_NAME = {"P": "P-core", "E": "E-core", "LPE": "LP E-core", "-": "core",
             "?": "core"}


# --- reading and writing, relative to a root ---
class Paths:
    """Where to read and write."""

    def __init__(self, root="/"):
        self.root = root

    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def sys(self, *parts):
        return self.p("sys", *parts)

    def cpu(self, *parts):
        return self.p("sys", "devices", "system", "cpu", *parts)

    def proc(self, *parts):
        return self.p("proc", *parts)

    @property
    def state(self):
        return self.p(*STATE_REL)


def read_text(path, default=None):
    if not path:
        return default
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return default


def write_text(path, value):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{value}\n")


def _int(text, default=None):
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def run_cmd(argv, timeout=15):
    """(code, stdout, stderr), never an exception."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", str(e)


def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (TypeError, ValueError):
        return False
    return True


# --- CPU lists: the kernel's two formats ---
def parse_cpu_list(spec):
    """"0,5,12-21" -> [0, 5, 12, ..., 21]."""
    if spec is None:
        return []
    out = set()
    for part in re.split(r"[,\s]+", str(spec).strip()):
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            lo, hi = int(a), int(b)
            if hi < lo:
                raise ValueError(f"reversed range: {part!r}")
            out.update(range(lo, hi + 1))
        else:
            out.add(int(part))
    return sorted(out)


def format_cpu_list(cpus):
    """[0, 5, 12, 13, 14] -> "0,5,12-14"."""
    cpus = sorted(set(int(c) for c in cpus))
    if not cpus:
        return ""
    runs, start, prev = [], cpus[0], cpus[0]
    for c in cpus[1:]:
        if c == prev + 1:
            prev = c
            continue
        runs.append((start, prev))
        start = prev = c
    runs.append((start, prev))
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in runs)


def cpu_mask_hex(cpus):
    """Hex mask in the kernel bitmap format."""
    mask = 0
    for c in cpus:
        mask |= 1 << int(c)
    if not mask:
        return "0"
    groups = []
    while mask:
        groups.append(mask & 0xFFFFFFFF)
        mask >>= 32
    groups.reverse()
    return ",".join([f"{groups[0]:x}"] + [f"{g:08x}" for g in groups[1:]])


def parse_cpu_mask(text):
    mask = int(str(text).replace(",", "").strip() or "0", 16)
    return [i for i in range(mask.bit_length()) if (mask >> i) & 1]


# --- topology ---
class Topology:
    """The online CPUs, the physical core of each (SMT siblings), the core
    type and the frequencies."""

    def __init__(self, online, cpus, hybrid):
        self.online = sorted(online)
        self.cpus = cpus
        self.hybrid = hybrid

    @classmethod
    def read(cls, paths=None):
        paths = paths or Paths()
        online = parse_cpu_list(read_text(paths.cpu("online")))
        if not online:
            try:
                online = sorted(int(m.group(1)) for m in (
                    re.fullmatch(r"cpu(\d+)", n)
                    for n in os.listdir(paths.cpu())) if m)
            except OSError:
                online = list(range(os.cpu_count() or 1))
        core_set = set(parse_cpu_list(
            read_text(paths.sys("devices", "cpu_core", "cpus"))))
        atom_set = set(parse_cpu_list(
            read_text(paths.sys("devices", "cpu_atom", "cpus"))))
        hybrid = bool(core_set and atom_set)
        l3 = {c: os.path.isdir(paths.cpu(f"cpu{c}", "cache", "index3"))
              for c in online}
        some_l3 = any(l3.values())
        cpus = {}
        for c in online:
            def rd(*parts):
                return read_text(paths.cpu(f"cpu{c}", *parts))
            sib = (parse_cpu_list(rd("topology", "thread_siblings_list"))
                   or parse_cpu_list(rd("topology", "core_cpus_list"))
                   or [c])
            sib = tuple(s for s in sib if s in online) or (c,)
            l2 = tuple(s for s in parse_cpu_list(
                rd("cache", "index2", "shared_cpu_list")) if s in online)
            cluster = tuple(sorted(set(l2) | set(sib))) if c in l2 else sib
            if hybrid:
                if c in core_set:
                    kind = "P"
                elif c in atom_set:
                    kind = "LPE" if (some_l3 and not l3[c]) else "E"
                else:
                    kind = "?"
            else:
                kind = "-"
            cpus[c] = dict(core=sib, cluster=cluster,
                           core_id=_int(rd("topology", "core_id"), c),
                           pkg=_int(rd("topology", "physical_package_id"), 0),
                           kind=kind,
                           max_khz=_int(rd("cpufreq", "cpuinfo_max_freq")),
                           min_khz=_int(rd("cpufreq", "cpuinfo_min_freq")),
                           base_khz=_int(rd("cpufreq", "base_frequency")))
        return cls(online, cpus, hybrid)

    @property
    def smt(self):
        return any(len(v["core"]) > 1 for v in self.cpus.values())

    @property
    def structured(self):
        """There is a choice to make."""
        return self.hybrid or self.smt

    def core(self, cpu):
        return self.cpus[cpu]["core"] if cpu in self.cpus else (cpu,)

    def siblings(self, cpu):
        return [s for s in self.core(cpu) if s != cpu]

    def cluster(self, cpu):
        """The CPUs sharing the L2 with `cpu` (itself included)."""
        if cpu not in self.cpus:
            return (cpu,)
        return self.cpus[cpu].get("cluster") or self.core(cpu)

    def kind(self, cpu):
        return self.cpus.get(cpu, {}).get("kind", "?")

    def cores(self):
        """The physical cores, as tuples of their threads, by first CPU."""
        return sorted({v["core"] for v in self.cpus.values()},
                      key=lambda t: t[0])

    def label(self, cpu):
        parts = []
        k = self.kind(cpu)
        if k not in ("-", "?"):
            parts.append(k)
        sib = self.siblings(cpu)
        if sib:
            parts.append("sibling " + ",".join(str(s) for s in sib))
        mod = [s for s in self.cluster(cpu) if s != cpu and s not in sib]
        if mod:
            parts.append("L2 module with " + format_cpu_list(mod))
        return f"cpu{cpu}" + (f" ({', '.join(parts)})" if parts else "")

    def summary(self):
        if not self.hybrid:
            return (f"{len(self.online)} CPUs, "
                    + ("SMT" if self.smt else "no SMT") + ", not hybrid")
        groups = {}
        for c in self.online:
            groups.setdefault(self.kind(c), []).append(c)
        parts = []
        for k in ("P", "E", "LPE", "?"):
            if k not in groups:
                continue
            cs = groups[k]
            mx = max((self.cpus[c]["max_khz"] or 0) for c in cs)
            base = max((self.cpus[c]["base_khz"] or 0) for c in cs)
            smt = any(len(self.core(c)) > 1 for c in cs)
            parts.append(f"{KIND_NAME[k]} {format_cpu_list(cs)}"
                         + (" (SMT)" if smt else "")
                         + (f" base {base // 1000}" if base else "")
                         + (f" max {mx // 1000} MHz" if mx else ""))
        return "hybrid: " + "; ".join(parts)


# --- roles ---
def plan_roles(topo, n_gen=None, want_egress=False, allow_cpu0=False,
               exclude=()):
    """DUT, egress and generator on distinct physical cores."""
    notes = []
    ex = set(exclude)
    cores = [c for c in topo.cores()
             if (allow_cpu0 or 0 not in c) and not (set(c) & ex)]
    if not cores:
        cores = [c for c in topo.cores() if not (set(c) & ex)] \
            or list(topo.cores())
        notes.append("no core outside CPU 0's: using it "
                     "anyway")

    def rank(core):
        return KIND_RANK.get(topo.kind(core[0]), 1)

    def turbo(core):
        return max((topo.cpus.get(c, {}).get("max_khz") or 0) for c in core)

    best = min(rank(c) for c in cores)
    fast = sorted((c for c in cores if rank(c) == best),
                  key=lambda c: (turbo(c), c[0]))
    slow = [c for c in cores if best < rank(c) < KIND_RANK["LPE"]]
    if best > KIND_RANK["P"]:
        notes.append("no P-core available: the bench runs on slow cores")
    dut = fast[0]
    rest = list(fast[1:])
    explicit = bool(n_gen) and int(n_gen) > 0
    want = int(n_gen) if explicit else DEFAULT_GEN_THREADS

    egress = None
    if want_egress:
        keep_for_gen = want if explicit else MIN_GEN_THREADS
        if len(rest) >= keep_for_gen + 1:
            egress, rest = rest[0], rest[1:]
        else:
            notes.append(f"no free {KIND_NAME[topo.kind(dut[0])]} for "
                         f"the egress after DUT and generator: the egress stays "
                         f"on the DUT CPU (softirq)")

    gen = list(rest[:want])
    if len(gen) < want and (explicit or len(gen) < MIN_GEN_THREADS):
        need = (want if explicit else MIN_GEN_THREADS) - len(gen)
        extra = slow[:need]
        if extra:
            gen += extra
            notes.append("generator extended to slow cores ("
                         + ", ".join(topo.label(c[0]) for c in extra)
                         + "): they offer fewer packets per second, less "
                           "regularly")
    if explicit and len(gen) < want:
        notes.append(f"{want} generator threads requested, there are {len(gen)} "
                     f"free physical cores: using {len(gen)}")
    if not gen:
        sib = tuple(s for s in dut if s != dut[0])
        gen = [sib] if sib else [dut]
        notes.append("no free core for the generator: it shares the "
                     "DUT's physical core, and the absolute figure measures the "
                     "sum of the two")
    return dict(dut=[dut[0]], gen=[c[0] for c in gen],
                egress=(egress[0] if egress else None), notes=notes)


def spare_core(topo, used, allow_cpu0=False):
    """The first CPU of a physical core of the fastest type with no thread
    in `used`, or None."""
    used = set(used)
    cores = [c for c in topo.cores()
             if (allow_cpu0 or 0 not in c) and not (set(c) & used)]
    if not cores:
        return None
    best = min(KIND_RANK.get(topo.kind(c[0]), 1) for c in topo.cores())
    cands = [c for c in cores if KIND_RANK.get(topo.kind(c[0]), 1) == best]
    if not cands:
        return None
    return min(cands, key=lambda c: (max((topo.cpus.get(x, {}).get("max_khz")
                                           or 0) for x in c), c[0]))[0]


def egress_cpus(egress):
    """The egress as a list of CPUs."""
    if egress is None:
        return []
    if isinstance(egress, int):
        return [egress]
    return [int(c) for c in egress]


def idle_siblings(topo, used):
    """The SMT siblings of the used threads, and the L2-module mates on E-cores."""
    used = set(used)
    return sorted({s for c in used for s in topo.cluster(c)} - used)


def housekeeping(topo, used):
    """The system CPUs: all of them, minus the bench ones and their siblings."""
    busy = set(used) | set(idle_siblings(topo, used))
    return [c for c in topo.online if c not in busy]


class Roles:
    """The roles of an arbitrary command (--run)."""

    def __init__(self, topo, dut, gen=(), egress=None):
        self.topo = topo
        self.dut = list(dut)
        self.gen = list(gen)
        self.egress = egress

    @property
    def used(self):
        return sorted(set(self.dut) | set(self.gen)
                      | set(egress_cpus(self.egress)))


# --- saved state and restore ---
def load_state(paths):
    txt = read_text(paths.state)
    if not txt:
        return None
    try:
        return json.loads(txt)
    except ValueError:
        return None


def _comm_of(paths, pid):
    return read_text(paths.proc(str(pid), "comm"))


def restore_changes(changes, runner=None, paths=None, setaffinity=None):
    """Writes back in reverse order."""
    runner = runner or run_cmd
    paths = paths or Paths()
    setaffinity = setaffinity or os.sched_setaffinity
    failed = []
    for ch in reversed(list(changes)):
        kind = ch.get("kind")
        try:
            if kind == "file":
                write_text(ch["path"], ch["old"])
            elif kind == "unit":
                rc, _, err = runner(["systemctl", "set-property", "--runtime",
                                     ch["unit"], f"{ch['prop']}={ch['old']}"])
                if rc:
                    raise OSError(err.strip() or f"systemctl rc={rc}")
            elif kind == "profile":
                rc, _, err = runner(["powerprofilesctl", "set", ch["old"]])
                if rc:
                    raise OSError(err.strip() or f"powerprofilesctl rc={rc}")
            elif kind == "affinity":
                if _comm_of(paths, ch["pid"]) == ch.get("comm"):
                    setaffinity(int(ch["pid"]), set(parse_cpu_list(ch["old"])))
        except (OSError, ValueError, KeyError) as e:
            failed.append((ch, str(e)))
    return failed


def recover_stale_state(paths=None, runner=None, alive=None, me=None,
                        setaffinity=None):
    """If a previous run died without restoring, restore now."""
    paths = paths or Paths()
    alive = alive or pid_alive
    data = load_state(paths)
    if data is None:
        if os.path.exists(paths.state):
            os.remove(paths.state)
        return 0
    pid = data.get("pid")
    if pid and pid != me and alive(pid):
        raise RuntimeError(
            f"the machine conditions are already applied by process "
            f"{pid} ({paths.state}). If that process is not a bench: sudo "
            f"python3 ipa/test/host_conditions.py --restore --force")
    changes = data.get("changes", [])
    warn(f"state of a run interrupted without restore (pid {pid}, "
         f"{data.get('started', '?')}): restoring {len(changes)} "
         f"settings before starting")
    failed = restore_changes(changes, runner, paths, setaffinity)
    for ch, err in failed:
        warn(f"not restored: {_describe_change(ch)} -- {err}")
    os.remove(paths.state)
    return len(changes)


def _describe_change(ch):
    k = ch.get("kind")
    if k == "file":
        return f"{ch.get('path')} = {ch.get('old')}"
    if k == "unit":
        return f"{ch.get('unit')} {ch.get('prop')}={ch.get('old')}"
    if k == "profile":
        return f"profile {ch.get('old')}"
    if k == "affinity":
        return f"affinita' di {ch.get('comm')} ({ch.get('pid')}) = {ch.get('old')}"
    return str(ch)


def _uniform(values, fmt=str):
    """{cpu: value} -> "cpu 1,3,6: v" if all equal, otherwise per CPU."""
    vals = {c: v for c, v in values.items()}
    if not vals:
        return "n/d"
    distinct = set(vals.values())
    if len(distinct) == 1:
        return f"cpu {format_cpu_list(vals)}: {fmt(next(iter(distinct)))}"
    return "; ".join(f"cpu{c} {fmt(v)}" for c, v in sorted(vals.items()))


# --- applying the conditions ---
class HostConditioner:
    """Applies the bench conditions and restores them."""

    def __init__(self, topo, dut, gen=(), egress=None, *, freq=DEFAULT_FREQ,
                 system_max_mhz=DEFAULT_SYSTEM_MAX_MHZ,
                 uncore=DEFAULT_UNCORE, cstate_max_us=DEFAULT_CSTATE_MAX_US,
                 isolate=True, profile=DEFAULT_PROFILE, nmi_off=True,
                 paths=None, runner=None, setaffinity=None, getaffinity=None,
                 getpid=None, alive=None):
        self.topo = topo
        self.paths = paths or Paths()
        self.run = runner or run_cmd
        self._setaff = setaffinity or os.sched_setaffinity
        self._getaff = getaffinity or os.sched_getaffinity
        self._getpid = getpid or os.getpid
        self._alive = alive or pid_alive
        self.dut = [int(c) for c in dut]
        self.gen = [int(c) for c in gen]
        self.egress = egress_cpus(egress) or None
        self.bench = sorted(set(self.dut) | set(self.gen)
                            | set(egress_cpus(self.egress)))
        self.siblings = idle_siblings(topo, self.bench)
        self.hk = housekeeping(topo, self.bench)
        self.freq = freq
        self.system_max_mhz = system_max_mhz
        self.uncore = uncore
        self.cstate_max_us = cstate_max_us
        self.isolate = isolate
        self.profile = profile
        self.nmi_off = nmi_off
        self.changes = []
        self.facts = []
        self.target_khz = {}
        self.requested_khz = {}
        self.active = False
        self._scoped = False
        self._handlers = {}
        self._started = time.strftime("%Y-%m-%d %H:%M:%S")

    def _write_state(self):
        path = self.paths.state
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(dict(pid=self._getpid(), started=self._started,
                           changes=self.changes), f, indent=1)
        os.replace(tmp, path)

    def _record(self, ch):
        self.changes.append(ch)
        self._write_state()
        return ch

    def _unrecord(self, ch):
        if ch in self.changes:
            self.changes.remove(ch)
            self._write_state()

    def _set_file(self, path, new, what=""):
        """None: the file does not exist. False: write refused (the value stays
        as before). True: the file holds `new`."""
        old = read_text(path)
        if old is None:
            return None
        new = str(new)
        if old == new:
            return True
        ch = self._record(dict(kind="file", path=path, old=old, new=new,
                               what=what))
        try:
            write_text(path, new)
        except OSError:
            self._unrecord(ch)
            return False
        return True

    def _remember_file(self, path, what=""):
        """Saves the value without writing it."""
        old = read_text(path)
        if old is not None:
            self._record(dict(kind="file", path=path, old=old, new=None,
                              what=what))

    def apply(self):
        if self.active:
            return self
        recover_stale_state(self.paths, self.run, self._alive, self._getpid(),
                            self._setaff)
        self.active = True
        self._write_state()
        self._install_signals()
        atexit.register(self.restore)
        _say(f"\n{YELLOW}{'=' * 78}{NC}")
        _say(f"{YELLOW} Machine conditions (host_conditions){NC}")
        _say(f"{YELLOW}{'=' * 78}{NC}")
        try:
            self._check_power()
            self._step_profile()
            if self.isolate and not self.hk:
                warn("no CPU left to the system: isolation skipped")
                self.isolate = False
            if self.isolate:
                self._step_scope()
                self._step_cgroups()
                self._step_kthreads()
                self._step_irqs()
                self._step_workqueue()
            else:
                self.facts.append(("isolamento", "no"))
            self._step_freq()
            self._step_measure_freq()
            self._step_system_cap()
            self._step_uncore()
            self._step_cstates()
            self._step_nmi()
        except BaseException:
            self.restore()
            raise
        for k, v in self.facts:
            note(f"{k:22s} {v}")
        info(f"{len(self.changes)} settings changed, saved in "
             f"{self.paths.state}; restored at the end of the run")
        return self

    def restore(self):
        if not self.active:
            return []
        self.active = False
        during = {}
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                during[s] = signal.signal(s, signal.SIG_IGN)
            except (ValueError, OSError):
                pass
        try:
            failed = restore_changes(self.changes, self.run, self.paths,
                                     self._setaff)
            n = len(self.changes)
            self.changes = []
            try:
                os.remove(self.paths.state)
            except OSError:
                pass
        finally:
            for s, h in during.items():
                try:
                    signal.signal(s, self._handlers.get(s, h))
                except (ValueError, OSError):
                    pass
            self._handlers = {}
        try:
            atexit.unregister(self.restore)
        except Exception:
            pass
        if failed:
            for ch, err in failed:
                warn(f"not restored: {_describe_change(ch)} -- {err}")
        _say(f"  {GREY}machine conditions restored: {n - len(failed)}"
             f"/{n} settings{NC}")
        return failed

    def __enter__(self):
        return self.apply()

    def __exit__(self, *exc):
        self.restore()

    def _install_signals(self):
        """SIGTERM e SIGHUP come Ctrl-C."""
        def handler(signum, frame):
            raise KeyboardInterrupt(f"signal {signum}")
        for s in (signal.SIGTERM, signal.SIGHUP):
            try:
                self._handlers[s] = signal.signal(s, handler)
            except (ValueError, OSError):
                pass

    def _check_power(self):
        on_ac, pct = power_source(self.paths)
        if on_ac is False:
            warn("the laptop is on BATTERY: power limits and profile "
                 "change, and power-profiles-daemon may change them in the "
                 "middle of the run. Plug in the power supply.")
        self.facts.append(("alimentazione", _power_text(on_ac, pct)))

    def _ppd_active(self):
        rc, out, _ = self.run(["systemctl", "is-active",
                               "power-profiles-daemon"])
        return rc == 0 and out.strip() == "active"

    def _step_profile(self):
        target = self.profile
        if target in (None, "", "keep"):
            self.facts.append(("profilo", "not touched"))
            return
        if self._ppd_active():
            rc, cur, _ = self.run(["powerprofilesctl", "get"])
            cur = cur.strip()
            if rc == 0 and cur and cur != target:
                ch = self._record(dict(kind="profile", old=cur, new=target))
                rc2, _, err = self.run(["powerprofilesctl", "set", target])
                if rc2:
                    self._unrecord(ch)
                    warn(f"powerprofilesctl set {target}: "
                         f"{err.strip() or rc2}")
            _, now, _ = self.run(["powerprofilesctl", "get"])
            self.facts.append(("profilo", f"{now.strip() or '?'} (was "
                                          f"{cur or '?'}, power-profiles-daemon)"))
            return
        path = self.paths.sys("firmware", "acpi", "platform_profile")
        choices = (read_text(self.paths.sys(
            "firmware", "acpi", "platform_profile_choices")) or "").split()
        old = read_text(path)
        if old is None:
            self.facts.append(("profilo", "platform_profile missing"))
            return
        if target not in choices:
            warn(f"profile {target!r} not among {choices}: keeping {old}")
            self.facts.append(("profilo", old))
            return
        self._set_file(path, target, "platform_profile")
        self.facts.append(("profilo", f"{read_text(path)} (was {old})"))

    def _cgroup_of_self(self):
        return read_text(self.paths.proc("self", "cgroup")) or ""

    def _tids(self):
        try:
            return [int(t) for t in os.listdir(self.paths.proc("self", "task"))
                    if t.isdigit()]
        except OSError:
            return [self._getpid()]

    def _step_scope(self):
        """The bench process in its own scope, under ipa-bench.slice."""
        me = self._getpid()
        if SCOPE_SLICE not in self._cgroup_of_self():
            unit = f"ipa-bench-{me}-{int(time.time())}.scope"
            rc, _, err = self.run([
                "busctl", "call", "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager", "StartTransientUnit",
                "ssa(sv)a(sa(sv))", unit, "fail", "3",
                "PIDs", "au", "1", str(me),
                "Slice", "s", SCOPE_SLICE,
                "Description", "s", "IPA bench (host_conditions)", "0"])
            if rc == 0:
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    if SCOPE_SLICE in self._cgroup_of_self():
                        break
                    time.sleep(0.02)
            if SCOPE_SLICE not in self._cgroup_of_self():
                warn("the bench process did not move into its own scope "
                     f"({err.strip() or 'busctl rc=' + str(rc)}): confining "
                     "user.slice would take it away from the CPUs it must use. "
                     "Skipping process confinement; IRQs, workqueues and "
                     "kernel threads are moved anyway.")
                self.facts.append(("isolamento_processi", "no (scope not "
                                                          "created)"))
                return
        self._scoped = True
        hk = set(self.hk)
        for tid in self._tids():
            try:
                self._setaff(tid, hk)
            except OSError:
                pass

    def _step_cgroups(self):
        if not self._scoped:
            return
        hk = format_cpu_list(self.hk)
        done = []
        for unit in CONFINED_UNITS:
            rc, state, _ = self.run(["systemctl", "show", "-p", "ActiveState",
                                     "--value", unit])
            if rc or state.strip() != "active":
                continue
            rc, old, _ = self.run(["systemctl", "show", "-p", "AllowedCPUs",
                                   "--value", unit])
            if rc:
                continue
            ch = self._record(dict(kind="unit", unit=unit, prop="AllowedCPUs",
                                   old=old.strip(), new=hk))
            rc, _, err = self.run(["systemctl", "set-property", "--runtime",
                                   unit, f"AllowedCPUs={hk}"])
            if rc:
                self._unrecord(ch)
                warn(f"{unit}: AllowedCPUs refused ({err.strip() or rc})")
                continue
            done.append(unit)
        self.facts.append(("isolamento_processi",
                           f"{', '.join(done)} -> cpu {hk}" if done
                           else "not applied"))

    def _step_kthreads(self):
        """The kernel threads not bound to a CPU (rcu_preempt, kswapd,
        khugepaged, kcompactd, ...) onto the system CPUs."""
        hk = set(self.hk)
        moved = refused = 0
        try:
            pids = [int(n) for n in os.listdir(self.paths.proc())
                    if n.isdigit()]
        except OSError:
            pids = []
        for pid in sorted(pids):
            stat = read_text(self.paths.proc(str(pid), "stat"))
            if not stat or ")" not in stat:
                continue
            fields = stat.rsplit(")", 1)[1].split()
            flags = _int(fields[6] if len(fields) > 6 else None, 0)
            if not flags & PF_KTHREAD or flags & PF_NO_SETAFFINITY:
                continue
            comm = _comm_of(self.paths, pid) or ""
            if comm.startswith(("napi/", "kpktgend", "irq/")):
                continue
            try:
                cur = set(self._getaff(pid))
            except OSError:
                continue
            if cur <= hk:
                continue
            ch = self._record(dict(kind="affinity", pid=pid, comm=comm,
                                   old=format_cpu_list(cur),
                                   new=format_cpu_list(hk)))
            try:
                self._setaff(pid, hk)
                moved += 1
            except OSError:
                self._unrecord(ch)
                refused += 1
        self.facts.append(("isolamento_kthread",
                           f"{moved} moved to the system CPUs"
                           + (f", {refused} refused" if refused else "")))

    def _step_irqs(self):
        hk_list = format_cpu_list(self.hk)
        hk = set(self.hk)
        base = self.paths.proc("irq")
        moved = refused = 0
        try:
            names = sorted((n for n in os.listdir(base) if n.isdigit()),
                           key=int)
        except OSError:
            names = []
        for n in names:
            path = os.path.join(base, n, "smp_affinity_list")
            cur = read_text(path)
            if cur is None:
                continue
            try:
                if set(parse_cpu_list(cur)) <= hk:
                    continue
            except ValueError:
                continue
            r = self._set_file(path, hk_list, f"irq {n}")
            if r:
                moved += 1
            elif r is False:
                refused += 1
        self._set_file(os.path.join(base, "default_smp_affinity"),
                       cpu_mask_hex(self.hk), "irq default")
        self.facts.append(("isolamento_irq",
                           f"{moved} IRQs on cpu {hk_list}"
                           + (f", {refused} not movable (affinity managed "
                              f"by the kernel)" if refused else "")))

    def _step_workqueue(self):
        path = self.paths.sys("devices", "virtual", "workqueue", "cpumask")
        r = self._set_file(path, cpu_mask_hex(self.hk), "workqueue unbound")
        self.facts.append(("isolamento_workqueue",
                           f"unbound on cpu {format_cpu_list(self.hk)}"
                           if r else "not applied"))

    def _step_freq(self):
        if self.freq in (None, "", "keep"):
            self.facts.append(("frequenza", "not touched"))
            return
        cpus = sorted(set(self.bench) | set(self.siblings))
        missing, pinned, unpinned = [], {}, []
        for c in cpus:
            def f(name):
                return self.paths.cpu(f"cpu{c}", "cpufreq", name)
            gov = read_text(f("scaling_governor"))
            if gov is None:
                missing.append(c)
                continue
            lo = _int(read_text(f("cpuinfo_min_freq")))
            hi = _int(read_text(f("cpuinfo_max_freq")))
            base = _int(read_text(f("base_frequency")))
            if self.freq == "max":
                target = None
            elif self.freq == "base":
                target = base
            else:
                target = int(self.freq) * 1000
                if lo:
                    target = max(target, lo)
                if hi:
                    target = min(target, hi)
            avail = (read_text(f("scaling_available_governors")) or "").split()
            if "performance" in avail and gov != "performance":
                self._remember_file(f("energy_performance_preference"),
                                    f"epp cpu{c}")
                self._set_file(f("scaling_governor"), "performance",
                               f"governor cpu{c}")
            if target:
                if lo:
                    self._set_file(f("scaling_min_freq"), lo, f"min cpu{c}")
                self._set_file(f("scaling_max_freq"), target, f"max cpu{c}")
                self._set_file(f("scaling_min_freq"), target, f"min cpu{c}")
                pinned[c] = target
                if c in self.bench:
                    self.target_khz[c] = target
            elif self.freq == "max":
                if hi:
                    self._set_file(f("scaling_max_freq"), hi, f"max cpu{c}")
            else:
                unpinned.append(c)
        if missing and len(missing) == len(cpus):
            self.facts.append(("frequenza", "cpufreq missing: not "
                                            "controllable"))
            return
        def readback():
            out = {}
            for c in pinned:
                d = self.paths.cpu(f"cpu{c}", "cpufreq")
                out[c] = (_int(read_text(os.path.join(d, "scaling_min_freq"))),
                          _int(read_text(os.path.join(d, "scaling_max_freq"))))
            return out
        deadline = time.monotonic() + 2.0
        got = readback()
        while (any(v != (pinned[c], pinned[c]) for c, v in got.items())
               and time.monotonic() < deadline):
            time.sleep(0.05)
            got = readback()
        wanted = pinned
        pinned = got
        if pinned:
            self.facts.append(("frequenza", _uniform(
                pinned, lambda v: f"performance, {(v[0] or 0) // 1000}-"
                                  f"{(v[1] or 0) // 1000} MHz")))
        if self.freq == "max":
            self.facts.append(("frequenza", f"performance, free turbo on "
                                            f"cpu {format_cpu_list(cpus)} "
                                            f"(not fixed)"))
        if unpinned:
            warn(f"base_frequency not exposed on cpu "
                 f"{format_cpu_list(unpinned)}: frequency not fixed "
                 f"(use --freq MHz)")
        if missing:
            warn(f"cpufreq missing on cpu {format_cpu_list(missing)}")
        bad = [c for c, (a, b) in pinned.items()
               if a != b or b != wanted.get(c)] if pinned else []
        if bad:
            warn(f"frequency not fixed as requested on cpu "
                 f"{format_cpu_list(bad)}: " + _uniform(
                     {c: pinned[c] for c in bad},
                     lambda v: f"{(v[0] or 0) // 1000}-{(v[1] or 0) // 1000} "
                               f"MHz"))

    def _step_measure_freq(self):
        """The frequency the bench cores ACTUALLY hold, from APERF/MPERF,
        with a busy loop of MEASURE_S seconds pinned on each."""
        self.requested_khz = dict(self.target_khz)
        if not self.target_khz or self.paths.root != "/":
            return
        measured = {}
        for c in sorted(self.target_khz):
            mon = HostMonitor(self.topo, [c], dut=c, paths=self.paths,
                              use_msr=True)
            if mon._fd is None:
                mon.close()
                self.facts.append(("frequenza_misurata",
                                   f"not measurable ({mon.msr_note})"))
                return
            a = mon.mark()
            try:
                subprocess.run(
                    [sys.executable, "-c",
                     f"import time\nt=time.time()+{MEASURE_S}\n"
                     "while time.time()<t: pass"],
                    preexec_fn=lambda c=c: os.sched_setaffinity(0, {c}),
                    timeout=10)
            except (OSError, subprocess.SubprocessError):
                mon.close()
                continue
            cols = mon.delta(a, mon.mark())
            mon.close()
            if cols.get("host_dut_mhz") and \
                    (cols.get("host_dut_busy_pct") or 0) > 80:
                measured[c] = cols["host_dut_mhz"] * 1000
        if not measured:
            return
        self.target_khz.update(measured)
        spread = (max(measured.values()) - min(measured.values())) \
            / max(measured.values())
        self.facts.append((
            "frequenza_misurata",
            _uniform({c: v // 1000 for c, v in measured.items()},
                     lambda v: f"{v} MHz")
            + f" (APERF/MPERF, {MEASURE_S} s at full load; requested "
              + _uniform({c: v // 1000 for c, v in self.requested_khz.items()},
                         lambda v: f"{v} MHz") + ")"))
        if spread > FREQ_TOLERANCE:
            warn("the bench cores do not hold the same frequency: "
                 + ", ".join(f"cpu{c} {v // 1000} MHz"
                             for c, v in sorted(measured.items())))
        off = {c: v for c, v in measured.items()
               if abs(v - self.requested_khz[c])
               > FREQ_TOLERANCE * self.requested_khz[c]}
        if off:
            info("real frequency different from the one written in sysfs ("
                 + ", ".join(f"cpu{c}: {self.requested_khz[c] // 1000} "
                             f"requested, {v // 1000} measured"
                             for c, v in sorted(off.items()))
                 + "): it is fixed anyway; the monitor's reference is the "
                   "measured one")

    def _step_system_cap(self):
        """Frequency cap on the system CPUs."""
        cap = self.system_max_mhz
        if cap in (None, "", "keep") or not self.hk:
            return
        capped = []
        for c in self.hk:
            def f(name):
                return self.paths.cpu(f"cpu{c}", "cpufreq", name)
            hi = _int(read_text(f("scaling_max_freq")))
            if hi is None:
                continue
            cmin = _int(read_text(f("cpuinfo_min_freq")))
            target = max(int(cap) * 1000, cmin or 0)
            if hi <= target:
                continue
            lo = _int(read_text(f("scaling_min_freq")))
            if lo and lo > target:
                self._set_file(f("scaling_min_freq"), cmin or target,
                               f"min cpu{c}")
            if self._set_file(f("scaling_max_freq"), target, f"max cpu{c}"):
                capped.append(c)
        if capped:
            self.facts.append(("frequenza_sistema",
                               f"cpu {format_cpu_list(capped)}: max "
                               f"{int(cap)} MHz (no turbo during the run)"))

    def _step_uncore(self):
        if self.uncore in (None, "", "keep"):
            return
        base = self.paths.cpu("intel_uncore_frequency")
        dirs = sorted(glob.glob(os.path.join(base, "package_*_die_*"))
                      + glob.glob(os.path.join(base, "uncore[0-9]*")))
        done = []
        for d in dirs:
            imin = _int(read_text(os.path.join(d, "initial_min_freq_khz")))
            imax = _int(read_text(os.path.join(d, "initial_max_freq_khz")))
            if not imax:
                continue
            if self.uncore == "max":
                target = imax
            else:
                target = min(max(int(self.uncore) * 1000, imin or 0), imax)
            name = os.path.basename(d)
            if imin:
                self._set_file(os.path.join(d, "min_freq_khz"), imin,
                               f"uncore min {name}")
            self._set_file(os.path.join(d, "max_freq_khz"), target,
                           f"uncore max {name}")
            self._set_file(os.path.join(d, "min_freq_khz"), target,
                           f"uncore min {name}")
            done.append(f"{name} {target // 1000} MHz")
        self.facts.append(("uncore", ", ".join(done) if done
                           else "not controllable (intel_uncore_frequency "
                                "missing)"))

    def _step_cstates(self):
        lim = self.cstate_max_us
        if lim in (None, "", "keep"):
            self.facts.append(("idle", "not touched"))
            return
        lim = int(lim)
        off, kept, seen = {}, {}, False
        for c in self.bench:
            base = self.paths.cpu(f"cpu{c}", "cpuidle")
            try:
                states = sorted((s for s in os.listdir(base)
                                 if re.fullmatch(r"state\d+", s)),
                                key=lambda s: int(s[5:]))
            except OSError:
                continue
            seen = True
            for s in states:
                d = os.path.join(base, s)
                name = read_text(os.path.join(d, "name")) or s
                lat = _int(read_text(os.path.join(d, "latency")))
                if lat is None:
                    continue
                if lat > lim:
                    r = self._set_file(os.path.join(d, "disable"), "1",
                                       f"idle {name} cpu{c}")
                    if r:
                        off[name] = lat
                else:
                    kept[name] = lat
        if not seen:
            self.facts.append(("idle", "cpuidle missing (driver none?): "
                                       "nothing to limit"))
            return
        self.facts.append(("idle", f"cpu {format_cpu_list(self.bench)}: "
                           + (("off " + ", ".join(
                               f"{n} ({l} us)" for n, l in off.items()))
                              if off else "no state above the threshold")
                           + ("; kept " + ", ".join(kept) if kept else "")))

    def _step_nmi(self):
        if not self.nmi_off:
            return
        path = self.paths.proc("sys", "kernel", "nmi_watchdog")
        old = read_text(path)
        r = self._set_file(path, "0", "nmi_watchdog")
        if r is not None:
            self.facts.append(("nmi_watchdog", f"0 (era {old})" if old != "0"
                               else "0"))

    def env_pairs(self):
        out = [("condizionamento", "applied by host_conditions, "
                                   "restored at the end of the run")]
        out += [(f"host_{k}", v) for k, v in self.facts]
        return out


# --- IL MONITOR ---
def power_source(paths=None):
    """(on mains: True/False/None, battery %: int or None)."""
    paths = paths or Paths()
    online, pct = [], None
    for d in sorted(glob.glob(paths.sys("class", "power_supply", "*"))):
        typ = read_text(os.path.join(d, "type"))
        if typ in ("Mains", "USB"):
            v = _int(read_text(os.path.join(d, "online")))
            if v is not None:
                online.append(bool(v))
        elif typ == "Battery" and pct is None:
            pct = _int(read_text(os.path.join(d, "capacity")))
    return (any(online) if online else None), pct


def _power_text(on_ac, pct):
    src = {True: "mains (AC)", False: "BATTERY", None: "unknown"}[on_ac]
    return src + (f", battery {pct}%" if pct is not None else "")


def _thermal_zone(paths, typ):
    for d in sorted(glob.glob(paths.sys("class", "thermal", "thermal_zone*"))):
        if read_text(os.path.join(d, "type")) == typ:
            return os.path.join(d, "temp")
    return None


def _coretemp_input(paths, topo, cpu):
    """The coretemp tempN_input of the physical core of `cpu` (label "Core
    <core_id>")."""
    if topo is None or cpu is None or cpu not in topo.cpus:
        return None
    want = f"Core {topo.cpus[cpu]['core_id']}"
    for h in glob.glob(paths.sys("class", "hwmon", "hwmon*")):
        if read_text(os.path.join(h, "name")) != "coretemp":
            continue
        for lab in glob.glob(os.path.join(h, "temp*_label")):
            if read_text(lab) == want:
                return lab[:-len("_label")] + "_input"
    return None


def _cooling_devices(paths, typ):
    return [os.path.join(d, "cur_state") for d in
            glob.glob(paths.sys("class", "thermal", "cooling_device*"))
            if read_text(os.path.join(d, "type")) == typ]


def _max_state(files):
    vals = [_int(read_text(f)) for f in files]
    vals = [v for v in vals if v is not None]
    return max(vals) if vals else None


def host_columns(a, b, target_khz=None):
    """The host_* columns between two monitor readings."""
    if not a or not b:
        return {}
    dt = b["t"] - a["t"]

    def deltas(key):
        out = []
        for c, v in b.get(key, {}).items():
            v0 = a.get(key, {}).get(c)
            if v is not None and v0 is not None:
                out.append(v - v0)
        return out

    core = deltas("core_thr")
    pkg = deltas("pkg_thr")
    busy = mhz = None
    if a.get("msr") and b.get("msr"):
        da = b["msr"][0] - a["msr"][0]
        dm = b["msr"][1] - a["msr"][1]
        dtsc = b["msr"][2] - a["msr"][2]
        if dtsc > 0 and dt > 0:
            busy = 100.0 * dm / dtsc
            if dm > 0:
                mhz = (dtsc / dt / 1e6) * da / dm
    smi = (b["smi"] - a["smi"]
           if a.get("smi") is not None and b.get("smi") is not None else None)
    clamp = max([v for v in (a.get("clamp"), b.get("clamp")) if v is not None],
                default=None)
    cooling = max([v for v in (a.get("cooling"), b.get("cooling"))
                   if v is not None], default=None)
    on_ac = b.get("ac")
    off = bool(target_khz and mhz is not None and busy is not None
               and busy >= FREQ_CHECK_MIN_BUSY_PCT
               and abs(mhz * 1000 - target_khz) > FREQ_TOLERANCE * target_khz)
    disturbed = bool((core and sum(core)) or (pkg and max(pkg)) or clamp
                     or cooling or on_ac is False or off)

    def temp(k):
        v = b.get(k)
        return round(v / 1000.0, 1) if v is not None else None

    return dict(
        host_throttle_core=sum(core) if core else None,
        host_throttle_pkg=max(pkg) if pkg else None,
        host_pkg_temp_c=temp("pkg_temp_mc"),
        host_dut_temp_c=temp("dut_temp_mc"),
        host_dut_busy_pct=round(busy, 1) if busy is not None else None,
        host_dut_mhz=int(round(mhz)) if mhz is not None else None,
        host_smi=smi, host_powerclamp=clamp, host_on_ac=on_ac,
        host_off_target=off, host_disturbed=disturbed)


class HostMonitor:
    """Machine readings around the measurements. mark() costs a few sysfs
    reads and, if /dev/cpu/N/msr exists, three MSR reads on the DUT."""

    def __init__(self, topo, watch, dut=None, paths=None, target_khz=None,
                 use_msr=True):
        self.topo = topo
        self.paths = paths or Paths()
        self.watch = sorted(set(int(c) for c in watch))
        self.dut = dut if dut is not None else (self.watch[0] if self.watch
                                                else None)
        self.target_khz = target_khz
        self._fd = None
        self.msr_note = "not requested"
        if use_msr and self.dut is not None:
            self._open_msr()
        self._pkg_zone = _thermal_zone(self.paths, "x86_pkg_temp")
        self._dut_temp = _coretemp_input(self.paths, topo, self.dut)
        self._clamp = _cooling_devices(self.paths, "intel_powerclamp")
        self._cool = _cooling_devices(self.paths, "Processor")
        self._start = None
        self._log = None
        self._log_path = None

    def _open_msr(self):
        path = self.paths.p("dev", "cpu", str(self.dut), "msr")
        if not os.path.exists(path) and self.paths.root == "/":
            run_cmd(["modprobe", "msr"])
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as e:
            self.msr_note = f"missing ({e.strerror})"
            return
        try:
            os.pread(fd, 8, MSR_APERF)
        except OSError as e:
            os.close(fd)
            self.msr_note = f"unreadable ({e.strerror})"
            return
        self._fd = fd
        self.msr_note = f"APERF/MPERF su cpu{self.dut}"

    def _rdmsr(self, reg):
        return int.from_bytes(os.pread(self._fd, 8, reg), "little")

    @property
    def dut_target_khz(self):
        t = self.target_khz
        if isinstance(t, dict):
            return t.get(self.dut)
        return t

    def mark(self):
        m = dict(t=time.monotonic(), core_thr={}, pkg_thr={})
        for c in self.watch:
            d = self.paths.cpu(f"cpu{c}", "thermal_throttle")
            m["core_thr"][c] = _int(read_text(os.path.join(
                d, "core_throttle_count")))
            m["pkg_thr"][c] = _int(read_text(os.path.join(
                d, "package_throttle_count")))
        m["pkg_temp_mc"] = _int(read_text(self._pkg_zone))
        m["dut_temp_mc"] = _int(read_text(self._dut_temp))
        m["clamp"] = _max_state(self._clamp)
        m["cooling"] = _max_state(self._cool)
        m["ac"] = power_source(self.paths)[0]
        if self._fd is not None:
            try:
                m["msr"] = (self._rdmsr(MSR_APERF), self._rdmsr(MSR_MPERF),
                            self._rdmsr(MSR_TSC))
            except OSError:
                pass
            try:
                m["smi"] = self._rdmsr(MSR_SMI_COUNT)
            except OSError:
                pass
        return m

    def delta(self, a, b):
        return host_columns(a, b, self.dut_target_khz)

    def start_run(self):
        self._start = self.mark()
        return self._start

    def run_columns(self):
        return host_columns(self._start, self.mark(), self.dut_target_khz)

    def start_log(self, path, period=1.0):
        """The per-second log, in a separate process."""
        self.stop_log()
        argv = [sys.executable, os.path.abspath(__file__), "--log", path,
                "--period", str(period), "--watch",
                format_cpu_list(self.watch), "--root", self.paths.root]
        try:
            self._log = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL,
                                         close_fds=True)
            self._log_path = path
        except OSError as e:
            warn(f"machine log not started: {e}")
            self._log = None

    def stop_log(self):
        p, self._log = self._log, None
        if p is None:
            return None
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
        return summarise_log(self._log_path)

    def close(self):
        self.stop_log()
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


LOG_COLS = ("tempo", "t_s", "temp_pacchetto_c", "throttle_core",
            "throttle_pacchetto", "powerclamp", "raffreddamento_cpu",
            "alimentazione_rete")


def log_loop(path, watch, period=1.0, paths=None, max_samples=None):
    """The body of `--log`."""
    paths = paths or Paths()
    parent = os.getppid()
    mon = HostMonitor(None, watch, paths=paths, use_msr=False)
    cols = list(LOG_COLS) + [f"mhz_cpu{c}" for c in mon.watch]
    t0 = time.monotonic()
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        f.flush()
        while os.getppid() == parent:
            m = mon.mark()
            core = [v for v in m["core_thr"].values() if v is not None]
            pkg = [v for v in m["pkg_thr"].values() if v is not None]
            freqs = [_int(read_text(paths.cpu(f"cpu{c}", "cpufreq",
                                              "scaling_cur_freq")))
                     for c in mon.watch]
            w.writerow([time.strftime("%H:%M:%S"),
                        round(m["t"] - t0, 2),
                        (round(m["pkg_temp_mc"] / 1000.0, 1)
                         if m["pkg_temp_mc"] is not None else ""),
                        sum(core) if core else "", max(pkg) if pkg else "",
                        "" if m["clamp"] is None else m["clamp"],
                        "" if m["cooling"] is None else m["cooling"],
                        "" if m["ac"] is None else int(m["ac"])]
                       + ["" if v is None else v // 1000 for v in freqs])
            f.flush()
            n += 1
            if max_samples and n >= max_samples:
                break
            time.sleep(period)


def summarise_log(path):
    """Maxima and differences of the log."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except OSError:
        return None
    if not rows:
        return None

    def col(k):
        out = []
        for r in rows:
            try:
                out.append(float(r.get(k, "")))
            except ValueError:
                pass
        return out

    temps = col("temp_pacchetto_c")
    core = col("throttle_core")
    pkg = col("throttle_pacchetto")
    clamp = col("powerclamp")
    ac = col("alimentazione_rete")
    return dict(samples=len(rows), durata_s=col("t_s")[-1] if col("t_s") else 0,
                temp_max_c=max(temps) if temps else None,
                temp_min_c=min(temps) if temps else None,
                throttle_core=int(core[-1] - core[0]) if len(core) > 1 else 0,
                throttle_pkg=int(pkg[-1] - pkg[0]) if len(pkg) > 1 else 0,
                powerclamp_max=max(clamp) if clamp else None,
                campioni_a_batteria=sum(1 for v in ac if v == 0))


# --- the conditions, as read (also without conditioning) ---
def _dmi(paths):
    def rd(n):
        return read_text(paths.sys("class", "dmi", "id", n)) or ""
    name = " ".join(x for x in (rd("sys_vendor"), rd("product_version"),
                                f"({rd('product_name')})" if rd("product_name")
                                else "") if x)
    bios = rd("bios_version")
    return (name or "n/d") + (f", BIOS {bios}" if bios else "")


def _microcode(paths):
    for line in (read_text(paths.proc("cpuinfo")) or "").splitlines():
        if line.startswith("microcode"):
            return line.split(":", 1)[1].strip()
    return "n/d"


def read_conditions(topo, cpus, paths=None):
    """The conditions of the bench CPUs as they are NOW."""
    paths = paths or Paths()
    gov, lim, epp, idle, thr = {}, {}, {}, {}, {}
    for c in cpus:
        def f(*p):
            return read_text(paths.cpu(f"cpu{c}", *p))
        g = f("cpufreq", "scaling_governor")
        if g is not None:
            gov[c] = g
            lim[c] = (f"{(_int(f('cpufreq', 'scaling_min_freq')) or 0) // 1000}-"
                      f"{(_int(f('cpufreq', 'scaling_max_freq')) or 0) // 1000}"
                      f" MHz")
        e = f("cpufreq", "energy_performance_preference")
        if e is not None:
            epp[c] = e
        base = paths.cpu(f"cpu{c}", "cpuidle")
        if os.path.isdir(base):
            on = []
            for s in sorted(glob.glob(os.path.join(base, "state*")),
                            key=lambda p: _int(p.rsplit("state", 1)[1], 0)):
                if read_text(os.path.join(s, "disable")) == "0":
                    on.append(read_text(os.path.join(s, "name")) or
                              os.path.basename(s))
            idle[c] = ",".join(on) or "none"
        ct = f("thermal_throttle", "core_throttle_count")
        if ct is not None:
            thr[c] = ct
    return dict(governor=gov, limiti=lim, epp=epp, idle=idle, throttle=thr)


def env_pairs(plan, host=None, monitor=None, paths=None, runner=None,
              log_summary=None):
    """The env.csv rows about the machine."""
    paths = paths or Paths()
    runner = runner or run_cmd
    topo = getattr(plan, "topo", None) or Topology.read(paths)
    dut = list(getattr(plan, "dut", []) or [])
    gen = list(getattr(plan, "gen", []) or [])
    egress = getattr(plan, "egress", None)
    used = sorted(set(dut) | set(gen) | set(egress_cpus(egress)))
    env = []

    def add(k, v):
        env.append((k, "n/d" if v is None or v == "" else str(v)))

    add("macchina", _dmi(paths))
    add("topologia_cpu", topo.summary())
    add("microcode", _microcode(paths))
    if used:
        add("ruolo_dut", ", ".join(topo.label(c) for c in dut))
        add("ruolo_uscita", ", ".join(topo.label(c)
                                      for c in egress_cpus(egress))
            if egress is not None else "no CPU of its own (softirq on the DUT CPU)")
        add("ruolo_generatore", ", ".join(topo.label(c) for c in gen))
        add("fratelli_smt_a_riposo",
            format_cpu_list(idle_siblings(topo, used)) or "none")
        add("cpu_sistema", format_cpu_list(housekeeping(topo, used)))
    add("intel_pstate", read_text(paths.cpu("intel_pstate", "status")))
    nt = read_text(paths.cpu("intel_pstate", "no_turbo"))
    add("turbo", {"0": "on", "1": "off"}.get(nt, nt))
    cond = read_conditions(topo, used, paths)
    add("governor_banco", _uniform(cond["governor"]))
    add("frequenza_banco", _uniform(cond["limiti"]))
    add("epp_banco", _uniform(cond["epp"]))
    add("idle_banco", _uniform(cond["idle"]))
    unc = []
    for d in sorted(glob.glob(paths.cpu("intel_uncore_frequency",
                                        "package_*_die_*"))):
        lo = _int(read_text(os.path.join(d, "min_freq_khz")))
        hi = _int(read_text(os.path.join(d, "max_freq_khz")))
        if lo and hi:
            unc.append(f"{os.path.basename(d)} {lo // 1000}-{hi // 1000} MHz")
    add("uncore", ", ".join(unc))
    add("profilo_piattaforma",
        read_text(paths.sys("firmware", "acpi", "platform_profile")))
    add("alimentazione", _power_text(*power_source(paths)))
    t = _int(read_text(_thermal_zone(paths, "x86_pkg_temp")))
    add("temperatura_pacchetto_c", round(t / 1000.0, 1) if t is not None
        else None)
    add("nmi_watchdog", read_text(paths.proc("sys", "kernel",
                                             "nmi_watchdog")))
    add("throttle_dal_boot_banco", _uniform(cond["throttle"]))
    for svc in ("thermald", "irqbalance", "power-profiles-daemon"):
        rc, out, _ = runner(["systemctl", "is-active", svc])
        add(f"servizio_{svc}", out.strip() or f"rc {rc}")
    if host is not None and host.active:
        env += host.env_pairs()
    else:
        add("condizionamento", "no (--no-tune): machine conditions "
                               "left as they were, only recorded")
    if monitor is not None:
        add("msr", monitor.msr_note)
        if monitor._start is not None:
            cols = monitor.run_columns()
            for k in ("host_throttle_core", "host_throttle_pkg", "host_smi",
                      "host_dut_busy_pct", "host_dut_mhz", "host_pkg_temp_c",
                      "host_powerclamp", "host_disturbed"):
                if k in cols:
                    add(f"run_{k[5:]}", cols[k])
    if log_summary:
        for k, v in log_summary.items():
            add(f"registro_{k}", v)
    return env


# --- for the benches: arguments and construction ---
def add_args(parser):
    g = parser.add_argument_group(
        "machine conditions (host_conditions.py, all reversible)")
    g.add_argument("--no-tune", action="store_true",
                   help="do not touch the machine: no fixed frequency, "
                        "idle, isolation, profile. The conditions are "
                        "still read and written to env.csv.")
    g.add_argument("--freq", default=DEFAULT_FREQ, metavar="F",
                   help=f"frequency of the bench cores in MHz (default "
                        f"{DEFAULT_FREQ}: the highest the lab laptop holds "
                        f"for a whole run), base (the one guaranteed at "
                        f"TDP), max "
                        "(performance governor and free turbo: faster, "
                        "less repeatable), keep, or MHz")
    g.add_argument("--system-max-mhz", default=str(DEFAULT_SYSTEM_MAX_MHZ),
                   metavar="MHZ",
                   help=f"frequency cap of the system CPUs (desktop, "
                        f"browser, the bench process) during the run "
                        f"(default {DEFAULT_SYSTEM_MAX_MHZ}): a core in turbo "
                        f"heats the package up to throttling. keep to "
                        f"leave them alone")
    g.add_argument("--uncore", default=DEFAULT_UNCORE, metavar="U",
                   help="uncore frequency (L3, ring): max (default), "
                        "keep, or MHz")
    g.add_argument("--cstate-max-us", default=str(DEFAULT_CSTATE_MAX_US),
                   metavar="US",
                   help="on the bench CPUs, disable the idle states with "
                        "exit slower than US microseconds (default 1: "
                        "POLL and C1E stay); 0 = POLL only; keep")
    g.add_argument("--profile", default=DEFAULT_PROFILE, metavar="P",
                   help="power-profiles-daemon profile during the run "
                        "(default performance), or keep")
    g.add_argument("--no-isolate", action="store_true",
                   help="do not confine processes, IRQs, workqueues and kernel "
                        "threads to the system CPUs")
    g.add_argument("--keep-nmi-watchdog", action="store_true",
                   help="leave the NMI watchdog on")
    return g


def check_args(a):
    """Validates the values argparse cannot validate by itself."""
    def num_or(v, words, what):
        if v in words:
            return v
        try:
            n = int(v)
        except (TypeError, ValueError):
            sys.exit(f"{what}: expected {' | '.join(words)} or a number, "
                     f"got {v!r}")
        if n < 0:
            sys.exit(f"{what}: a non-negative number is needed")
        return str(n)

    a.freq = num_or(a.freq, ("base", "max", "keep"), "--freq")
    a.system_max_mhz = num_or(a.system_max_mhz, ("keep",),
                              "--system-max-mhz")
    a.uncore = num_or(a.uncore, ("max", "keep"), "--uncore")
    a.cstate_max_us = num_or(a.cstate_max_us, ("keep",), "--cstate-max-us")
    return a


def from_args(a, plan, **kw):
    """Il HostConditioner per `plan`, o None con --no-tune."""
    if getattr(a, "no_tune", False):
        return None
    topo = getattr(plan, "topo", None) or Topology.read()
    return HostConditioner(
        topo, plan.dut, plan.gen, getattr(plan, "egress", None),
        freq=a.freq, system_max_mhz=a.system_max_mhz, uncore=a.uncore,
        cstate_max_us=(None if a.cstate_max_us == "keep"
                       else int(a.cstate_max_us)),
        isolate=not a.no_isolate, profile=a.profile,
        nmi_off=not a.keep_nmi_watchdog, **kw)


def parse_egress(spec):
    """--egress-cpu: "auto", "none", a number or a list (one CPU per egress
    queue used, see bench_capacity.pin_egress_napi). None = no CPU of its
    own."""
    if spec is None:
        return None
    s = str(spec).strip().lower()
    if s in ("", "none", "no", "off"):
        return None
    if s == "auto":
        return "auto"
    try:
        cpus = [int(c) for c in s.split(",") if c.strip()]
        if len(set(cpus)) != len(cpus) or not cpus:
            raise ValueError
        return cpus[0] if len(cpus) == 1 else cpus
    except ValueError:
        sys.exit(f"--egress-cpu: expected auto, none, a CPU number or a "
                 f"list without repetitions, "
                 f"got {spec!r}")


# --- command line ---
def _toolchain_hints():
    hints = []
    import shutil
    if not shutil.which("clang"):
        hints.append("clang")
    if not os.path.exists("/usr/include/bpf/bpf_helpers.h"):
        hints += ["libbpf-dev", "libelf-dev", "zlib1g-dev", "libzstd-dev",
                  "liblzma-dev"]
    return hints


def show(paths=None, allow_cpu0=False):
    """--show: the topology, the plan the benches would use, and the current
    conditions. No root, no changes."""
    paths = paths or Paths()
    topo = Topology.read(paths)
    _say(f"\n{YELLOW}== topology =={NC}")
    _say(f"  {topo.summary()}")
    _say(f"  {'cpu':>4s} {'type':5s} {'core':>9s} {'base':>6s} {'max':>6s} "
         f"{'governor':12s} {'min-max MHz':>12s} {'epp':22s} active idle"
         f"{'':2s}throttle")
    cond = read_conditions(topo, topo.online, paths)
    for c in topo.online:
        v = topo.cpus[c]
        _say(f"  {c:4d} {v['kind']:5s} {format_cpu_list(v['core']):>9s} "
             f"{(v['base_khz'] or 0) // 1000:6d} {(v['max_khz'] or 0) // 1000:6d} "
             f"{cond['governor'].get(c, '-'):12s} "
             f"{cond['limiti'].get(c, '-').replace(' MHz', ''):>12s} "
             f"{cond['epp'].get(c, '-'):22s} {cond['idle'].get(c, '-'):12s} "
             f"{cond['throttle'].get(c, '-')}")
    r = plan_roles(topo, want_egress=True, allow_cpu0=allow_cpu0)
    used = sorted(set(r["dut"]) | set(r["gen"])
                  | ({r["egress"]} if r["egress"] is not None else set()))
    _say(f"\n{YELLOW}== automatic bench plan =={NC}")
    _say(f"  DUT ........... {', '.join(topo.label(c) for c in r['dut'])}")
    _say(f"  egress ........ " + (topo.label(r["egress"])
                                  if r["egress"] is not None else "none"))
    _say(f"  generatore .... {', '.join(topo.label(c) for c in r['gen'])}")
    _say(f"  idle .......... {format_cpu_list(idle_siblings(topo, used))}"
         f"  (SMT siblings)")
    _say(f"  system ........ {format_cpu_list(housekeeping(topo, used))}")
    for n in r["notes"]:
        warn(n)
    _say(f"\n{YELLOW}== current conditions (of the plan's CPUs) =={NC}")
    for k, v in env_pairs(Roles(topo, r["dut"], r["gen"], r["egress"]),
                          paths=paths):
        if k in ("topologia_cpu",) or k.startswith(("ruolo_", "fratelli_",
                                                    "cpu_sistema")):
            continue
        _say(f"  {GREY}{k:28s}{NC} {v}")
    if os.path.exists(paths.state):
        warn(f"{paths.state} exists: a run is in progress, or died without "
             f"restoring (sudo python3 {sys.argv[0]} --restore)")
    hints = _toolchain_hints()
    if hints:
        warn("missing for P1/P1.5 (AOT object): sudo apt install "
             + " ".join(hints))
    return 0


def _run_command(a, cmd):
    """--run: conditions applied, `cmd` on the DUT core, restore."""
    if os.geteuid() != 0:
        sys.exit("--run needs root: sudo python3 ipa/test/host_conditions.py "
                 "--run -- COMMAND")
    if not cmd:
        sys.exit("--run: the command after -- is missing")
    topo = Topology.read()
    if a.cpu is not None:
        if a.cpu not in topo.online:
            sys.exit(f"--cpu {a.cpu}: CPU not online")
        dut = a.cpu
    else:
        dut = plan_roles(topo, allow_cpu0=a.allow_cpu0)["dut"][0]
    roles = Roles(topo, [dut])
    info(f"command on {topo.label(dut)}: {' '.join(cmd)}")
    host = from_args(a, roles)
    if host is not None:
        host.apply()
    mon = HostMonitor(topo, [dut], dut=dut,
                      target_khz=(host.target_khz if host else None))
    mon.start_run()
    rc = 1
    try:
        rc = subprocess.call(cmd, preexec_fn=lambda: os.sched_setaffinity(
            0, {dut}))
    finally:
        cols = mon.run_columns()
        mon.close()
        if host is not None:
            host.restore()
        _say(f"\n  {GREY}machine during the command: core throttling "
             f"{cols.get('host_throttle_core')}, package "
             f"{cols.get('host_throttle_pkg')}; {cols.get('host_dut_mhz')} MHz; "
             f"{cols.get('host_pkg_temp_c')} C; disturbed: "
             f"{cols.get('host_disturbed')}{NC}")
        if cols.get("host_disturbed"):
            warn("the command did NOT run in the declared conditions "
                 "(throttling, powerclamp, battery or frequency off "
                 "target): see the lines above")
        if a.env:
            os.makedirs(a.env, exist_ok=True)
            with open(os.path.join(a.env, "env.csv"), "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["campo", "valore"])
                w.writerow(["comando", " ".join(cmd)])
                w.writerow(["cpu_dut", dut])
                for k, v in cols.items():
                    w.writerow([("run_" + k[5:]) if k.startswith("host_")
                                else k, v])
    return rc


def main(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__.strip().split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--show", action="store_true",
                   help="topology, automatic plan and current conditions "
                        "(no root, no changes)")
    p.add_argument("--restore", action="store_true",
                   help="restore the conditions left by a killed run")
    p.add_argument("--force", action="store_true",
                   help="with --restore: even if the process that applied "
                        "them is still alive")
    p.add_argument("--run", action="store_true",
                   help="apply the conditions, run the command after -- on "
                        "the DUT core, restore")
    p.add_argument("--cpu", type=int, default=None,
                   help="with --run: the command's CPU (default: the DUT of "
                        "the automatic plan)")
    p.add_argument("--allow-cpu0", action="store_true")
    p.add_argument("--env", default=None, metavar="DIR",
                   help="with --run: write to DIR/env.csv what the machine "
                        "did during the command (run_disturbed, ...)")
    p.add_argument("--log", default=None, help=argparse.SUPPRESS)
    p.add_argument("--watch", default="", help=argparse.SUPPRESS)
    p.add_argument("--period", type=float, default=1.0,
                   help=argparse.SUPPRESS)
    p.add_argument("--root", default="/", help=argparse.SUPPRESS)
    add_args(p)
    p.add_argument("cmd", nargs=argparse.REMAINDER,
                   help="with --run: the command, after --")
    a = p.parse_args(argv)
    cmd = list(a.cmd or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    paths = Paths(a.root)

    if a.log:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        log_loop(a.log, parse_cpu_list(a.watch), a.period, paths)
        return 0
    if a.restore:
        if os.geteuid() != 0 and a.root == "/":
            sys.exit("--restore needs root")
        data = load_state(paths)
        if data is None:
            info(f"nothing to restore ({paths.state} does not exist)")
            return 0
        alive = (lambda pid: False) if a.force else pid_alive
        n = recover_stale_state(paths, alive=alive, me=os.getpid())
        ok(f"restored {n} settings")
        return 0
    if a.run:
        check_args(a)
        return _run_command(a, cmd)
    return show(paths, a.allow_cpu0)


if __name__ == "__main__":
    sys.exit(main())
