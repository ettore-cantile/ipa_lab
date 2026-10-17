#!/usr/bin/env python3
"""hw_counters.py -- instructions, cycles, cache and branch misses per CPU from the
hardware counters (perf_event_open), read together with the packet counters.
Needs root.
"""
import ctypes
import ctypes.util
import os
import struct
import sys
import time

PERF_TYPE_HARDWARE = 0
PERF_COUNT_HW_CPU_CYCLES = 0
PERF_COUNT_HW_INSTRUCTIONS = 1
PERF_COUNT_HW_CACHE_MISSES = 3
PERF_COUNT_HW_BRANCH_MISSES = 5
PERF_FORMAT_TOTAL_TIME_ENABLED = 1
PERF_FORMAT_TOTAL_TIME_RUNNING = 2
PERF_EVENT_IOC_ENABLE = 0x2400
PERF_FLAG_FD_CLOEXEC = 1 << 3
PERF_TYPE_SHIFT = 32
SYS_PERF_EVENT_OPEN = {"x86_64": 298, "aarch64": 241}.get(os.uname().machine)

EVENTS = (
    ("ins", PERF_COUNT_HW_INSTRUCTIONS, "instructions"),
    ("cyc", PERF_COUNT_HW_CPU_CYCLES, "cycles"),
    ("llc", PERF_COUNT_HW_CACHE_MISSES, "cache-misses"),
    ("brm", PERF_COUNT_HW_BRANCH_MISSES, "branch-misses"),
)
PMU_DIR = "/sys/bus/event_source/devices"


class PerfEventAttr(ctypes.Structure):
    """The fixed part of perf_event_attr (PERF_ATTR_SIZE_VER0, 64 bytes)."""
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("sample_period", ctypes.c_uint64),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("wakeup_events", ctypes.c_uint32),
        ("bp_type", ctypes.c_uint32),
        ("config1", ctypes.c_uint64),
    ]


FLAG_DISABLED = 1 << 0
FLAG_PINNED = 1 << 2
FLAG_EXCLUDE_HV = 1 << 6


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _cpu_list(text):
    out = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def hybrid_pmus():
    """{cpu: PMU type} on hybrid processors, {} elsewhere."""
    out = {}
    for name in ("cpu_core", "cpu_atom"):
        t = _read(os.path.join(PMU_DIR, name, "type"))
        cpus = _cpu_list(_read(os.path.join(PMU_DIR, name, "cpus")))
        if t is None or not cpus:
            continue
        for c in cpus:
            out[c] = int(t)
    return out


def pmu_name(cpu):
    """"cpu_core", "cpu_atom" o "cpu"."""
    for name in ("cpu_core", "cpu_atom"):
        if cpu in _cpu_list(_read(os.path.join(PMU_DIR, name, "cpus"))):
            return name
    return "cpu"


_libc = None


def _syscall():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        _libc.syscall.restype = ctypes.c_long
    return _libc.syscall


def perf_open(cpu, hw_id, pmu_type=None):
    """One counter on the whole CPU `cpu`."""
    if SYS_PERF_EVENT_OPEN is None:
        raise OSError(38, "perf_event_open: unsupported architecture")
    attr = PerfEventAttr()
    attr.type = PERF_TYPE_HARDWARE
    attr.size = ctypes.sizeof(PerfEventAttr)
    attr.config = hw_id | ((pmu_type or 0) << PERF_TYPE_SHIFT)
    attr.read_format = (PERF_FORMAT_TOTAL_TIME_ENABLED
                        | PERF_FORMAT_TOTAL_TIME_RUNNING)
    attr.flags = FLAG_PINNED | FLAG_EXCLUDE_HV
    fd = _syscall()(SYS_PERF_EVENT_OPEN, ctypes.byref(attr), -1, cpu, -1,
                    PERF_FLAG_FD_CLOEXEC)
    if fd < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return fd


class HwCounters:
    """The counters of a group of CPUs."""

    def __init__(self, cpus, events=EVENTS):
        self.cpus = sorted(set(int(c) for c in cpus))
        self.events = list(events)
        self.fds = {}
        self.why = None
        self.dropped = []

    def open(self):
        pmus = hybrid_pmus()
        for key, hw_id, name in self.events:
            for c in self.cpus:
                try:
                    fd = perf_open(c, hw_id, pmus.get(c))
                except OSError as e:
                    if pmus.get(c) is not None and e.errno in (2, 22, 95):
                        try:
                            fd = perf_open(c, hw_id, None)
                        except OSError as e2:
                            e = e2
                            fd = None
                    else:
                        fd = None
                    if fd is None:
                        self.dropped.append(f"{name}@cpu{c}: {e.strerror}")
                        continue
                self.fds[(key, c)] = fd
        have = {k for k, _ in self.fds}
        if "ins" not in have or "cyc" not in have:
            self.why = ("hardware counters not available ("
                        + ("; ".join(self.dropped[:3]) or "no event")
                        + ")")
            self.close()
            return None
        return self

    def read(self):
        """{"_hw<key><cpu>": value}; a multiplexed or failed event is left out."""
        out = {}
        for (key, c), fd in self.fds.items():
            try:
                buf = os.read(fd, 24)
            except OSError:
                continue
            if len(buf) < 24:
                continue
            val, enabled, running = struct.unpack("QQQ", buf)
            if running < enabled:
                continue
            out[f"_hw{key}{c}"] = val
        return out

    def describe(self):
        """One line for env.csv."""
        ev = sorted({k for k, _ in self.fds}, key=[e[0] for e in EVENTS].index)
        names = [n for k, _, n in EVENTS if k in ev]
        return (", ".join(names) + " on cpu "
                + ",".join(f"{c} ({pmu_name(c)})" for c in self.cpus)
                + " (perf_event_open, user + kernel, pinned)"
                + (f"; not opened: {'; '.join(self.dropped)}"
                   if self.dropped else ""))

    def close(self):
        for fd in self.fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self.fds = {}


def _sum(d, key, cpus):
    vals = [d.get(f"_hw{key}{c}") for c in cpus]
    if any(v is None for v in vals):
        return None
    return sum(vals)


def per_packet(d, dut, pkts, secs, egress=(), prefix=""):
    """The columns of a window from the counter DIFFERENCES `d`."""
    out = {}
    if not d or not pkts or pkts <= 0 or not dut:
        return out
    ins = _sum(d, "ins", dut)
    cyc = _sum(d, "cyc", dut)
    if ins is None or cyc is None:
        return out
    out[prefix + "instr_pkt"] = round(ins / pkts, 1)
    out[prefix + "cycles_pkt"] = round(cyc / pkts, 1)
    out[prefix + "ipc"] = round(ins / cyc, 3) if cyc else None
    llc = _sum(d, "llc", dut)
    if llc is not None:
        out[prefix + "llc_miss_pkt"] = round(llc / pkts, 3)
    brm = _sum(d, "brm", dut)
    if brm is not None:
        out[prefix + "br_miss_pkt"] = round(brm / pkts, 3)
    if secs and secs > 0:
        out[prefix + "dut_ghz_busy"] = round(cyc / (secs * len(dut) * 1e9), 3)
    eg = [c for c in egress if c not in dut]
    if eg:
        ecyc = _sum(d, "cyc", eg)
        eins = _sum(d, "ins", eg)
        if ecyc is not None:
            out[prefix + "egress_cycles_pkt"] = round(ecyc / pkts, 1)
        if ecyc and eins is not None:
            out[prefix + "egress_ipc"] = round(eins / ecyc, 3)
    return out


COLUMNS = ("instr_pkt", "cycles_pkt", "ipc", "llc_miss_pkt", "br_miss_pkt",
           "dut_ghz_busy", "egress_cycles_pkt", "egress_ipc")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="try the hardware counters "
                                             "on one or more CPUs")
    ap.add_argument("--cpu", default="0", help="CPU list, e.g. 6,12,20")
    ap.add_argument("--seconds", type=float, default=1.0)
    a = ap.parse_args(argv)
    cpus = _cpu_list(a.cpu)
    hw = HwCounters(cpus).open()
    if hw is None:
        sys.exit("counters not available (root needed?)")
    print(hw.describe())
    r0 = hw.read()
    time.sleep(a.seconds)
    r1 = hw.read()
    d = {k: r1[k] - r0.get(k, 0) for k in r1}
    for c in cpus:
        ins, cyc = d.get(f"_hwins{c}"), d.get(f"_hwcyc{c}")
        ipc = f"{ins / cyc:.3f}" if ins is not None and cyc else "-"
        print(f"cpu{c:<3d} {pmu_name(c):9s} instructions {ins}  cycles {cyc}  "
              f"IPC {ipc}  cycles/s {cyc / a.seconds / 1e9 if cyc else 0:.3f} G")
    hw.close()


if __name__ == "__main__":
    main()
