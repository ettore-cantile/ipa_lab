#!/usr/bin/env python3
"""bench_capacity.py -- capacity of the node under real traffic.

A generator sends packets over veth to the node running a pipeline, and the
bench counts what comes out. For each pipeline: packets per second, CPU time
per packet, instructions and cycles per packet (hardware counters), where the
packets are lost. Needs root.

Usage:
    sudo python3 ipa/test/bench_capacity.py --mode compare --generator xdp \\
        --gen-cpus 10 --dut-cpus 6 --egress-cpu 8 --model <dir> --out <dir>
"""
import io
import contextlib
import os
import re
import sys
import csv
import time
import argparse
import subprocess
import statistics
import threading
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import host_conditions as HC  # noqa: E402
import hw_counters as HW  # noqa: E402

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")


class PktgenEmptyRun(RuntimeError):
    """A run that transmitted nothing."""


PKTGEN_DIR = "/proc/net/pktgen"
PKTGEN_MAGIC_MODEL_ID = 0xBE
ESCALATE_CLONE = 100000
XMIT_MODES = ("start_xmit", "netif_receive", "queue_xmit")
_BURST_SUPPORTED = True
_CLONE_SUPPORTED = True
DEFAULT_FRAMES = [64, 512, 1514]
DEFAULT_LOSS_THRESHOLD = 0.1
DEFAULT_REPEAT = 3
DEFAULT_ROUNDS = 3
WINDOW_S = 0.30
WINDOW_MODE = "steady"
STEADY_SETTLE_S = 0.10
STEADY_READ_MAX_S = 0.003
STEADY_READ_TRIES = 50
STEADY_START_TIMEOUT_S = 1.0
STEADY_SAFETY_S = 3.0
STEADY_MAX_PPS_PER_INST = 10_000_000
STEADY_INFLIGHT = 512
_STARTED_RE = re.compile(r"started:\s*(\d+)us")
DEFAULT_WARMUP_S = 0.10
MIN_WINDOW_PKTS = 20000
MAX_WINDOW_PKTS = 4_000_000
WINDOW_SHORT_FRACTION = 0.5
WINDOW_MIN_TX_FRACTION = 0.5
VETH_RING_TARGET = 4096
DRAIN_S = 0.05
CALIB_WINDOWS = 3
KNEE_STEPS = 5
MAX_SPREAD_PCT = 25.0
VALID_TOL = 0.10
DEFAULT_DELAYS = [0, 200, 500, 1000, 2000, 5000, 10000]
SATURATE_LADDER = (0.60, 0.80, 0.90, 1.00, 1.15)
SATURATE_DESCENT = (0.40, 0.25, 0.15, 0.08, 0.04)
MIN_LADDER_PPS = 20_000
GEN_KNOB_MIN_GAIN = 0.10
CPU_BUSY_PCT = 90.0
METHODS = ("baseline", "p1_static", "hardcoded", "template", "modular")
RX_ONLY = "rxonly"
RXONLY_SRC = """
#include <uapi/linux/bpf.h>
BPF_PERCPU_ARRAY(pkt_stats, __u64, 3);
BPF_PERCPU_ARRAY(cls_stats, __u64, 8);
int xdp_rxonly(struct xdp_md *ctx) {
    int k = 0;
    __u64 *v = pkt_stats.lookup(&k);
    if (v) *v += 1;
    return XDP_DROP;
}
"""


RX_FWD = "rxonly_fwd"
RXFWD_SRC = """
#include <uapi/linux/bpf.h>
struct fwd_action { __u32 ifindex; __u8 src_mac[6]; __u8 dst_mac[6]; } __attribute__((packed));
BPF_ARRAY(mac_table, struct fwd_action, 8);
BPF_PERCPU_ARRAY(pkt_stats, __u64, 3);
BPF_PERCPU_ARRAY(cls_stats, __u64, 8);
int xdp_rxonly_fwd(struct xdp_md *ctx) {
    int k = 0;
    __u64 *v = pkt_stats.lookup(&k);
    if (v) *v += 1;
    __u32 port = 0;
    struct fwd_action *a = mac_table.lookup(&port);
    if (!a || !a->ifindex)
        return XDP_DROP;
    return bpf_redirect(a->ifindex, 0);
}
"""


def setup_rxonly_fwd():
    """rxonly that forwards: HIT is pkt_stats[0], RX the egress counter, as
    for the baseline."""
    from bcc import BPF
    b = BPF(text=RXFWD_SRC)
    fn = b.load_func("xdp_rxonly_fwd", BPF.XDP)
    return {"b": b, "fn": fn, "disp": fn, "pipeline": 0,
            "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"],
            "progs": {"xdp_rxonly_fwd": fn.fd}}


def setup_rxonly():
    """The ingress counter with the shape of a pipeline setup."""
    from bcc import BPF
    b = BPF(text=RXONLY_SRC)
    fn = b.load_func("xdp_rxonly", BPF.XDP)
    return {"b": b, "fn": fn, "disp": fn, "pipeline": 0, "rx_is_hit": True,
            "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"],
            "progs": {"xdp_rxonly": fn.fd}}

STATIC_NODE = 7
TRAFFIC_TTL = 32
RX_COUNTER_SRC = r"""
#include <uapi/linux/bpf.h>
BPF_PERCPU_ARRAY(rx_count, __u64, 1);
int xdp_rx_count(struct xdp_md *ctx) {
    int k = 0;
    __u64 *v = rx_count.lookup(&k);
    if (v) *v += 1;
    return XDP_DROP;
}
"""


def ok(m):
    print(f"  {GREEN}[PASS]{NC} {m}")


def info(m):
    print(f"  {YELLOW}[INFO]{NC} {m}")


def warn(m):
    print(f"  {RED}[WARN]{NC} {m}")


def note(m):
    print(f"  {GREY}{m}{NC}")


# --- CPUs: who generates and who processes ---


def parse_cpu_list(spec):
    """"1,3-5" -> [1, 3, 4, 5]."""
    if spec is None:
        return None
    spec = str(spec).strip()
    if not spec or spec.lower() == "auto":
        return None
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                raise ValueError(f"invalid CPU range: {part!r}")
            if hi < lo:
                raise ValueError(f"reversed range: {part!r}")
            out.extend(range(lo, hi + 1))
        else:
            try:
                out.append(int(part))
            except ValueError:
                raise ValueError(f"invalid CPU: {part!r}")
    return sorted(set(out))


def online_cpus():
    """The CPUs actually online, from the kernel."""
    try:
        with open("/sys/devices/system/cpu/online") as f:
            cpus = parse_cpu_list(f.read().strip())
        if cpus:
            return cpus
    except OSError:
        pass
    return list(range(os.cpu_count() or 1))


def pg_thread_path(cpu):
    return f"{PKTGEN_DIR}/kpktgend_{cpu}"


def pg_thread_exists(cpu):
    """Is there a pktgen thread on this CPU?"""
    return os.path.exists(pg_thread_path(cpu))


class CpuPlan:
    """Who generates, who processes, who receives downstream, and what was
    discarded to get there."""

    def __init__(self, gen, dut, online, notes, shared=False, egress=None,
                 topo=None):
        self.gen = list(gen)
        self.dut = list(dut)
        self.online = list(online)
        self.notes = list(notes)
        self.shared = shared
        self.egress = egress
        self.topo = topo

    @property
    def threads(self):
        return len(self.gen)

    @property
    def used(self):
        return sorted(set(self.gen) | set(self.dut)
                      | set(HC.egress_cpus(self.egress)))

    @property
    def idle_siblings(self):
        return HC.idle_siblings(self.topo, self.used) if self.topo else []

    @property
    def excluded(self):
        """The CPUs left to the system."""
        if self.topo:
            return HC.housekeeping(self.topo, self.used)
        return [c for c in self.online if c not in self.used]

    def _fmt(self, xs):
        if not xs:
            return "(none)"
        if self.topo and self.topo.structured:
            return ", ".join(self.topo.label(x) for x in xs)
        return ",".join(str(x) for x in xs)

    def describe(self):
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} CPU plan: generator and DUT on this machine{NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        fmt = lambda xs: ",".join(str(x) for x in xs) if xs else "(none)"
        if self.topo:
            info(f"topology ................ {self.topo.summary()}")
        info(f"CPU online .............. {fmt(self.online)}")
        info(f"CPU generatore .......... {self._fmt(self.gen)}  "
             f"-> {self.threads} thread")
        info(f"CPU DUT (XDP/NAPI) ...... {self._fmt(self.dut)}")
        if self.egress is not None:
            info(f"egress CPU (NAPI downstream) "
                 f"{self._fmt(HC.egress_cpus(self.egress))}")
        if self.idle_siblings:
            info(f"idle SMT siblings ....... {fmt(self.idle_siblings)}")
        info(f"CPUs left to the system . {fmt(self.excluded)}")
        for n in self.notes:
            warn(n)
        if self.shared:
            warn("generator and DUT share CPUs: the absolute figure "
                 "measures the sum of the two, not the pipeline.")
        else:
            note("generator and DUT on disjoint cores: the loss you see "
                 "is the pipeline's, not the generator stealing its core.")


def plan_cpus(gen_spec=None, dut_spec=None, threads=None, allow_cpu0=False,
              check_pktgen=True, egress_spec=None, topo=None):
    """Decides the CPU lists, checking them against the real machine."""
    notes = []
    if topo is None:
        try:
            topo = HC.Topology.read()
        except Exception:
            topo = None
    online = topo.online if topo is not None else online_cpus()
    pool = [c for c in online if allow_cpu0 or c != 0]
    if not pool:
        notes.append("a single CPU online and CPU 0 excluded: admitting it "
                     "again, there is nothing else to run on.")
        pool = list(online)

    want_gen = parse_cpu_list(gen_spec)
    want_dut = parse_cpu_list(dut_spec)
    fixed_egress = (egress_spec if isinstance(egress_spec, (int, list))
                    else None)
    egress = fixed_egress
    auto_roles = (want_gen is None and want_dut is None and topo is not None
                  and topo.structured)

    if auto_roles:
        roles = HC.plan_roles(
            topo, n_gen=threads, want_egress=(egress_spec == "auto"),
            allow_cpu0=allow_cpu0,
            exclude=HC.egress_cpus(fixed_egress))
        gen, dut = roles["gen"], roles["dut"]
        if egress_spec == "auto":
            egress = roles["egress"]
        notes += roles["notes"]
    else:
        if want_gen is not None:
            gen = [c for c in want_gen if c in online]
            dropped = [c for c in want_gen if c not in online]
            if dropped:
                notes.append(f"CPU {dropped} requested for the generator but not "
                             f"online: discarded.")
            if 0 in gen and not allow_cpu0:
                notes.append("CPU 0 requested explicitly for the generator: "
                             "using it, but timers, RCU and IRQs run there and "
                             "the offered rate is less stable.")
        else:
            n = len(pool)
            if threads and threads > 0:
                gen_n = min(threads, n)
                if threads > n:
                    notes.append(f"{threads} generator threads requested but only "
                                 f"{n} usable CPUs: using {gen_n}. Two "
                                 f"pktgen threads on the same CPU do not exist "
                                 f"-- the thread IS the CPU.")
            else:
                dut_n = max(1, n // 3)
                gen_n = max(1, n - dut_n)
            gen = pool[:gen_n]

        if want_dut is not None:
            dut = [c for c in want_dut if c in online]
            dropped = [c for c in want_dut if c not in online]
            if dropped:
                notes.append(f"CPU {dropped} requested for the DUT but not online: "
                             f"discarded.")
        else:
            dut = [c for c in pool if c not in gen
                   and c not in HC.egress_cpus(fixed_egress)]
        if egress_spec == "auto":
            found = []
            while topo is not None and len(found) < len(dut):
                e = HC.spare_core(topo, set(gen) | set(dut) | set(found),
                                  allow_cpu0)
                if e is None:
                    break
                found.append(e)
            egress = (found[0] if len(found) == 1
                      else found if found else None)
            if egress is None:
                notes.append("no free physical core for the egress: it stays "
                             "in softirq on the DUT CPU.")
            elif len(found) < len(dut):
                notes.append(f"{len(found)} egress cores for {len(dut)} "
                             f"DUT cores: the egress queues of several DUT "
                             f"cores drain on the same core, which "
                             f"may become the bottleneck "
                             f"(--egress-cpu N,M to choose them).")

    if check_pktgen and os.path.isdir(PKTGEN_DIR):
        missing = [c for c in gen if not pg_thread_exists(c)]
        if missing:
            notes.append(f"no pktgen thread on CPU {missing} "
                         f"(kpktgend_<cpu> missing): removed from the generator.")
            gen = [c for c in gen if c not in missing]

    if not gen:
        gen = pool[:1] or online[:1]
        notes.append(f"no usable CPU for the generator: falling back "
                     f"to {gen}.")

    shared = False
    overlap = sorted(set(gen) & set(dut))
    if overlap:
        notes.append(f"CPU {overlap} requested for both the generator and the "
                     f"DUT: on those cores the two compete for time.")
        shared = True
    if topo is not None:
        smt = sorted(c for c in gen if c not in dut
                     and set(topo.core(c)) & set(dut))
        if smt:
            notes.append(f"generator CPU {smt} on the same physical core as the "
                         f"DUT (SMT siblings): they share pipeline and cache.")
            shared = True
    if not dut:
        dut = list(gen)
        shared = True
        notes.append("no free CPU for the DUT: NAPI will stay on the "
                     "generator cores.")
    return CpuPlan(gen, dut, online, notes, shared=shared, egress=egress,
                   topo=topo)


# --- pktgen: the low level ---
def pg_write(path, cmd):
    """Write one pktgen command, and say which one if it fails."""
    try:
        fd = os.open(path, os.O_WRONLY)
    except OSError as e:
        raise RuntimeError(
            f"pktgen: cannot open {path} ({e.strerror}). "
            f"If the file does not exist, `add_device` had no effect.") from e
    try:
        os.write(fd, (cmd + "\n").encode())
    except OSError as e:
        raise RuntimeError(
            f"pktgen: command '{cmd}' refused by {path} "
            f"({e.strerror}). This kernel may not support it.") from e
    finally:
        os.close(fd)


def pg_available():
    """Is pktgen loaded -- and if not, load it."""
    if os.path.isdir(PKTGEN_DIR):
        return True
    subprocess.run(["modprobe", "pktgen"], check=False, capture_output=True)
    if os.path.isdir(PKTGEN_DIR):
        info("pktgen module loaded")
        return True
    return False


def pg_reset():
    pg_write(f"{PKTGEN_DIR}/pgctrl", "reset")


def pg_stop():
    """Stops the running threads."""
    try:
        pg_write(f"{PKTGEN_DIR}/pgctrl", "stop")
    except RuntimeError:
        pass


def pg_dev_path(name):
    """The control file of ONE instance."""
    return f"{PKTGEN_DIR}/{name}"


class GenCaps:
    """What this device ACTUALLY accepts in this xmit_mode."""

    _cache = {}

    def __init__(self, clone=False, burst=False, probed=False):
        self.clone = clone
        self.burst = burst
        self.probed = probed

    @classmethod
    def probe(cls, name, xmit_mode="start_xmit", quiet=False):
        dev = name.split("@")[0]
        key = (dev, xmit_mode)
        if key in cls._cache:
            return cls._cache[key]
        caps = cls()
        path = pg_dev_path(name)
        if not os.path.exists(path):
            return caps
        for attr, cmd_on, cmd_off in (("clone", "clone_skb 1", "clone_skb 0"),
                                      ("burst", "burst 2", "burst 0")):
            try:
                pg_write(path, cmd_on)
                pg_write(path, cmd_off)
                setattr(caps, attr, True)
            except RuntimeError:
                setattr(caps, attr, False)
        caps.probed = True
        cls._cache[key] = caps
        global _CLONE_SUPPORTED, _BURST_SUPPORTED
        _CLONE_SUPPORTED, _BURST_SUPPORTED = caps.clone, caps.burst
        if not quiet:
            yn = lambda v: "si" if v else "no"
            info(f"{dev} ({xmit_mode}): clone_skb={yn(caps.clone)} "
                 f"burst={yn(caps.burst)}")
            if not caps.clone and not caps.burst:
                note("neither: the normal case on veth, which does not "
                     "advertise IFF_TX_SKB_SHARING. The only knob left "
                     "to raise the offered load is the number of threads.")
        return caps


def pg_clear_threads(threads):
    """Detaches every device from the given threads."""
    cpus = range(threads) if isinstance(threads, int) else list(threads)
    for cpu in cpus:
        try:
            pg_write(pg_thread_path(cpu), "rem_device_all")
        except RuntimeError:
            continue


def pg_ensure_device(dev, thread=0):
    """Attaches `dev` if pktgen does not know it (any more)."""
    if os.path.exists(pg_dev_path(dev)):
        return pg_dev_path(dev)
    return pg_add_device(dev, thread)


def pg_add_device(dev, thread=0):
    """Attaches `dev` to generator thread `thread` (= CPU) and checks that it
    is there."""
    pg_write(pg_thread_path(thread), f"add_device {dev}")
    d = pg_dev_path(dev)
    if not os.path.exists(d):
        raise RuntimeError(
            f"pktgen: {d} does not exist after `add_device {dev}` on thread "
            f"{thread}. Does the interface exist and is it UP? `ip link show "
            f"{dev.split('@')[0]}`")
    return d


def pg_set_params(dev, pkt_size, count, delay, dst_ip="10.0.0.2",
                  dst_mac="02:00:00:00:00:02", queue_map=None):
    """Changes the parameters of an ALREADY attached device, without detaching it."""
    d = pg_dev_path(dev)
    cmds = [f"count {count}", f"pkt_size {pkt_size}", f"delay {delay}",
            f"dst {dst_ip}", f"dst_mac {dst_mac}",
            "udp_src_min 1234", "udp_src_max 1234",
            "udp_dst_min 9999", "udp_dst_max 9999"]
    if queue_map is not None:
        cmds += [f"queue_map_min {queue_map}", f"queue_map_max {queue_map}"]
    for cmd in cmds:
        pg_write(d, cmd)


def pg_configure(dev, pkt_size, count, delay, dst_ip, dst_mac, clone=0,
                 thread=0, burst=0, xmit_mode="start_xmit", queue_map=None):
    """Put one device on one generator thread and configure it."""
    pg_write(pg_thread_path(thread), f"add_device {dev}")
    d = pg_dev_path(dev)
    if not os.path.exists(d):
        raise RuntimeError(
            f"pktgen: {d} does not exist after `add_device {dev}`. "
            f"Does the interface exist and is it UP? `ip link show "
            f"{dev.split('@')[0]}`")
    if xmit_mode != "start_xmit":
        pg_write(d, f"xmit_mode {xmit_mode}")
    caps = GenCaps.probe(dev, xmit_mode, quiet=True)
    if burst:
        if caps.burst:
            try:
                pg_write(d, f"burst {burst}")
            except RuntimeError:
                warn("burst refused by this device, continuing without it.")
        else:
            pass
    if clone:
        if caps.clone:
            try:
                pg_write(d, f"clone_skb {clone}")
            except RuntimeError:
                warn("clone_skb refused by this device: veth hands "
                     "the skb to the peer's RX and cannot share it.")
        else:
            pass
    pg_set_params(dev, pkt_size, count, delay, dst_ip, dst_mac,
                  queue_map=queue_map)


_SOFAR_RE = re.compile(r"pkts-sofar:\s*(\d+)")
_USEC_RE = re.compile(r"Result: OK:\s*(\d+)\(")
_PPS_RE = re.compile(r"(\d+)pps")
_ERR_RE = re.compile(r"errors:\s*(\d+)")


class GenRun(tuple):
    """The outcome of ONE generator window."""

    def __new__(cls, tx, pps, secs, per_dev=None, wall=0.0, errors=0):
        self = super().__new__(cls, (tx, pps, secs))
        self.tx = tx
        self.pps = pps
        self.secs = secs
        self.per_dev = per_dev or []
        self.wall = wall
        self.errors = errors
        self.steady = False
        self.dut = None
        self.start_offset_ms = None
        self.read_ms = None
        self.window = max(wall, secs)
        durs = [d["secs"] for d in self.per_dev if d.get("secs")]
        self.skew_pct = (round(100.0 * (max(durs) - min(durs)) / max(durs), 1)
                         if len(durs) > 1 and max(durs) > 0 else 0.0)
        agg = (tx / self.window) if self.window else 0.0
        self.rate_mismatch_pct = (round(100.0 * abs(agg - pps) / pps, 1)
                                  if pps else 0.0)
        return self

    @property
    def tx_pps_aggregate(self):
        """Total TX divided by the GLOBAL duration."""
        return int(self.tx / self.window) if self.window else 0


def pg_run_and_read(devs):
    """Start every configured thread, wait, and sum what they sent."""
    if isinstance(devs, str):
        devs = [devs]
    wall0 = time.time()
    pg_write(f"{PKTGEN_DIR}/pgctrl", "start")
    wall = time.time() - wall0

    sent = pps = errors = 0
    secs = 0.0
    per_dev = []
    for dev in devs:
        try:
            with open(pg_dev_path(dev)) as f:
                text = f.read()
        except FileNotFoundError:
            raise PktgenEmptyRun(
                f"pktgen has lost {dev} (fabric rebuilt?)")
        m = _SOFAR_RE.search(text)
        d_tx = int(m.group(1)) if m else 0
        m = _USEC_RE.search(text)
        d_secs = int(m.group(1)) / 1e6 if m else 0.0
        m = _PPS_RE.search(text)
        d_pps = int(m.group(1)) if m else 0
        errs = _ERR_RE.findall(text)
        d_err = int(errs[-1]) if errs else 0
        sent += d_tx
        pps += d_pps
        errors += d_err
        secs = max(secs, d_secs)
        per_dev.append(dict(dev=dev, tx=d_tx, pps=d_pps, secs=round(d_secs, 4),
                            errors=d_err))
    secs = secs or wall
    pps = pps or (int(sent / secs) if secs else 0)
    if sent == 0:
        raise PktgenEmptyRun(
            f"pktgen reports no packets for {devs}")
    return GenRun(sent, pps, secs, per_dev=per_dev, wall=wall, errors=errors)


# --- the generator as an object: configured once, reused for every point ---


def _num_queues(dev, kind="tx"):
    """How many queues this device really has."""
    path = f"/sys/class/net/{dev}/queues"
    try:
        n = len([x for x in os.listdir(path) if x.startswith(kind + "-")])
    except OSError:
        return 1
    return max(1, n)


class Generator:
    """pktgen on N chosen CPUs, towards one or more devices."""

    def __init__(self, devs, plan, xmit_mode="start_xmit", topology="shared",
                 clone=0, burst=0, dst_ip="10.0.0.2",
                 dst_mac="02:00:00:00:00:02", window_s=WINDOW_S,
                 warmup_s=DEFAULT_WARMUP_S, window_mode=None):
        self.devs = [devs] if isinstance(devs, str) else list(devs)
        self.window_mode = window_mode or WINDOW_MODE
        self.plan = plan
        self.xmit_mode = xmit_mode
        self.topology = topology
        self.clone = clone
        self.burst = burst
        self.dst_ip = dst_ip
        self.dst_mac = dst_mac
        self.window_s = window_s
        self.warmup_s = warmup_s
        self.caps = GenCaps()
        self.rate_estimate = 0
        self.last_run = None
        self.instances = []
        self._build_instances()

    def _build_instances(self):
        cpus = list(self.plan.gen) or [0]
        self.instances = []
        if self.topology == "links":
            for i, dev in enumerate(self.devs[:len(cpus)]):
                self.instances.append(dict(name=dev, dev=dev, cpu=cpus[i],
                                           queue_map=None))
            if not self.instances:
                raise RuntimeError(
                    "topology='links' needs at least one ingress device"
                )
            return
        dev = self.devs[0]
        ntx = _num_queues(dev, "tx")
        for i, cpu in enumerate(cpus):
            name = dev if len(cpus) == 1 else f"{dev}@{i}"
            qmap = None if ntx <= 1 else (i % ntx)
            self.instances.append(dict(name=name, dev=dev, cpu=cpu,
                                       queue_map=qmap))
        if not self.instances:
            raise RuntimeError("no pktgen instance built")
        _warn_unbalanced_gen(self.instances)

    @property
    def names(self):
        return [i["name"] for i in self.instances]

    @property
    def n_inst(self):
        return len(self.instances)

    def attach(self, verbose=True):
        """Attaches every instance to its thread and applies the fixed
        configuration (xmit_mode, queue_map, clone, burst)."""
        pg_clear_threads(self.plan.gen)
        for inst in self.instances:
            pg_add_device(inst["name"], inst["cpu"])
            self._configure(inst)
        self.caps = GenCaps.probe(self.instances[0]["name"], self.xmit_mode,
                                  quiet=not verbose)
        for inst in self.instances:
            self._apply_knobs(inst)
        if verbose:
            self.describe()
        return self

    def _configure(self, inst):
        d = pg_dev_path(inst["name"])
        if self.xmit_mode != "start_xmit":
            pg_write(d, f"xmit_mode {self.xmit_mode}")
        if inst["queue_map"] is not None:
            pg_write(d, f"queue_map_min {inst['queue_map']}")
            pg_write(d, f"queue_map_max {inst['queue_map']}")

    def _apply_knobs(self, inst):
        """clone_skb and burst, but ONLY if the device accepted them in the probe."""
        d = pg_dev_path(inst["name"])
        if self.clone and self.caps.clone:
            try:
                pg_write(d, f"clone_skb {self.clone}")
            except RuntimeError:
                pass
        if self.burst and self.caps.burst:
            try:
                pg_write(d, f"burst {self.burst}")
            except RuntimeError:
                pass

    def ensure(self):
        """Re-attaches what has disappeared."""
        for inst in self.instances:
            if not os.path.exists(pg_dev_path(inst["name"])):
                pg_add_device(inst["name"], inst["cpu"])
                self._configure(inst)
                self._apply_knobs(inst)

    def detach(self):
        pg_clear_threads(self.plan.gen)

    def describe(self):
        where = ", ".join(f"cpu{i['cpu']}:{i['name']}"
                          + (f"(q{i['queue_map']})"
                             if i["queue_map"] is not None else "")
                          for i in self.instances)
        info(f"generatore: {self.n_inst} thread -- {where}")
        info(f"xmit_mode {self.xmit_mode}, clone_skb "
             f"{self.clone if self.caps.clone else 0}, burst "
             f"{self.burst if self.caps.burst else 0}")
        if self.xmit_mode == "netif_receive":
            warn("netif_receive injects into the device's RX path: XDP runs "
                 "in GENERIC mode and on the GENERATOR's CPU. In this "
                 "mode the gen/DUT separation does not exist, and the numbers "
                 "are not comparable with the native-mode ones.")

    def delay_for(self, total_pps):
        """The `delay` (ns between one packet and the next, PER INSTANCE) that
        offers `total_pps` in aggregate."""
        if total_pps <= 0:
            return 0
        per_inst = max(1.0, float(total_pps) / self.n_inst)
        return max(1, int(1e9 / per_inst))

    def window_count(self, total_pps, seconds=None):
        """How many packets PER INSTANCE for a window of `seconds`."""
        seconds = self.window_s if seconds is None else seconds
        total = max(MIN_WINDOW_PKTS,
                    min(MAX_WINDOW_PKTS, int(max(0.0, total_pps) * seconds)))
        return max(1000, total // self.n_inst)

    def run(self, frame, count, delay):
        """A raw window."""
        self.ensure()
        for inst in self.instances:
            pg_set_params(inst["name"], frame, count, delay,
                          dst_ip=self.dst_ip, dst_mac=self.dst_mac,
                          queue_map=inst["queue_map"])
        self.last_run = pg_run_and_read(self.names)
        return self.last_run

    def warmup(self, frame, delay=0, seconds=None):
        """A window thrown away before the measurement."""
        seconds = self.warmup_s if seconds is None else seconds
        if seconds <= 0:
            return None
        if self.window_mode == "steady":
            return None
        if delay > 0:
            rate = (1e9 / delay) * self.n_inst
        else:
            rate = self.rate_estimate or 1_000_000
        try:
            return self.run(frame, self.window_count(rate, seconds), delay)
        except (PktgenEmptyRun, RuntimeError):
            return None

    def timed_run(self, frame, delay, seconds=None, expect_pps=None):
        """A window that aims to last `seconds`, and checks it."""
        seconds = self.window_s if seconds is None else seconds
        if self.window_mode == "steady":
            return self.steady(frame, delay, seconds=seconds)
        rate = expect_pps or self.rate_estimate or 1_000_000
        r = self.run(frame, self.window_count(rate, seconds), delay)
        if r.secs < seconds * WINDOW_SHORT_FRACTION and r.secs > 0:
            better = r.tx / r.secs
            r2 = self.run(frame, self.window_count(better, seconds), delay)
            return r2
        return r

    def _running(self):
        """The instances pktgen declares as transmitting NOW."""
        out = set()
        for cpu in {i["cpu"] for i in self.instances}:
            try:
                with open(pg_thread_path(cpu)) as f:
                    text = f.read()
            except OSError:
                continue
            for line in text.splitlines():
                if line.startswith("Running:"):
                    out.update(line.split(":", 1)[1].split())
        return out

    def _gen_counters(self):
        """{instance: (pkts-sofar, errors, started_us)} read while
        transmitting: the `Current:` section of the device file is updated
        live."""
        out = {}
        for inst in self.instances:
            with open(pg_dev_path(inst["name"])) as f:
                text = f.read()
            m = _SOFAR_RE.search(text)
            errs = _ERR_RE.findall(text)
            st = _STARTED_RE.search(text)
            out[inst["name"]] = (int(m.group(1)) if m else 0,
                                 int(errs[-1]) if errs else 0,
                                 int(st.group(1)) if st else 0)
        return out

    def _snapshot(self, probe):
        """(instant, pktgen counters, DUT counters, read duration)."""
        best = None
        for _ in range(STEADY_READ_TRIES):
            t0 = time.monotonic()
            g = self._gen_counters()
            d = probe() if probe else {}
            t1 = time.monotonic()
            if t1 - t0 <= STEADY_READ_MAX_S:
                return (t0 + t1) / 2.0, g, d, t1 - t0
            best = t1 - t0 if best is None else min(best, t1 - t0)
        raise PktgenEmptyRun(
            f"steady window: no counter read below "
            f"{STEADY_READ_MAX_S * 1000:.0f} ms in {STEADY_READ_TRIES} "
            f"attempts (shortest {best * 1000:.1f} ms): the machine "
            f"suspends the process, the window cannot be timed")

    def steady(self, frame, delay, probe=None, seconds=None):
        """A STEADY window."""
        seconds = self.window_s if seconds is None else seconds
        self.ensure()
        per_inst = (1e9 / delay) if delay else STEADY_MAX_PPS_PER_INST
        safety = max(1000, int(per_inst * (STEADY_START_TIMEOUT_S
                                           + STEADY_SETTLE_S + seconds
                                           + STEADY_SAFETY_S)))
        for inst in self.instances:
            pg_set_params(inst["name"], frame, safety, delay,
                          dst_ip=self.dst_ip, dst_mac=self.dst_mac,
                          queue_map=inst["queue_map"])
        failed = []

        def _start():
            try:
                pg_write(f"{PKTGEN_DIR}/pgctrl", "start")
            except Exception as e:
                failed.append(e)

        names = set(self.names)
        th = threading.Thread(target=_start, name="pgctrl-start", daemon=True)
        t0 = time.monotonic()
        th.start()
        try:
            while not names <= self._running():
                if failed or time.monotonic() - t0 > STEADY_START_TIMEOUT_S:
                    raise PktgenEmptyRun(
                        f"steady window: not every instance "
                        f"started within {STEADY_START_TIMEOUT_S}s ("
                        f"transmitting: {sorted(self._running())}"
                        + (f"; start: {failed[0]}" if failed else "") + ")")
                time.sleep(0.005)
            time.sleep(STEADY_SETTLE_S)
            ta, ga, da, ra = self._snapshot(probe)
            time.sleep(max(0.0, ta + seconds - time.monotonic()))
            tb, gb, db, rb = self._snapshot(probe)
            fermi = sorted(names - self._running())
        finally:
            pg_stop()
            th.join(timeout=5.0)
        if th.is_alive():
            raise RuntimeError("pktgen: `start` did not return after `stop`")
        if failed:
            raise RuntimeError(f"pktgen start: {failed[0]}")
        if fermi:
            raise PktgenEmptyRun(
                f"steady window: {fermi} stopped before the second "
                f"read (safety count exhausted?): the window is not "
                f"all at steady state, discarded")
        secs = tb - ta
        per_dev, tx, errors = [], 0, 0
        for inst in self.instances:
            n = inst["name"]
            d_tx = gb[n][0] - ga[n][0]
            d_err = gb[n][1] - ga[n][1]
            tx += d_tx
            errors += d_err
            per_dev.append(dict(dev=n, tx=d_tx, pps=int(d_tx / secs),
                                secs=round(secs, 4), errors=d_err))
        if tx == 0:
            raise PktgenEmptyRun(
                f"steady window: no packet transmitted between the two "
                f"reads ({self.names})")
        run = GenRun(tx, sum(d["pps"] for d in per_dev), secs,
                     per_dev=per_dev, wall=secs, errors=errors)
        run.steady = True
        run.dut = {k: db[k] - da.get(k, 0) for k in db}
        run.read_ms = round(1000.0 * max(ra, rb), 2)
        starts = [g[2] for g in gb.values() if g[2]]
        run.start_offset_ms = (round((max(starts) - min(starts)) / 1000.0, 1)
                               if len(starts) > 1 else 0.0)
        self.last_run = run
        return run

    def calibrate(self, frame=64, seconds=None):
        """How much this generator offers at delay 0, measured and not assumed."""
        seconds = self.window_s if seconds is None else seconds
        self.warmup(frame, 0, min(self.warmup_s, seconds))
        migliore = None
        for _ in range(max(1, CALIB_WINDOWS)):
            try:
                r = self.timed_run(frame, 0, seconds)
            except (PktgenEmptyRun, RuntimeError):
                continue
            if migliore is None or r.tx_pps_aggregate > migliore.tx_pps_aggregate:
                migliore = r
        if migliore is None:
            raise PktgenEmptyRun("calibration: no usable window")
        self.rate_estimate = migliore.tx_pps_aggregate
        return migliore

    def tune(self, frame=64, seconds=None, verbose=True):
        """Tries the knobs this device accepts and KEEPS only those that
        really raise the offered rate."""
        seconds = self.window_s if seconds is None else seconds
        base = self.calibrate(frame, seconds)
        best = base.tx_pps_aggregate
        chosen = dict(clone=0, burst=0)
        if verbose:
            info(f"generator at delay 0, reference condition: "
                 f"{best} pps offered")
        if not (self.caps.clone or self.caps.burst):
            if verbose:
                note("no knob available on this device: the offered "
                     "load rises only with threads (there are "
                     f"{self.n_inst}).")
            self.rate_estimate = best
            return chosen
        trials = []
        if self.caps.clone:
            trials.append(("clone", ESCALATE_CLONE))
        if self.caps.burst:
            trials.append(("burst", max(2, self.burst or 8)))
        for knob, value in trials:
            old = getattr(self, knob)
            setattr(self, knob, value)
            for inst in self.instances:
                self._apply_knobs(inst)
            try:
                r = self.timed_run(frame, 0, seconds)
            except (PktgenEmptyRun, RuntimeError) as e:
                warn(f"{knob}={value} broke the generation ({e}): discarded")
                setattr(self, knob, old)
                continue
            got = r.tx_pps_aggregate
            gain = (got - best) / best if best else 0.0
            if gain >= GEN_KNOB_MIN_GAIN:
                chosen[knob] = value
                best = got
                if verbose:
                    info(f"{knob}={value}: {got} pps ({gain:+.0%}) -- kept")
            else:
                setattr(self, knob, old)
                if verbose:
                    note(f"{knob}={value}: {got} pps ({gain:+.0%}), below the "
                         f"{GEN_KNOB_MIN_GAIN:.0%} threshold: discarded, the "
                         f"reference condition is more representative.")
        for inst in self.instances:
            self._apply_knobs(inst)
        self.rate_estimate = best
        return chosen


def _window_count(rate_pps):
    """How many packets for a WINDOW_S window at this rate."""
    return max(MIN_WINDOW_PKTS, min(MAX_WINDOW_PKTS, int(rate_pps * WINDOW_S)))


# --- diagnostics: who is the bottleneck, with numbers ---


def _read_proc_stat():
    """{cpu: (busy_jiffies, total_jiffies)}. Only the 'cpuN' rows."""
    out = {}
    try:
        with open("/proc/stat") as f:
            for line in f:
                if not line.startswith("cpu") or line.startswith("cpu "):
                    continue
                parts = line.split()
                try:
                    cpu = int(parts[0][3:])
                except ValueError:
                    continue
                vals = [int(v) for v in parts[1:]]
                total = sum(vals)
                idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
                out[cpu] = (total - idle, total)
    except OSError:
        return {}
    return out


def cpu_util(before, after):
    """Per-core busy time between two reads, in percent."""
    out = {}
    for cpu, (busy1, tot1) in after.items():
        busy0, tot0 = before.get(cpu, (0, 0))
        dt = tot1 - tot0
        if dt > 0:
            out[cpu] = round(100.0 * (busy1 - busy0) / dt, 1)
    return out


_DEV_FIELDS = ("rx_packets", "tx_packets", "rx_dropped", "tx_dropped",
               "rx_errors", "tx_errors")


def _dev_counters(dev):
    """The device's standard counters."""
    base = f"/sys/class/net/{dev}/statistics"
    out = {}
    for f in _DEV_FIELDS:
        try:
            with open(os.path.join(base, f)) as fh:
                out[f] = int(fh.read().strip())
        except OSError:
            pass
    return out


def _softnet():
    """[(cpu, processed, dropped, time_squeeze)] da /proc/net/softnet_stat."""
    rows = []
    try:
        with open("/proc/net/softnet_stat") as f:
            for i, line in enumerate(f):
                c = line.split()
                if len(c) < 3:
                    continue
                rows.append((i, int(c[0], 16), int(c[1], 16), int(c[2], 16)))
    except OSError:
        return []
    return rows


def ethtool_stats(dev):
    """The ethtool counters, or None if ethtool is missing."""
    try:
        p = subprocess.run(["ethtool", "-S", dev], capture_output=True,
                           text=True, check=False)
    except OSError:
        return None
    if p.returncode != 0:
        return None
    out = {}
    for line in p.stdout.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        v = v.strip()
        if v.isdigit():
            out[k.strip()] = int(v)
    return out or None


class Diag:
    """One snapshot before and one after."""

    def __init__(self, devs=(), plan=None, enabled=False):
        self.devs = list(devs)
        self.plan = plan
        self.enabled = enabled
        self._t0 = None
        self._cpu0 = {}
        self._dev0 = {}
        self._eth0 = {}
        self._soft0 = []

    def start(self):
        if not self.enabled:
            return self
        self._t0 = time.time()
        self._cpu0 = _read_proc_stat()
        self._dev0 = {d: _dev_counters(d) for d in self.devs}
        self._eth0 = {d: (ethtool_stats(d) or {}) for d in self.devs}
        self._soft0 = _softnet()
        return self

    def stop(self):
        """{cpu_pct, dev, softnet_dropped, softnet_squeeze, secs} or {}."""
        if not self.enabled or self._t0 is None:
            return {}
        secs = time.time() - self._t0
        cpu = cpu_util(self._cpu0, _read_proc_stat())
        dev = {}
        for d in self.devs:
            now, before = _dev_counters(d), self._dev0.get(d, {})
            dev[d] = {k: now.get(k, 0) - before.get(k, 0) for k in now}
        eth = {}
        for d in self.devs:
            now = ethtool_stats(d)
            if now is None:
                continue
            before = self._eth0.get(d) or {}
            delta = {k: v - before.get(k, 0) for k, v in now.items()
                     if (v - before.get(k, 0)) != 0
                     and ("xdp" in k or "drop" in k or "err" in k)}
            if delta:
                eth[d] = delta
        soft_now = _softnet()
        drop = sum(r[2] for r in soft_now) - sum(r[2] for r in self._soft0)
        squeeze = sum(r[3] for r in soft_now) - sum(r[3] for r in self._soft0)
        return dict(secs=round(secs, 3), cpu_pct=cpu, dev=dev, ethtool=eth,
                    ethtool_available=bool(self._eth0 and
                                           any(self._eth0.values())),
                    softnet_dropped=drop, softnet_squeeze=squeeze)

    def report(self, d, rate=None):
        if not d:
            return
        print(f"\n{YELLOW}  -- diagnostics ({d['secs']} s window) "
              f"--{NC}")
        cpu = d.get("cpu_pct") or {}
        if not cpu:
            warn("per-core busy time not readable (/proc/stat): not "
                 "estimated from other numbers, it is simply missing.")
        else:
            gen = set(self.plan.gen) if self.plan else set()
            dut = set(self.plan.dut) if self.plan else set()
            for c in sorted(cpu):
                tag = ("gen" if c in gen else
                       "DUT" if c in dut else "system")
                if tag == "system" and cpu[c] < 1.0:
                    continue
                bar = "#" * int(cpu[c] / 5)
                col = RED if cpu[c] >= CPU_BUSY_PCT else GREY
                print(f"    cpu{c:<3d} {tag:8s} {col}{cpu[c]:5.1f}%{NC} {bar}")
        for dev, ctr in (d.get("dev") or {}).items():
            if not ctr:
                continue
            bits = " ".join(f"{k}={v}" for k, v in sorted(ctr.items()) if v)
            print(f"    {dev:12s} {bits or 'no counter moved'}")
        if d.get("ethtool"):
            for dev, delta in d["ethtool"].items():
                bits = " ".join(f"{k}={v}" for k, v in sorted(delta.items()))
                print(f"    {dev:12s} [ethtool] {bits}")
        elif not d.get("ethtool_available"):
            note("ethtool not available or without counters on these devices: "
                 "veth's XDP counters cannot be read here, and they are "
                 "not replaced with an estimate.")
        print(f"    softnet     dropped={d.get('softnet_dropped', 0)} "
              f"time_squeeze={d.get('softnet_squeeze', 0)}")


def gen_cpu_load(diag_data, plan):
    """(mean load of the generator CPUs, mean load of the DUT CPUs)."""
    if not diag_data or not plan:
        return None, None
    cpu = diag_data.get("cpu_pct") or {}
    g = [cpu[c] for c in plan.gen if c in cpu]
    d = [cpu[c] for c in plan.dut if c in cpu]
    return (round(sum(g) / len(g), 1) if g else None,
            round(sum(d) / len(d), 1) if d else None)


BN_GEN = "generatore"
BN_IN = "pipeline-ingresso"
BN_OUT = "pipeline-uscita"
BN_PIPE = "pipeline"
BN_NOISE = "macchina"
BN_UNKNOWN = "indeterminato"


def classify_bottleneck(row, threshold=DEFAULT_LOSS_THRESHOLD, plan=None,
                        diag_data=None, noisy=False):
    """(label, explanation) for ONE measurement point."""
    loss = row.get("loss_worst", row.get("loss_pct", 0.0)) or 0.0
    before = row.get("lost_before")
    after = row.get("lost_after")
    g_load, d_load = gen_cpu_load(diag_data, plan)
    tail = ""
    if g_load is not None and d_load is not None:
        tail = f" (cpu gen {g_load}%, cpu DUT {d_load}%)"

    if noisy:
        return BN_NOISE, ("the loss does not grow with the rate: it is machine "
                          "noise, not saturation" + tail)
    if loss <= threshold:
        if g_load is not None and g_load >= CPU_BUSY_PCT and (
                d_load is None or d_load < CPU_BUSY_PCT):
            return BN_GEN, ("the generator CPUs are saturated and the DUT "
                            "ones are not: the ceiling is the generator" + tail)
        return BN_GEN, ("no loss: the DUT is not saturated, so this "
                        "is the rate the generator could offer, not "
                        "the pipeline's maximum" + tail)
    if before is None or after is None:
        return BN_PIPE, ("there is loss, but this row has no HIT counters: "
                         "cannot tell whether at ingress or egress" + tail)
    if after > before:
        return BN_OUT, (f"{after} packets processed and not sent out against "
                        f"{before} never arrived: the egress saturates (the second "
                        f"veth and the counter), not the inference" + tail)
    if before > after:
        return BN_IN, (f"{before} packets never reached the program against "
                       f"{after} processed and not sent out: the DUT ingress "
                       f"saturates" + tail)
    return BN_UNKNOWN, "loss present but not attributable" + tail


def report_generator(gen):
    """What every generator THREAD did in the last window."""
    r = getattr(gen, "last_run", None)
    if r is None or not r.per_dev:
        note("no recent generator window to report")
        return
    print("")
    print(f"{YELLOW}  -- generator, last window --{NC}")
    cpu_of = {i["name"]: i["cpu"] for i in getattr(gen, "instances", [])}
    for d in r.per_dev:
        print(f"    {d['dev']:16s} cpu{cpu_of.get(d['dev'], '?'):<3} "
              f"tx={d['tx']:>9d} {d['pps']:>9d} pps  {d['secs']:>6.3f} s  "
              f"errors={d['errors']}")
    print(f"    {'AGGREGATO':16s}     tx={r.tx:>9d} "
          f"{r.tx_pps_aggregate:>9d} pps  {r.secs:>6.3f} s")
    if r.skew_pct > 20.0:
        warn(f"the instances did not work in the same window "
             f"(spread {r.skew_pct}% between the longest and the shortest): the "
             f"aggregate rate is an average over different periods.")
    if r.rate_mismatch_pct > 25.0:
        warn(f"TX/global duration and sum of per-instance pps differ by "
             f"{r.rate_mismatch_pct}%: one of them does not describe this "
             f"window. The figure used is always TX divided by the GLOBAL "
             f"duration, the one that cannot inflate the result.")


# --- RX counter ---
def _percpu_sum(table, key=0):
    vals = table[ct.c_int(key)]
    return sum(int(v) for v in vals)


# --- one measurement point ---
def _read_u64(table, key):
    """A counter, summed over every CPU (pkt_stats/cls_stats are per-CPU)."""
    from stats_maps import read_counter
    return read_counter(table, key)


def _zero_counters(setup, rx_tab, n_out):
    from stats_maps import zero_all
    zero_all(setup["cls_stats"], min(n_out, len(setup["cls_stats"])))
    zero_all(setup["pkt_stats"])
    rx_tab.clear()


def _agg(values):
    """Mean, minimum, maximum, standard deviation and coefficient of variation
    of a list of measurements."""
    vals = [v for v in values if v is not None]
    if not vals:
        return dict(mean=0, min=0, max=0, std=0.0, cv_pct=0.0)
    mean = sum(vals) / len(vals)
    std = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    return dict(mean=int(mean), min=min(vals), max=max(vals),
                std=round(std, 1),
                cv_pct=round(100.0 * std / mean, 1) if mean else 0.0)


def measure_point(setup, rx_tab, fab, frame, delay, count, n_out, clone=0,
                  tg_devs=None, repeat=DEFAULT_REPEAT, burst=0,
                  xmit_mode="start_xmit", gen=None, warmup=True,
                  threshold=DEFAULT_LOSS_THRESHOLD, plan=None, diag=None,
                  steady=True):
    """`repeat` windows of the same point."""
    if warmup and gen is not None:
        gen.warmup(frame, delay)
    runs = []
    if diag is not None:
        diag.start()
    for _ in range(max(1, repeat)):
        try:
            r = _measure_once(setup, rx_tab, fab, frame, delay, count,
                              n_out, clone, tg_devs, burst, xmit_mode, gen,
                              steady=steady)
        except PktgenEmptyRun as e:
            warn(f"measurement discarded: {e}")
            continue
        classe_drop = r.get("drop", 0) > 0 and r.get("hit", 0) == 0
        if r["rx"] == 0 and r.get("offered_tx", 0) > 0 and not classe_drop:
            dove = (f"{r['hit']} processed and 0 counted at egress"
                    if r["hit"] > 0 else
                    f"{r['offered_tx']} offered and the program never "
                    f"started (hit 0)")
            warn(f"measurement discarded: {dove} -- window instrumentally empty, "
                 f"not 100% loss")
            continue
        runs.append(r)
    diag_data = diag.stop() if diag is not None else {}
    if not runs:
        return None
    runs.sort(key=lambda r: r["rx_pps"])
    med = runs[len(runs) // 2]
    med["repeat"] = len(runs)
    med["loss_worst"] = max(r["loss_pct"] for r in runs)
    med["loss_best"] = min(r["loss_pct"] for r in runs)
    med["loss_med"] = round(statistics.median([r["loss_pct"] for r in runs]), 3)
    med["rx_pps_min"] = runs[0]["rx_pps"]
    med["rx_pps_max"] = runs[-1]["rx_pps"]
    med["burst"] = burst
    med["xmit_mode"] = xmit_mode
    a = _agg([r["rx_pps"] for r in runs])
    med["rx_pps_mean"] = a["mean"]
    med["rx_pps_std"] = a["std"]
    med["rx_pps_cv_pct"] = a["cv_pct"]
    med["secs_mean"] = round(sum(r["secs"] for r in runs) / len(runs), 3)
    lo, hi = med["rx_pps_min"], med["rx_pps_max"]
    med["spread_pct"] = round(100.0 * (hi - lo) / lo, 1) if lo else None
    pps_ord = sorted(r["rx_pps"] for r in runs)
    n = len(pps_ord)
    if n >= 4:
        q1, q2, q3 = (pps_ord[n // 4], pps_ord[n // 2], pps_ord[(3 * n) // 4])
        med["spread_iqr_pct"] = round(100.0 * (q3 - q1) / q2, 1) if q2 else None
        iqr = q3 - q1
        med["ripetizioni_anomale"] = sum(
            1 for v in pps_ord if v < q1 - 1.5 * iqr or v > q3 + 1.5 * iqr)
    else:
        med["spread_iqr_pct"] = None
        med["ripetizioni_anomale"] = 0
    disp = (med["spread_iqr_pct"] if med.get("spread_iqr_pct") is not None
            else med["spread_pct"])
    med["spread_deciso_pct"] = disp
    med["unreliable"] = bool(
        (disp is not None and disp > MAX_SPREAD_PCT)
        or med.get("gen_skew_pct", 0.0) > 20.0
        or med.get("offered_pps") == 0 and med.get("tx", 0) > 0
    )
    med["invalid_reason"] = []
    if med.get("gen_skew_pct", 0.0) > 20.0:
        med["invalid_reason"].append("generator threads not synchronized")
    if med.get("offered_pps") == 0 and med.get("tx", 0) > 0:
        med["invalid_reason"].append("zero offered rate with nonzero TX")
    if disp is not None and disp > MAX_SPREAD_PCT:
        med["invalid_reason"].append(
            f"spread between repetitions {disp}% "
            f"(min-max {med['spread_pct']}%)")
    sonda = count < MIN_WINDOW_PKTS // max(1, gen.n_inst if gen else 1)
    if med.get("gen_skew_pct", 0) > 20.0 and not sonda:
        warn(f"generator threads out of step by {med['gen_skew_pct']}%: they "
             f"did not work in the same window")
    if med.get("gen_rate_mismatch_pct", 0) > 25.0 and not sonda:
        warn(f"TX/duration and sum of per-instance pps differ by "
             f"{med['gen_rate_mismatch_pct']}%: using TX divided by the global "
             f"duration, the read that does not inflate")
    if med["unreliable"]:
        tag = "indeterminato"
        why = "unreliable measurement: " + "; ".join(med["invalid_reason"])
    else:
        tag, why = classify_bottleneck(med, threshold=threshold, plan=plan,
                                       diag_data=diag_data)
    med["bottleneck"] = tag
    med["bottleneck_why"] = why
    if diag_data:
        g, d = gen_cpu_load(diag_data, plan)
        med["cpu_gen_pct"] = g
        med["cpu_dut_pct_punto"] = d
        med["cpu_dut_pct"] = d
    win = [r.get("_cpu_win") or {} for r in runs]
    if plan and plan.dut and all(all(c in w for c in plan.dut) for w in win):
        per_run = [sum(w[c] for c in plan.dut) / len(plan.dut) for w in win]
        med["cpu_dut_pct"] = round(statistics.median(per_run), 1)
    if med.get("cpu_dut_pct") is not None:
        med["ns_cpu"] = ns_cpu(med, med["cpu_dut_pct"], plan)
        med["softnet_dropped"] = diag_data.get("softnet_dropped")
        med["_diag"] = diag_data
    med.update(hw_columns(runs, plan))
    return med


def hw_columns(runs, plan):
    """Instructions, cycles and IPC per packet (hw_counters.per_packet) of every
    repetition, then the median over repetitions, like the rate."""
    if not plan or not plan.dut:
        return {}
    per = []
    for r in runs:
        hw = r.get("_hw_win") or {}
        if not hw:
            continue
        pkts = (r.get("hit", 0) + r.get("miss", 0) + r.get("drop", 0)
                or r.get("rx", 0))
        cols = HW.per_packet(hw, plan.dut, pkts, r.get("secs"),
                             egress=HC.egress_cpus(plan.egress))
        if cols:
            per.append(cols)
    if not per:
        return {}
    out = {}
    for k in HW.COLUMNS:
        vals = [c[k] for c in per if c.get(k) is not None]
        if vals:
            out[k] = round(statistics.median(vals), 3)
    return out


def _measure_once(setup, rx_tab, fab, frame, delay, count, n_out, clone=0,
                  tg_devs=None, burst=0, xmit_mode="start_xmit", gen=None,
                  steady=True):
    """One (frame size, offered rate) point."""
    cpu_win = {}
    hw_win = {}
    if gen is not None and steady and gen.window_mode == "steady":
        def probe():
            out = dict(hit=_read_u64(setup["pkt_stats"], 0),
                       miss=_read_u64(setup["pkt_stats"], 1),
                       drop=_read_u64(setup["pkt_stats"], 2),
                       rx=(_read_u64(setup["pkt_stats"], 0)
                           if setup.get("rx_is_hit") else _percpu_sum(rx_tab)))
            for c, (busy, tot) in _read_proc_stat().items():
                out[f"_cpub{c}"] = busy
                out[f"_cput{c}"] = tot
            if HW_COUNTERS is not None:
                out.update(HW_COUNTERS.read())
            return out
        run = gen.steady(frame, delay, probe)
        devs = gen.names
        tx, tx_pps, elapsed = run
        d = run.dut
        hit, miss, drop, rx = d["hit"], d["miss"], d["drop"], d["rx"]
        secs = run.window if run.window > 0 else 1e-9
        for k, dt in d.items():
            if k.startswith("_cput") and dt > 0:
                c = int(k[5:])
                cpu_win[c] = round(100.0 * d.get(f"_cpub{c}", 0) / dt, 1)
        hw_win = {k: v for k, v in d.items() if k.startswith("_hw")}
    else:
        time.sleep(DRAIN_S)
        _zero_counters(setup, rx_tab, n_out)
        if gen is not None:
            run = gen.run(frame, count, delay)
            devs = gen.names
        else:
            devs = tg_devs or [fab.ingress_peer]
            pg_clear_threads(len(devs))
            for i, dev in enumerate(devs):
                pg_configure(dev, frame, count, delay,
                             dst_ip="10.0.0.2", dst_mac="02:00:00:00:00:02",
                             clone=clone, thread=i, burst=burst,
                             xmit_mode=xmit_mode)
            run = pg_run_and_read(devs)
        tx, tx_pps, elapsed = run
        atteso = count * (gen.n_inst if gen is not None else len(devs))
        if atteso and tx < atteso * WINDOW_MIN_TX_FRACTION:
            raise PktgenEmptyRun(
                f"truncated window: {tx} transmitted out of {atteso} requested "
                f"({100.0 * tx / atteso:.1f}%) in {elapsed:.2f}s")
        time.sleep(DRAIN_S)
        hit = _read_u64(setup["pkt_stats"], 0)
        miss = _read_u64(setup["pkt_stats"], 1)
        drop = _read_u64(setup["pkt_stats"], 2)
        rx = (hit if setup.get("rx_is_hit") else _percpu_sum(rx_tab))
        secs = getattr(run, "window", 0.0) or elapsed
        secs = secs if secs > 0 else 1e-9
    offered = int(1e9 / delay) * len(devs) if delay else None
    errors = getattr(run, "errors", 0)
    offered_tx = tx + errors
    return dict(frame=frame, delay=delay, secs=round(secs, 3),
                tx=tx, tx_pps=run.tx_pps_aggregate or int(tx / secs),
                tx_pps_sum=tx_pps, offered_pps=offered,
                gen_threads=len(devs),
                window_mode=("steady" if getattr(run, "steady", False)
                             else "count"),
                gen_start_offset_ms=getattr(run, "start_offset_ms", None),
                t_wall=round(time.time(), 2),
                read_ms=getattr(run, "read_ms", None),
                gen_skew_pct=getattr(run, "skew_pct", 0.0),
                gen_rate_mismatch_pct=getattr(run, "rate_mismatch_pct", 0.0),
                gen_errors=errors,
                offered_tx=offered_tx,
                offered_real_pps=int(offered_tx / secs),
                hit=hit, miss=miss, drop=drop, rx=rx,
                _cpu_win=cpu_win,
                _hw_win=hw_win,
                rx_pps=int(rx / secs),
                hit_pps=int(hit / secs),
                proc_pps=int((hit + miss + drop) / secs),
                respinti=errors,
                persi_in_coda=max(0, tx - hit),
                persi_dopo=max(0, hit - rx),
                respinti_pct=(round(100.0 * errors / offered_tx, 3)
                              if offered_tx else 0.0),
                loss_dut_pct=(round(100.0 * (max(0, tx - hit)
                                             + max(0, hit - rx)) / offered_tx, 3)
                              if offered_tx else 0.0),
                rx_mbps=round(rx * frame * 8 / secs / 1e6, 2),
                lost_before=max(0, offered_tx - hit),
                lost_after=max(0, hit - rx),
                loss_pct=(round(100.0 * max(0, offered_tx - rx) / offered_tx, 3)
                          if offered_tx else 0.0),
                loss_wire_pct=(round(100.0 * max(0, tx - rx) / tx, 3)
                               if tx else 0.0))


# --- arrival -> departure latency, on real traffic ---

LAT_DECLS_SRC = r"""
BPF_PERCPU_ARRAY(ts_in, __u64, 1);
/* T2: written just before the redirect; the sums are done at the egress */
BPF_PERCPU_ARRAY(ts_mid, __u64, 1);
/* 0 = count, 1 = sum ns, 2 = minimum, 3 = maximum */
BPF_PERCPU_ARRAY(lat_acc, __u64, 4);      /* T3 - T1: end-to-end */
BPF_PERCPU_ARRAY(pipe_acc, __u64, 4);     /* T2 - T1: the pipeline */
BPF_PERCPU_ARRAY(xport_acc, __u64, 4);    /* T3 - T2: redirect + veth + NAPI */
/* packets reaching the egress, counted with or without timestamps */
BPF_PERCPU_ARRAY(rx_n, __u64, 1);
/* log2 histograms, for the percentiles */
BPF_PERCPU_ARRAY(lat_hist, __u64, LAT_BUCKETS);   /* log2: [2^i, 2^(i+1)) */
BPF_PERCPU_ARRAY(pipe_hist, __u64, LAT_BUCKETS);
BPF_PERCPU_ARRAY(xport_hist, __u64, LAT_BUCKETS);
"""

def _lat_accum(acc, hist, delta):
    return f"""
    {{ __u64 _d = {delta};
      __u32 _bk = bpf_log2l(_d);
      if (_bk >= LAT_BUCKETS) _bk = LAT_BUCKETS - 1;
      int _bi = (int)_bk;
      __u64 *_hb = {hist}.lookup(&_bi); if (_hb) *_hb += 1;
      int _k = 0;
      __u64 *_n = {acc}.lookup(&_k); if (_n) *_n += 1;
      _k = 1; __u64 *_sm = {acc}.lookup(&_k); if (_sm) *_sm += _d;
      _k = 2; __u64 *_mn = {acc}.lookup(&_k);
      if (_mn && (*_mn == 0 || _d < *_mn)) *_mn = _d;
      _k = 3; __u64 *_mx = {acc}.lookup(&_k); if (_mx && _d > *_mx) *_mx = _d; }}"""


LAT_COUNTER_SRC = """
int xdp_lat_count(struct xdp_md *ctx) {
    int z = 0;
    __u64 now = bpf_ktime_get_ns();

    __u64 *rn = rx_n.lookup(&z); if (rn) *rn += 1;

    __u64 *t0 = ts_in.lookup(&z);
    __u64 *t1 = ts_mid.lookup(&z);
    __u64 a = t0 ? *t0 : 0;
    __u64 m = t1 ? *t1 : 0;

    if (a && now > a) %(e2e)s

    if (a && m && m > a) %(pipe)s

    if (m && now > m) %(xport)s

    return XDP_DROP;
}
""" % {"e2e": _lat_accum("lat_acc", "lat_hist", "now - a"),
       "pipe": _lat_accum("pipe_acc", "pipe_hist", "m - a"),
       "xport": _lat_accum("xport_acc", "xport_hist", "now - m")}

LAT_STAMP = ("\n    { int _lz = 0; __u64 _lt = bpf_ktime_get_ns();\n"
             "      ts_in.update(&_lz, &_lt); }\n")

LAT_STAMP_MID = ("{ int _mz = 0; __u64 _mt = bpf_ktime_get_ns();\n"
                 "          ts_mid.update(&_mz, &_mt); }\n"
                 "        ")
LAT_REDIRECT_ANCHOR = "return bpf_redirect("

LAT_BUCKETS = 40

LAT_ENTRY = {
    "baseline": "xdp_baseline",
    "p1_static": "xdp_dispatch",
    "hardcoded": "xdp_dispatch",
    "template": "ipa_switch_template",
    "modular": "modular_dispatcher",
}


def _instrumented_source(method, model_path, node=STATIC_NODE):
    """(source, weights, scales) of the pipeline with the timestamp and the counter."""
    import check_pipelines as V
    weights, scale = V.load_weights(model_path)

    if method == "baseline":
        src = V.EBPF_BASELINE
    elif method in ("hardcoded", "p1_static"):
        raise RuntimeError("P1/P1.5 are the AOT object: their instrumented "
                           "build is _load_instrumented_aot")
    elif method == "template":
        from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                        EBPF_ARCH_GENERIC_2LAYER)
        src = ("#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
               + "\n" + EBPF_ARCH_GENERIC_2LAYER)
    else:
        from ebpf_modular import EBPF_MODULAR_FULL
        src = EBPF_MODULAR_FULL
    return _stamp_bcc_source(src, method), weights, scale


def _stamp_bcc_source(src, method):
    """The BCC source of `method` with T1 at ingress, T2 at the redirect and
    the egress counter (T3) appended."""
    anchor = f"int {LAT_ENTRY[method]}(struct xdp_md *ctx) {{"
    if src.count(anchor) != 1:
        raise RuntimeError(
            f"entry point '{anchor}' not found in the source of "
            f"{method} (found {src.count(anchor)} times). Has the "
            f"dispatcher signature changed?")
    n_red = src.count(LAT_REDIRECT_ANCHOR)
    if n_red != 1:
        raise RuntimeError(
            f"the source of {method} has {n_red} redirect sites, not 1: "
            f"T2 would have to go in {n_red} places and the measurement would "
            f"cover only part of the packets. Review LAT_STAMP_MID before "
            f"using this mode.")
    primo_uso = min(p for p in (src.find(anchor),
                                src.find(LAT_REDIRECT_ANCHOR)) if p >= 0)
    incs = [m for m in re.finditer(r"^#include .*$", src, re.M)
            if m.end() < primo_uso]
    if incs:
        at = incs[-1].end() + 1
    else:
        first_fn = re.search(r"^int \w+\(struct xdp_md ", src, re.M)
        if not first_fn:
            raise RuntimeError(
                f"no XDP function in the source of {method}: cannot tell where "
                f"to put the instrumentation declarations.")
        at = first_fn.start()
    defines = f"#define LAT_BUCKETS {LAT_BUCKETS}\n"
    src = src[:at] + defines + LAT_DECLS_SRC + "\n" + src[at:]

    src = src.replace(anchor, anchor + LAT_STAMP, 1)
    src = src.replace(LAT_REDIRECT_ANCHOR,
                      LAT_STAMP_MID + LAT_REDIRECT_ANCHOR, 1)

    for m in ("ts_in", "ts_mid", "lat_acc", "pipe_acc", "xport_acc",
              "lat_hist", "pipe_hist", "xport_hist", "rx_n"):
        decl = src.find(f"BPF_PERCPU_ARRAY({m},")
        uso = src.find(f"{m}.")
        if decl < 0 or (uso >= 0 and uso < decl):
            raise RuntimeError(
                f"{method}: map `{m}` would be used (offset {uso}) before "
                f"being declared (offset {decl}). clang would stop "
                f"with 'undeclared identifier'.")

    return src + "\n" + LAT_COUNTER_SRC


# --- the same instrumentation for P1 and P1.5, which are the AOT object (libbpf) ---
_LAT_MAPS = (("ts_in", "1"), ("ts_mid", "1"), ("lat_acc", "4"),
             ("pipe_acc", "4"), ("xport_acc", "4"), ("rx_n", "1"),
             ("lat_hist", "LAT_BUCKETS"), ("pipe_hist", "LAT_BUCKETS"),
             ("xport_hist", "LAT_BUCKETS"))

LAT_DECLS_LIBBPF = "\n".join(
    f"struct {{ __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); "
    f"__uint(max_entries, {n}); __type(key, __u32); __type(value, __u64); }} "
    f"{name} SEC(\".maps\");" for name, n in _LAT_MAPS) + """
static __always_inline unsigned int ipa_log2(unsigned int v) {
    unsigned int r, shift;
    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);
    return r;
}
static __always_inline unsigned int bpf_log2l(unsigned long v) {
    unsigned int hi = v >> 32;
    if (hi) return ipa_log2(hi) + 32 + 1;
    return ipa_log2(v) + 1;
}
"""


def _lat_accum_libbpf(acc, hist, delta):
    return f"""
    {{ __u64 _d = {delta};
      __u32 _bk = bpf_log2l(_d);
      if (_bk >= LAT_BUCKETS) _bk = LAT_BUCKETS - 1;
      __u32 _bi = _bk;
      __u64 *_hb = bpf_map_lookup_elem(&{hist}, &_bi); if (_hb) *_hb += 1;
      __u32 _k = 0;
      __u64 *_n = bpf_map_lookup_elem(&{acc}, &_k); if (_n) *_n += 1;
      _k = 1; __u64 *_sm = bpf_map_lookup_elem(&{acc}, &_k); if (_sm) *_sm += _d;
      _k = 2; __u64 *_mn = bpf_map_lookup_elem(&{acc}, &_k);
      if (_mn && (*_mn == 0 || _d < *_mn)) *_mn = _d;
      _k = 3; __u64 *_mx = bpf_map_lookup_elem(&{acc}, &_k); if (_mx && _d > *_mx) *_mx = _d; }}"""


LAT_COUNTER_LIBBPF = """
SEC("xdp")
int xdp_lat_count(struct xdp_md *ctx) {
    __u32 z = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *rn = bpf_map_lookup_elem(&rx_n, &z); if (rn) *rn += 1;
    __u64 *t0 = bpf_map_lookup_elem(&ts_in, &z);
    __u64 *t1 = bpf_map_lookup_elem(&ts_mid, &z);
    __u64 a = t0 ? *t0 : 0;
    __u64 m = t1 ? *t1 : 0;
    if (a && now > a) %(e2e)s
    if (a && m && m > a) %(pipe)s
    if (m && now > m) %(xport)s
    return XDP_DROP;
}
""" % {"e2e": _lat_accum_libbpf("lat_acc", "lat_hist", "now - a"),
       "pipe": _lat_accum_libbpf("pipe_acc", "pipe_hist", "m - a"),
       "xport": _lat_accum_libbpf("xport_acc", "xport_hist", "now - m")}

LAT_STAMP_LIBBPF = ("\n    { __u32 _lz = 0; __u64 _lt = bpf_ktime_get_ns();\n"
                    "      bpf_map_update_elem(&ts_in, &_lz, &_lt, BPF_ANY); }\n")
LAT_STAMP_MID_LIBBPF = ("{ __u32 _mz = 0; __u64 _mt = bpf_ktime_get_ns();\n"
                        "          bpf_map_update_elem(&ts_mid, &_mz, &_mt, BPF_ANY); }\n"
                        "        ")
LAT_ENTRY_AOT = "int xdp_dispatch(struct xdp_md *ctx) {"


def _instrument_aot_latency(src):
    """T1 at the dispatcher entry, T2 at the redirect, T3 in the egress
    counter -- as _instrumented_source does for the BCC sources."""
    if src.count(LAT_ENTRY_AOT) != 1:
        raise RuntimeError(f"AOT object: '{LAT_ENTRY_AOT}' found "
                           f"{src.count(LAT_ENTRY_AOT)} times, expected 1")
    n_red = src.count(LAT_REDIRECT_ANCHOR)
    if n_red != 1:
        raise RuntimeError(f"AOT object: {n_red} redirect sites, not 1: T2 "
                           f"would cover only part of the packets")
    at = src.index('SEC("xdp")')
    src = (src[:at] + f"#define LAT_BUCKETS {LAT_BUCKETS}\n" + LAT_DECLS_LIBBPF
           + "\n" + src[at:])
    src = src.replace(LAT_ENTRY_AOT, LAT_ENTRY_AOT + LAT_STAMP_LIBBPF, 1)
    src = src.replace(LAT_REDIRECT_ANCHOR,
                      LAT_STAMP_MID_LIBBPF + LAT_REDIRECT_ANCHOR, 1)
    return src + "\n" + LAT_COUNTER_LIBBPF


def _load_instrumented_aot(method, model_path, fab, sem, node=STATIC_NODE):
    """P1 / P1.5 instrumented."""
    import p1_aot
    import check_pipelines as V
    import test_forwarding as TF

    weights, scale = V.load_weights(model_path)
    src = p1_aot.p1_source([(0, weights, scale)],
                           static_node=(node if method == "p1_static" else None))
    src = _instrument_aot_latency(src)
    o_path, _ = p1_aot.compile_object(src)
    obj = p1_aot.AotObject(o_path, p1_aot._PROG_RE.findall(src))
    b = obj.b
    model_fn = obj.progs["xdp_model"]
    b["model_progs"][ct.c_int(PKTGEN_MAGIC_MODEL_ID)] = ct.c_int(model_fn.fd)
    setup = {"b": b, "disp": obj.progs["xdp_dispatch"], "fn": model_fn,
             "weights": weights, "scale": scale, "pipeline": 1,
             "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"],
             "owner": obj}
    V._seed_link_state(b, 1)
    TF._install_fabric_mac_table(b, "mac_table", fab, sem.logical_ports)
    b["ingress_port"][ct.c_uint32(fab.ingress_ifindex)] = \
        ct.c_uint32(TF.FABRIC_INGRESS_SLOT)
    if method != "p1_static":
        b["node_id"][ct.c_uint32(0)] = ct.c_uint32(TF.FABRIC_NODE_INDEX)
    return setup, obj.progs["xdp_lat_count"]


@contextlib.contextmanager
def _latency_in_sources(method):
    """For the duration of the block the sources pipeline_setup compiles
    carry T1, T2 and the egress counter."""
    import p1_aot
    import pipeline_setup as PS
    orig_src, orig_p1 = PS._source, p1_aot.p1_source

    def bcc_source(raw, instrument):
        return _stamp_bcc_source(orig_src(raw, instrument), method)

    def p1_source(*a, **k):
        return _instrument_aot_latency(orig_p1(*a, **k))

    PS._source, p1_aot.p1_source = bcc_source, p1_source
    try:
        yield
    finally:
        PS._source, p1_aot.p1_source = orig_src, orig_p1


def _load_instrumented_model(method, model_path, fab, sem):
    """The instrumented build of the model under test (--model)."""
    with _latency_in_sources(method):
        setup = build_pipeline(method, model_path, fab, sem)
    if method in ("hardcoded", "p1_static"):
        lat_fn = setup["owner"].progs.get("xdp_lat_count")
    else:
        from bcc import BPF
        lat_fn = setup["b"].load_func("xdp_lat_count", BPF.XDP)
    if lat_fn is None:
        raise RuntimeError(f"{method}: the object does not contain xdp_lat_count "
                           f"-- did the source not go through the timestamps?")
    return setup, lat_fn


def _load_instrumented(method, model_path, fab, sem, node=STATIC_NODE):
    """Compiles everything together, loads, and wires the pipeline on this fabric."""
    import check_pipelines as V
    if V._mut() is not None:
        return _load_instrumented_model(method, model_path, fab, sem)
    if method in ("hardcoded", "p1_static"):
        return _load_instrumented_aot(method, model_path, fab, sem, node)
    from bcc import BPF
    import check_pipelines as V
    import test_forwarding as TF

    src, weights, scale = _instrumented_source(method, model_path, node)
    try:
        b = BPF(text=src)
    except Exception as e:
        raise RuntimeError(
            f"the instrumented build of {method} does not compile. The clang "
            f"error is in the lines ABOVE this one. ({e})") from e
    entry = b.load_func(LAT_ENTRY[method], BPF.XDP)
    lat_fn = b.load_func("xdp_lat_count", BPF.XDP)

    pl = {"baseline": 0, "p1_static": 1, "hardcoded": 1,
          "template": 2, "modular": 3}[method]
    setup = {"b": b, "disp": entry, "fn": entry, "weights": weights,
             "scale": scale, "pipeline": pl,
             "cls_stats": b["cls_stats" if pl in (0, 1) else
                            TF._MAC_NAME[pl].replace("mac_table", "cls_stats")],
             "pkt_stats": b["pkt_stats" if pl in (0, 1) else
                            TF._MAC_NAME[pl].replace("mac_table", "pkt_stats")]}

    if pl == 1:
        model_fn = b.load_func("model_0", BPF.XDP)
        b["model_progs"][ct.c_int(0)] = ct.c_int(model_fn.fd)
        b["model_progs"][ct.c_int(PKTGEN_MAGIC_MODEL_ID)] = ct.c_int(model_fn.fd)
    elif pl == 2:
        from ebpf_template_arch import load_arch_weights
        leaf = b.load_func("arch_generic_2layer", BPF.XDP)
        b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
        for mid in (0, PKTGEN_MAGIC_MODEL_ID):
            load_arch_weights(b, weights, model_id=mid, scale=scale)
    elif pl == 3:
        from ebpf_modular import load_modular_weights
        first = b.load_func("layer_first", BPF.XDP)
        hidden = b.load_func("layer_hidden", BPF.XDP)
        b["layer_chain"][ct.c_int(0)] = ct.c_int(first.fd)
        for i in range(1, 16):
            b["layer_chain"][ct.c_int(i)] = ct.c_int(hidden.fd)
        for mid in (0, PKTGEN_MAGIC_MODEL_ID):
            load_modular_weights(b, weights, model_id=mid, scale=scale,
                                 layer_dims=[(65, 4), (4, 4), (4, 7)])

    V._seed_link_state(b, 1)
    mac_name = "mac_table" if pl in (0, 1) else TF._MAC_NAME[pl]
    TF._install_fabric_mac_table(b, mac_name, fab, sem.logical_ports)
    if pl != 0:
        b[TF._INGRESS_NAME[pl]][ct.c_uint32(fab.ingress_ifindex)] = \
            ct.c_uint32(TF.FABRIC_INGRESS_SLOT)
        if method != "p1_static":
            b[TF._NODEID_NAME[pl]][ct.c_uint32(0)] = \
                ct.c_uint32(TF.FABRIC_NODE_INDEX)
    return setup, lat_fn


def _map_extra_ingress(setup, ifindexes):
    """Makes the program recognise the additional ingresses too."""
    import test_forwarding as TF
    pl = setup["pipeline"]
    _, slot = _node_slot()
    if pl == 0 or not slot:
        return
    ing = setup["b"][TF._INGRESS_NAME[pl]]
    for idx in ifindexes:
        ing[ct.c_uint32(idx)] = ct.c_uint32(slot)


def _read_lat(b, acc="lat_acc", hist="lat_hist"):
    """Latency statistics, summing the per-CPU cells."""
    acc = b[acc]
    n = sum(int(v) for v in acc[ct.c_int(0)])
    if not n:
        return None
    tot = sum(int(v) for v in acc[ct.c_int(1)])
    mins = [int(v) for v in acc[ct.c_int(2)] if int(v) > 0]
    maxs = [int(v) for v in acc[ct.c_int(3)]]

    hist = b[hist]
    buckets = [sum(int(v) for v in hist[ct.c_int(i)])
               for i in range(LAT_BUCKETS)]
    over = buckets[-1]

    def pct(q):
        """The UPPER edge of the log2 bucket the quantile q falls in."""
        target = q * n
        run = 0
        for i, c in enumerate(buckets):
            run += c
            if run >= target:
                return 1 << (i + 1)
        return None

    return dict(n=n, lat_min_ns=(min(mins) if mins else 0),
                lat_p50_ns=pct(0.50), lat_p90_ns=pct(0.90),
                lat_p99_ns=pct(0.99), lat_avg_ns=tot // n,
                lat_max_ns=max(maxs), over=over)


LAT_TRIPLE = (("pipe", "pipe_acc", "pipe_hist"),
              ("e2e", "lat_acc", "lat_hist"),
              ("xport", "xport_acc", "xport_hist"))


def _read_lat_all(b):
    """The three latencies plus the true RX, in one go."""
    out = {"rx": sum(int(v) for v in b["rx_n"][ct.c_int(0)])}
    for nome, acc, hist in LAT_TRIPLE:
        st = _read_lat(b, acc, hist)
        out[nome] = st
    return out


def _clear_lat(b):
    for _, acc, hist in LAT_TRIPLE:
        b[acc].clear()
        b[hist].clear()
    b["rx_n"].clear()


# --- fair comparison: the same conditions for every pipeline ---


class _quiet:
    """Silences stdout. attach_xdp prints one line per interface, and in the
    rounds comparison that is 6 interfaces x 5 pipelines x N rounds."""

    def __enter__(self):
        self._old = sys.stdout
        sys.stdout = io.StringIO()
        return self

    def __exit__(self, *a):
        sys.stdout = self._old
        return False


def _detach(iface):
    subprocess.run(["ip", "link", "set", "dev", iface, "xdp", "off"],
                   check=False, capture_output=True)


def _noop():
    class _N:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    return _N()


def _fmt_ns(v):
    return f"{v:5d}n" if v is not None else "  n/a"


def _fmt_bucket(v):
    """A percentile from a log2 histogram, printed for what it is."""
    return f"<{v:5d}n" if v is not None else "   n/a"


def run_fair(methods, model_path, frames, delays, count, threads,
             threaded_napi=True, repeat=DEFAULT_REPEAT, rounds=DEFAULT_ROUNDS,
             tol=0.0, plan=None, xmit_mode="start_xmit", diag=None,
             window_s=WINDOW_S, warmup_s=DEFAULT_WARMUP_S):
    """Every pipeline on the same fabric, compiled first, measured in rounds."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    plan = plan or plan_cpus(threads=threads)
    sem, n_out = class_semantics()
    raw = []

    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False,
                     port_queues=egress_queues(plan)) as fab:
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Phase 1: compiling and loading {len(methods)} pipelines "
              f"(no measurement running){NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        loaded = {}
        for m in methods:
            try:
                setup, lat_fn = _load_instrumented(m, model_path, fab, sem)
                loaded[m] = (setup, lat_fn)
                info(f"{m}: loaded")
            except Exception as e:
                warn(f"{m}: not loaded, skipping it -- {type(e).__name__}: {e}")
        if not loaded:
            warn("no pipeline loaded")
            return []

        gen = Generator([fab.ingress_peer], plan, xmit_mode=xmit_mode,
                        topology="shared", window_s=window_s,
                        warmup_s=warmup_s).attach()
        napi_devs = []

        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Phase 2: {rounds} rounds x {len(loaded)} pipelines, "
              f"same fabric, no compilation{NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        hdr = (f"  {'round':>5s} {'pipeline':10s} {'frame':>5s} "
               f"{'phase':12s} "
               f"{'RX pps':>9s} {'Mb/s':>7s} {'rej':>7s} {'loss':>8s} "
               f"{'min':>6s} {'p50<':>7s} {'p99<':>8s}")
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))

        first = True
        for rnd in range(1, rounds + 1):
            for m, (setup, lat_fn) in loaded.items():
                b = setup["b"]
                ctx = (lambda: _quiet()) if not first else (lambda: _noop())
                with ctx():
                    for peer in fab.peer_of.values():
                        try:
                            attach_xdp(b, lat_fn, peer)
                        except Exception:
                            pass
                    attach_xdp(b, setup["disp"], fab.ingress)
                if first:
                    if threaded_napi:
                        napi_devs = [fab.ingress]
                        if enable_threaded_napi(napi_devs, plan):
                            info("threaded NAPI: generator and DUT on separate "
                                 "cores")
                        else:
                            napi_devs = []
                    first = False
                gen.warmup(64, 0)
                for frame in frames:
                    for r in _fair_sweep(b, fab, frame, tol, gen=gen,
                                         plan=plan, diag=diag):
                        r.update(method=m, round=rnd, threads=gen.n_inst)
                        raw.append(r)
                        if r["phase"] == "ricerca":
                            continue
                        print(f"  {rnd:5d} {m:10s} {frame:5d} "
                              f"{r['phase']:12s} "
                              f"{r['rx_pps']:9d} {r['rx_mbps']:7.1f} "
                              f"{r.get('respinti_pct', 0.0):6.2f}% "
                              f"{r['loss_pct']:7.2f}% "
                              f"{_fmt_ns(r['lat_min_ns'])} "
                              f"{_fmt_bucket(r['lat_p50_ns'])} "
                              f"{_fmt_bucket(r['lat_p99_ns'])}")

        gen.detach()
        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        _detach(fab.ingress)
        for peer in fab.peer_of.values():
            _detach(peer)
    return raw


# --- the maximum rate without loss (RFC 2544) ---


def _fair_sweep(b, fab, frame, tol, steps=KNEE_STEPS, gen=None, plan=None,
                diag=None):
    """Three points per pipeline."""
    rows = []
    wc = (gen.window_count if gen is not None
          else (lambda r, s=None: _window_count(r)))

    full = _one_fair_point(b, fab, frame, 0, wc(3_000_000), gen=gen)
    if full is None:
        warn(f"frame {frame}: no usable window at full load, "
             f"this round produces no rows for this pipeline (the final "
             f"median will be computed over fewer rounds).")
        return rows
    full["phase"] = "pieno"
    rows.append(full)

    if full["loss_pct"] <= tol:
        clean = dict(full)
        clean["phase"] = "zero-perdite"
        clean["gen_bound"] = 1
        rows.append(clean)
    else:
        SU = (0.98, 1.02, 1.05, 1.09, 1.14, 1.20)
        GIU = (0.92, 0.85, 0.75, 0.60, 0.40, 0.25)
        est = float(full["rx_pps"])
        best = None
        rate = est * SU[0]
        i_su, i_giu = 1, 0
        for _ in range(steps):
            if rate < 1000:
                break
            r = _one_fair_point(b, fab, frame, _delay_for(rate, gen),
                                wc(rate), gen=gen)
            if r is None:
                break
            r["phase"] = "ricerca"
            rows.append(r)
            if r["loss_pct"] <= tol:
                best = r
                if i_su >= len(SU):
                    break
                rate, i_su = est * SU[i_su], i_su + 1
            else:
                if best is not None:
                    break
                if i_giu >= len(GIU):
                    break
                rate, i_giu = est * GIU[i_giu], i_giu + 1
        if best is not None:
            clean = dict(best)
            clean["phase"] = "zero-perdite"
            clean["gen_bound"] = 0
            rows.append(clean)

    idle_rate = 50_000
    idle = _one_fair_point(b, fab, frame, _delay_for(idle_rate, gen),
                           wc(idle_rate), gen=gen)
    if idle is not None:
        idle["phase"] = "scarico"
        rows.append(idle)
    for r in rows:
        r.setdefault("gen_bound", 0)
        tag, why = classify_bottleneck(r, threshold=max(tol, 0.0), plan=plan)
        r["bottleneck"] = tag
        r["bottleneck_why"] = why
    return rows


def _delay_for(rate, gen=None):
    """The delay to offer `rate` in aggregate, given that with N
    instances each transmits at rate/N."""
    if gen is not None:
        return gen.delay_for(rate)
    return int(1e9 / rate) if rate > 0 else 0


def _one_fair_point(b, fab, frame, delay, count, gen=None):
    """One point: throughput and latency from the same packet."""
    time.sleep(DRAIN_S)
    b["lat_acc"].clear()
    b["lat_hist"].clear()
    try:
        if gen is not None and gen.window_mode == "steady":
            run = gen.steady(frame, delay, lambda: {
                "rx": sum(int(v) for v in b["rx_n"][ct.c_int(0)])})
            tx, tx_pps, secs = run
            threads = gen.n_inst
            skew = run.skew_pct
        elif gen is not None:
            run = gen.run(frame, count, delay)
            tx, tx_pps, secs = run
            threads = gen.n_inst
            skew = run.skew_pct
        else:
            pg_ensure_device(fab.ingress_peer, thread=0)
            pg_set_params(fab.ingress_peer, frame, count, delay)
            run = pg_run_and_read([fab.ingress_peer])
            tx, tx_pps, secs = run
            threads, skew = 1, getattr(run, "skew_pct", 0.0)
    except PktgenEmptyRun as e:
        warn(f"point discarded: {e}")
        return None
    atteso = count * (gen.n_inst if gen is not None else 1)
    if (not getattr(run, "steady", False) and atteso
            and tx < atteso * WINDOW_MIN_TX_FRACTION):
        warn(f"point discarded: truncated window, {tx} transmitted out of {atteso} "
             f"requested ({100.0 * tx / atteso:.1f}%) in {secs:.2f}s")
        return None
    time.sleep(DRAIN_S)
    st = _read_lat(b)
    if st is None:
        return None
    rx = run.dut["rx"] if getattr(run, "steady", False) else st["n"]
    secs = secs or 1e-9
    errors = getattr(run, "errors", 0)
    offered_tx = tx + errors
    return dict(frame=frame, delay=delay, tx=tx, rx=rx, tx_pps=tx_pps,
                rx_pps=int(rx / secs),
                rx_mbps=round(rx * frame * 8 / secs / 1e6, 1),
                secs=round(secs, 3), gen_threads=threads,
                gen_skew_pct=skew,
                window_mode=("steady" if getattr(run, "steady", False)
                             else "count"),
                offered_pps=(int(1e9 / delay) * threads if delay else None),
                gen_errors=errors, offered_tx=offered_tx,
                offered_real_pps=int(offered_tx / secs),
                loss_pct=(round(100.0 * max(0, offered_tx - rx) / offered_tx, 3)
                          if offered_tx else 0.0),
                respinti_pct=(round(100.0 * errors / offered_tx, 3)
                              if offered_tx else 0.0),
                loss_dut_pct=(round(100.0 * max(0, tx - rx) / offered_tx, 3)
                              if offered_tx else 0.0),
                excess_rx=max(0, rx - tx),
                **{k: st[k] for k in ("lat_min_ns", "lat_p50_ns", "lat_p90_ns",
                                      "lat_p99_ns", "lat_avg_ns",
                                      "lat_max_ns")})


def _give_back(*paths):
    """Give the files back to the user who ran sudo."""
    uid = os.environ.get("SUDO_UID")
    if not uid:
        return
    gid = int(os.environ.get("SUDO_GID", uid))
    for base in paths:
        for root, dirs, files in os.walk(base):
            for name in list(dirs) + list(files):
                try:
                    os.chown(os.path.join(root, name), int(uid), gid)
                except OSError:
                    pass
        try:
            os.chown(base, int(uid), gid)
        except OSError:
            pass


def _latency_verdict(rows):
    """Latency holds even where throughput does not."""
    lat = [r for r in rows
           if r.get("lat_spread_pct") is not None and r.get("phase") == "scarico"]
    if not lat:
        lat = [r for r in rows if r.get("lat_spread_pct") is not None]
    if not lat:
        return
    worst = max(lat, key=lambda r: r["lat_spread_pct"])
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Latency: how reproducible it is{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    if worst["lat_spread_pct"] <= 5.0:
        print(f"  {GREEN}[PASS]{NC} the minimum latency varies at most by "
              f"{worst['lat_spread_pct']:.1f}% between rounds "
              f"({worst['method']}, frame {worst['frame']}, delay "
              f"{worst['delay']}).")
        print(f"  {GREY}This is the measurement to cite: reproducible even where "
              f"throughput is not.{NC}")
    else:
        print(f"  {RED}[FAIL]{NC} the minimum latency varies up to "
              f"{worst['lat_spread_pct']:.1f}% between rounds "
              f"({worst['method']}): raise --rounds.")


def summarise_fair(raw, methods):
    """Median over rounds, per method and configuration."""
    import statistics as stats
    if not raw:
        return []
    raw = [r for r in raw if r.get("phase") != "ricerca"]
    ordine_fase = {"pieno": 0, "zero-perdite": 1, "scarico": 2}
    ordine_met = {m: i for i, m in enumerate(METHODS)}
    keys = sorted({(r["method"], r["frame"], r["phase"]) for r in raw},
                  key=lambda k: (ordine_met.get(k[0], 99), k[1],
                                 ordine_fase.get(k[2], 99)))
    out = []
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Summary: median over rounds{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    hdr = (f"  {'pipeline':10s} {'frame':>5s} {'phase':12s} {'rnds':>4s} "
           f"{'RX pps':>9s} {'Mb/s':>7s} {'rej':>7s} {'loss':>8s} "
           f"{'min':>6s} {'p50<':>7s} {'p99<':>8s} {'bottleneck':>18s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for m, frame, phase in keys:
        pts = [r for r in raw if (r["method"], r["frame"], r["phase"])
               == (m, frame, phase)]
        delay = int(stats.median([r["delay"] for r in pts]))
        med = {k: stats.median([r[k] for r in pts if r[k] is not None] or [0])
               for k in ("rx_pps", "rx_mbps", "loss_pct", "respinti_pct",
                         "lat_min_ns", "lat_p50_ns", "lat_p99_ns")}
        pps = [r["rx_pps"] for r in pts if r["rx_pps"]]
        spread = (100.0 * (max(pps) - min(pps)) / min(pps)) if pps else 0.0
        stat = _agg(pps)
        lats = [r["lat_min_ns"] for r in pts if r["lat_min_ns"]]
        lat_spread = (100.0 * (max(lats) - min(lats)) / min(lats)) if lats else 0.0
        bad = spread > MAX_SPREAD_PCT
        tags = [r.get("bottleneck") for r in pts if r.get("bottleneck")]
        tag = max(set(tags), key=tags.count) if tags else BN_UNKNOWN
        row = dict(method=m, frame=frame, phase=phase, delay=delay,
                   rounds=len(pts),
                   pps_spread_pct=round(spread, 1),
                   rx_pps_mean=stat["mean"], rx_pps_min=stat["min"],
                   rx_pps_max=stat["max"], rx_pps_std=stat["std"],
                   rx_pps_cv_pct=stat["cv_pct"],
                   secs=round(stats.median([r.get("secs", 0) for r in pts]), 3),
                   bottleneck=tag,
                   lat_spread_pct=round(lat_spread, 1), unreliable=bad, **med)
        out.append(row)
        flag = f" {RED}pps +-{spread:.0f}%{NC}" if bad else ""
        col = GREEN if phase == "zero-perdite" else ""
        end = NC if col else ""
        print(f"  {col}{m:10s} {frame:5d} {phase:12s}{end} {len(pts):4d} "
              f"{int(med['rx_pps']):9d} {med['rx_mbps']:7.1f} "
              f"{med['respinti_pct']:6.2f}% "
              f"{med['loss_pct']:7.2f}% "
              f"{int(med['lat_min_ns']):5d}n "
              f"<{int(med['lat_p50_ns']):5d}n "
              f"<{int(med['lat_p99_ns']):6d}n {tag:>18s}{flag}")
    return out


# --- threaded NAPI: really separating the generator from the DUT ---


def _napi_threads(dev):
    """The PIDs of the NAPI kernel threads of `dev`, in napi id order."""
    try:
        out = subprocess.run(["ps", "-eo", "pid,comm"], capture_output=True,
                             text=True, check=False).stdout
    except OSError:
        warn("`ps` not available: cannot find the NAPI threads, so "
             "cannot pin them. They stay where the scheduler puts them.")
        return []
    found = []
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        comm = parts[1].strip()
        if not comm.startswith(f"napi/{dev}-"):
            continue
        try:
            nid = int(comm.rsplit("-", 1)[1])
        except (IndexError, ValueError):
            nid = 0
        found.append((nid, parts[0].strip()))
    return [pid for _, pid in sorted(found)]


def enable_threaded_napi(devs, plan_or_first_cpu=None, ncpu=None):
    """Put the NAPI of `devs` in threaded mode and pin the threads on the DUT CPUs."""
    if isinstance(plan_or_first_cpu, CpuPlan):
        dut = list(plan_or_first_cpu.dut)
    else:
        first = plan_or_first_cpu if isinstance(plan_or_first_cpu, int) else 0
        total = ncpu or (os.cpu_count() or 1)
        dut = [c for c in range(first, total)] or [first]
    if not dut:
        dut = [0]

    placed = []
    next_cpu = 0
    for dev in devs:
        path = f"/sys/class/net/{dev}/threaded"
        if not os.path.exists(path):
            warn(f"{dev}: /sys/.../threaded missing, staying in softirq "
                 f"(kernel < 5.12?)")
            continue
        try:
            with open(path, "w") as f:
                f.write("1\n")
        except OSError as e:
            warn(f"{dev}: threaded refused ({e.strerror}), staying in softirq")
            continue
        pids = _napi_threads(dev)
        used = []
        for pid in pids:
            cpu = dut[next_cpu % len(dut)]
            next_cpu += 1
            try:
                r = subprocess.run(
                    ["taskset", "-pc", str(cpu), pid],
                    capture_output=True, text=True, check=False
                )
            except OSError:
                warn("`taskset` not available (util-linux): the NAPI threads "
                     "are threaded but not pinned, so the "
                     "separation between CPUs is up to the scheduler.")
                break
            if r.returncode == 0:
                used.append(cpu)
            else:
                warn(f"{dev}: taskset on cpu{cpu} failed for pid {pid} "
                     f"({(r.stderr or '').strip() or 'reason not reported'})")
        if pids:
            placed.append((dev, len(pids), sorted(set(used))))
        else:
            warn(f"{dev}: threaded mode on but no napi/{dev}-* thread "
                 f"found: the poll may still be in softirq")
    return placed


def pin_egress_napi(devs, egress, plan):
    """The NAPI of the egress veths threaded, one core per queue used."""
    cpus = HC.egress_cpus(egress)
    placed = enable_threaded_napi(
        devs, CpuPlan([], cpus[:1], online_cpus(), []))
    n_q = egress_queues(plan)
    queue_cpu = {q: cpus[0] for q in range(n_q)}
    for i, d in enumerate(plan.dut):
        queue_cpu[d % n_q] = cpus[i % len(cpus)]
    threads = {}
    for dev, _, _ in placed:
        for q, pid in enumerate(_napi_threads(dev)):
            cpu = queue_cpu.get(q, cpus[0])
            if cpu != cpus[0]:
                r = subprocess.run(["taskset", "-pc", str(cpu), pid],
                                   capture_output=True, text=True,
                                   check=False)
                if r.returncode != 0:
                    warn(f"{dev}: taskset on cpu{cpu} failed for pid "
                         f"{pid}: queue {q} stays on cpu{cpus[0]}")
                    cpu = cpus[0]
            threads[pid] = (dev, q, cpu, _thread_ticks(pid))
    return placed, threads, queue_cpu


def _thread_ticks(pid):
    """(utime + stime in ticks, last CPU) of a thread, or (None, None)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            st = f.read().rsplit(")", 1)[1].split()
        return int(st[11]) + int(st[12]), int(st[36])
    except (OSError, IndexError, ValueError):
        return None, None


def egress_napi_report(threads):
    """Which egress threads worked, on which CPU."""
    hz = os.sysconf("SC_CLK_TCK")
    rows = []
    for pid, (dev, q, cpu, (t0, _)) in sorted(threads.items(),
                                              key=lambda kv: kv[1][:2]):
        t1, last = _thread_ticks(pid)
        if t0 is None or t1 is None or t1 - t0 < hz // 10:
            continue
        rows.append(f"{dev} queue {q}: {(t1 - t0) / hz:.1f} s of CPU, "
                    f"pinned on cpu{cpu}, last cpu{last}")
    print("  -- egress NAPI threads that worked (>= 0.1 s) --")
    for r in rows or ["none above 0.1 s"]:
        print(f"    {r}")


def disable_threaded_napi(devs):
    for dev in devs:
        path = f"/sys/class/net/{dev}/threaded"
        if os.path.exists(path):
            try:
                with open(path, "w") as f:
                    f.write("0\n")
            except OSError:
                pass


# --- dedicated ingress links: one or more, sized on the CPUs ---
TG_PREFIX = "ipatg"


def _ip(*args, check=True):
    return subprocess.run(["ip", *args], capture_output=True, text=True,
                          check=check)


def _make_pair(rx, tx, rx_queues, tx_queues):
    """One sized veth pair."""
    _ip("link", "del", rx, check=False)
    rxq = max(rx_queues, tx_queues)
    _ip("link", "add", rx, "numrxqueues", str(rxq), "numtxqueues", str(rxq),
        "type", "veth", "peer", tx,
        "numrxqueues", str(tx_queues), "numtxqueues", str(tx_queues))
    for dev in (rx, tx):
        _ip("link", "set", dev, "up")
        subprocess.run(["sysctl", "-qw",
                        f"net.ipv6.conf.{dev}.disable_ipv6=1"],
                       capture_output=True, check=False)
    raise_veth_ring(rx)
    idx = int(_ip("-o", "link", "show", rx).stdout.split(":")[0])
    return rx, tx, idx


VETH_RING_STATE = {}
_RING_DETTO = set()


def _ethtool_ring(dev):
    """(current RX, maximum RX) from the right section of `ethtool -g`."""
    r = subprocess.run(["ethtool", "-g", dev], capture_output=True, text=True,
                       check=False)
    if r.returncode != 0:
        return None, None
    massimo = attuale = None
    sezione = None
    for line in r.stdout.splitlines():
        s = line.strip()
        if s.startswith("Pre-set maximums"):
            sezione = "max"
        elif s.startswith("Current hardware settings"):
            sezione = "cur"
        elif s.startswith("RX:") and sezione:
            val = s.split(":", 1)[1].strip()
            if val.isdigit():
                if sezione == "max":
                    massimo = int(val)
                else:
                    attuale = int(val)
    return attuale, massimo


def raise_veth_ring(dev, target=VETH_RING_TARGET):
    """Raises the veth RX queue, BEFORE XDP is attached."""
    attuale, massimo = _ethtool_ring(dev)
    stato = dict(dev=dev, supportato=attuale is not None,
                 prima=attuale, massimo=massimo, chiesto=target, dopo=attuale)
    if attuale is None:
        VETH_RING_STATE[dev] = stato
        if dev not in _RING_DETTO:
            _RING_DETTO.add(dev)
            warn(f"RX queue of {dev}: fixed at 256 descriptors (veth), not "
                 f"configurable")
        return stato
    voluto = min(target, massimo) if massimo else target
    if attuale >= voluto:
        VETH_RING_STATE[dev] = stato
        return stato
    subprocess.run(["ethtool", "-G", dev, "rx", str(voluto)],
                   capture_output=True, text=True, check=False)
    stato["dopo"] = _ethtool_ring(dev)[0]
    VETH_RING_STATE[dev] = stato
    if stato["dopo"] and stato["dopo"] != attuale:
        info(f"RX queue of {dev}: {attuale} -> {stato['dopo']} descriptors "
             f"(maximum {massimo})")
    else:
        warn(f"RX queue of {dev} stays at {attuale} descriptors: "
             f"`ethtool -G rx {voluto}` had no effect. At 1 Mpps "
             f"{attuale} descriptors are {attuale} us of traffic, and the rejects at low "
             f"rate are structural.")
    return stato


def make_tg_links(n, gen_queues=1, dut_queues=1):
    """`n` veth pairs, each the ingress of one more generator thread."""
    made = []
    for i in range(n):
        rx, tx = f"{TG_PREFIX}{i}", f"{TG_PREFIX}{i}p"
        made.append(_make_pair(rx, tx, dut_queues, gen_queues))
    return made


DUT_QUEUES = None


EGRESS_QUEUES = None


def egress_queues(plan):
    """Queues for every egress veth."""
    if EGRESS_QUEUES is not None:
        return EGRESS_QUEUES
    dut = list(getattr(plan, "dut", None) or [0])
    n = len(dut)
    while len({c % n for c in dut}) < len(dut):
        n += 1
    return n


def _warn_unbalanced_gen(instances):
    """Warns if the ingress queues receive from a different number of pktgen
    threads."""
    per_q = {}
    for i in instances:
        if i["queue_map"] is not None:
            per_q.setdefault(i["queue_map"], []).append(i["cpu"])
    if len({len(cs) for cs in per_q.values()}) > 1:
        warn("generator threads badly distributed over the ingress "
             "queues: "
             + "; ".join(f"queue {q} <- cpu{','.join(map(str, cs))}"
                         for q, cs in sorted(per_q.items()))
             + ". The queue with fewer threads receives less traffic and its core "
               "may not saturate (rxonly and baseline): use a multiple of the "
               "number of queues (--gen-cpus).")


def _warn_shared_queues(plan):
    """Warns if two XDP generator threads write into the same queue."""
    n_e = egress_queues(plan)
    if len({c % n_e for c in plan.dut}) < len(plan.dut):
        warn(f"{len(plan.dut)} node cores forward into the SAME egress "
             f"queues ({n_e} per veth, --egress-queues): two writers per "
             f"queue there too. With "
             f"the light pipelines the egress clogs and the redirect fails, "
             f"i.e. the node pays the drop: on 2 cores the baseline loses "
             f"about half its packets after XDP with the egress busy at "
             f"~77%. P2 and P3 are not affected.")
    n_q = ingress_queues(plan)[1] if len(plan.gen) > 1 else 1
    per_q = {}
    for c in plan.gen:
        per_q.setdefault(c % n_q, []).append(c)
    shared = {q: cs for q, cs in per_q.items() if len(cs) > 1}
    if shared:
        warn("several generator threads on the same node queue: "
             + "; ".join(f"queue {q} <- cpu{','.join(map(str, cs))}"
                         for q, cs in sorted(shared.items()))
             + ". Contention on the queue lowers what the light pipelines "
               "(baseline, P1, P1.5) process by up to 70%: to measure them use "
               "one thread per queue (--gen-cpus with as many CPUs as --dut-cpus, "
               "or a different number from the number of queues).")


def ingress_queues(plan, dut_queues=None):
    """(generator TX queues, DUT RX queues) for the shared topology."""
    n_gen, n_dut = max(1, len(plan.gen)), max(1, len(plan.dut))
    q = DUT_QUEUES if dut_queues is None else dut_queues
    if q is None:
        return n_gen, max(n_dut, n_gen)
    q = max(1, int(q))
    return min(n_gen, q), q


def make_shared_tg_link(gen_threads, dut_queues, index=0):
    """ONE veth pair for the "shared" topology."""
    rx, tx = f"{TG_PREFIX}{index}", f"{TG_PREFIX}{index}p"
    return _make_pair(rx, tx, max(1, dut_queues), max(1, gen_threads))


def del_tg_links(n):
    for i in range(max(1, n)):
        _ip("link", "del", f"{TG_PREFIX}{i}", check=False)


# --- setup ---
def _node_slot():
    """(node index, logical ingress port) the bench declares."""
    import test_forwarding as TF
    import check_pipelines as V
    m = V._mut()
    if m is None:
        return TF.FABRIC_NODE_INDEX, TF.FABRIC_INGRESS_SLOT
    import pipeline_setup as PS
    return (PS.node_index_for(m, TF.FABRIC_NODE_INDEX),
            PS.ingress_slot_for(m, TF.FABRIC_INGRESS_SLOT))


def _forwarding_inputs(setup, m, node, slot, ttl=TRAFFIC_TTL):
    """The link (and queue) state with which the generators' packet --
    fixed TTL, this node, this port -- is FORWARDED by the model
    under test, written in the maps."""
    import itertools
    import random
    import pipeline_setup as PS
    size = {f["type"]: f["size"] for f in m.features}
    n_ls, n_q = size.get("link_state", 0), size.get("queue_occupancy", 0)
    cands = [([1] * n_ls, [0] * n_q)]
    cands += [(list(b), [0] * n_q)
              for b in itertools.product([1, 0], repeat=n_ls)]
    if n_q:
        rng = random.Random(20260929)
        cands += [([rng.randint(0, 1) for _ in range(n_ls)],
                   [rng.randint(0, 15) for _ in range(n_q)])
                  for _ in range(5000)]
    for ls, q in cands:
        c, _ = PS.reference(m, ttl, link_state=ls or None,
                            ingress_port=slot or 0, node_index=node,
                            queues=q or None)
        if m.semantics.action_of(c) == "FORWARD":
            PS.seed_inputs(setup, link_state=ls or None, queues=q or None)
            setup["traffic_class"] = c
            return ls, q, c
    raise PS.NotApplicable(f"with TTL {ttl} no link or queue state "
                           f"brings {m.name} to a forward")


def setup_p1_static(model_id, model_path, node=STATIC_NODE):
    """setup_hardcoded, but with the node index frozen in the source."""
    import check_pipelines as V
    return V.setup_p1_static(model_id, model_path, node=node)


def class_semantics():
    """The declared class semantics, resolved the same way test_forwarding
    does."""
    import check_pipelines as V
    m = V._mut()
    if m is not None:
        return m.semantics, m.n_out
    import model_meta as mm
    meta_path = os.path.join(SHARED_DIR, "weights.json")
    n_out = mm.derive_shape(
        mm.load_model_meta(meta_path),
        topology_config=mm.load_topology_config())["n_out"]
    return mm.load_class_semantics(meta_path, n_out), n_out


def build_pipeline(method, model_path, fab, sem):
    """Load the pipeline, point it at THIS fabric, and make it answer to the
    model_id pktgen actually puts on the wire."""
    import check_pipelines as V
    import test_forwarding as TF

    if method == RX_ONLY:
        return setup_rxonly()
    if method == RX_FWD:
        setup = setup_rxonly_fwd()
    elif method == "baseline":
        setup = V.setup_baseline(0, model_path)
    elif method == "p1_static":
        setup = setup_p1_static(0, model_path)
    else:
        setup = getattr(V, TF._SETUP[method])(0, model_path)
    b, pl = setup["b"], setup["pipeline"]

    mac_name = "mac_table" if pl in (0, 1) else TF._MAC_NAME[pl]
    TF._install_fabric_mac_table(b, mac_name, fab, sem.logical_ports)

    if method in ("baseline", RX_FWD):
        return setup

    node, slot = _node_slot()
    if slot:
        b[TF._INGRESS_NAME[pl]][ct.c_uint32(fab.ingress_ifindex)] = \
            ct.c_uint32(slot)
    if method != "p1_static" and node is not None:
        b[TF._NODEID_NAME[pl]][ct.c_uint32(0)] = ct.c_uint32(node)

    _register_alias(method, setup, PKTGEN_MAGIC_MODEL_ID)

    m = V._mut()
    if m is not None:
        ls, q, c = _forwarding_inputs(setup, m, node, slot)
        info(f"{method}: traffic of {m.name} with link_state="
             f"{''.join(map(str, ls)) or '-'}"
             + (f" queues={q}" if q else "")
             + f", TTL {TRAFFIC_TTL}, node {node}, port {slot} -> class "
             f"{c} (FORWARD, logical port {m.semantics.port_of(c)})")
    return setup


def _register_alias(method, setup, model_id):
    import check_pipelines as V
    if V._mut() is not None:
        import pipeline_setup as PS
        PS.register_model_id(setup, model_id, V._mut())
        return
    b, w, scale = setup["b"], setup["weights"], setup["scale"]
    if method in ("hardcoded", "p1_static"):
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(setup["fn"].fd)
    elif method == "template":
        from ebpf_template_arch import load_arch_weights
        load_arch_weights(b, w, model_id=model_id, scale=scale)
    else:
        from ebpf_modular import load_modular_weights
        load_modular_weights(b, w, model_id=model_id, scale=scale,
                             layer_dims=[(65, 4), (4, 4), (4, 7)])


def attach_rx_counter(fab):
    """Replace the fabric's XDP_PASS stubs with a counting XDP_DROP."""
    from bcc import BPF
    from common import attach_xdp
    b = BPF(text=RX_COUNTER_SRC)
    fn = b.load_func("xdp_rx_count", BPF.XDP)
    attached = []
    for port, peer in fab.peer_of.items():
        try:
            raise_veth_ring(peer)
            attach_xdp(b, fn, peer)
            attached.append(peer)
        except Exception as e:
            warn(f"counter not attached to {peer}: {e}")
    return b, b["rx_count"], attached


class Ingress:
    """Where the traffic enters."""

    def __init__(self, dut_devs, gen_devs, ifindexes, created=0,
                 topology="shared"):
        self.dut_devs = list(dut_devs)
        self.gen_devs = list(gen_devs)
        self.ifindexes = list(ifindexes)
        self.created = created
        self.topology = topology

    def cleanup(self):
        if self.created:
            del_tg_links(self.created)


def build_ingress(fab, plan, topology="shared", rx_side=False):
    """Builds the ingress part of the bench following the CPU plan."""
    n_gen, n_dut = len(plan.gen), len(plan.dut)
    if n_gen <= 1 and topology == "shared":
        dut, gen_dev = fab.ingress, fab.ingress_peer
        return Ingress([dut], [dut if rx_side else gen_dev], [], 0, "shared")
    if topology == "links":
        made = make_tg_links(n_gen - 1, gen_queues=1, dut_queues=1)
        dut_devs = [fab.ingress] + [m[0] for m in made]
        gen_devs = ([fab.ingress] + [m[0] for m in made]) if rx_side else \
                   ([fab.ingress_peer] + [m[1] for m in made])
        return Ingress(dut_devs, gen_devs, [m[2] for m in made],
                       max(0, n_gen - 1), "links")
    tx_q, rx_q = ingress_queues(plan)
    rx, tx, idx = make_shared_tg_link(tx_q, rx_q)
    info(f"shared ingress {rx}: {n_gen} generator threads on {tx_q} "
         f"TX queues, {rx_q} RX queues on the DUT, i.e. {rx_q} NAPI threads on "
         f"{n_dut} CPUs (veth requires rx(DUT) >= tx(peer))")
    return Ingress([rx], [rx if rx_side else tx], [idx], 1, "shared")


# --- one method at a time: probe, measure, summarise ---
def run_method(method, model_path, frames, delays, count, out_rows,
               clone=0, threads=1, threshold=DEFAULT_LOSS_THRESHOLD,
               repeat=DEFAULT_REPEAT, burst=0, xmit_mode="start_xmit",
               threaded_napi=True, plan=None, topology="shared",
               diag_enabled=False, offered_pps=None, window_s=WINDOW_S,
               warmup_s=DEFAULT_WARMUP_S, tune=False, search="ladder"):
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    plan = plan or plan_cpus(threads=threads)
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} {method} -- end-to-end throughput, TG and DUT on the same "
          f"machine but on different cores{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")

    sem, n_out = class_semantics()
    rc = 0
    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False,
                     port_queues=egress_queues(plan)) as fab:
        rx_side = (xmit_mode == "netif_receive")
        rx_b, rx_tab, attached = attach_rx_counter(fab)
        info(f"RX counter on {len(attached)} egress peers (XDP_DROP)")

        setup = build_pipeline(method, model_path, fab, sem)
        ing = build_ingress(fab, plan, topology, rx_side)
        xdp_mode = "generic" if rx_side else None
        for dev in ing.dut_devs:
            attach_xdp(setup["b"], setup["disp"], dev, mode=xdp_mode)
        _map_extra_ingress(setup, ing.ifindexes)
        info(f"pipeline attached to {', '.join(ing.dut_devs)}")

        gen_devs = ing.gen_devs if ing.topology == "links" else ing.gen_devs[:1]
        gen = Generator(gen_devs, plan, xmit_mode=xmit_mode,
                        topology=ing.topology, clone=clone, burst=burst,
                        window_s=window_s, warmup_s=warmup_s).attach()

        napi_devs = []
        if threaded_napi and not rx_side:
            napi_devs = list(ing.dut_devs)
            placed = enable_threaded_napi(napi_devs, plan)
            if placed:
                where = ", ".join(
                    f"{d}({n} thread)->cpu{','.join(str(c) for c in cs)}"
                    for d, n, cs in placed)
                info(f"NAPI in thread, pinnata: {where}")
                info(f"pktgen su cpu {','.join(str(c) for c in plan.gen)}, "
                     f"inferenza su cpu {','.join(str(c) for c in plan.dut)}")
            else:
                napi_devs = []
                warn("no NAPI thread pinned: generator and pipeline "
                     "stay on the same core, and the figures measure the sum")
        elif rx_side:
            warn("xmit_mode netif_receive: XDP runs in GENERIC mode and on the "
                 "generator CPU -- no separation, and numbers not "
                 "comparable with the other runs")

        diag = Diag(devs=ing.dut_devs + attached[:1], plan=plan,
                    enabled=diag_enabled)

        probe = measure_point(setup, rx_tab, fab, 64, 0, 1, n_out, clone,
                              repeat=1, burst=burst, xmit_mode=xmit_mode,
                              gen=gen, warmup=False, threshold=threshold,
                              plan=plan, steady=False)
        if probe is None:
            warn("the probe transmitted nothing: re-attaching the generator "
                 "and retrying (the fabric was rebuilt and pktgen may "
                 "keep an old ifindex).")
            gen.detach()
            time.sleep(0.2)
            gen.attach(verbose=False)
            probe = measure_point(setup, rx_tab, fab, 64, 0, 1, n_out, clone,
                                  repeat=1, burst=burst, xmit_mode=xmit_mode,
                                  gen=gen, warmup=False, threshold=threshold,
                                  plan=plan, steady=False)
        if probe is None:
            warn("the probe transmitted nothing even after re-attaching: "
                 "pktgen did not start.")
            gen.detach()
            ing.cleanup()
            return 1
        if probe["hit"] == 0 and method == "baseline":
            warn("the baseline produced no HIT: it does not read model_id, so "
                 "the problem is upstream (the packet does not arrive or mac_table "
                 "is empty). Stopping.")
            gen.detach()
            ing.cleanup()
            return 1
        if probe["hit"] == 0:
            warn(f"the probe produced no HIT "
                 f"(tx={probe['tx']} miss={probe['miss']}).")
            warn("The dispatcher drops the packets: probably the "
                 "model_id byte on the wire is neither 0 nor 190.")
            warn("Measuring now would give the cost of NOT doing inference. "
                 "Stopping.")
            gen.detach()
            ing.cleanup()
            return 1
        ok(f"probe: {probe['hit']} HIT out of {probe['tx']} sent -- real "
           f"inference is being measured")

        try:
            if tune:
                gen.tune(frames[0] if frames else 64)
            else:
                gen.calibrate(frames[0] if frames else 64)
        except (PktgenEmptyRun, RuntimeError) as e:
            gen.rate_estimate = gen.rate_estimate or 1_000_000
            warn(f"calibration failed ({e}): starting from "
                 f"{gen.rate_estimate} pps as a placeholder, the first point "
                 f"corrects it.")
        info(f"generator ceiling on this bench: {gen.rate_estimate} pps "
             f"offered by {gen.n_inst} threads on cpu "
             f"{','.join(str(c) for c in plan.gen)}")

        hdr = (f"  {'frame':>5s} {'offered':>9s} {'TX':>9s} {'HIT':>9s} "
               f"{'RX':>9s} {'RX pps':>9s} {'Mb/s':>8s} {'s':>5s} "
               f"{'loss.worst':>10s} {'loss.med':>9s} {'bottleneck':>18s}")
        print(f"\n{hdr}")
        print("  " + "-" * (len(hdr) - 2))
        print(f"  {GREY}offered = transmitted + refused by the device (ingress "
              f"queue full); the loss is computed on that. "
              f"`loss.worst` is the worst of the repetitions (strict "
              f"RFC 2544 reading), `loss.med` the median: the first is reported, "
              f"the decision uses the second, and the second is coloured.{NC}")

        def printer(r):
            deciso = _loss_decide(r)
            mark = GREEN if deciso <= threshold else (
                RED if deciso > 1 else YELLOW)
            spread = ""
            if r.get("repeat", 0) <= 1:
                spread = f" {YELLOW}(1 window only, no spread){NC}"
            elif r.get("spread_pct") is not None:
                col = RED if r.get("unreliable") else GREY
                flag = " INAFFIDABILE" if r.get("unreliable") else ""
                disp = r.get("spread_deciso_pct", r["spread_pct"])
                due = (f"+-{disp:.0f}%" if abs(disp - r["spread_pct"]) < 1
                       else f"+-{disp:.0f}% (min-max {r['spread_pct']:.0f}%)")
                fuori = r.get("ripetizioni_anomale", 0)
                anom = f", {fuori} outlier(s)" if fuori else ""
                spread = f" {col}(x{r['repeat']}, {due}{anom}{flag}){NC}"
            off = r.get("offered_pps") or r.get("offered_real_pps") or 0
            med = r.get("loss_med")
            print(f"  {r['frame']:5d} {off:9d} {r['tx']:9d} "
                  f"{r['hit']:9d} {r['rx']:9d} "
                  f"{r['rx_pps']:9d} {r['rx_mbps']:8.1f} {r['secs']:5.2f} "
                  f"{GREY}{r['loss_worst']:8.2f}%{NC} "
                  f"{mark}{(f'{med:8.2f}%' if med is not None else ' ' * 9)}"
                  f"{NC} {r.get('bottleneck', ''):>18s}{spread}")

        for frame in frames:
            if delays:
                for delay in delays:
                    r = measure_point(setup, rx_tab, fab, frame, delay,
                                      count,
                                      n_out, clone, repeat=repeat, burst=burst,
                                      xmit_mode=xmit_mode, gen=gen,
                                      threshold=threshold, plan=plan,
                                      diag=diag)
                    if r is None:
                        continue
                    r["clone_skb"], r["method"] = gen.clone, method
                    r["threads"] = gen.n_inst
                    out_rows.append(r)
                    printer(r)
            elif offered_pps:
                r = _point_at_rate(setup, rx_tab, fab, frame, offered_pps,
                                   n_out, gen, repeat, threshold, plan, diag,
                                   xmit_mode)
                if r is not None:
                    r["method"], r["phase"] = method, "confronto"
                    out_rows.append(r)
                    printer(r)
            elif search == "bisect":
                find_knee(setup, rx_tab, fab, frame, count, n_out, clone,
                          out_rows, method, printer, tg_devs=gen.names,
                          threads=gen.n_inst, threshold=threshold,
                          repeat=repeat, burst=burst, xmit_mode=xmit_mode,
                          gen=gen)
            else:
                find_saturation(setup, rx_tab, fab, frame, n_out, gen,
                                out_rows, method, printer, threshold, repeat,
                                plan, diag, xmit_mode)
            _summarise(method, frame, out_rows, threshold)

        if diag_enabled:
            diag.start()
            gen.timed_run(frames[0] if frames else 64, 0)
            diag.report(diag.stop())
            report_generator(gen)

        gen.detach()
        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        for dev in ing.dut_devs:
            _detach(dev)
        ing.cleanup()
        for peer in attached:
            _detach(peer)
        del rx_b
    return rc


def _point_at_rate(setup, rx_tab, fab, frame, rate_pps, n_out, gen, repeat,
                   threshold, plan, diag, xmit_mode="start_xmit"):
    """One point at fixed OFFERED rate, with the target-length window."""
    delay = gen.delay_for(rate_pps)
    count = gen.window_count(rate_pps)
    r = measure_point(setup, rx_tab, fab, frame, delay, count, n_out,
                      gen.clone, repeat=repeat, burst=gen.burst,
                      xmit_mode=xmit_mode, gen=gen, threshold=threshold,
                      plan=plan, diag=diag)
    if r is not None:
        r["offered_pps"] = rate_pps
        r["threads"] = gen.n_inst
        r["clone_skb"] = gen.clone
    return r


# --- saturation: climb in steps, do not bisect ---
def _loss_decide(row):
    """The loss on which it is DECIDED whether a rate is clean."""
    if row.get("repeat", 1) >= 3 and row.get("loss_med") is not None:
        return row["loss_med"]
    return row.get("loss_worst", row.get("loss_pct", 0.0))


def find_saturation(setup, rx_tab, fab, frame, n_out, gen, out_rows, method,
                    printer, threshold=DEFAULT_LOSS_THRESHOLD,
                    repeat=DEFAULT_REPEAT, plan=None, diag=None,
                    xmit_mode="start_xmit", ladder=SATURATE_LADDER):
    """The highest rate this pipeline holds, and whose limit it is."""
    est_count = gen.window_count(gen.rate_estimate or 3_000_000)
    full = measure_point(setup, rx_tab, fab, frame, 0, est_count, n_out,
                         gen.clone, repeat=repeat, burst=gen.burst,
                         xmit_mode=xmit_mode, gen=gen, threshold=threshold,
                         plan=plan, diag=diag)
    if full is not None and 0 < full["secs"] < gen.window_s * WINDOW_SHORT_FRACTION:
        vero = full.get("tx_pps") or 0
        if vero > 0:
            note(f"frame {frame}: window lasted {full['secs']:.2f}s instead "
                 f"of {gen.window_s:.2f}s (rate estimate too low: "
                 f"{gen.rate_estimate} against {vero} measured). Redoing the "
                 f"point with the right count.")
            gen.rate_estimate = max(gen.rate_estimate, vero)
            rifatto = measure_point(
                setup, rx_tab, fab, frame, 0, gen.window_count(vero), n_out,
                gen.clone, repeat=repeat, burst=gen.burst,
                xmit_mode=xmit_mode, gen=gen, threshold=threshold, plan=plan,
                diag=diag)
            if rifatto is not None:
                full = rifatto
    if full is None:
        warn(f"frame {frame}: no usable measurement at full rate")
        return None, None
    full.update(method=method, phase="pieno", delay=0, clone_skb=gen.clone,
                threads=gen.n_inst, offered_pps=None)
    gen.rate_estimate = max(gen.rate_estimate, full["tx_pps"])
    out_rows.append(full)
    printer(full)

    if _loss_decide(full) <= threshold:
        clean = dict(full)
        clean.update(phase="zero-perdite", gen_bound=1)
        out_rows.append(clean)
        print(f"  {GREY}at full load nothing is lost: the pipeline is not "
              f"saturated and this is NOT its maximum. The ceiling is the "
              f"generator ({full.get('offered_real_pps') or full['tx_pps']}"
              f" pps offered by "
              f"{gen.n_inst} threads). To raise it: more CPUs to the generator "
              f"(--gen-cpus), or fewer to the DUT (--dut-cpus).{NC}")
        return full, clean

    base = float(full["rx_pps"])
    steps = []
    for frac in ladder:
        rate = base * frac
        if rate < 1000:
            continue
        r = measure_point(setup, rx_tab, fab, frame, gen.delay_for(rate),
                          gen.window_count(rate), n_out, gen.clone,
                          repeat=repeat, burst=gen.burst, xmit_mode=xmit_mode,
                          gen=gen, threshold=threshold, plan=plan, diag=diag)
        if r is None:
            continue
        r.update(method=method, phase="ricerca", clone_skb=gen.clone,
                 threads=gen.n_inst, offered_pps=int(rate))
        out_rows.append(r)
        printer(r)
        steps.append(r)
        if len(steps) >= 2 and all(_loss_decide(s) > threshold
                                   for s in steps[-2:]):
            break

    if not steps:
        return full, None
    steps.sort(key=lambda r: r["offered_pps"])
    best = None
    giu = []
    for s in steps:
        if _loss_decide(s) > threshold:
            break
        best = s

    if best is None:
        print(f"  {GREY}even the lowest step loses "
              f"({steps[0]['offered_pps']} pps offered, "
              f"{steps[0]['loss_worst']:.2f}%): going down instead of concluding "
              f"on an interval never measured.{NC}")
        for frac in SATURATE_DESCENT:
            rate = base * frac
            if rate < MIN_LADDER_PPS:
                print(f"  {GREY}descent stopped at {int(rate)} pps: below "
                      f"{MIN_LADDER_PPS} pps the window does not contain "
                      f"enough packets for the loss to mean "
                      f"anything.{NC}")
                break
            r = measure_point(setup, rx_tab, fab, frame, gen.delay_for(rate),
                              gen.window_count(rate), n_out, gen.clone,
                              repeat=repeat, burst=gen.burst,
                              xmit_mode=xmit_mode, gen=gen,
                              threshold=threshold, plan=plan, diag=diag)
            if r is None:
                continue
            r.update(method=method, phase="ricerca", clone_skb=gen.clone,
                     threads=gen.n_inst, offered_pps=int(rate))
            out_rows.append(r)
            printer(r)
            giu.append(r)
            if len(giu) >= 2 and _loss_decide(giu[-1]) <= threshold \
                    and _loss_decide(giu[-2]) <= threshold:
                best = giu[-2]
                break
        if best is None and giu:
            puliti = [r for r in giu if _loss_decide(r) <= threshold]
            if puliti:
                print(f"  {YELLOW}isolated clean point at "
                      f"{puliti[-1]['offered_pps']} pps, not confirmed by the "
                      f"step below: not reported as the limit.{NC}")

    if best is None:
        giu_txt = ""
        piu_basso = min((r["offered_pps"] for r in giu), default=None)
        if piu_basso:
            giu_txt = (f" The descent went down to {piu_basso} pps "
                       f"offered, i.e. {100.0 * piu_basso / base:.0f}% of the "
                       f"rate delivered at full load, and loses there too.")
        print(f"  {RED}no zero-loss rate can be determined{NC}{GREY}: loss "
              f"already at the lowest step ({steps[0]['offered_pps']} "
              f"pps offered, {steps[0]['loss_worst']:.2f}%), i.e. well below "
              f"the capacity measured at full rate.{giu_txt} The loss here "
              f"does not depend on the rate: it is machine noise.{NC}")
        noisy = dict(full)
        noisy.update(phase="rumore", gen_bound=0)
        tag, why = classify_bottleneck(noisy, threshold=threshold, plan=plan,
                                       noisy=True)
        noisy["bottleneck"], noisy["bottleneck_why"] = tag, why
        out_rows.append(noisy)
        return full, None
    clean = dict(best)
    clean.update(phase="zero-perdite", gen_bound=0)
    out_rows.append(clean)
    print(f"  {GREEN}zero-loss limit{NC}{GREY}: {clean['rx_pps']} pps "
          f"delivered with {clean['offered_pps']} offered, loss "
          f"{clean['loss_worst']:.2f}% over {clean['repeat']} windows. The "
          f"next step loses: it is the pipeline saturating, not the "
          f"generator.{NC}")
    return full, clean


def find_knee(setup, rx_tab, fab, frame, count, n_out, clone, out_rows,
              method, printer, max_delay=20000, steps=6, tg_devs=None,
              threads=1, threshold=DEFAULT_LOSS_THRESHOLD,
              repeat=DEFAULT_REPEAT, burst=0, xmit_mode="start_xmit",
              gen=None):
    """Knee search by bisection on the delay (alternative path)."""
    full = measure_point(setup, rx_tab, fab, frame, 0, count, n_out, clone,
                         tg_devs, repeat, burst, xmit_mode, gen=gen,
                         threshold=threshold)
    if full is None:
        warn(f"frame {frame}: no usable measurement at full rate")
        return None, None
    full["method"], full["clone_skb"], full["delay"] = method, clone, 0
    full["threads"] = threads
    out_rows.append(full)
    printer(full)

    if full["loss_worst"] <= threshold and clone == 0 and _CLONE_SUPPORTED:
        hard = measure_point(setup, rx_tab, fab, frame, 0, count, n_out,
                             ESCALATE_CLONE, tg_devs, repeat, burst,
                             xmit_mode, gen=gen, threshold=threshold)
        if hard is None:
            return full, full
        hard["method"], hard["clone_skb"], hard["delay"] = \
            method, ESCALATE_CLONE, 0
        hard["threads"] = threads
        out_rows.append(hard)
        printer(hard)
        if hard["loss_worst"] > threshold:
            print(f"  {GREY}with clone_skb={ESCALATE_CLONE} the pipeline loses: "
                  f"the knee exists, searching for it{NC}")
            return find_knee(setup, rx_tab, fab, frame, count, n_out,
                             ESCALATE_CLONE, out_rows, method, printer,
                             max_delay, steps, tg_devs, threads,
                             threshold, repeat, burst, xmit_mode, gen)
        print(f"  {GREY}not even with clone_skb={ESCALATE_CLONE}: on this "
              f"machine the generator saturates, not the pipeline{NC}")
        return (hard if hard["rx_pps"] > full["rx_pps"] else full), hard

    if full["loss_worst"] <= threshold:
        return full, full

    lo, hi = 0, max_delay
    best_clean = None
    for _ in range(steps):
        mid = (lo + hi) // 2
        if mid in (lo, hi):
            break
        r = measure_point(setup, rx_tab, fab, frame, mid, count, n_out,
                          clone, tg_devs, repeat, burst, xmit_mode, gen=gen,
                          threshold=threshold)
        if r is None:
            break
        r["method"], r["clone_skb"], r["threads"] = method, clone, threads
        out_rows.append(r)
        printer(r)
        if r["loss_worst"] <= threshold:
            best_clean = r if (best_clean is None or
                               r["rx_pps"] > best_clean["rx_pps"]) else best_clean
            hi = mid
        else:
            lo = mid
    if best_clean is not None:
        dirty_below = [r for r in out_rows
                       if r.get("method") == method and r["frame"] == frame
                       and r["loss_worst"] > threshold
                       and r["rx_pps"] < best_clean["rx_pps"]]
        if dirty_below:
            worst = min(dirty_below, key=lambda r: r["rx_pps"])
            print(f"  {RED}the loss does not depend on the rate{NC}{GREY}: "
                  f"{worst['loss_worst']:.2f}% at {worst['rx_pps']} pps, "
                  f"clean at {best_clean['rx_pps']}. Below saturation here "
                  f"packets are lost for machine reasons, not datapath ones: "
                  f"a 'zero-loss' rate cannot be determined.{NC}")
            best_clean = None
    return full, best_clean


def _summarise(method, frame, rows, threshold=DEFAULT_LOSS_THRESHOLD):
    """Three numbers, because two would hide what matters."""
    pts = [r for r in rows if r.get("method") == method
           and r["frame"] == frame and r.get("phase") != "rumore"]
    if not pts:
        return
    peak = max(pts, key=lambda r: r["rx_pps"])
    under = [r for r in pts if _loss_decide(r) <= threshold]
    strict = [r for r in pts if r["loss_worst"] == 0.0]
    best = max(under, key=lambda r: r["rx_pps"]) if under else None
    print(f"  {GREY}frame {frame}: maximum {peak['rx_pps']} pps "
          f"({peak['rx_mbps']} Mb/s, loss {peak['loss_pct']}%)")
    resp = peak.get("respinti", 0)
    dut = peak.get("persi_in_coda", 0) + peak.get("persi_dopo", 0)
    if resp or dut:
        if dut == 0:
            print(f"  {GREY}  the pipeline lost NOTHING: "
                  f"{peak['rx']} received out of {peak['hit']} processed out of "
                  f"{peak['tx']} accepted. The {resp} missing "
                  f"({peak.get('respinti_pct', 0)}%) were REJECTED by "
                  f"veth_xmit with the queue full and never entered the DUT: "
                  f"it is backpressure, i.e. the DUT is saturated, not losing."
                  f"{NC}")
        else:
            print(f"  {GREY}  DUT loss: {dut} packets "
                  f"({peak.get('loss_dut_pct', 0)}%) of which "
                  f"{peak.get('persi_in_coda', 0)} never reached the program "
                  f"and {peak.get('persi_dopo', 0)} processed and not sent out. "
                  f"Another {resp} rejected by veth_xmit before entering."
                  f"{NC}")
    if peak["lost_before"] or peak["lost_after"]:
        if peak["lost_after"] > peak["lost_before"]:
            print(f"  {GREY}  the loss is AFTER the inference: "
                  f"{peak['lost_after']} packets processed and not sent out "
                  f"({peak['lost_before']} had not even arrived). "
                  f"The egress saturates, not the pipeline.{NC}")
        else:
            print(f"  {GREY}  the loss is BEFORE the inference: "
                  f"{peak['lost_before']} packets never reached the program "
                  f"({peak['lost_after']} processed and not sent out). "
                  f"The ingress saturates.{NC}")
    if best and any(_loss_decide(r) > threshold
                    and r["rx_pps"] < best["rx_pps"] for r in pts):
        print(f"  {GREY}  no zero-loss rate can be determined: loss "
              f"also at rates lower than the clean ones, so the loss "
              f"below saturation is machine noise{NC}")
        best = None
    elif best and not any(r["rx_pps"] > best["rx_pps"] for r in pts):
        print(f"  {GREY}  at zero loss: >= {best['rx_pps']} pps "
              f"({best['rx_mbps']} Mb/s). It is a LOWER bound: at full "
              f"load nothing was lost, so the pipeline is not "
              f"saturated and the ceiling is the generator.{NC}")
    elif best and not any(r["rx_pps"] < best["rx_pps"] for r in pts):
        print(f"  {GREY}  {best['rx_pps']} pps is clean but it is the slowest "
              f"point tried: there is no step below to confirm it, "
              f"so it is not reported as the zero-loss limit{NC}")
        best = None
    if best:
        print(f"  {GREY}  below {threshold}% loss: {best['rx_pps']} pps "
              f"({best['rx_mbps']} Mb/s, loss {best['loss_pct']}%)")
        print(f"  {GREY}  bottleneck: {best.get('bottleneck', 'n/a')} "
              f"-- {best.get('bottleneck_why', '')}{NC}")
    if strict and best:
        b0 = max(strict, key=lambda r: r["rx_pps"])
        print(f"  {GREY}  at exactly zero loss: {b0['rx_pps']} pps "
              f"({b0['rx_mbps']} Mb/s){NC}")
    else:
        print(f"  {GREY}  no point at exactly zero loss{NC}")


# --- compare mode: same load, same knobs, same duration ---


def run_compare(methods, model_path, frames, offered_pps=None,
                threads=1, threshold=DEFAULT_LOSS_THRESHOLD,
                repeat=DEFAULT_REPEAT, rounds=DEFAULT_ROUNDS, plan=None,
                topology="shared", xmit_mode="start_xmit",
                threaded_napi=True, diag_enabled=False, window_s=WINDOW_S,
                warmup_s=DEFAULT_WARMUP_S, clone=0, burst=0,
                generator="pktgen", egress_cpu=None, ttl_mix=None,
                scenario=None, xdp_batch=None):
    """Every pipeline, same fabric, same generator, same rate."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp
    import statistics as stats

    plan = plan or plan_cpus(threads=threads)
    sem, n_out = class_semantics()
    raw = []

    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False,
                     port_queues=egress_queues(plan)) as fab:
        rx_side = (xmit_mode == "netif_receive")
        rx_b, rx_tab, attached = attach_rx_counter(fab)
        info(f"RX counter on {len(attached)} egress peers (XDP_DROP)")

        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Phase 1: compiling and loading {len(methods)} pipelines "
              f"(no measurement running){NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        loaded = {}
        import prog_census as PC
        for m in methods:
            try:
                before = PC.snapshot()
                loaded[m] = build_pipeline(m, model_path, fab, sem)
                size = PC.loaded_since(before)
                if size:
                    PROG_SIZE[m] = size
                info(f"{m}: loaded"
                     + (f" ({size['n_progs']} programs, {size['xlated']} "
                        f"instructions)" if size else ""))
            except Exception as e:
                warn(f"{m}: not loaded, skipping it -- {type(e).__name__}: {e}")
        if not loaded:
            warn("no pipeline loaded")
            return [], []

        ing = build_ingress(fab, plan, topology, rx_side)
        xdp_mode = "generic" if rx_side else None
        for setup in loaded.values():
            _map_extra_ingress(setup, ing.ifindexes)
        gen_devs = ing.gen_devs if ing.topology == "links" else ing.gen_devs[:1]
        if generator == "xdp":
            from xdp_gen import XdpGen, BATCH_SIZE
            gen = XdpGen(gen_devs[0], plan, window_s=window_s,
                         ttls=ttl_mix,
                         batch_size=xdp_batch or BATCH_SIZE).attach()
            _warn_shared_queues(plan)
        else:
            gen = Generator(gen_devs, plan, xmit_mode=xmit_mode,
                            topology=ing.topology, clone=clone, burst=burst,
                            window_s=window_s, warmup_s=warmup_s).attach()
        diag = Diag(devs=ing.dut_devs, plan=plan, enabled=diag_enabled)

        def use(method):
            """Put THIS pipeline on the ingress. attach_xdp replaces the
            program without detaching."""
            setup = loaded[method]
            with _quiet():
                for dev in ing.dut_devs:
                    attach_xdp(setup["b"], setup["disp"], dev, mode=xdp_mode)
            return setup

        use(next(iter(loaded)))
        napi_devs = []
        if threaded_napi and not rx_side:
            napi_devs = list(ing.dut_devs)
            placed = enable_threaded_napi(napi_devs, plan)
            if placed:
                where = ", ".join(
                    f"{d}({n} thread)->cpu{','.join(str(c) for c in cs)}"
                    for d, n, cs in placed)
                info(f"NAPI in thread, pinnata: {where}")
            else:
                napi_devs = []
                warn("no NAPI thread pinned: generator and pipeline "
                     "stay on the same core")
        egress_napi, egress_threads = [], {}
        if egress_cpu is not None:
            placed_e, egress_threads, queue_cpu = pin_egress_napi(
                list(attached), egress_cpu, plan)
            egress_napi = [d for d, _, _ in placed_e]
            e_cpus = ",".join(str(c) for c in HC.egress_cpus(egress_cpu))
            if egress_napi:
                n_e = len(queue_cpu)
                info(f"separate egress: NAPI of the {len(egress_napi)} egress "
                     f"veths threaded on cpu{e_cpus} ("
                     + ", ".join(f"DUT {d} -> queue {d % n_e} -> "
                                 f"cpu{queue_cpu[d % n_e]}" for d in plan.dut)
                     + f"). On the "
                     f"DUT CPU only the node's work remains, from reception "
                     f"to forwarding.")
            else:
                warn(f"egress NOT separated: no egress NAPI thread "
                     f"pinned on cpu{e_cpus}; 1/RX also contains the "
                     f"downstream reception")

        if scenario is not None:
            from common import write_vector_map
            s_cls, s_ls, s_ttl, s_act = scenario
            for m, setup in loaded.items():
                if setup.get("rx_is_hit") or m == "baseline":
                    continue
                try:
                    write_vector_map(setup["b"], "link_state", s_ls)
                except Exception as e:
                    warn(f"{m}: link_state not written ({e})")
            gen.set_ttl(s_ttl)
            info(f"scenario: class {s_cls} ({s_act}), link_state={s_ls}, "
                 f"ttl={s_ttl}")

        alive = []
        for m in list(loaded):
            setup = use(m)
            p = measure_point(setup, rx_tab, fab, 64, 0, 1, n_out, gen.clone,
                              repeat=1, burst=gen.burst, xmit_mode=xmit_mode,
                              gen=gen, warmup=False, threshold=threshold,
                              plan=plan, steady=False)
            if p is None or p["hit"] + p.get("drop", 0) == 0:
                warn(f"{m}: the probe produces no HIT -- excluding it from "
                     f"the comparison instead of measuring the cost of not "
                     f"doing inference")
                continue
            alive.append(m)
        if not alive:
            warn("no pipeline passed the probe")
            gen.detach()
            ing.cleanup()
            return [], []

        frame0 = frames[0] if frames else 64
        full_count = gen.window_count(gen.rate_estimate or 3_000_000)
        if generator == "xdp":
            offered_pps = None
        elif not offered_pps:
            print(f"\n{YELLOW} Calibration of the common rate (once, then "
                  f"frozen){NC}")
            delivered = {}
            for m in alive:
                setup = use(m)
                r = measure_point(setup, rx_tab, fab, frame0, 0, full_count,
                                  n_out, gen.clone, repeat=1,
                                  burst=gen.burst, xmit_mode=xmit_mode,
                                  gen=gen, threshold=threshold, plan=plan)
                if r is not None:
                    delivered[m] = r["rx_pps"]
                    info(f"{m}: {r['rx_pps']} pps delivered at full load "
                         f"(rejected {r.get('respinti_pct', 0.0):.2f}%)")
            if not delivered:
                warn("calibration failed: no rate delivered")
                gen.detach()
                ing.cleanup()
                return [], []
            slowest = min(delivered, key=delivered.get)
            offered_pps = int(0.9 * delivered[slowest])
            note(f"common rate = 90% of what the slowest ({slowest}) "
                 f"delivered in ONE window at full load: {offered_pps} "
                 f"pps. That nobody loses at this load is not assumed: the "
                 f"`confronto` phase checks it.")

        phases = (("saturazione", 0),) if not offered_pps else \
            (("saturazione", 0), ("confronto", offered_pps))
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Phase 2: {rounds} rounds x {len(alive)} pipelines x "
              f"{len(phases)} (full load"
              + (f"; {offered_pps} pps offered" if offered_pps else "")
              + f"), frame {frames}, generator {generator}{NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        hdr = (f"  {'round':>5s} {'pipeline':10s} {'frame':>5s} "
               f"{'phase':11s} {'requested':>9s} {'offered':>9s} "
               f"{'RX pps':>9s} {'rej':>7s} {'after':>7s} {'loss':>8s} "
               f"{'bottleneck':>18s}")
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))
        for rnd in range(1, rounds + 1):
            for m in alive:
                setup = use(m)
                for frame in frames:
                    for phase, rate in phases:
                        if rate:
                            r = _point_at_rate(setup, rx_tab, fab, frame, rate,
                                               n_out, gen, repeat, threshold,
                                               plan, diag, xmit_mode)
                        else:
                            r = measure_point(setup, rx_tab, fab, frame, 0,
                                              full_count, n_out, gen.clone,
                                              repeat=repeat, burst=gen.burst,
                                              xmit_mode=xmit_mode, gen=gen,
                                              threshold=threshold, plan=plan,
                                              diag=diag)
                            if r is not None:
                                r.update(offered_pps=None, threads=gen.n_inst,
                                         clone_skb=gen.clone)
                        if r is None:
                            continue
                        r.update(method=m, round=rnd, phase=phase)
                        raw.append(r)
                        if rate:
                            mark = GREEN if r["loss_worst"] <= threshold else (
                                RED if r["loss_worst"] > 1 else YELLOW)
                        else:
                            mark = ""
                        print(f"  {rnd:5d} {m:10s} {frame:5d} {phase:11s} "
                              f"{(str(rate) if rate else 'max'):>9s} "
                              f"{r.get('offered_real_pps', 0):9d} "
                              f"{r['rx_pps']:9d} "
                              f"{r.get('respinti_pct', 0.0):6.2f}% "
                              f"{r.get('loss_dut_pct', 0.0):6.2f}% "
                              f"{mark}{r['loss_worst']:7.2f}%"
                              f"{NC if mark else ''} "
                              f"{r.get('bottleneck', ''):>18s}")

        if diag_enabled:
            diag.start()
            gen.timed_run(frame0, gen.delay_for(offered_pps))
            diag.report(diag.stop())
            report_generator(gen)

        gen.detach()
        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        if egress_threads:
            egress_napi_report(egress_threads)
        if egress_napi:
            disable_threaded_napi(egress_napi)
        _class_mix_report({m: loaded[m] for m in alive}, n_out, sem)
        for dev in ing.dut_devs:
            _detach(dev)
        ing.cleanup()
        for peer in attached:
            _detach(peer)
        del rx_b

    summary = []
    if raw:
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Comparison summary: median over rounds, per "
              f"pipeline and phase{NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        hdr = (f"  {'pipeline':10s} {'frame':>5s} {'phase':11s} {'rnds':>4s} "
               f"{'offered':>9s} {'RX pps':>9s} {'min':>9s} {'max':>9s} "
               f"{'rej':>7s} {'after':>7s} {'loss':>8s} {'node%':>6s} "
               f"{'ns CPU':>7s} {'bottleneck':>18s}")
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))
        ordine = {m: i for i, m in enumerate((RX_ONLY,) + tuple(METHODS))}
        ordine_fase = {"saturazione": 0, "confronto": 1}
        keys = sorted({(r["method"], r["frame"], r["phase"]) for r in raw},
                      key=lambda k: (ordine.get(k[0], 99), k[1],
                                     ordine_fase.get(k[2], 9)))
        for m, frame, phase in keys:
            pts = [r for r in raw if (r["method"], r["frame"], r["phase"])
                   == (m, frame, phase)]
            pps = [r["rx_pps"] for r in pts]
            a = _agg(pps)
            loss = stats.median([r["loss_worst"] for r in pts])
            tags = [r.get("bottleneck") for r in pts if r.get("bottleneck")]
            tag = max(set(tags), key=tags.count) if tags else BN_UNKNOWN
            spread = (100.0 * (a["max"] - a["min"]) / a["min"]) if a["min"] else 0
            row = dict(method=m, frame=frame, phase=phase,
                       rounds=len(pts),
                       offered_pps=(offered_pps if phase == "confronto"
                                    else None),
                       offered_real_pps=int(stats.median(
                           [r.get("offered_real_pps", 0) for r in pts])),
                       rx_pps=int(stats.median(pps)), rx_pps_mean=a["mean"],
                       hit_pps=int(stats.median([r.get("hit_pps", 0)
                                                 for r in pts])),
                       proc_pps=int(stats.median([r.get("proc_pps", 0)
                                                  for r in pts])),
                       rx_pps_min=a["min"], rx_pps_max=a["max"],
                       rx_pps_std=a["std"], rx_pps_cv_pct=a["cv_pct"],
                       loss_pct=round(loss, 3),
                       loss_worst=round(max(r["loss_worst"] for r in pts), 3),
                       respinti_pct=round(stats.median(
                           [r.get("respinti_pct", 0.0) for r in pts]), 3),
                       loss_dut_pct=round(stats.median(
                           [r.get("loss_dut_pct", 0.0) for r in pts]), 3),
                       rx=int(stats.median([r["rx"] for r in pts])),
                       tx=int(stats.median([r["tx"] for r in pts])),
                       offered_tx=int(stats.median([r["offered_tx"]
                                                    for r in pts])),
                       lost_before=int(stats.median([r["lost_before"]
                                                     for r in pts])),
                       lost_after=int(stats.median([r["lost_after"]
                                                    for r in pts])),
                       rx_mbps=round(stats.median([r["rx_mbps"]
                                                   for r in pts]), 2),
                       secs=round(stats.median([r["secs"] for r in pts]), 3),
                       window_mode=pts[0].get("window_mode", "count"),
                       pps_spread_pct=round(spread, 1),
                       unreliable=spread > MAX_SPREAD_PCT,
                       threads=len(plan.gen), bottleneck=tag,
                       cpu_dut_pct=_median_or_none(
                           [r.get("cpu_dut_pct") for r in pts]),
                       ns_cpu=_median_or_none([r.get("ns_cpu") for r in pts]))
            for k in HW.COLUMNS:
                v = _median_or_none([r.get(k) for r in pts])
                if v is not None:
                    row[k] = round(v, 3)
            summary.append(row)
            flag = f" {RED}+-{spread:.0f}%{NC}" if row["unreliable"] else ""
            print(f"  {m:10s} {frame:5d} {phase:11s} {len(pts):4d} "
                  f"{row['offered_real_pps']:9d} "
                  f"{row['rx_pps']:9d} {a['min']:9d} {a['max']:9d} "
                  f"{row['respinti_pct']:6.2f}% {row['loss_dut_pct']:6.2f}% "
                  f"{row['loss_pct']:7.2f}% "
                  f"{_fmt_opt(row['cpu_dut_pct']):>6s} "
                  f"{_fmt_opt(row['ns_cpu']):>7s} {tag:>18s}{flag}")
        _hw_table(summary)
        _compare_verdict(summary, offered_pps, threshold)
    return raw, summary


def _fmt_opt(v):
    return "-" if v is None else f"{v:.1f}"


def _hw_table(summary):
    """Cycles, instructions and IPC per packet, if the counters were there."""
    rows = [r for r in summary if r.get("ipc") is not None]
    if not rows:
        if HW_WHY:
            note(f"no instructions per cycle: {HW_WHY}")
        return
    print(f"\n  {'pipeline':10s} {'frame':>5s} {'phase':11s} "
          f"{'ns CPU':>7s} {'cyc/pk':>9s} {'ins/pk':>9s} {'IPC':>6s} "
          f"{'LLC/pk':>7s} {'br-miss':>7s} {'GHz':>6s} {'egr cyc':>8s}")
    for r in rows:
        def g(k, spec):
            v = r.get(k)
            return "-" if v is None else format(v, spec)
        print(f"  {r['method']:10s} {r['frame']:5d} {r['phase']:11s} "
              f"{_fmt_opt(r.get('ns_cpu')):>7s} {g('cycles_pkt', '9.0f')} "
              f"{g('instr_pkt', '9.0f')} {g('ipc', '6.2f')} "
              f"{g('llc_miss_pkt', '7.3f')} {g('br_miss_pkt', '7.3f')} "
              f"{g('dut_ghz_busy', '6.2f')} {g('egress_cycles_pkt', '8.0f')}")


def _median_or_none(vals):
    vals = [v for v in vals if v is not None and v != ""]
    return round(statistics.median(vals), 1) if vals else None


RXONLY_FAILS = []
PROG_SIZE = {}


def _write_prog_size(out_dir):
    if not PROG_SIZE:
        return
    _write_csv(os.path.join(out_dir, "prog_size.csv"),
               [dict(method=m, n_progs=s["n_progs"], xlated_insns=s["xlated"],
                     jited_bytes=s["jited"], programs=" ".join(s["names"]))
                for m, s in PROG_SIZE.items()])


def _read_any(table, key):
    """Any counter."""
    try:
        v = table[ct.c_int(key)]
    except Exception:
        return 0
    if isinstance(v, (bytes, bytearray)):
        return int.from_bytes(v, "little")
    if isinstance(v, list):
        return sum(int(x) for x in v)
    try:
        return sum(int(x) for x in v)
    except TypeError:
        return int(getattr(v, "value", v))


LAST_CLASS_MIX = {}


def _class_scenarios(model_path):
    """[(class, link_state, ttl, action)] for every class the model
    reaches with some link state, searched as test_forwarding does
    (TTL alone does not move this model's argmax)."""
    import check_pipelines as V
    import test_forwarding as TF
    sem, n_out = class_semantics()
    weights, scale = V.load_weights(model_path)
    node, slot = _node_slot()
    cases = TF._cases_covering_classes(
        V, weights, scale, 0, n_out, ingress_port=slot or 0,
        node_index=node)
    out = []
    for c in sorted(cases):
        act = sem.action_of(c)
        if act == "UNUSED":
            continue
        ls, ttl = cases[c]
        out.append((c, list(ls), int(ttl), act))
    return out


def _per_class_table(per, frames):
    """Node cost (ns, 1e9 / processed) per pipeline and decided class."""
    classi = sorted(per)
    metodi = [m for m in (RX_ONLY,) + tuple(METHODS)
              if any(m in per[c] for c in classi)]
    for frame in frames:
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Node cost per decided class, {frame}B "
              f"(ns/packet = 1e9 / processed, saturation){NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        print("  " + f"{'pipeline':10s}" + "".join(
            f"{f'c{c} {per[c][None]}':>13s}" for c in classi))
        for m in metodi:
            celle = []
            for c in classi:
                r = per[c].get(m, {}).get(frame)
                celle.append(f"{r:13.1f}" if r else f"{'-':>13s}")
            print(f"  {m:10s}" + "".join(celle))
        print(f"  {GREY}The baseline always forwards on class 0 and rxonly "
              f"drops at ingress: in their rows the column does not change "
              f"what they do, only when.{NC}")


def _class_mix_report(loaded, n_out, sem):
    """The classes decided by every pipeline over the whole run."""
    righe = []
    LAST_CLASS_MIX.clear()
    for m, setup in loaded.items():
        if setup.get("rx_is_hit"):
            continue
        cs = setup.get("cls_stats")
        ps = setup.get("pkt_stats")
        if cs is None or ps is None:
            continue
        cls = [_read_any(cs, c) for c in range(n_out)]
        tot = sum(cls)
        if not tot:
            continue
        miss, drop = _read_any(ps, 1), _read_any(ps, 2)
        LAST_CLASS_MIX[m] = cls
        dist = " ".join(f"{c}:{100.0 * v / tot:4.1f}%"
                        for c, v in enumerate(cls) if v)
        righe.append((m, len([v for v in cls if v]), dist, miss, drop))
    if not righe:
        return
    print(f"\n  {YELLOW}Classes decided on the run's traffic (cls_stats, "
          f"cumulative){NC}")
    for m, n, dist, miss, drop in righe:
        print(f"    {m:10s} {n} classi  {dist}   miss {miss} drop {drop}")
    if all(n == 1 for _, n, _, _, _ in righe):
        warn("a single class per pipeline: the traffic exercised a "
             "single path (one port, no DROP). The cost holds for that "
             "path; for mixed traffic --generator xdp --ttl-mix.")


def _rxonly_verdict(sat, cmp_, threshold):
    """The pipelines against the reception-only ceiling measured TOGETHER with them."""
    RXONLY_FAILS.clear()
    for frame in sorted({r["frame"] for r in sat}):
        top = next((r for r in sat if r["frame"] == frame
                    and r["method"] == RX_ONLY), None)
        if top is None or not top["rx_pps"]:
            continue
        cap = top["rx_pps"]

        nodo = node_pps
        base = next((r for r in sat if r["frame"] == frame
                     and r["method"] == "baseline"), None)
        base_ns = 1e9 / nodo(base) if base is not None and nodo(base) else None
        print(f"\n  {YELLOW}Cost per packet on the DUT CPU ({frame}B, "
              f"saturation, same session). Reception-only ceiling "
              f"({RX_ONLY}): {cap} pps = {1e9 / cap:.1f} ns{NC}")
        print(f"    {'':10s} {'RX pps':>9s} {'proc pps':>9s} {'ns/pkt':>7s} "
              f"{'vs base':>8s} {'% ceil':>8s} {'after':>6s}")
        uscita_corta = []
        for r in sat:
            if r["frame"] != frame or r["method"] == RX_ONLY or not r["rx_pps"]:
                continue
            ns = 1e9 / nodo(r)
            vs = (f"{ns - base_ns:+7.1f}" if base_ns is not None
                  and r["method"] != "baseline" else f"{'':>7s}")
            print(f"    {r['method']:10s} {r['rx_pps']:9d} {nodo(r):9d} "
                  f"{ns:7.1f} {vs} {100.0 * nodo(r) / cap:7.1f}% "
                  f"{r.get('loss_dut_pct', 0.0):5.2f}%")
            if r.get("loss_dut_pct", 0.0) > threshold:
                uscita_corta.append(r["method"])
        print(f"    {GREY}ns/pkt = 1e9 / processed (HIT + MISS + DROP): "
              f"from taking the packet off the receive queue to the decision and "
              f"the redirect. If the egress is on the "
              f"same CPU (without --egress-cpu) it also contains the "
              f"downstream node's reception.{NC}")
        if uscita_corta:
            note(f"`after` above threshold on {', '.join(uscita_corta)}: the egress "
                 f"does not keep up with the node, so RX underestimates the node "
                 f"and the cost is read from the processed (above).")
        base = next((r for r in sat if r["frame"] == frame
                     and r["method"] == "baseline"), None)
        if base is not None and nodo(base) > cap * (1 + VALID_TOL):
            RXONLY_FAILS.append(("FAIL", f"{frame}B: {RX_ONLY} {cap} pps "
                                         f"below the baseline "
                                         f"{base['rx_pps']}: the session "
                                         f"measures the machine"))
            print(f"  {RED}[FAIL]{NC} {RX_ONLY} ({cap}) delivers less than the "
                  f"baseline ({base['rx_pps']}) beyond {VALID_TOL:.0%}: it does "
                  f"strictly less work, so the session measures the "
                  f"machine, not the programs.")
        elif base is not None and base["rx_pps"] > cap:
            print(f"  {GREY}The baseline exceeds {RX_ONLY} within "
                  f"{VALID_TOL:.0%}: indistinguishable, i.e. the redirect and the "
                  f"egress veth do not show in the throughput.{NC}")
    cont = [r for r in cmp_ if r["method"] == RX_ONLY
            and r["respinti_pct"] > threshold]
    for r in cont:
        note(f"comparison phase -- {RX_ONLY} also rejects "
             f"{r['respinti_pct']:.2f}% at this rate ({r['frame']}B): part "
             f"of the rejects below capacity belongs to the transport (veth "
             f"queue, NAPI thread wake-up), not to the pipelines. The pipelines' "
             f"part is what is ABOVE this figure.")


def _compare_verdict(summary, offered_pps, threshold):
    """What can be said about the table, decided on the numbers and not written
    before having them."""
    sat = [r for r in summary if r["phase"] == "saturazione"]
    cmp_ = [r for r in summary if r["phase"] == "confronto"]
    _rxonly_verdict(sat, cmp_, threshold)
    if sat:
        piene = [r for r in sat if r["respinti_pct"] > threshold]
        vuote = [r for r in sat if r["respinti_pct"] <= threshold]
        if piene:
            note("saturation phase -- rejects > 0 on: "
                 + ", ".join(f"{r['method']}/{r['frame']}B" for r in piene)
                 + ". The ingress queue overflows, so the DUT is "
                   "overloaded and the processed rate (HIT) is its "
                   "capacity on this veth path: between these rows "
                   "the HIT differences "
                   "beyond the spread between rounds are cost per "
                   "packet.")
        if vuote:
            warn("saturation phase -- no reject on: "
                 + ", ".join(f"{r['method']}/{r['frame']}B" for r in vuote)
                 + ". The DUT is not saturated even at full load: RX is "
                   "what the generator offered, not the pipeline's "
                   "capacity.")
    if cmp_:
        corti = [r for r in cmp_ if r["offered_real_pps"] < 0.9 * offered_pps]
        sporchi = [r for r in cmp_ if r["loss_worst"] > threshold]
        if corti:
            warn(f"comparison phase -- the generator did not offer the "
                 f"{offered_pps} pps requested to: "
                 + ", ".join(f"{r['method']}/{r['frame']}B "
                             f"({r['offered_real_pps']})" for r in corti)
                 + ". For these rows the load is not identical.")
        if sporchi:
            warn(f"comparison phase -- at {offered_pps} pps offered there is loss: "
                 + "; ".join(f"{r['method']}/{r['frame']}B rejected "
                             f"{r['respinti_pct']:.2f}%, after ingress "
                             f"{r['loss_dut_pct']:.2f}%" for r in sporchi)
                 + ". The common rate is NOT below everyone's capacity, "
                   "or the ingress queue overflows because of the NAPI "
                   "thread wake-up time and not the pipeline's work: in "
                   "both cases the RX differences in "
                   "this phase do not belong to the XDP program.")
        elif not corti:
            note(f"comparison phase -- at {offered_pps} pps offered no "
                 f"pipeline loses more than {threshold}%: all hold this "
                 f"load, and RX is the same by construction. The capacity "
                 f"comparison is in the saturation phase.")


VERDICT = []


# --- rate sweep: where the system stops keeping up, and which of the three is the bottleneck ---
DEFAULT_RATES_MPPS = (0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0)


def _sane(st):
    """The three statistics in printable form, even when missing."""
    if not st:
        return dict(n=0, min=None, p50=None, p90=None, p99=None, avg=None,
                    max=None)
    return dict(n=st["n"], min=st["lat_min_ns"], p50=st["lat_p50_ns"],
                p90=st["lat_p90_ns"], p99=st["lat_p99_ns"],
                avg=st["lat_avg_ns"], max=st["lat_max_ns"])


def _median(vals):
    import statistics as _s
    vals = [v for v in vals if v is not None]
    return _s.median(vals) if vals else None


def run_rates(methods, model_path, frame=64, rates=None, rounds=DEFAULT_ROUNDS,
              threads=1, plan=None, threaded_napi=True,
              xmit_mode="start_xmit", threshold=DEFAULT_LOSS_THRESHOLD,
              window_s=WINDOW_S, warmup_s=DEFAULT_WARMUP_S,
              topology="shared", clone=0, burst=0, generator="pktgen",
              xdp_batch=None):
    """Every pipeline, same fabric and same generator, at growing rate."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    plan = plan or plan_cpus(threads=threads)
    sem, n_out = class_semantics()
    rates = list(rates or [int(r * 1e6) for r in DEFAULT_RATES_MPPS])
    raw = []

    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False,
                     port_queues=egress_queues(plan)) as fab:
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Phase 1: compiling and loading the instrumented pipelines "
              f"(no measurement running){NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        loaded, lat_fns = {}, {}
        for m in methods:
            try:
                setup, lat_fn = _load_instrumented(m, model_path, fab, sem)
                loaded[m], lat_fns[m] = setup, lat_fn
                info(f"{m}: loaded (T1, T2, T3)")
            except Exception as e:
                warn(f"{m}: not loaded, skipping it -- {type(e).__name__}: {e}")
        if not loaded:
            warn("no pipeline loaded")
            return []

        ing = build_ingress(fab, plan, topology, False)
        for setup in loaded.values():
            _map_extra_ingress(setup, ing.ifindexes)
        gen_devs = ing.gen_devs if ing.topology == "links" else ing.gen_devs[:1]
        if generator == "xdp":
            from xdp_gen import XdpGen, BATCH_SIZE
            gen = XdpGen(gen_devs[0], plan, window_s=window_s,
                         batch_size=xdp_batch or BATCH_SIZE).attach()
            _warn_shared_queues(plan)
        else:
            gen = Generator(gen_devs, plan, xmit_mode=xmit_mode,
                            topology=ing.topology, clone=clone, burst=burst,
                            window_s=window_s, warmup_s=warmup_s).attach()

        def use(method):
            """This pipeline on the ingress, and ITS counter on the egresses."""
            setup = loaded[method]
            with _quiet():
                for peer in fab.peer_of.values():
                    attach_xdp(setup["b"], lat_fns[method], peer)
                for dev in ing.dut_devs:
                    attach_xdp(setup["b"], setup["disp"], dev)
            return setup

        use(next(iter(loaded)))
        napi_devs = []
        if threaded_napi:
            napi_devs = list(ing.dut_devs)
            if enable_threaded_napi(napi_devs, plan):
                info("threaded NAPI: generator and DUT on separate cores")
            else:
                napi_devs = []
                warn("no NAPI thread pinned: generator and pipeline "
                     "stay on the same core")

        alive = []
        for m in list(loaded):
            setup = use(m)
            _zero_counters(setup, setup["b"]["rx_n"], n_out)
            _clear_lat(setup["b"])
            try:
                gen.run(frame, 1000, gen.delay_for(100_000))
            except PktgenEmptyRun:
                pass
            time.sleep(DRAIN_S)
            if _read_u64(setup["pkt_stats"], 0) == 0:
                warn(f"{m}: the probe produces no HIT -- excluding it instead of "
                     f"measuring the cost of not doing inference")
                continue
            alive.append(m)
        if not alive:
            warn("no pipeline passed the probe")
            gen.detach(); ing.cleanup()
            return []

        print(f"\n{YELLOW} Phase 2: sweep -- {len(rates)} rates x "
              f"{len(alive)} pipelines x {rounds} rounds, frame {frame} B{NC}")
        hdr = (f"  {'rate':>8s} {'pipeline':11s} {'TX':>9s} {'HIT':>9s} "
               f"{'RX':>9s} {'TX-HIT':>8s} {'HIT-RX':>8s} {'rej':>7s} "
               f"{'after':>8s} {'total':>8s} "
               f"{'pipe':>7s} {'e2e':>7s} {'xport':>7s}")
        print(f"\n{hdr}")
        print("  " + "-" * (len(hdr) - 2))

        for rnd in range(rounds):
            seq = alive if rnd % 2 == 0 else list(reversed(alive))
            for rate in rates:
                delay = gen.delay_for(rate)
                cnt = gen.window_count(rate)
                for m in seq:
                    setup = use(m)
                    b = setup["b"]
                    gen.warmup(frame, delay)
                    time.sleep(DRAIN_S)
                    _zero_counters(setup, b["rx_n"], n_out)
                    _clear_lat(b)
                    try:
                        if gen.window_mode == "steady":
                            run = gen.steady(frame, delay, lambda: dict(
                                hit=_read_u64(setup["pkt_stats"], 0),
                                rx=sum(int(v) for v in
                                       b["rx_n"][ct.c_int(0)])))
                        else:
                            run = gen.run(frame, cnt, delay)
                    except PktgenEmptyRun as e:
                        warn(f"rate {rate/1e6:.2f} Mpps {m}: point discarded "
                             f"-- {e}")
                        continue
                    time.sleep(DRAIN_S)

                    tx = run[0]
                    errors = getattr(run, "errors", 0)
                    secs = (getattr(run, "window", 0.0) or run[2]) or 1e-9
                    atteso_tx = cnt * gen.n_inst
                    if not run.steady and tx < atteso_tx:
                        warn(f"rate {rate/1e6:.2f} Mpps {m}: point discarded "
                             f"-- {tx} transmitted out of {atteso_tx} requested "
                             f"({100.0 * tx / atteso_tx:.0f}%), i.e. one or "
                             f"more generator instances did not "
                             f"deliver. What is missing was not offered "
                             f"to the pipeline, so it is not its loss.")
                        continue
                    st = _read_lat_all(b)
                    if run.steady:
                        hit, rx = run.dut["hit"], run.dut["rx"]
                    else:
                        hit = _read_u64(setup["pkt_stats"], 0)
                        rx = st["rx"]
                    offered = tx + errors
                    persi_coda = max(0, tx - hit)
                    persi_dopo = max(0, hit - rx)
                    residui = max(0, hit - tx)
                    if run.steady and residui <= STEADY_INFLIGHT:
                        residui = 0
                    loss = (round(100.0 * (persi_coda + persi_dopo) / offered, 3)
                            if offered else 0.0)
                    loss_tot = (round(100.0 * (errors + persi_coda + persi_dopo)
                                      / offered, 3) if offered else 0.0)
                    resp = (round(100.0 * errors / offered, 3)
                            if offered else 0.0)
                    row = dict(
                        round=rnd, method=m, frame=frame,
                        rate_req_pps=rate, delay_ns=delay, secs=round(secs, 3),
                        tx=tx, hit=hit, rx=rx, gen_errors=errors,
                        offered_tx=offered, tx_minus_hit=persi_coda,
                        hit_minus_rx=persi_dopo, respinti_pct=resp,
                        loss_dut_pct=loss, loss_tot_pct=loss_tot,
                        window_mode="steady" if run.steady else "count",
                        residui_finestra=residui,
                        rx_pps=int(rx / secs), tx_pps=int(tx / secs),
                        rx_mbps=round(rx * frame * 8 / secs / 1e6, 2),
                        samples=st["pipe"]["n"] if st["pipe"] else 0)
                    for nome in ("pipe", "e2e", "xport"):
                        v = _sane(st[nome])
                        row[f"{nome}_min_ns"] = v["min"]
                        row[f"{nome}_p50_ns"] = v["p50"]
                        row[f"{nome}_p90_ns"] = v["p90"]
                        row[f"{nome}_p99_ns"] = v["p99"]
                        row[f"{nome}_avg_ns"] = v["avg"]
                        row[f"{nome}_max_ns"] = v["max"]
                        row[f"{nome}_n"] = v["n"]
                    raw.append(row)

                    if residui:
                        warn(f"rate {rate/1e6:.2f} Mpps {m}: HIT ({hit}) > TX "
                             f"({tx}) by {residui} packets -- leftovers of the "
                             f"previous window, draining is not enough at "
                             f"this rate. The row is not comparable with "
                             f"the others.")
                    mark = (GREEN if loss_tot <= threshold else
                            (RED if loss_tot > 1 else YELLOW))
                    print(f"  {rate/1e6:7.2f}M {m:11s} {tx:9d} {hit:9d} "
                          f"{rx:9d} {persi_coda:8d} {persi_dopo:8d} "
                          f"{resp:6.2f}% {loss:7.3f}% "
                          f"{mark}{loss_tot:7.3f}%{NC} "
                          f"{_fmt_ns(row['pipe_min_ns']):>7s} "
                          f"{_fmt_ns(row['e2e_min_ns']):>7s} "
                          f"{_fmt_ns(row['xport_min_ns']):>7s}")

        gen.detach()
        if generator != "xdp":
            pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        ing.cleanup()

    _report_rates(raw, threshold)
    return raw


def _report_rates(raw, threshold=DEFAULT_LOSS_THRESHOLD):
    """Median over rounds, and the sustainable rate for each pipeline."""
    if not raw:
        return
    per = {}
    for r in raw:
        per.setdefault((r["method"], r["rate_req_pps"]), []).append(r)

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Median over rounds{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    hdr = (f"  {'requested':>9s} {'obtained':>9s} {'yield':>6s} {'pipeline':11s} "
           f"{'after':>8s} {'total':>8s} {'pipe T2-T1':>11s} {'e2e T3-T1':>10s} "
           f"{'xport T3-T2':>12s} {'rounds':>6s}")
    print(f"\n{hdr}")
    print("  " + "-" * (len(hdr) - 2))

    sostenibile, sost_dopo, offerto_gen, ottenuti = {}, {}, {}, {}
    for (m, rate) in sorted(per, key=lambda k: (k[0], k[1])):
        rs = per[(m, rate)]
        loss_dopo = _median([x["loss_dut_pct"] for x in rs])
        loss = _median([x.get("loss_tot_pct", x["loss_dut_pct"]) for x in rs])
        rxp = _median([x["rx_pps"] for x in rs]) or 0
        pipe = _median([x["pipe_min_ns"] for x in rs])
        e2e = _median([x["e2e_min_ns"] for x in rs])
        xp = _median([x["xport_min_ns"] for x in rs])
        resa = 100.0 * rxp / rate if rate else 0.0
        ok = loss is not None and loss <= threshold
        if ok and rxp > sostenibile.get(m, (0, 0))[0]:
            sostenibile[m] = (int(rxp), rate)
        if (loss_dopo is not None and loss_dopo <= threshold
                and rxp > sost_dopo.get(m, (0, 0))[0]):
            sost_dopo[m] = (int(rxp), rate)
        offp = _median([x["offered_tx"] / x["secs"] for x in rs
                        if x.get("secs")]) or 0
        offerto_gen.setdefault(m, {})[rate] = (100.0 * offp / rate
                                               if rate else 0.0)
        ottenuti.setdefault(m, []).append((rate, rxp))
        mark = GREEN if ok else RED
        rmark = GREEN if resa >= 90 else (YELLOW if resa >= 70 else RED)
        print(f"  {rate/1e6:7.2f}M {int(rxp)/1e6:8.2f}M "
              f"{rmark}{resa:5.0f}%{NC} {m:11s} "
              f"{loss_dopo if loss_dopo is not None else 0:7.3f}% "
              f"{mark}{loss if loss is not None else 0:7.3f}%{NC} "
              f"{_fmt_ns(pipe):>11s} {_fmt_ns(e2e):>10s} "
              f"{_fmt_ns(xp):>12s} {len(rs):6d}")

    print(f"\n{YELLOW} SUSTAINABLE throughput -- the rate OBTAINED, not the "
          f"requested one (rejected + lost <= {threshold}% of offered){NC}")
    print("  " + "-" * 68)
    metodi = sorted({r["method"] for r in raw})
    for m in metodi:
        v = sostenibile.get(m)
        if v:
            print(f"    {m:11s} {GREEN}>= {v[0]/1e6:.2f} Mpps{NC}  "
                  f"{GREY}(at the requested point {v[1]/1e6:.2f} Mpps){NC}")
        else:
            print(f"    {m:11s} {RED}no rate tried is sustainable{NC} "
                  f"{GREY}(already the lowest loses: lower --rates){NC}")
        d = sost_dopo.get(m)
        if d and (not v or d[0] > v[0]):
            print(f"    {'':11s} {GREY}counting only the loss AFTER "
                  f"ingress it would be >= {d[0]/1e6:.2f} Mpps: the difference "
                  f"is rejects with the ingress queue full, i.e. load the "
                  f"node did not take.{NC}")

    non_mono = []
    for m, coppie in ottenuti.items():
        v = [rx for _, rx in sorted(coppie)]
        if len(v) > 1 and not all(v[i] <= v[i + 1] for i in range(len(v) - 1)):
            non_mono.append(m)
    if non_mono:
        warn(f"the DELIVERED rate does not grow with the requested rate on: "
             f"{', '.join(sorted(non_mono))}. It is therefore not a function of "
             f"the offered load but generator noise, and the `sustainable` "
             f"above is the maximum among noisy points -- the "
             f"luckiest, not a threshold. It means \"the DUT held at least "
             f"this\", not a measured capacity.")

    corti = {}
    for m, per_rate in offerto_gen.items():
        low = min(per_rate)
        if per_rate[low] < 90.0:
            corti[m] = (low, per_rate[low])
    if corti:
        warn("the generator did not offer even the lowest rate to: "
             + ", ".join(f"{m} ({v:.0f}% of {low/1e6:.2f} Mpps)"
                         for m, (low, v) in sorted(corti.items()))
             + ". For these the sweep ceiling is the GENERATOR: the numbers "
               "say the node holds at least that load, not where it "
               "would break.")
    top = max((r["rate_req_pps"] for r in raw), default=0)
    if sostenibile and all(v[1] >= top for v in sostenibile.values()):
        warn(f"no pipeline lost a packet even at the highest rate "
             f"tried ({top/1e6:.2f} Mpps requested): the knee was not "
             f"reached and every sustainable figure is a LOWER "
             f"BOUND. Raise --rates, or add generator threads.")
    print(f"\n  {GREY}`requested` is the rate offered to pktgen, `obtained` "
          f"the one actually delivered, `yield` the ratio between them. A low "
          f"yield has two causes the raw rows separate: load the "
          f"generator did not offer (offered_tx below the requested one), or "
          f"packets the node rejected with the queue full (rej).{NC}")
    print(f"  {GREY}The maximum Mpps observed is NOT the pipeline's "
          f"throughput if TX > HIT or HIT > RX: in that zone the number "
          f"describes the generator or the veth. The row to cite is the "
          f"sustainable one, read as a >=.{NC}")
    print(f"  {GREY}pipe = T2-T1, the pipeline on the real path. "
          f"e2e = T3-T1. xport = T3-T2, i.e. redirect + veth + NAPI. "
          f"They are MINIMA: the median over rounds is in the column, the "
          f"percentiles in the CSV.{NC}")
    print(f"  {GREY}INSTRUMENTED build: two bpf_ktime_get_ns and two writes "
          f"per packet that the production datapath does not do.{NC}")


# --- generator mode: the bench ceiling, measured without the bench under test ---

GEN_COUNTER_SRC = """
#include <uapi/linux/bpf.h>
BPF_PERCPU_ARRAY(gen_rx, __u64, 1);
int xdp_gen_count(struct xdp_md *ctx) {
    int k = 0;
    __u64 *v = gen_rx.lookup(&k);
    if (v) *v += 1;
    return %(action)s;
}
"""

GEN_RX_ACTIONS = ("drop", "pass")


def _pct(a, b):
    return (100.0 * a / b) if b else 0.0


def run_generator(frame=64, rates=None, rounds=DEFAULT_ROUNDS, threads=1,
                  plan=None, threaded_napi=True, xmit_mode="start_xmit",
                  window_s=WINDOW_S, warmup_s=DEFAULT_WARMUP_S,
                  threshold=DEFAULT_LOSS_THRESHOLD, clone=0, burst=0,
                  rx_action="drop"):
    """pktgen -> veth -> counter."""
    from bcc import BPF
    from common import attach_xdp

    plan = plan or plan_cpus(threads=threads)
    rates = list(rates or [int(r * 1e6) for r in DEFAULT_RATES_MPPS])
    verdict = "XDP_DROP" if rx_action == "drop" else "XDP_PASS"

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} RECEIVE-PATH CEILING TEST{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    info("generator mode: NO DUT pipeline loaded")
    info(f"receiver: minimal RX counter only ({verdict})")
    info("measured path: pktgen -> veth -> RX counter")
    if rx_action == "pass":
        warn("--rx-action pass: the packet goes to the NETWORK STACK, which "
             "the real path never crosses. The resulting ceiling "
             "is lower than the one the pipelines see, and is not an "
             "upper bound for them.")

    rx_dev, tx_dev, _ = make_shared_tg_link(*ingress_queues(plan))
    info(f"veth pair {rx_dev} (DUT side, carries the counter) <- {tx_dev} "
         f"(generator side)")

    b = BPF(text=GEN_COUNTER_SRC % {"action": verdict})
    fn = b.load_func("xdp_gen_count", BPF.XDP)
    napi_devs, raw = [], []
    try:
        attach_xdp(b, fn, rx_dev)
        info(f"counter attached to {rx_dev}: counting happens "
             f"AT THE INGRESS of the DUT side, at the same point where "
             f"`--mode rates` puts the pipeline's dispatcher")
        if threaded_napi:
            napi_devs = [rx_dev]
            if enable_threaded_napi(napi_devs, plan):
                info("threaded NAPI: generator and receiver on separate cores")
            else:
                napi_devs = []
                warn("no NAPI thread pinned: generator and receiver "
                     "stay on the same core")

        gen = Generator([tx_dev], plan, xmit_mode=xmit_mode,
                        topology="shared", clone=clone, burst=burst,
                        window_s=window_s, warmup_s=warmup_s).attach()

        hdr = (f"  {'round':>5s} {'target':>9s} {'TX':>10s} {'RX':>10s} "
               f"{'offered':>8s} {'TX Mpps':>8s} {'RX Mpps':>8s} "
               f"{'yield':>6s} {'loss':>7s} {'rej':>7s} {'state':>26s}")
        print(f"\n{hdr}")
        print("  " + "-" * (len(hdr) - 2))

        for rnd in range(1, rounds + 1):
            for rate in rates:
                delay = gen.delay_for(rate)
                cnt = gen.window_count(rate)
                expected_nominale = int(rate * gen.window_s)
                expected_chiesto = cnt * gen.n_inst
                capped = (gen.window_mode != "steady"
                          and expected_chiesto < expected_nominale)
                gen.warmup(frame, delay)
                time.sleep(DRAIN_S)
                b["gen_rx"].clear()
                try:
                    if gen.window_mode == "steady":
                        run = gen.steady(frame, delay, lambda t=b["gen_rx"]: {
                            "rx": _percpu_sum(t)})
                    else:
                        run = gen.run(frame, cnt, delay)
                except PktgenEmptyRun as e:
                    warn(f"round {rnd} target {rate/1e6:.2f} Mpps: point "
                         f"discarded -- {e}")
                    continue
                time.sleep(DRAIN_S)

                tx = run[0]
                errors = getattr(run, "errors", 0)
                secs = (getattr(run, "window", 0.0) or run[2]) or 1e-9
                if not run.steady and tx < expected_chiesto:
                    warn(f"round {rnd} target {rate/1e6:.2f} Mpps: point "
                         f"discarded -- {tx} transmitted out of {expected_chiesto} "
                         f"requested ({100.0 * tx / expected_chiesto:.0f}%), "
                         f"i.e. {gen.n_inst - round(gen.n_inst * tx / expected_chiesto)}"
                         f" generator instance(s) did not deliver. The "
                         f"window ({secs:.3f}s) does not describe this rate.")
                    continue
                rx = run.dut["rx"] if run.steady else _percpu_sum(b["gen_rx"])
                tx_mpps = tx / secs / 1e6
                rx_mpps = rx / secs / 1e6
                offerti_mpps = (tx + errors) / secs / 1e6
                target_mpps = rate / 1e6
                resa = 100.0 * tx_mpps / target_mpps if target_mpps else 0.0
                loss = _pct(max(0, tx - rx), tx)
                resp = _pct(errors, tx + errors)

                gen_resa = 100.0 * offerti_mpps / target_mpps if target_mpps else 0.0
                cause = []
                if loss > threshold:
                    cause.append("RX_LOSS")
                if resp > threshold:
                    cause.append("RX_BACKPRESSURE")
                if gen_resa < 99.0:
                    cause.append("GEN_LIMIT")
                if capped:
                    cause.append("CAP_WINDOW")
                stato = "+".join(cause) or "OK"
                col = (RED if "RX_LOSS" in cause else
                       YELLOW if cause else GREEN)

                raw.append(dict(
                    mode="generator", rate_target_mpps=round(rate / 1e6, 3),
                    round=rnd, frames=frame, window_s=round(secs, 4),
                    TX=tx, RX=rx, tx_mpps=round(tx_mpps, 4),
                    rx_mpps=round(rx_mpps, 4),
                    offered_mpps=round(offerti_mpps, 4),
                    expected_packets=expected_nominale,
                    expected_chiesto=expected_chiesto,
                    window_capped=int(capped),
                    tx_achievement=round(resa / 100.0, 4),
                    gen_achievement=round(gen_resa / 100.0, 4),
                    loss_percent=round(loss, 4),
                    resp_percent=round(resp, 4), gen_errors=errors,
                    threads=gen.n_inst,
                    cpu_generator=",".join(str(c) for c in plan.gen),
                    cpu_dut=",".join(str(c) for c in plan.dut),
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    commit=_cmd_line(["git", "-C", SHARED_DIR, "rev-parse",
                                      "--short", "HEAD"]),
                    rx_action=verdict, status=stato))
                segno = "*" if capped else " "
                print(f"  {rnd:4d} {rate/1e6:7.2f}M{segno} {tx:10d} {rx:10d} "
                      f"{offerti_mpps:8.3f} {tx_mpps:8.3f} {rx_mpps:8.3f} "
                      f"{resa:5.0f}% {loss:6.2f}% {resp:6.2f}% "
                      f"{col}{stato:>26s}{NC}")

        gen.detach()
        pg_reset()
    finally:
        if napi_devs:
            disable_threaded_napi(napi_devs)
        _detach(rx_dev)
        del_tg_links(1)
        del b

    _report_generator(raw, rates, threshold)
    return raw


def _report_generator(raw, rates, threshold=DEFAULT_LOSS_THRESHOLD):
    """Medians per target, the observed ceiling, and what it does NOT say."""
    if not raw:
        warn("no point measured")
        return
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Receive-path ceiling summary{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    hdr = (f"  {'target':>8s} {'offered':>9s} {'TX Mpps':>9s} "
           f"{'RX Mpps':>9s} {'min RX':>8s} {'max RX':>8s} "
           f"{'TX/target':>10s} {'loss':>7s} {'rnds':>5s}")
    print(f"\n{hdr}")
    print("  " + "-" * (len(hdr) - 2))

    per_rate = {}
    for r in raw:
        per_rate.setdefault(r["rate_target_mpps"], []).append(r)

    best_rx = best_tx = 0.0
    best_rx_at = best_tx_at = None
    for t in sorted(per_rate):
        rs = per_rate[t]
        rxs = [x["rx_mpps"] for x in rs]
        txm = _median([x["tx_mpps"] for x in rs]) or 0.0
        offm = _median([x.get("offered_mpps") for x in rs]) or 0.0
        rxm = _median(rxs) or 0.0
        resa = _median([x["tx_achievement"] for x in rs]) or 0.0
        loss = _median([x["loss_percent"] for x in rs]) or 0.0
        if rxm > best_rx:
            best_rx, best_rx_at = rxm, t
        if txm > best_tx:
            best_tx, best_tx_at = txm, t
        rmark = GREEN if resa >= 0.99 else (YELLOW if resa >= 0.7 else RED)
        lmark = GREEN if loss <= threshold else RED
        print(f"  {t:7.2f}M {offm:9.3f} {txm:9.3f} {rxm:9.3f} "
              f"{min(rxs):8.3f} {max(rxs):8.3f} "
              f"{rmark}{resa * 100:9.0f}%{NC} "
              f"{lmark}{loss:6.2f}%{NC} {len(rs):5d}")

    print(f"\n  {YELLOW}Maximum achieved RX rate: {best_rx:.2f} Mpps{NC} "
          f"{GREY}(al target {best_rx_at:.2f} Mpps){NC}")
    print(f"  {YELLOW}Maximum achieved TX rate: {best_tx:.2f} Mpps{NC} "
          f"{GREY}(al target {best_tx_at:.2f} Mpps){NC}")
    print(f"  {GREY}It is the maximum OBSERVED in this test, not the "
          f"absolute limit of the machine: outside this range of targets "
          f"nothing was measured.{NC}")

    top = max(per_rate)
    rs = per_rate[top]
    resa_top = _median([x["tx_achievement"] for x in rs]) or 0.0
    loss_top = _median([x["loss_percent"] for x in rs]) or 0.0
    top_capped = any(x.get("window_capped") for x in rs)
    print("")
    if top_capped:
        n_cap = sum(1 for t in per_rate
                    if any(x.get("window_capped") for x in per_rate[t]))
        warn(f"the highest target ({top:.2f} Mpps) was TRUNCATED by the "
             f"ceiling of {MAX_WINDOW_PKTS} packets per window "
             f"(MAX_WINDOW_PKTS): above "
             f"{MAX_WINDOW_PKTS / WINDOW_S / 1e6:.2f} Mpps of target the bench "
             f"always asks for the same number of packets and the window "
             f"gets longer. {n_cap} targets out of {len(per_rate)} are in this "
             f"condition (marked `*`).")
        print(f"  {GREY}The printed yield stays valid -- it is the ratio between "
              f"RATES, which does not depend on the window length -- but on a "
              f"truncated point it cannot be said whether the ceiling was "
              f"reached: that target was never offered for the "
              f"target duration. To really try it raise --duration, "
              f"or stay below "
              f"{MAX_WINDOW_PKTS / WINDOW_S / 1e6:.2f} Mpps of target.{NC}")
    elif resa_top >= 0.99 and loss_top <= threshold:
        warn(f"receive-path ceiling not reached; highest tested target "
             f"({top:.2f} Mpps) is still achievable. Increase --rates to "
             f"determine a higher ceiling.")
    else:
        off_top = _median([x.get("gen_achievement", 0.0) for x in rs]) or 0.0
        resp_top = _median([x.get("resp_percent", 0.0) for x in rs]) or 0.0
        dove = []
        if loss_top > threshold:
            dove.append("loss on the RX side")
        if resp_top > threshold:
            dove.append(f"the receiver rejects {resp_top:.1f}% "
                        f"of the offered load (RX queue full)")
        if off_top < 0.99:
            dove.append(f"the generator offers only {off_top * 100:.0f}% "
                        f"of the target")
        print(f"  {GREEN}Observed saturation{NC}: at the highest target "
              f"({top:.2f} Mpps) the yield is {resa_top * 100:.0f}% and the loss "
              f"{loss_top:.2f}% -- {'; '.join(dove) or 'cause not isolated'}.")
        primo_rx = next((t for t in sorted(per_rate)
                         if (_median([x.get("resp_percent", 0.0)
                                      for x in per_rate[t]]) or 0)
                         > threshold), None)
        primo_gen = next((t for t in sorted(per_rate)
                          if (_median([x.get("gen_achievement", 1.0)
                                       for x in per_rate[t]]) or 0) < 0.99),
                         None)
        if primo_rx is not None:
            print(f"  {GREY}The receiver rejects from {primo_rx:.2f} Mpps of "
                  f"target up.{NC}")
        if primo_gen is not None:
            print(f"  {GREY}The generator stops offering the target from "
                  f"{primo_gen:.2f} Mpps up.{NC}")

    print(f"\n  {GREY}`offered` = (TX + rejected) / window, i.e. how much "
          f"the generator was really putting on the wire. TX = how many the "
          f"veth accepted. The difference between the two columns is the "
          f"RECEIVER's backpressure: if `offered` stays above TX, "
          f"it is not the sender that stops.{NC}")
    print(f"  {GREY}TX = packets pktgen declares transmitted. "
          f"RX = packets counted at the ingress of the DUT side. "
          f"`rej` = rejected by veth_xmit with the queue full: they are offered "
          f"load NEVER transmitted, so they stay out of TX and of loss.{NC}")
    print(f"  {GREY}TX < RX is impossible by construction; TX > RX is "
          f"loss of the veth or the receiver -- NOT of a pipeline, which in "
          f"this mode does not exist.{NC}")


def _confronto_con_rates(out_dir, ceiling_rx):
    """Sets the ceiling next to the values already measured by --mode rates, if any."""
    if not out_dir:
        return
    path = os.path.join(out_dir, "rates_raw.csv")
    if not os.path.exists(path):
        return
    try:
        with open(path, newline="", encoding="utf-8") as f:
            righe = list(csv.DictReader(f))
    except OSError:
        return
    per = {}
    for r in righe:
        try:
            if float(r.get("loss_tot_pct") or r.get("loss_dut_pct")
                     or 0) > DEFAULT_LOSS_THRESHOLD:
                continue
            m, v = r["method"], float(r["rx_pps"]) / 1e6
        except (KeyError, ValueError):
            continue
        per[m] = max(per.get(m, 0.0), v)
    if not per:
        return
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Comparison with --mode rates (read from {path}){NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    print("\n  Receive-path control (no pipeline):")
    print(f"      maximum achieved RX = {ceiling_rx:.2f} Mpps")
    print("\n  Pipeline benchmark (maximum RX without loss, rejects "
          "included):")
    for m in sorted(per, key=lambda k: -per[k]):
        print(f"      {m:11s} >= {per[m]:.2f} Mpps")
    print(f"\n  {GREY}No ranking and no winner: the two columns "
          f"serve one purpose only, to see whether the pipelines' values are "
          f"COMPATIBLE with the generator ceiling. If they all stay "
          f"below and no pipeline was losing, then the generator was "
          f"limiting them and their knee was not reached.{NC}")


def ns_cpu(r, dut_pct, plan):
    """The node's CPU TIME per packet."""
    pps = node_pps(r)
    if not dut_pct or not pps or not plan or not plan.dut:
        return None
    return round(dut_pct / 100.0 * len(plan.dut) * 1e9 / pps, 1)


def node_pps(r):
    """The NODE rate: the packets the program processed (HIT + MISS + DROP,
    see proc_pps in _measure_once), otherwise those decided (HIT),
    otherwise the received ones. With an always-identical packet processed
    and HIT coincide; rxonly has no egress, and for it processed and RX coincide."""
    return r.get("proc_pps") or r.get("hit_pps") or r["rx_pps"]


def check_validity(rows):
    """The baseline must be the fastest."""
    VERDICT.clear()
    per_frame = {}
    for r in rows:
        m = r.get("method")
        if not m:
            continue
        best = per_frame.setdefault(r.get("frame"), {})
        if m not in best or node_pps(r) > node_pps(best[m]):
            best[m] = r
    usable = {k: b for k, b in per_frame.items()
              if "baseline" in b and len(b) >= 2}
    if not usable:
        return 0
    order = sorted(usable, key=lambda k: (k is None, k))
    faster, close, clean_frames = {}, {}, []
    noisy, gen_bound = set(), set()
    for k in order:
        best = usable[k]
        base = node_pps(best["baseline"])
        sopra = {m: node_pps(r) for m, r in best.items()
                 if m != "baseline" and node_pps(r) > base * (1 + VALID_TOL)}
        for m, v in sopra.items():
            faster[(k, m)] = (v, base)
        for m, r in best.items():
            if m != "baseline" and base < node_pps(r) <= base * (1 + VALID_TOL):
                close[(k, m)] = node_pps(r)
            if r.get("unreliable"):
                noisy.add(m)
            if r.get("bottleneck") == BN_GEN:
                gen_bound.add(m)
        if not sopra:
            clean_frames.append(k)
    noisy, gen_bound = sorted(noisy), sorted(gen_bound)

    def _fr(k):
        return "every size" if k is None else f"{k}B"

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Validity check{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    if gen_bound:
        print(f"  {YELLOW}[NOTE]{NC} limited by the GENERATOR, not by "
              f"themselves: {', '.join(gen_bound)}.")
        print(f"  {GREY}For these rows the number is the bench ceiling. "
              f"Raise the generator CPUs (--gen-cpus) or lower the "
              f"DUT ones (--dut-cpus) until loss appears: only then is the "
              f"number the pipeline's.{NC}")
    if not faster and not noisy:
        det = ", ".join(f"{_fr(k)} {node_pps(usable[k]['baseline'])} pps"
                        for k in order)
        msg = (f"the baseline is the fastest within {VALID_TOL:.0%} at every "
               f"size ({det}), as it must be: it does strictly less "
               f"work. The differences beyond the tolerance belong "
               f"to the pipelines.")
        VERDICT.append(("PASS", msg))
        print(f"  {GREEN}[PASS]{NC} {msg}")
        if close:
            det = ", ".join(f"{_fr(k)} {m} {v}" for (k, m), v
                            in sorted(close.items(), key=lambda kv: str(kv[0])))
            print(f"  {GREY}Indistinguishable from it within the noise: {det}. "
                  f"They are limited by the generator, not by themselves: "
                  f"throughput does not separate them, latency does.{NC}")
        return 0
    if faster:
        det = "; ".join(f"{_fr(k)}: {m} {v} against baseline {b}"
                        for (k, m), (v, b) in sorted(faster.items(),
                                                     key=lambda kv: str(kv[0])))
        msg = (f"the baseline is NOT the fastest -- {det}. The baseline does "
               f"strictly less work, so it cannot deliver less: "
               f"on those sizes the run measures the machine's load and "
               f"not the datapath, and the figures are not comparable between "
               f"pipelines.")
        VERDICT.append(("FAIL", msg))
        print(f"  {RED}[FAIL]{NC} the baseline is NOT the fastest: {det}.")
        print(f"  {GREY}The baseline does strictly less work, so it cannot "
              f"deliver less. On those sizes the run measures the "
              f"machine's load, not the datapath.{NC}")
        if clean_frames:
            det2 = ", ".join(_fr(k) for k in clean_frames)
            print(f"  {GREY}Consistent instead at: {det2}.{NC}")
    if noisy:
        VERDICT.append(("FAIL", f"spread between rounds above "
                                f"{MAX_SPREAD_PCT:.0f}% on: "
                                f"{', '.join(noisy)}. A median over measurements "
                                f"swinging like this is not a throughput, it is "
                                f"the machine's load at different "
                                f"moments."))
        print(f"  {RED}[FAIL]{NC} spread between rounds above "
              f"{MAX_SPREAD_PCT:.0f}% on: {', '.join(noisy)}.")
        print(f"  {GREY}A median over measurements swinging like this is not "
              f"a throughput: it is the machine's load at different moments, "
              f"and it can end up below a pipeline that does more work. "
              f"The throughput of these rows is not a result."
              f"{NC}")
        print(f"  {GREY}The latency of the same rows is another measurement "
              f"with another spread. An unusable throughput does not "
              f"invalidate it.{NC}")
    print(f"\n  {YELLOW}What to do{NC}: close everything else, then run again with "
          f"--rounds 7, with the conditions applied (no --no-tune). "
          f"If the spread stays, look at host_monitor.csv: throttling, "
          f"temperature and DUT frequency tell whether it is the machine.")
    return 1


def _write_csv(path, rows):
    """Writes the union of the keys, not those of the first row."""
    if not rows:
        return 0
    cols = []
    for row in rows:
        for k in row:
            if not k.startswith("_") and k not in cols:
                cols.append(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, restval="", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"  {GREEN}written{NC} {path}  ({len(rows)} rows)")
    return len(rows)


# --- test conditions: the only part of the measurement that cannot be redone later ---


def _read_text(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def _first_line(path, default="n/d"):
    txt = _read_text(path).strip()
    return txt.splitlines()[0].strip() if txt else default


def _cmd_line(args, default="n/d"):
    """First line of a command's output, or the default."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return default
    out = (r.stdout or r.stderr or "").strip().splitlines()
    return out[0].strip() if out else default


def _cpu_model():
    for line in _read_text("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return "n/d"


def _mem_total_mb():
    for line in _read_text("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            try:
                return str(int(line.split()[1]) // 1024)
            except (IndexError, ValueError):
                break
    return "n/d"


def _distro():
    for line in _read_text("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "n/d"


def _bcc_version():
    try:
        import bcc
    except ImportError:
        return "missing"
    v = getattr(bcc, "__version__", None)
    if v:
        return str(v)
    return _cmd_line(["dpkg-query", "-W", "-f=${Version}", "python3-bpfcc"],
                     "present, unknown version")


def capture_env(a=None, plan=None, methods=(), frames=()):
    """Hardware, software and run conditions, as an ordered list of pairs."""
    u = os.uname()
    env = []

    def add(k, v):
        env.append((k, "n/d" if v is None or v == "" else str(v)))

    add("data", time.strftime("%Y-%m-%d %H:%M:%S"))
    add("commit", _cmd_line(["git", "-C", SHARED_DIR, "rev-parse", "--short",
                             "HEAD"]))

    add("cpu", _cpu_model())
    add("cpu_online", len(online_cpus()))
    add("cpu_governor", _first_line(
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"))
    add("ram_mb", _mem_total_mb())

    add("kernel", f"{u.sysname} {u.release} {u.machine}")
    add("distribuzione", _distro())
    add("cmdline_kernel", _first_line("/proc/cmdline"))
    add("python", sys.version.split()[0])
    add("clang", _cmd_line(["clang", "--version"]))
    add("bcc", _bcc_version())
    add("pktgen", "present" if os.path.isdir(PKTGEN_DIR) else "missing")

    add("datapath", "veth (native XDP), TG and DUT on the same machine")
    if VETH_RING_STATE:
        for dev, st in VETH_RING_STATE.items():
            if not st["supportato"]:
                add(f"coda_rx_{dev}",
                    "not configurable on this kernel (ethtool -g refused)"
                    " -- fixed VETH_RING_SIZE, 256 descriptors")
            else:
                add(f"coda_rx_{dev}",
                    f"{st['dopo']} descriptors (was {st['prima']}, maximum "
                    f"{st['massimo']})")
    add("copia_headroom",
        "yes -- pktgen reserves NET_SKB_PAD (64B), XDP on veth requires "
        "XDP_PACKET_HEADROOM (256B): one copy per packet")

    egress = None
    if plan is not None:
        add("cpu_generatore", ",".join(str(c) for c in plan.gen))
        add("cpu_dut", ",".join(str(c) for c in plan.dut))
        egress = getattr(plan, "egress", None)
        if getattr(plan, "gen", None) and getattr(plan, "dut", None):
            tx_q, rx_q = ingress_queues(plan)
            add("code_ingresso_dut",
                f"{rx_q} (generator on {tx_q} TX queues)"
                if len(plan.gen) > 1 else "1 (fabric ingress)")
        if getattr(plan, "dut", None):
            n_e = egress_queues(plan)
            add("code_uscita", f"{n_e} per egress veth (DUT CPU -> queue "
                + ", ".join(f"{c}->{c % n_e}" for c in plan.dut) + ")")
    if egress is None and a is not None and \
            isinstance(getattr(a, "egress_cpu", None), (int, list)):
        egress = a.egress_cpu
    if a is not None:
        add("modalita", "latency" if getattr(a, "latency", False) else a.mode)
        add("napi_threaded", "no" if a.no_threaded_napi else "si")
        add("topologia_generatore", a.gen_topology)
        add("xmit_mode", a.xmit_mode)
        add("finestra_s", a.duration)
        add("finestra_modo", getattr(a, "window", WINDOW_MODE))
        add("generatore", getattr(a, "generator", "pktgen"))
        add("ttl_mix", getattr(a, "ttl_mix", None) or "no (fixed packet, TTL 32)")
        import check_pipelines as V
        import model_under_test as MUT
        m = V._mut()
        add("modello", f"{m.name} ({m.ref})" if m else "configured checkpoint")
        add("modello_forma", m.shape if m else "from the checkpoint")
        topo = MUT.active_topology() if m else None
        add("scenario", topo["topology"] if topo else "from the checkpoint (trained_on)")
        add("cpu_uscita", "separate: cpu" + ",".join(
            str(c) for c in HC.egress_cpus(egress)) if egress is not None
            else "same as the DUT")
        add("warmup_s", a.warmup)
        add("ripetizioni_per_punto", a.repeat)
        add("giri", a.rounds)
        add("soglia_perdita_pct", a.loss_threshold)
        add("clone_skb", a.clone_skb)
        add("burst", a.burst)
    if frames:
        add("frame_byte", ",".join(str(f) for f in frames))
    if methods:
        add("pipeline", ",".join(methods))

    try:
        if HOST_ENV is not None:
            env += HOST_ENV()
        elif plan is not None and getattr(plan, "topo", None) is not None:
            env += HC.env_pairs(plan)
    except Exception as e:
        add("host_conditions", f"n/d ({type(e).__name__}: {e})")
    return env


HOST_ENV = None
HW_COUNTERS = None
HW_WHY = None


def open_hw_counters(plan, enabled=True):
    """Opens the counters on the node and egress cores."""
    global HW_COUNTERS, HW_WHY
    HW_COUNTERS, HW_WHY = None, None
    if not enabled:
        HW_WHY = "off (--no-hw)"
        return [("contatori_hw", HW_WHY)]
    cpus = sorted(set(plan.dut) | set(HC.egress_cpus(plan.egress)))
    hw = HW.HwCounters(cpus)
    HW_COUNTERS = hw.open()
    if HW_COUNTERS is None:
        HW_WHY = hw.why
        warn(f"instructions per cycle not measured: {HW_WHY}")
        return [("contatori_hw", f"n/d ({HW_WHY})")]
    info(f"hardware counters: {HW_COUNTERS.describe()}")
    return [("contatori_hw", HW_COUNTERS.describe())]


def close_hw_counters():
    global HW_COUNTERS
    if HW_COUNTERS is not None:
        HW_COUNTERS.close()
    HW_COUNTERS = None


def print_env(env):
    print(f"\n{YELLOW}== test conditions =={NC}")
    keys = ("data", "commit", "modello", "modello_forma", "pipeline",
            "generatore", "cpu_generatore", "cpu_dut", "frequenza_banco",
            "alimentazione")
    for k, v in env:
        if k in keys:
            print(f"  {GREY}{k:<16}{NC}  {v}")
    print(f"  {GREY}(all {len(env)} entries go to env.csv){NC}")


def write_env(out_dir, env):
    """env.csv next to the numbers."""
    path = os.path.join(out_dir, "env.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["campo", "valore"])
        w.writerows(env)
    print(f"  {GREEN}written{NC} {path}  ({len(env)} fields)")
    return path


# --- the report: one row per configuration, with what gets cited ---


def _num(row, key, default=0):
    v = row.get(key, default)
    return default if v in (None, "") else v


def _loss_of(row):
    return float(_num(row, "loss_worst", _num(row, "loss_pct", 0.0)))


def report_rows(rows, threshold=DEFAULT_LOSS_THRESHOLD):
    """Reduces the raw points to one row per (pipeline, frame)."""
    ordine = {m: i for i, m in enumerate(METHODS)}
    keys = []
    for r in rows:
        k = (r.get("method"), r.get("frame"))
        if k[0] and k[1] and k not in keys:
            keys.append(k)
    keys.sort(key=lambda k: (ordine.get(k[0], 99), k[1]))

    out = []
    for meth, frame in keys:
        pts = [r for r in rows
               if r.get("method") == meth and r.get("frame") == frame
               and r.get("phase") not in ("rumore", "ricerca")]
        if not pts:
            continue
        peak = max(pts, key=lambda r: _num(r, "rx_pps"))
        clean = [r for r in pts if r.get("phase") == "zero-perdite"]
        if not clean:
            clean = [r for r in pts if _loss_of(r) <= threshold]
        best = max(clean, key=lambda r: _num(r, "rx_pps")) if clean else None
        strict = [r for r in pts if _loss_of(r) == 0.0]
        zero = max(strict, key=lambda r: _num(r, "rx_pps")) if strict else None
        lat_src = next((r for r in pts if r.get("phase") == "scarico"), None)
        if lat_src is None:
            with_lat = [r for r in pts if _num(r, "lat_p50_ns")]
            lat_src = (min(with_lat, key=lambda r: _num(r, "rx_pps"))
                       if with_lat else peak)
        out.append(dict(
            method=meth, frame=frame,
            max_rx_pps=int(_num(peak, "rx_pps")),
            max_rx_mbps=_num(peak, "rx_mbps"),
            ns_cpu=peak.get("ns_cpu") if peak.get("ns_cpu") is not None else "",
            cpu_dut_pct=peak.get("cpu_dut_pct")
            if peak.get("cpu_dut_pct") is not None else "",
            **{k: (peak.get(k) if peak.get(k) is not None else "")
               for k in HW.COLUMNS},
            max_loss_pct=round(_loss_of(peak), 3),
            max_loss_med_pct=_num(peak, "loss_med", ""),
            max_offered_pps=int(_num(peak, "offered_real_pps",
                                     _num(peak, "offered_pps"))),
            rx_pkts=int(_num(peak, "rx")),
            tx_pkts=int(_num(peak, "offered_tx", _num(peak, "tx"))),
            lost_before=int(_num(peak, "lost_before")),
            lost_after=int(_num(peak, "lost_after")),
            respinti=int(_num(peak, "respinti")),
            respinti_pct=_num(peak, "respinti_pct"),
            persi_dut=int(_num(peak, "persi_in_coda")
                          + _num(peak, "persi_dopo")),
            persi_in_coda=int(_num(peak, "persi_in_coda")),
            persi_dopo=int(_num(peak, "persi_dopo")),
            loss_dut_pct=_num(peak, "loss_dut_pct"),
            noloss_rx_pps=int(_num(best, "rx_pps")) if best else 0,
            noloss_gen_bound=bool(best and _num(best, "gen_bound")),
            noloss_rx_mbps=_num(best, "rx_mbps") if best else 0,
            noloss_loss_pct=round(_loss_of(best), 3) if best else "",
            zero_rx_pps=int(_num(zero, "rx_pps")) if zero else 0,
            lat_p50_ns=int(_num(lat_src, "lat_p50_ns")) or "",
            lat_min_ns=int(_num(lat_src, "lat_min_ns")) or "",
            lat_rx_pps=int(_num(lat_src, "rx_pps")) or "",
            bottleneck=(best or peak).get("bottleneck", "n/d"),
            unreliable=bool(peak.get("unreliable", False)),
            rounds=_num(peak, "rounds", _num(peak, "repeat", 1)),
        ))
    return out


def _costo_ns(pps):
    return round(1e9 / pps, 1) if pps else None


def aggiungi_costo(summ):
    """Adds ns/packet and the delta against the baseline, per size."""
    base = {r["frame"]: r["max_rx_pps"] for r in summ
            if r["method"] == "baseline"}
    base_cpu = {r["frame"]: r.get("ns_cpu") for r in summ
                if r["method"] == "baseline"}
    for r in summ:
        bc = base_cpu.get(r["frame"])
        r["ns_cpu_vs_baseline"] = (round(r["ns_cpu"] - bc, 1)
                                   if r.get("ns_cpu") not in (None, "")
                                   and bc not in (None, "")
                                   and r["method"] != "baseline" else "")
        r["ns_pkt"] = _costo_ns(r["max_rx_pps"])
        b = _costo_ns(base.get(r["frame"]))
        if b is not None and r["ns_pkt"] is not None and r["method"] != "baseline":
            r["ns_pkt_vs_baseline"] = round(r["ns_pkt"] - b, 1)
        else:
            r["ns_pkt_vs_baseline"] = ""
    return summ


def write_report(out_dir, rows, env, threshold=DEFAULT_LOSS_THRESHOLD,
                 title="End-to-end throughput, measured"):
    """A markdown file with the table per configuration and the conditions below."""
    summ = aggiungi_costo(report_rows(rows, threshold))
    if not summ:
        return None
    costo_pulito = all(r["max_loss_pct"] <= threshold for r in summ)
    lat = any(r["lat_p50_ns"] for r in summ)
    path = os.path.join(out_dir, "throughput_report.md")
    L = []
    L.append(f"# {title}")
    L.append("")
    rip = next((int(v) for k, v in env if k == "ripetizioni_per_punto"
                and str(v).isdigit()), None)
    if rip is not None and rip < 3:
        L.append(f"> **MEASURED WITH {rip} WINDOW(S) PER POINT -- not "
                 f"comparable between pipelines.**")
        L.append(">")
        L.append("> With fewer than three repetitions the median rate, the "
                 "worst loss and the spread do not exist. In "
                 "particular the `baseline` row, the denominator of the "
                 "`ns/pkt vs baseline` column, is a single window: its "
                 "error propagates to every cost in the table. At least "
                 "`--repeat 3` is needed, 5 is better.")
        L.append("")
    bad = [m for e, m in VERDICT if e == "FAIL"]
    if bad:
        L.append("> **RUN BOCCIATO: rejected by the validity check -- "
                 "the figures below are NOT citable.**")
        L.append(">")
        for m in bad:
            L.append(f"> - {m}")
        L.append(">")
        L.append("> The table stays written because it helps to understand "
                 "*why* the run was rejected, not to "
                 "report a throughput.")
        L.append("")
    elif VERDICT:
        for _, m in VERDICT:
            L.append(f"Validity check: **PASS** -- {m}")
            L.append("")
    L.append("REAL traffic: pktgen (TG) generates, the XDP pipeline (DUT) "
             "infers and redirects, an XDP counter on the egress counts what "
             "actually arrived. No figure in this table is "
             "`1/latency` under `BPF_PROG_TEST_RUN`.")
    L.append("")
    L.append(f"Loss threshold for the \"zero loss\" column: "
             f"{threshold}%.")
    L.append("")
    L.append("**Two loss columns, and a declared deviation from RFC "
             "2544.** The standard defines throughput as the rate at which "
             "not a single frame is lost, and disqualifies the rate if a single "
             "window is dirty. It assumes, however, a quiet and dedicated DUT. "
             "Here DUT, generator and counter are on the same machine, "
             "and an interruption of the DUT core as long as the window "
             "describes the machine, not the rate. So the **worst** loss "
             "over the repetitions is reported, but the decision uses the "
             "**median**. Whoever wants the strict RFC 2544 reading reads the "
             "worst column.")
    L.append("")
    head = ["pipeline", "frame B", "max RX pps", "max Mb/s", "ns/pkt",
            "ns/pkt vs baseline",
            "loss @max % (worst)", "loss @max % (median)",
            "RX pkt", "offered pkt", "rejected (veth)", "lost by the DUT",
            "DUT loss %", "zero loss pps", "zero loss Mb/s",
            "strict zero pps", "bottleneck"]
    if lat:
        head[-1:-1] = ["lat p50 ns", "lat measured at pps"]
    L.append("| " + " | ".join(head) + " |")
    L.append("|" + "|".join("---" for _ in head) + "|")
    for r in summ:
        name = r["method"] + (" *" if r["unreliable"] else "")
        cells = [name, r["frame"], r["max_rx_pps"], r["max_rx_mbps"],
                 r["ns_pkt"], r["ns_pkt_vs_baseline"],
                 r["max_loss_pct"], r["max_loss_med_pct"],
                 r["rx_pkts"], r["tx_pkts"],
                 r["respinti"], r["persi_dut"], r["loss_dut_pct"],
                 (f">= {r['noloss_rx_pps']}" if r["noloss_gen_bound"]
                  else (r["noloss_rx_pps"] or "not determined")),
                 r["noloss_rx_mbps"] or "",
                 r["zero_rx_pps"] or "none"]
        if lat:
            cells.append(r["lat_p50_ns"] or "")
            cells.append(r["lat_rx_pps"] or "")
        cells.append(r["bottleneck"])
        L.append("| " + " | ".join(str(c) for c in cells) + " |")
    L.append("")
    L.append("Pipelines: `baseline` = no inference, only redirect (the "
             "floor of the path); `p1_static` = P1, weights and node "
             "compiled; `hardcoded` = intermediate version (P1.5), weights "
             "compiled and node read from a map; `template` = P2, only the "
             "compiled ceilings; `modular` = P3, depth at runtime too.")
    L.append("")
    if costo_pulito:
        L.append("**`ns/pkt vs baseline` is the cost of inference per "
                 "packet**, measured on real traffic. It holds because here "
                 "nothing is lost: without queues in between `1/RX pps` is the "
                 "time of the whole path, and the baseline does the same "
                 "path minus the inference. If the generator is in softirq "
                 "the rate is `1/(t_gen + t_pipeline)`, but `t_gen` is common "
                 "to every row of the same size and subtracting the baseline "
                 "cancels it.")
        L.append("")
    else:
        L.append("**`ns/pkt vs baseline` is NOT citable in this table**: "
                 "there are rows with loss, and with queues in between "
                 "`1/RX pps` measures the waiting time, not the cost of the "
                 "program. The column stays for internal comparison.")
        L.append("")
    if any(r["noloss_gen_bound"] for r in summ):
        L.append("`>=` in the zero-loss column means **lower "
                 "bound**: at full load not a single packet was lost, so "
                 "the pipeline was not saturated and the measured ceiling "
                 "is the GENERATOR's. The real NDR is higher and this bench, "
                 "on this machine, does not reach it. "
                 "The comparison between pipelines stays valid because they all "
                 "saw the same generator.")
        L.append("")
    L.append("**The two losses are not the same thing.** `rejected (veth)` "
             "are packets to which `veth_xmit` answered `NET_XMIT_DROP` "
             "because the DUT's RX ptr_ring was full: they NEVER "
             "entered the device under test, so they are not a loss "
             "of the pipeline -- they prove the pipeline is saturated and "
             "applying backpressure. `lost by the DUT` are those accepted and "
             "then not delivered (ingress queue, or processed and not "
             "sent out because of a failed redirect or a DROP class), and those "
             "ARE datapath loss. The `loss @max %` column adds "
             "both over the offered load, and is therefore the most pessimistic "
             "of the three.")
    if any(r["unreliable"] for r in summ):
        L.append("")
        L.append(f"`*` = spread between repetitions above "
                 f"{MAX_SPREAD_PCT}%: that row is not usable for a "
                 f"comparison.")
    L.append("")
    L.append("## Test conditions")
    L.append("")
    L.append("| field | value |")
    L.append("|---|---|")
    for k, v in env:
        L.append(f"| {k} | {v} |")
    L.append("")
    L.append("TG, DUT and counter are on the same machine and the path "
             "is veth: the cost of the traversal and of the headroom copy is "
             "inside every figure. The COMPARISON between pipelines in equal "
             "conditions holds; the absolute figures belong to this veth "
             "path, not to a NIC.")
    L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"  {GREEN}written{NC} {path}  ({len(summ)} configurations)")
    _write_csv(os.path.join(out_dir, "throughput_summary.csv"), summ)
    return path


def _rates_from(a):
    """The list of rates in pps, from --rates or the default."""
    if not a.rates:
        return [int(r * 1e6) for r in DEFAULT_RATES_MPPS]
    try:
        rates = [int(float(x) * 1e6) for x in a.rates.split(",") if x.strip()]
    except ValueError:
        sys.exit(f"--rates: comma-separated numbers in Mpps expected, "
                 f"got {a.rates!r}")
    if not rates or min(rates) <= 0:
        sys.exit("--rates: positive rates needed")
    return sorted(rates)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(
        description=__doc__.split("USO")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--method", default="all",
                   help=f"all = the five pipelines; in --mode compare also "
                        f"{RX_ONLY}, the reception-only ceiling measured in the "
                        f"same session. Or a comma-separated list "
                        f"among {', '.join(METHODS)}, {RX_ONLY}, "
                        f"{RX_FWD} ({RX_ONLY} that forwards instead of dropping).")
    p.add_argument("--rates", default=None, metavar="LIST",
                   help="rates mode: offered rates in Mpps, comma-separated "
                        "(default: 0.1,0.2,0.4,0.6,0.8,1,1.2,1.5,2)")
    p.add_argument("--rx-action", choices=GEN_RX_ACTIONS, default="drop",
                   help="generator mode: what the RX counter does with the "
                        "packet. drop (default) frees it at once and is the "
                        "only way to get an UPPER bound; pass hands it "
                        "to the stack, which the real path never "
                        "crosses.")
    p.add_argument("--mode", choices=("compare", "saturate", "rates",
                                      "generator"),
                   default="saturate",
                   help="compare: same offered rate for every pipeline, "
                        "it is the comparison. saturate (default): growing rate "
                        "to find where each one starts losing.")
    p.add_argument("--frames", default=None,
                   help="frame sizes in bytes, comma-separated. The "
                        "comparison uses only one (64) unless told otherwise: "
                        "six sizes multiply the run length by six "
                        "without changing the order between pipelines.")
    p.add_argument("--delays", default="",
                   help="fixed delays in ns, comma-separated. Empty (the "
                        "default) searches the saturation point instead of "
                        "sweeping: fewer points and it centres the answer")
    p.add_argument("--count", type=int, default=200000,
                   help="packets per point in the --latency path. In the "
                        "others the count is set by the duration (--duration), "
                        "because pktgen counts packets and not seconds.")

    g = p.add_argument_group("CPU: separating generator and DUT on the same "
                             "machine")
    g.add_argument("--gen-cpus", default=None, metavar="LIST",
                   help="generator CPUs, e.g. '1,2' or '1-3'. One CPU = one "
                        "pktgen thread (kpktgend_<cpu>). Default: automatic, "
                        "more cores to the generator than to the DUT.")
    g.add_argument("--dut-cpus", default=None, metavar="LIST",
                   help="CPUs on which to pin the NAPI threads running XDP. "
                        "Default: those that remain.")
    g.add_argument("--allow-cpu0", action="store_true",
                   help="admit CPU 0 again, excluded by default because "
                        "it carries timers, RCU and IRQs.")
    g.add_argument("--threads", type=int, default=None, metavar="N",
                   help="how many generator threads, if you do not want to "
                        "list the CPUs. It is the only way to raise the offered "
                        "load when veth refuses clone_skb and burst.")
    g.add_argument("--gen-topology", choices=("shared", "links"),
                   default="shared",
                   help="shared: ONE ingress veth, N pktgen instances on "
                        "distinct TX queues -- gen and DUT scale separately. "
                        "links: one veth per thread, "
                        "each veth bringing one DUT core with it.")
    g.add_argument("--no-threaded-napi", action="store_true",
                   help="leave RX in softirq on the transmitting CPU, "
                        "i.e. generator and pipeline on the same core. Only "
                        "to compare with that configuration.")
    g.add_argument("--dut-queues", default="auto", metavar="N|auto|gen",
                   help="DUT ingress queues (shared topology). auto "
                        "(default): one per DUT CPU, and the pktgen threads "
                        "all write there. gen: one per generator thread "
                        "(more NAPI threads on the same core, alternated by "
                        "the scheduler). See DUT_QUEUES.")

    g.add_argument("--egress-queues", default="auto", metavar="N|auto",
                   help="queues of every egress veth. auto (default): one per "
                        "DUT CPU, chosen so that two CPUs do not fall "
                        "in the same queue (veth picks it as CPU modulo "
                        "queues). 1: every DUT core in the same queue. "
                        "See EGRESS_QUEUES.")

    m = p.add_argument_group("measurement")
    m.add_argument("--duration", type=float, default=WINDOW_S, metavar="S",
                   help=f"target length of a measurement window "
                        f"(default {WINDOW_S}s). pktgen counts packets: the "
                        f"count is calibrated on this duration and the real "
                        f"duration is then read back from its counters.")
    m.add_argument("--warmup", type=float, default=DEFAULT_WARMUP_S,
                   metavar="S",
                   help=f"warm-up window discarded before every "
                        f"point (default {DEFAULT_WARMUP_S}s). 0 disables it.")
    m.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, metavar="N",
                   help="full rounds: every round measures ALL the "
                        "pipelines, then the median is kept. It removes the "
                        "order of the methods from the measurement.")
    m.add_argument("--repeat", type=int, default=DEFAULT_REPEAT, metavar="R",
                   help="windows per point; the median rate and the "
                        "WORST loss are kept")
    m.add_argument("--offered-pps", type=int, default=None, metavar="PPS",
                   help="rate of the `confronto` phase (compare mode). "
                        "Without it, a calibration decides: 90%% of what the "
                        "slowest delivers at full load. That nobody loses at "
                        "that rate is checked by the phase itself.")
    m.add_argument("--generator", choices=("pktgen", "xdp"),
                   default=None,
                   help="xdp (default in --mode compare and rates): raw XDP "
                        "frames from BPF_PROG_TEST_RUN live frames "
                        "(ipa/test/xdp_gen.py), as from a NIC with native "
                        "XDP; without further options one thread per DUT "
                        "CPU and, in compare, the egress on a core of its own "
                        "(--egress-cpu auto). In compare only the saturation "
                        "phase. pktgen (default of --latency, "
                        "saturate and generator, which need it): skb, which "
                        "the veth copies to give XDP the headroom -- a "
                        "transport cost on the DUT.")
    m.add_argument("--xdp-batch", type=int, default=None, metavar="N",
                   help="with --generator xdp: frames per test_run batch "
                        "(1-256, default 256). At the end of a batch the redirect "
                        "wakes the DUT.")
    m.add_argument("--per-class", action="store_true",
                   help="only --mode compare --generator xdp: one session "
                        "per class the model reaches (link state "
                        "and TTL searched as in test_forwarding), then the "
                        "node cost per pipeline and class. Shows how much "
                        "forwarding and DROP cost.")
    m.add_argument("--ttl-mix", default=None, metavar="LIST",
                   help="only with --generator xdp: cycling TTLs, e.g. '2-33' or "
                        "'2,8,16,32'. TTL is a model feature, "
                        "so the decided classes change and the traffic "
                        "exercises more egress ports and the DROP path. "
                        "A TTL of 1 sends the packet to the stack (expired).")
    m.add_argument("--egress-cpu", default=None, metavar="N[,M...]|auto",
                   help="only --mode compare. Moves the NAPI of the egress "
                        "veths (the next node's reception) to "
                        "CPU N, outside the DUT ones: 1/RX becomes the "
                        "node's cost from reception to forwarding. auto: "
                        "a physical core of its own chosen by the plan, if one "
                        "is left. A list (3,5): one core per egress queue "
                        "used, the queue of the i-th DUT core on the i-th "
                        "CPU -- with 2 DUT cores a single CPU does not "
                        "drain the queues (ceiling ~10 Mpps).")
    m.add_argument("--window", choices=("steady", "count"), default="steady",
                   help="steady (default): rates read as differences while "
                        "every pktgen instance transmits, then stop. "
                        "count: fixed count and rate divided by "
                        "the duration of the block on `pgctrl start`, which "
                        "contains up to ~225 ms of pktgen dead time. Kept "
                        "for comparison.")
    m.add_argument("--loss-threshold", type=float, default=None,
                   metavar="PCT",
                   help="below this percentage the loss is considered "
                        "machine noise, not saturation. The "
                        "--latency path starts from STRICT ZERO; the others from "
                        f"{DEFAULT_LOSS_THRESHOLD}%%, the packet lost "
                        "now and then for a core interruption.")
    m.add_argument("--search", choices=("ladder", "bisect"), default="ladder",
                   help="how to search the saturation point. ladder "
                        "(default) climbs in steps and checks monotonicity; "
                        "bisect is a bisection on the delay, kept "
                        "for comparison.")

    gk = p.add_argument_group("generator knobs")
    gk.add_argument("--burst", type=int, default=0, metavar="N",
                    help="deliver N packets per call (xmit_more). On "
                         "veth the kernel refuses it: it is tried and reported.")
    gk.add_argument("--clone-skb", type=int, default=0, metavar="N",
                    help="reuse the same skb N times instead of allocating one "
                         "per packet. On veth the kernel refuses it "
                         "(IFF_TX_SKB_SHARING missing).")
    gk.add_argument("--tune-generator", action="store_true",
                    help="try the supported knobs and keep only those "
                         f"that raise the rate by at least "
                         f"{int(GEN_KNOB_MIN_GAIN * 100)}%%.")
    gk.add_argument("--xmit-mode", choices=XMIT_MODES, default="start_xmit",
                    help="netif_receive injects into the RX path skipping the "
                         "veth traversal, but XDP runs GENERIC and on the "
                         "generator CPU: numbers not comparable with the other "
                         "modes, and no gen/DUT separation.")

    o = p.add_argument_group("output")
    o.add_argument("--diag", action="store_true", default=True,
                   help="collects per-core busy time, device counters "
                        "and softnet_stat around every measurement (reads procfs "
                        "before and after the window, never during). On by "
                        "default: the CPU time per packet comes from it.")
    o.add_argument("--no-diag", dest="diag", action="store_false",
                   help="turns diagnostics off (no CPU time)")
    o.add_argument("--no-hw", action="store_true",
                   help="do not open the hardware counters (instructions, cycles, "
                        "IPC per packet on the node and egress cores, "
                        "hw_counters.py)")
    o.add_argument("--out", default=None, help="where to write the CSVs")
    o.add_argument("--latency", action="store_true",
                   help="arrival->departure latency with an "
                        "instrumented build, in rounds, plus throughput.")
    o.add_argument("--cleanup", action="store_true",
                   help="remove a fabric left over by an interrupted run")
    HC.add_args(p)
    import model_under_test as MUT
    MUT.add_args(p)
    a = p.parse_args()
    HC.check_args(a)
    MUT.select(a.model, a.topology)
    a.egress_cpu = HC.parse_egress(a.egress_cpu)
    if a.out:
        a.out = os.path.abspath(a.out)
    global WINDOW_MODE, DUT_QUEUES, EGRESS_QUEUES
    WINDOW_MODE = a.window
    xdp_ok = not a.latency and a.mode in ("compare", "rates")
    if a.generator is None:
        a.generator = "xdp" if xdp_ok and a.window == "steady" else "pktgen"
        if a.generator == "xdp":
            if a.gen_cpus is None and a.threads is None:
                a.threads = len(parse_cpu_list(a.dut_cpus) or [None])
            if a.mode == "compare" and a.egress_cpu is None:
                a.egress_cpu = "auto"
    if a.generator == "xdp" and (not xdp_ok or a.window != "steady"):
        sys.exit("--generator xdp: only --mode compare or rates, with the "
                 "steady window (the minimum latency of --latency is T3-T1 of "
                 "--mode rates at low rate)")
    if a.xdp_batch is not None and a.generator != "xdp":
        sys.exit("--xdp-batch: solo con --generator xdp")
    if a.egress_cpu is not None and (a.latency or a.mode != "compare"):
        sys.exit("--egress-cpu: solo --mode compare")
    if a.per_class and (a.generator != "xdp" or a.mode != "compare"
                        or a.ttl_mix):
        sys.exit("--per-class: only --mode compare --generator xdp, without "
                 "--ttl-mix (the class decides the TTL)")
    if a.ttl_mix and a.generator != "xdp":
        sys.exit("--ttl-mix: only with --generator xdp (pktgen writes a fixed "
                 "TTL)")

    if sys.platform != "linux":
        sys.exit(f"Linux needed, not {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("root needed: sudo python3 ipa/test/bench_capacity.py")

    os.chdir(SHARED_DIR)
    if a.cleanup:
        from netns_fabric import cleanup
        cleanup()
        del_tg_links(16)
        if pg_available():
            pg_stop()
            pg_reset()
        return 0

    if a.generator == "pktgen" and not pg_available():
        sys.exit(f"{PKTGEN_DIR} does not exist and `modprobe pktgen` did not "
                 f"create it: this kernel lacks the module.")
    if a.repeat <= 1:
        warn("--repeat 1: every point is ONE window. The median rate, the "
             "worst loss and the spread -- i.e. everything that "
             "makes two pipelines comparable on this machine -- are "
             "switched off. The resulting rows are not comparable between "
             "methods; they only show whether the bench runs.")
    if pg_available():
        pg_reset()

    plan = plan_cpus(a.gen_cpus, a.dut_cpus, a.threads, a.allow_cpu0,
                     egress_spec=a.egress_cpu)
    plan.describe()
    for e in HC.egress_cpus(a.egress_cpu if a.egress_cpu != "auto"
                            else None):
        if e in plan.dut:
            sys.exit(f"--egress-cpu {e} is a DUT CPU: "
                     f"the egress would stay where the measurement happens")
        if e in plan.gen:
            sys.exit(f"--egress-cpu {e} is a "
                     f"generator CPU: it would take time from it")
        if e not in online_cpus():
            sys.exit(f"--egress-cpu {e}: CPU not online")
    DUT_QUEUES = parse_dut_queues(a.dut_queues, plan)
    if str(a.egress_queues).strip().lower() != "auto":
        try:
            EGRESS_QUEUES = int(a.egress_queues)
        except ValueError:
            sys.exit(f"--egress-queues: expected auto or a number, got "
                     f"{a.egress_queues!r}")
        if EGRESS_QUEUES < 1:
            sys.exit("--egress-queues: at least 1")

    return conditioned(a, plan, lambda mon: _main_run(a, plan), a.out)


def parse_dut_queues(spec, plan):
    """--dut-queues -> the value of DUT_QUEUES."""
    s = str(spec).strip().lower()
    if s == "gen":
        return None
    if s == "auto":
        return max(1, len(plan.dut))
    try:
        n = int(s)
    except ValueError:
        sys.exit(f"--dut-queues: expected auto, gen or a number, got "
                 f"{spec!r}")
    if n < 1:
        sys.exit("--dut-queues: at least 1")
    return n


def conditioned(a, plan, body, out_dir=None):
    """body(monitor) with the machine conditions applied (unless
    --no-tune) and the monitor on."""
    global HOST_ENV
    host = HC.from_args(a, plan)
    if host is not None:
        host.apply()
    mon = HC.HostMonitor(plan.topo, plan.used,
                         dut=(plan.dut[0] if plan.dut else None),
                         target_khz=(host.target_khz if host else None))
    mon.start_run()
    log_path = None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        log_path = os.path.join(out_dir, "host_monitor.csv")
        if os.path.exists(log_path):
            os.remove(log_path)
        mon.start_log(log_path)
    hw_env = open_hw_counters(plan, enabled=not getattr(a, "no_hw", False))
    HOST_ENV = lambda: HC.env_pairs(
        plan, host=host, monitor=mon,
        log_summary=HC.summarise_log(log_path) if log_path else None) \
        + hw_env
    try:
        return body(mon)
    finally:
        close_hw_counters()
        cols = mon.run_columns()
        mon.close()
        HOST_ENV = None
        if host is not None:
            host.restore()
        if out_dir and os.path.isdir(out_dir):
            _give_back(out_dir)
        host_verdict(cols)


def host_verdict(cols):
    """What the machine did during the run, in one line, and a warning
    if it did not stay in the declared conditions."""
    if not cols:
        return
    def f(k, spec=""):
        v = cols.get(k)
        return "n/d" if v is None else format(v, spec)
    print(f"\n  {GREY}machine during the run: core throttling "
          f"{f('host_throttle_core')}, package {f('host_throttle_pkg')}; "
          f"SMI {f('host_smi')}; DUT busy {f('host_dut_busy_pct')}% at "
          f"{f('host_dut_mhz')} MHz; package at {f('host_pkg_temp_c')} C{NC}")
    if cols.get("host_disturbed"):
        warn("the machine did NOT stay in the declared conditions for "
             "the whole run (thermal throttling, powerclamp, battery or "
             "DUT frequency off target): see host_monitor.csv and "
             "env.csv before citing the numbers.")


def _main_run(a, plan):
    """The body of main() after the CPU plan."""
    import model_meta as mm
    model_path = mm.default_checkpoint()
    if a.frames:
        frames = [int(x) for x in a.frames.split(",") if x.strip()]
    else:
        frames = [64] if (a.latency or a.mode == "compare") else \
            list(DEFAULT_FRAMES)
    delays = [int(x) for x in a.delays.split(",") if x.strip()]
    if a.loss_threshold is None:
        a.loss_threshold = 0.0 if a.latency else DEFAULT_LOSS_THRESHOLD
    methods = list(METHODS) if a.method == "all" else \
        [m.strip() for m in a.method.split(",") if m.strip()]
    unknown = [m for m in methods if m not in METHODS + (RX_ONLY, RX_FWD)]
    if unknown:
        sys.exit(f"--method: unknown {unknown}; valid: all, "
                 f"{', '.join(METHODS + (RX_ONLY, RX_FWD))}")
    if a.mode == "compare" and not a.latency and a.method == "all":
        methods = [RX_ONLY] + methods
    if (RX_ONLY in methods or RX_FWD in methods) and \
            (a.latency or a.mode != "compare"):
        sys.exit(f"{RX_ONLY} and {RX_FWD} exist only in --mode compare; on its "
                 f"own, the same ceiling is measured by --mode generator.")

    env = capture_env(a, plan, methods, frames)
    print_env(env)

    def env_finale():
        """The conditions READ BACK at the end of the run."""
        return capture_env(a, plan, methods, frames)

    rows = []
    rc = 0
    if a.latency:
        lat_delays = delays or [0, 5000, 20000]
        raw = run_fair(methods, model_path, frames, lat_delays, a.count,
                       plan.threads, not a.no_threaded_napi, a.repeat,
                       a.rounds, a.loss_threshold, plan=plan,
                       xmit_mode=a.xmit_mode, window_s=a.duration,
                       warmup_s=a.warmup)
        rows = summarise_fair(raw, methods)
        clean = [r for r in rows if r["phase"] == "zero-perdite"]
        rc |= check_validity([dict(method=r["method"], rx_pps=r["rx_pps"],
                                   unreliable=r["unreliable"],
                                   bottleneck=r.get("bottleneck"))
                              for r in (clean or rows)])
        _latency_verdict(rows)
        if a.out and rows:
            os.makedirs(a.out, exist_ok=True)
            for name, data in (("latency.csv", rows),
                               ("latency_raw.csv", raw)):
                if data:
                    _write_csv(os.path.join(a.out, name), data)
            write_env(a.out, env_finale())
            write_report(a.out, rows, env_finale(), a.loss_threshold,
                         "End-to-end throughput and latency, measured")
            _give_back(a.out)
        return rc

    if a.mode == "generator":
        raw = run_generator(
            frame=frames[0] if frames else 64, rates=sorted(_rates_from(a)),
            rounds=a.rounds, threads=plan.threads, plan=plan,
            threaded_napi=not a.no_threaded_napi, xmit_mode=a.xmit_mode,
            window_s=a.duration, warmup_s=a.warmup,
            threshold=a.loss_threshold, clone=a.clone_skb, burst=a.burst,
            rx_action=a.rx_action)
        if raw:
            _confronto_con_rates(a.out, max(r["rx_mpps"] for r in raw))
        if a.out and raw:
            os.makedirs(a.out, exist_ok=True)
            _write_csv(os.path.join(a.out, "generator_ceiling.csv"), raw)
            write_env(a.out, env_finale())
            _give_back(a.out)
        _closing_note(plan)
        return rc

    if a.mode == "rates":
        rates = _rates_from(a)
        raw = run_rates(
            methods, model_path, frame=frames[0] if frames else 64,
            rates=sorted(rates), rounds=a.rounds, threads=plan.threads,
            plan=plan, threaded_napi=not a.no_threaded_napi,
            xmit_mode=a.xmit_mode, threshold=a.loss_threshold,
            window_s=a.duration, warmup_s=a.warmup, topology=a.gen_topology,
            clone=a.clone_skb, burst=a.burst, generator=a.generator,
            xdp_batch=a.xdp_batch)
        if a.out and raw:
            os.makedirs(a.out, exist_ok=True)
            _write_csv(os.path.join(a.out, "rates_raw.csv"), raw)
            write_env(a.out, env_finale())
            _give_back(a.out)
        _closing_note(plan)
        return rc

    if a.mode == "compare" and a.per_class:
        return _run_per_class(a, methods, model_path, frames, plan, env_finale)

    if a.mode == "compare":
        raw, rows = run_compare(
            methods, model_path, frames, offered_pps=a.offered_pps,
            threads=plan.threads, threshold=a.loss_threshold,
            repeat=a.repeat, rounds=a.rounds, plan=plan,
            topology=a.gen_topology, xmit_mode=a.xmit_mode,
            threaded_napi=not a.no_threaded_napi, diag_enabled=a.diag,
            window_s=a.duration, warmup_s=a.warmup, clone=a.clone_skb,
            burst=a.burst, generator=a.generator,
            egress_cpu=plan.egress,
            ttl_mix=(parse_cpu_list(a.ttl_mix) if a.ttl_mix else None),
            xdp_batch=a.xdp_batch)
        rc |= check_validity([r for r in rows
                              if r.get("phase") == "saturazione"
                              and r.get("method") not in (RX_ONLY, RX_FWD)]
                             or rows)
        VERDICT.extend(RXONLY_FAILS)
        rc |= int(bool(RXONLY_FAILS))
        if a.out and (rows or raw):
            os.makedirs(a.out, exist_ok=True)
            if rows:
                _write_csv(os.path.join(a.out, "compare.csv"), rows)
            if raw:
                _write_csv(os.path.join(a.out, "compare_raw.csv"), raw)
            _write_prog_size(a.out)
            write_env(a.out, env_finale())
            write_report(a.out, rows or raw, env_finale(), a.loss_threshold,
                         "End-to-end throughput at identical load")
            _give_back(a.out)
        _closing_note(plan)
        return rc

    for meth in methods:
        rc |= run_method(meth, model_path, frames, delays, a.count, rows,
                         clone=a.clone_skb, threads=plan.threads,
                         threshold=a.loss_threshold, repeat=a.repeat,
                         burst=a.burst, xmit_mode=a.xmit_mode,
                         threaded_napi=not a.no_threaded_napi, plan=plan,
                         topology=a.gen_topology, diag_enabled=a.diag,
                         offered_pps=a.offered_pps, window_s=a.duration,
                         warmup_s=a.warmup, tune=a.tune_generator,
                         search=a.search)

    clean = [r for r in rows if r.get("phase") == "zero-perdite"]
    rc |= check_validity(clean or rows)

    if a.out and rows:
        os.makedirs(a.out, exist_ok=True)
        _write_csv(os.path.join(a.out, "throughput.csv"), rows)
        write_env(a.out, env_finale())
        write_report(a.out, rows, env_finale(), a.loss_threshold)
        _give_back(a.out)

    _closing_note(plan)
    return rc


def _run_per_class(a, methods, model_path, frames, plan, env_finale):
    """One comparison session per class."""
    scen = _class_scenarios(model_path)
    if not scen:
        sys.exit("no reachable class found")
    info("classes to measure: " + ", ".join(
        f"{c} ({act}, ttl {ttl}, link {''.join(map(str, ls))})"
        for c, ls, ttl, act in scen))
    per, tutti_raw, tutte_rows, rc = {}, [], [], 0
    for sc in scen:
        c, _, _, act = sc
        print(f"\n{YELLOW}{'#' * 78}{NC}\n{YELLOW} CLASS {c} ({act}){NC}"
              f"\n{YELLOW}{'#' * 78}{NC}")
        raw, rows = run_compare(
            methods, model_path, frames, threads=plan.threads,
            threshold=a.loss_threshold, repeat=a.repeat, rounds=a.rounds,
            plan=plan, topology=a.gen_topology, xmit_mode=a.xmit_mode,
            threaded_napi=not a.no_threaded_napi, diag_enabled=a.diag,
            window_s=a.duration, warmup_s=a.warmup, generator="xdp",
            egress_cpu=plan.egress, scenario=sc)
        for m, cls in LAST_CLASS_MIX.items():
            if m == "baseline" or not sum(cls):
                continue
            dom = max(range(len(cls)), key=cls.__getitem__)
            quota = 100.0 * cls[dom] / sum(cls)
            if dom != c or quota < 99.0:
                warn(f"class {c}: {m} decided class {dom} for "
                     f"{quota:.1f}% -- its cell measures another class")
                rc = 1
        per[c] = {None: {"FORWARD": "FWD"}.get(act, act)}
        for r in rows:
            if r.get("phase") != "saturazione":
                continue
            node = node_pps(r)
            if node:
                per[c].setdefault(r["method"], {})[r["frame"]] = 1e9 / node
            r.update(scenario_class=c, scenario_action=act)
        for r in raw:
            r.update(scenario_class=c, scenario_action=act)
        if act == "FORWARD":
            rc |= check_validity([r for r in rows
                                  if r.get("phase") == "saturazione"
                                  and r.get("method") not in (RX_ONLY, RX_FWD)]
                                 or rows)
        tutti_raw += raw
        tutte_rows += rows
    _per_class_table(per, frames)
    if a.out and tutte_rows:
        os.makedirs(a.out, exist_ok=True)
        _write_csv(os.path.join(a.out, "per_class.csv"), tutte_rows)
        _write_csv(os.path.join(a.out, "per_class_raw.csv"), tutti_raw)
        _write_prog_size(a.out)
        write_env(a.out, env_finale())
        _give_back(a.out)
    _closing_note(plan)
    return rc


def _closing_note(plan):
    print(f"\n  {GREY}generator (cpu {','.join(str(c) for c in plan.gen)}) and "
          f"node (cpu {','.join(str(c) for c in plan.dut)}) on the same "
          f"machine, connected by veth: absolute figures belong to this "
          f"path, the comparison between pipelines holds{NC}")


if __name__ == "__main__":
    sys.exit(main())
