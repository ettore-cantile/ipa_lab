#!/usr/bin/env python3
"""xdp_gen.py -- the XDP traffic generator: raw frames sent with
BPF_PROG_TEST_RUN in live-frames mode, no skb and no copy, like a NIC with
native XDP. Needs root.
"""
import argparse
import ctypes as ct
import errno
import os
import signal
import socket
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

_BPF_SYSCALL_NR = {"x86_64": 321, "aarch64": 280}
BPF_PROG_TEST_RUN = 10
BPF_F_TEST_XDP_LIVE_FRAMES = 1 << 1
HDR_COPY = 48
CALL_FRAMES = 1 << 20
BATCH_SIZE = 256
STEADY_CALL_FRAMES = 0xFFFFFFFF
STOP_SIGNAL = signal.SIGUSR1
CATCHUP = 16
PKTGEN_MAGIC = 0xBE9BE955
PKTGEN_HDR_OFF = 14 + 20 + 8
IPA_HDR_LEN = 21


class _AttrTestRun(ct.Structure):
    """union bpf_attr, `test` branch (BPF_PROG_TEST_RUN), up to batch_size."""
    _fields_ = [("prog_fd", ct.c_uint32), ("retval", ct.c_uint32),
                ("data_size_in", ct.c_uint32), ("data_size_out", ct.c_uint32),
                ("data_in", ct.c_uint64), ("data_out", ct.c_uint64),
                ("repeat", ct.c_uint32), ("duration", ct.c_uint32),
                ("ctx_size_in", ct.c_uint32), ("ctx_size_out", ct.c_uint32),
                ("ctx_in", ct.c_uint64), ("ctx_out", ct.c_uint64),
                ("flags", ct.c_uint32), ("cpu", ct.c_uint32),
                ("batch_size", ct.c_uint32), ("_pad", ct.c_uint32)]


assert ct.sizeof(_AttrTestRun) == 80

_libc = None


def _bpf(cmd, attr):
    global _libc
    import platform
    nr = _BPF_SYSCALL_NR.get(platform.machine())
    if nr is None:
        raise RuntimeError(f"bpf(2): unknown syscall number for "
                           f"{platform.machine()}")
    if _libc is None:
        _libc = ct.CDLL("libc.so.6", use_errno=True)
    return _libc.syscall(nr, cmd, ct.byref(attr), ct.sizeof(attr))


def _csum16(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_frame(frame_size, src_mac, dst_mac="02:00:00:00:00:02",
                src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=1234, dport=9999,
                ttl=32):
    """The frame pktgen sends with the bench parameters (pg_set_params)."""
    length = frame_size
    mac = lambda m: bytes(int(x, 16) for x in m.split(":"))  # noqa: E731
    eth = mac(dst_mac) + mac(src_mac) + b"\x08\x00"
    payload_len = length - 14 - 20 - 8
    if payload_len < max(16, IPA_HDR_LEN):
        raise ValueError(f"frame {frame_size}B: payload of {payload_len} "
                         f"bytes, {max(16, IPA_HDR_LEN)} needed (pktgen "
                         f"header / struct ipa_hdr)")
    payload = struct.pack("!IIII", PKTGEN_MAGIC, 0, 0, 0)
    payload += b"\0" * (payload_len - len(payload))
    udp = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + payload_len, 0, 0,
                     ttl, 17, 0, socket.inet_aton(src_ip),
                     socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", _csum16(ip)) + ip[12:]
    frame = eth + ip + udp + payload
    assert len(frame) == length, (len(frame), length)
    return frame


MIX_MAX = 256
GEN_SRC = r"""
#include <uapi/linux/bpf.h>
struct hdr_t { __u8 b[HDR_COPY]; };
struct mix_t { __u8 ttl; __u8 csum[2]; };
BPF_ARRAY(gen_hdr, struct hdr_t, 1);
BPF_ARRAY(gen_mix, struct mix_t, MIX_SLOTS);
BPF_PERCPU_ARRAY(gen_runs, __u64, 1);
BPF_ARRAY(gen_ctl, __u64, 3);
BPF_PERCPU_ARRAY(gen_next, __u64, 1);
BPF_PERCPU_ARRAY(gen_dbg, __u64, 3);
int xdp_gen(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    int k = 0, k_off = 1, k_stamp = 2;
    __u64 now = 0;
    __u64 *iv = gen_ctl.lookup(&k);
    if (iv && *iv) {
        __u64 *nx = gen_next.lookup(&k);
        if (!nx) return XDP_DROP;
        now = bpf_ktime_get_ns();
        int k_spin = 0, k_reset = 1, k_late = 2;
        if (now < *nx) {
            __u64 *c = gen_dbg.lookup(&k_spin);
            if (c) *c += 1;
            return XDP_DROP;
        }
        __u64 late = now - *nx;
        if (late > CATCHUP * *iv) {
            *nx = now - CATCHUP * *iv;
            __u64 *c = gen_dbg.lookup(&k_reset);
            if (c) *c += 1;
            late = CATCHUP * *iv;
        }
        __u64 *ls = gen_dbg.lookup(&k_late);
        if (ls) *ls += late;
        *nx += *iv;
    }
    __u64 *n = gen_runs.lookup(&k);
    if (n) *n += 1;
    if (data + HDR_COPY > end) return XDP_ABORTED;
    struct hdr_t *h = gen_hdr.lookup(&k);
    if (!h) return XDP_ABORTED;
    __builtin_memcpy(data, h->b, HDR_COPY);
    if (MIX_N > 0 && n) {
        int i = (int)(*n % (MIX_N > 0 ? MIX_N : 1));
        struct mix_t *m = gen_mix.lookup(&i);
        if (m) {
            __u8 *d = data;
            d[22] = m->ttl;            /* 14 Ethernet + 8: iphdr.ttl */
            d[24] = m->csum[0];        /* 14 + 10: iphdr.check */
            d[25] = m->csum[1];
        }
    }
    __u64 *st = gen_ctl.lookup(&k_stamp);
    if (st && *st && n && data + PG_OFF + 16 <= end) {
        __u64 *off = gen_ctl.lookup(&k_off);
        if (!now) now = bpf_ktime_get_ns();
        __u64 us = (now + (off ? *off : 0)) / 1000;
        __u32 sec = (__u32)(us / 1000000), usec = (__u32)(us % 1000000);
        __u32 seq = (__u32)*n;
        __u8 *h = (__u8 *)data + PG_OFF;
        h[4] = seq >> 24; h[5] = seq >> 16; h[6] = seq >> 8; h[7] = seq;
        h[8] = sec >> 24; h[9] = sec >> 16; h[10] = sec >> 8; h[11] = sec;
        h[12] = usec >> 24; h[13] = usec >> 16; h[14] = usec >> 8;
        h[15] = usec;
    }
    return bpf_redirect(TARGET_IFINDEX, 0);
}
"""


def _mac_of(dev):
    with open(f"/sys/class/net/{dev}/address") as f:
        return f.read().strip()


def xmit_counters(dev):
    """(sent, refused) by veth_xdp_xmit towards the peer of `dev`, from the
    per-queue ethtool counters."""
    import bench_capacity as BT
    st = BT.ethtool_stats(dev)
    if not st:
        return None
    ok = sum(v for k, v in st.items() if k.endswith("xdp_xmit"))
    err = sum(v for k, v in st.items() if k.endswith("xdp_xmit_errors"))
    if not any(k.endswith("xdp_xmit") for k in st):
        return None
    return ok, err


class XdpGen:
    """Same interface as bench_capacity's Generator, for what the steady
    window needs."""

    kind = "xdp"
    window_mode = "steady"
    clone = burst = 0
    rate_estimate = 0

    def __init__(self, target_dev, plan, window_s=0.3,
                 dst_mac="02:00:00:00:00:02", dst_ip="10.0.0.2", ttls=None,
                 batch_size=BATCH_SIZE):
        from bcc import BPF
        self.target = target_dev
        self.ifindex = socket.if_nametoindex(target_dev)
        self.cpus = list(plan.gen) or [0]
        self.window_s = window_s
        self.dst_mac, self.dst_ip = dst_mac, dst_ip
        self.src_mac = _mac_of(target_dev)
        self.ttls = list(ttls or [])
        if not 1 <= int(batch_size) <= 256:
            raise ValueError("batch_size: 1..256 (TEST_XDP_MAX_BATCH)")
        self.batch_size = int(batch_size)
        if len(self.ttls) > MIX_MAX or any(not 1 <= t <= 255
                                           for t in self.ttls):
            raise ValueError(f"ttls: at most {MIX_MAX} values in 1..255")
        self.b = BPF(text=GEN_SRC, cflags=[
            f"-DHDR_COPY={HDR_COPY}", f"-DTARGET_IFINDEX={self.ifindex}",
            f"-DMIX_N={len(self.ttls)}",
            f"-DMIX_SLOTS={max(1, len(self.ttls))}",
            f"-DPG_OFF={PKTGEN_HDR_OFF}", f"-DCATCHUP={CATCHUP}"])
        self.fn = self.b.load_func("xdp_gen", BPF.XDP)
        try:
            signal.signal(STOP_SIGNAL, lambda *_: None)
        except ValueError:
            pass
        self.last_run = None
        self._frame = None
        self.base_ttl = 32
        self._gap_ns = {c: 0 for c in self.cpus}
        self._calls = {c: 0 for c in self.cpus}

    def set_ttl(self, ttl):
        """The TTL of the base frame (the one without --ttl-mix)."""
        if not 1 <= int(ttl) <= 255:
            raise ValueError(f"ttl {ttl}")
        self.base_ttl = int(ttl)
        self._frame = None

    @property
    def names(self):
        return [f"xdpgen@cpu{c}" for c in self.cpus]

    @property
    def n_inst(self):
        return len(self.cpus)

    def attach(self, verbose=True):
        if verbose:
            print(f"  [INFO] generatore XDP (live frames): {self.n_inst} "
                  f"thread su cpu {','.join(map(str, self.cpus))} -> "
                  f"redirect su {self.target} (ifindex {self.ifindex})")
            if self.ttls:
                print(f"  [INFO] mixed traffic: TTL cycling over "
                      f"{len(self.ttls)} values ({min(self.ttls)}-"
                      f"{max(self.ttls)})")
        return self

    def detach(self):
        pass

    def ensure(self):
        pass

    def delay_for(self, total_pps):
        """The interval between two frames of ONE thread, in ns, for
        `total_pps` in total."""
        if not total_pps:
            return 0
        return max(1, int(round(self.n_inst * 1e9 / float(total_pps))))

    def set_stamp(self, on=True):
        """pktgen's timestamp in every frame (for the end-to-end latency)."""
        self._ctl(2, 1 if on else 0)

    def _ctl(self, i, v):
        self.b["gen_ctl"][ct.c_int(i)] = ct.c_ulonglong(int(v))

    def _clock_offset(self):
        """CLOCK_REALTIME - CLOCK_MONOTONIC in ns, for the timestamp."""
        return time.clock_gettime_ns(time.CLOCK_REALTIME) - \
            time.clock_gettime_ns(time.CLOCK_MONOTONIC)

    def window_count(self, total_pps, seconds=None):
        return CALL_FRAMES

    def warmup(self, frame, delay=0, seconds=None):
        return None

    def _set_frame(self, frame_size):
        if self._frame is not None and self._frame[0] == frame_size:
            return self._frame[1]
        data = build_frame(frame_size, self.src_mac, self.dst_mac,
                           dst_ip=self.dst_ip, ttl=self.base_ttl)
        hdr = self.b["gen_hdr"]
        v = hdr.Leaf()
        ct.memmove(ct.byref(v), data[:HDR_COPY], HDR_COPY)
        hdr[ct.c_int(0)] = v
        mix = self.b["gen_mix"]
        for i, ttl in enumerate(self.ttls):
            f = build_frame(frame_size, self.src_mac, self.dst_mac,
                            dst_ip=self.dst_ip, ttl=ttl)
            e = mix.Leaf()
            e.ttl = f[22]
            e.csum[0], e.csum[1] = f[24], f[25]
            mix[ct.c_int(i)] = e
        buf = ct.create_string_buffer(data, len(data))
        self._frame = (frame_size, buf, len(data))
        return buf

    def _test_run(self, buf, size, frames):
        """One call. False if interrupted by a signal (EINTR)."""
        attr = _AttrTestRun(prog_fd=self.fn.fd, data_size_in=size,
                            data_in=ct.cast(buf, ct.c_void_p).value,
                            repeat=frames, flags=BPF_F_TEST_XDP_LIVE_FRAMES,
                            batch_size=self.batch_size)
        if _bpf(BPF_PROG_TEST_RUN, attr) < 0:
            e = ct.get_errno()
            if e == errno.EINTR:
                return False
            raise OSError(e, f"BPF_PROG_TEST_RUN live frames: "
                             f"{os.strerror(e)}")
        return True

    def diag(self):
        """Cumulative counters for the pacing diagnostics (sums over the
        threads)."""
        vals = [self.b["gen_dbg"][ct.c_int(i)] for i in range(3)]
        out = {}
        for i, name in enumerate(("gen_spin", "gen_reset", "gen_late_ns")):
            out[name] = sum(int(vals[i][c]) for c in self.cpus
                            if c < len(vals[i]))
        out["gen_gap_ns"] = sum(self._gap_ns.values())
        out["gen_calls"] = sum(self._calls.values())
        return out

    def _runs(self):
        vals = self.b["gen_runs"][ct.c_int(0)]
        return {c: int(vals[c]) for c in self.cpus if c < len(vals)}

    def run(self, frame, count, delay):
        import bench_capacity as BT
        self._ctl(0, 0)
        buf = self._set_frame(frame)
        size = self._frame[2]
        before = sum(self._runs().values())
        t0 = time.monotonic()
        errs = []

        def one(cpu):
            try:
                os.sched_setaffinity(0, {cpu})
                self._test_run(buf, size, max(1, count))
            except OSError as e:
                errs.append(e)
        ths = [threading.Thread(target=one, args=(c,)) for c in self.cpus]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        if errs:
            raise RuntimeError(str(errs[0]))
        secs = max(1e-9, time.monotonic() - t0)
        tx = sum(self._runs().values()) - before
        r = BT.GenRun(tx, int(tx / secs), secs, wall=secs)
        self.last_run = r
        return r

    def timed_run(self, frame, delay, seconds=None):
        return self.steady(frame, delay, seconds=seconds)

    def steady(self, frame, delay, probe=None, seconds=None):
        """Come Generator.steady."""
        import bench_capacity as BT
        self._ctl(0, delay or 0)
        self._ctl(1, self._clock_offset())
        seconds = self.window_s if seconds is None else seconds
        buf = self._set_frame(frame)
        size = self._frame[2]
        stop = threading.Event()
        errs = []

        def loop(cpu):
            try:
                os.sched_setaffinity(0, {cpu})
                last = None
                while not stop.is_set():
                    t0 = time.monotonic_ns()
                    if last is not None:
                        self._gap_ns[cpu] += t0 - last
                    self._test_run(buf, size, STEADY_CALL_FRAMES)
                    last = time.monotonic_ns()
                    self._calls[cpu] += 1
            except OSError as e:
                errs.append(e)
                stop.set()

        eth0 = xmit_counters(self.target)
        base = self._runs()
        ths = [threading.Thread(target=loop, args=(c,), daemon=True)
               for c in self.cpus]
        t0 = time.monotonic()
        for t in ths:
            t.start()
        try:
            while True:
                now = self._runs()
                if all(now.get(c, 0) > base.get(c, 0) for c in self.cpus):
                    break
                if errs:
                    raise RuntimeError(f"generatore XDP: {errs[0]}")
                if time.monotonic() - t0 > BT.STEADY_START_TIMEOUT_S:
                    raise BT.PktgenEmptyRun(
                        "XDP generator: not every thread started")
                time.sleep(0.002)
            time.sleep(BT.STEADY_SETTLE_S)

            def snap():
                for _ in range(BT.STEADY_READ_TRIES):
                    a = time.monotonic()
                    g = self._runs()
                    d = probe() if probe else {}
                    z = time.monotonic()
                    if z - a <= BT.STEADY_READ_MAX_S:
                        return (a + z) / 2.0, g, d, z - a
                raise BT.PktgenEmptyRun("counter reads never "
                                        "instantaneous")
            ta, ga, da, ra = snap()
            time.sleep(max(0.0, ta + seconds - time.monotonic()))
            tb, gb, db, rb = snap()
            vivi = all(t.is_alive() for t in ths)
        finally:
            stop.set()
            deadline = time.monotonic() + 5.0
            while any(t.is_alive() for t in ths) and \
                    time.monotonic() < deadline:
                for t in ths:
                    if t.is_alive() and t.ident is not None:
                        try:
                            signal.pthread_kill(t.ident, STOP_SIGNAL)
                        except (ProcessLookupError, OSError):
                            pass
                for t in ths:
                    t.join(timeout=0.02)
        eth1 = xmit_counters(self.target)
        if errs:
            raise RuntimeError(f"generatore XDP: {errs[0]}")
        if not vivi:
            raise BT.PktgenEmptyRun("an XDP generator thread stopped "
                                    "before the second read")
        secs = tb - ta
        dut = {k: db[k] - da.get(k, 0) for k in db}
        offered = sum(gb[c] - ga.get(c, 0) for c in self.cpus)
        if "rx_xdp" in dut:
            errors = max(0, offered - dut["rx_xdp"])
        elif "hit" in dut:
            done = dut["hit"] + dut.get("miss", 0) + dut.get("drop", 0)
            errors = max(0, offered - done)
        else:
            errors = 0
        per_dev = [dict(dev=f"xdpgen@cpu{c}", tx=gb[c] - ga.get(c, 0),
                        pps=int((gb[c] - ga.get(c, 0)) / secs),
                        secs=round(secs, 4), errors=0) for c in self.cpus]
        run = BT.GenRun(offered - errors, int((offered - errors) / secs),
                        secs, per_dev=per_dev, wall=secs, errors=errors)
        run.steady = True
        run.dut = dut
        run.start_offset_ms = None
        run.read_ms = round(1000.0 * max(ra, rb), 2)
        run.xmit_ethtool = None
        if eth0 and eth1:
            ok, err = eth1[0] - eth0[0], eth1[1] - eth0[1]
            run.xmit_ethtool = (ok, err)
        self.last_run = run
        return run


# --- Feasibility probe: pktgen against the XDP generator, same receiver ---
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("USO")[0].strip())
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--frame", type=int, default=64)
    ap.add_argument("--duration", type=float, default=0.3)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("root needed")
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass

    import bench_capacity as BT
    from bcc import BPF
    from common import attach_xdp

    if not BT.pg_available():
        sys.exit("pktgen missing")
    BT.pg_reset()
    plan = BT.plan_cpus()
    plan.describe()
    rx_dev, tx_dev, _ = BT.make_shared_tg_link(*BT.ingress_queues(plan))
    cnt = BPF(text=BT.GEN_COUNTER_SRC % {"action": "XDP_DROP"})
    fn = cnt.load_func("xdp_gen_count", BPF.XDP)
    napi = []
    rows = []
    try:
        attach_xdp(cnt, fn, rx_dev)
        if BT.enable_threaded_napi([rx_dev], plan):
            napi = [rx_dev]
        probe = (lambda: {"rx": BT._percpu_sum(cnt["gen_rx"]),
                          "hit": BT._percpu_sum(cnt["gen_rx"])})
        pg = BT.Generator([tx_dev], plan, window_s=a.duration,
                          window_mode="steady").attach()
        xg = XdpGen(tx_dev, plan, window_s=a.duration).attach()
        print(f"\n  {'round':>5s} {'generator':10s} {'offered':>9s} "
              f"{'accepted':>9s} {'RX':>9s} {'rej':>7s}  ethtool cross-check")
        for rnd in range(1, a.rounds + 1):
            for name, g in (("pktgen", pg), ("xdp", xg)):
                try:
                    r = g.steady(a.frame, 0, probe)
                except Exception as e:
                    print(f"  {rnd:5d} {name:10s} FAILED: "
                          f"{type(e).__name__}: {e}")
                    continue
                s = r.window
                off = (r.tx + r.errors) / s
                acc = r.tx / s
                rx = r.dut["rx"] / s
                resp = 100.0 * r.errors / max(1, r.tx + r.errors)
                eth = ""
                xe = getattr(r, "xmit_ethtool", None)
                if xe:
                    tot = xe[0] + xe[1]
                    eth = (f"xdp_xmit {xe[0]} errors {xe[1]} "
                           f"({100.0 * xe[1] / max(1, tot):.1f}%)")
                elif name == "xdp":
                    eth = "xdp_xmit keys not found in ethtool -S"
                print(f"  {rnd:4d} {name:10s} {off / 1e6:8.3f}M "
                      f"{acc / 1e6:8.3f}M {rx / 1e6:8.3f}M {resp:6.2f}%  {eth}")
                rows.append((name, rx))
        pg.detach()
        BT.pg_reset()
    finally:
        if napi:
            BT.disable_threaded_napi(napi)
        BT._detach(rx_dev)
        BT.del_tg_links(1)
    for name in ("pktgen", "xdp"):
        v = sorted(rx for n, rx in rows if n == name)
        if v:
            print(f"\n  {name:7s} RX median {v[len(v) // 2] / 1e6:.3f} Mpps "
                  f"[{v[0] / 1e6:.3f}-{v[-1] / 1e6:.3f}] over {len(v)} rounds")
    print("\n  Same receiver (dropping counter, threaded NAPI on the DUT "
          "CPUs), same veth pair, alternating rounds: the difference between "
          "the two medians is the cost of skb and headroom copy on the DUT "
          "side, plus what changes in the generator.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
