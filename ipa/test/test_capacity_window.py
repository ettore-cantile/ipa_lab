"""test_capacity_window.py -- the measurement window of bench_capacity, checked
with a simulated generator. No root.

    python3 ipa/test/test_capacity_window.py
"""
import io
import os
import random
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import bench_capacity as B  # noqa: E402

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


class FakePG:
    def __init__(self, names, max_rate, rej, pickup_max=0.1, seed=1,
                 die_after=None, never_start=()):
        self.names = list(names)
        self.max_rate = max_rate
        self.rej = rej
        self.pickup_max = pickup_max
        self.rng = random.Random(seed)
        self.params = {n: dict(count=0, delay=0) for n in names}
        self.t_start, self.t_end = {}, {}
        self.stop_flag = False
        self.die_after = die_after
        self.never_start = set(never_start)
        self.lock = threading.Lock()

    def attempts(self, n):
        d = self.params[n]["delay"]
        return min(1e9 / d, self.max_rate) if d else self.max_rate

    def finish(self, n):
        acc = self.attempts(n) * (1 - self.rej)
        t = self.params[n]["count"] / acc
        if self.die_after is not None:
            t = min(t, self.die_after)
        return self.t_start[n] + t

    def counters(self, n, now):
        if n not in self.t_start or now < self.t_start[n]:
            return 0, 0
        end = min(self.t_end.get(n, now), self.finish(n), now)
        t = max(0.0, end - self.t_start[n])
        att = self.attempts(n) * t
        return int(att * (1 - self.rej)), int(att * self.rej)

    def running(self, now):
        return {n for n in self.names if n in self.t_start
                and self.t_start[n] <= now and n not in self.t_end
                and self.finish(n) > now}

    def start(self):
        self.stop_flag = False
        self.t_start, self.t_end = {}, {}
        t0 = time.monotonic()
        for n in self.names:
            if n not in self.never_start:
                self.t_start[n] = t0 + self.rng.uniform(0, self.pickup_max)
        time.sleep(0.125)
        while True:
            now = time.monotonic()
            if self.stop_flag:
                break
            if all(n in self.t_start and self.finish(n) <= now for n in self.names):
                break
            time.sleep(0.1)
        now = time.monotonic()
        for n in self.t_start:
            self.t_end.setdefault(n, min(now, self.finish(n)))

    def stop(self):
        now = time.monotonic()
        for n in self.running(now):
            self.t_end[n] = now
        self.stop_flag = True

    def dev_text(self, n):
        now = time.monotonic()
        sofar, err = self.counters(n, now)
        st = int(self.t_start.get(n, 0) * 1e6)
        txt = (f"Params: count {self.params[n]['count']}\nCurrent:\n"
               f"     pkts-sofar: {sofar}  errors: {err}\n"
               f"     started: {st}us  stopped: {int(now*1e6)}us idle: 0us\n")
        if n in self.t_end:
            us = int((self.t_end[n] - self.t_start[n]) * 1e6)
            pps = int(sofar / max(1e-9, self.t_end[n] - self.t_start[n]))
            txt += (f"Result: OK: {us}(c{us}+d0) usec, {sofar} (64byte,0frags)\n"
                    f"  {pps}pps 0Mb/sec (0bps) errors: {err}\n")
        else:
            txt += "Result: Starting\n"
        return txt

    def thread_text(self):
        run = self.running(time.monotonic())
        return ("Running: " + "".join(f"{n} " for n in sorted(run))
                + "\nStopped: \nResult: NA\n")


FAKE = None
STOPS = []


_real_open = open


def fake_open(path, *a, **k):
    if "/proc/net/pktgen" not in str(path):
        return _real_open(path, *a, **k)
    if "kpktgend_" in path:
        return io.StringIO(FAKE.thread_text())
    name = path.rsplit("/", 1)[1]
    return io.StringIO(FAKE.dev_text(name))


def fake_pg_write(path, cmd):
    if path.endswith("pgctrl") and cmd == "start":
        FAKE.start()
    elif path.endswith("pgctrl") and cmd == "stop":
        STOPS.append(time.monotonic())
        FAKE.stop()


def fake_set_params(name, frame, count, delay, **kw):
    FAKE.params[name] = dict(count=count, delay=delay)


B.open = fake_open
B.pg_write = fake_pg_write
B.pg_stop = lambda: fake_pg_write("x/pgctrl", "stop")
B.pg_set_params = fake_set_params
B._num_queues = lambda dev, kind="tx": 2
B.Generator.ensure = lambda self: None


class Plan:
    gen = [1, 2]
    dut = [3]


def make_gen(mode):
    return B.Generator(["veth0"], Plan(), window_mode=mode, window_s=0.3)


print("1. steady window, 2 instances, 1.25 M attempts/s each, 20% rejected")
FAKE = FakePG(["veth0@0", "veth0@1"], 1.25e6, 0.2)
g = make_gen("steady")
lag = 100


def probe():
    now = time.monotonic()
    acc = sum(FAKE.counters(n, now)[0] for n in FAKE.names)
    return {"rx": max(0, acc - lag)}


t0 = time.monotonic()
r = g.steady(64, 0, probe)
el = time.monotonic() - t0
true_acc = 2 * 1.25e6 * 0.8
rate = r.tx / r.secs
check("TX/s = true rate within 2%", abs(rate - true_acc) / true_acc < 0.02,
      f"{rate:.0f} against {true_acc:.0f}")
check("rejected = 20% of offered within 1 point",
      abs(r.errors / (r.tx + r.errors) - 0.2) < 0.01,
      f"{100 * r.errors / (r.tx + r.errors):.2f}%")
check("RX delta = TX delta within the in-flight queue",
      abs(r.dut["rx"] - r.tx) <= 2 * lag + 2, f"rx {r.dut['rx']} tx {r.tx}")
check("duration >= requested window, within 50 ms", 0.3 - 0.005 <= r.secs < 0.35,
      f"{r.secs:.4f}s, read {r.read_ms} ms")
check("stop written once", len(STOPS) == 1, f"{len(STOPS)}")
check("zero skew and mismatch", r.skew_pct == 0.0 and r.rate_mismatch_pct < 1.0,
      f"skew {r.skew_pct} mismatch {r.rate_mismatch_pct}")
print(f"     (window cost: {el:.2f}s, start offset {r.start_offset_ms} ms)")

print("2. check: legacy path (fixed count, divided by the block on start)")
FAKE = FakePG(["veth0@0", "veth0@1"], 1.25e6, 0.2)
g = make_gen("count")
cnt = g.window_count(3_000_000)
lr = g.run(64, cnt, 0)
old_rate = lr.tx_pps_aggregate
check("the legacy path UNDERESTIMATES (>10%): the defect the steady "
      "window removes", (true_acc - old_rate) / true_acc > 0.10,
      f"{old_rate} against {true_acc:.0f} ({100 * (old_rate - true_acc) / true_acc:+.1f}%), "
      f"block {lr.window:.3f}s")

print("3. negative check: one instance stops before the second read")
FAKE = FakePG(["veth0@0", "veth0@1"], 1.25e6, 0.2, die_after=0.2)
g = make_gen("steady")
n_stop = len(STOPS)
try:
    g.steady(64, 0, probe)
    check("window discarded", False, "no exception")
except B.PktgenEmptyRun as e:
    check("window discarded", True, str(e)[:70])
check("stop written on the error path too", len(STOPS) == n_stop + 1)

print("4. negative check: one instance never starts")
FAKE = FakePG(["veth0@0", "veth0@1"], 1.25e6, 0.2, never_start=("veth0@1",))
g = make_gen("steady")
n_stop = len(STOPS)
before = threading.active_count()
try:
    g.steady(64, 0, probe)
    check("start timeout", False, "no exception")
except B.PktgenEmptyRun as e:
    check("start timeout", True, str(e)[:70])
check("stop written and start thread closed",
      len(STOPS) == n_stop + 1 and threading.active_count() == before)

print("5. paced rate: 0.5 Mpps requested on 2 instances, 0% rejected")
FAKE = FakePG(["veth0@0", "veth0@1"], 1.25e6, 0.0)
g = make_gen("steady")
r = g.steady(64, g.delay_for(500_000), probe)
rate = r.tx / r.secs
check("TX/s = 0.5 M within 2%", abs(rate - 5e5) / 5e5 < 0.02, f"{rate:.0f}")

print("6. _measure_once with the steady window: rejects counted as loss")
FAKE = FakePG(["veth0@0", "veth0@1"], 1.25e6, 0.2)
g = make_gen("steady")


class Cell:
    def __init__(self, v):
        self.value = v


class PktStats:
    def __getitem__(self, k):
        now = time.monotonic()
        acc = sum(FAKE.counters(n, now)[0] for n in FAKE.names)
        return Cell({0: acc, 1: 0, 2: 0}[k.value])

    def __setitem__(self, k, v):
        raise AssertionError("steady path must not zero counters")

    def __len__(self):
        return 3


class RxTab:
    def __getitem__(self, k):
        now = time.monotonic()
        acc = sum(FAKE.counters(n, now)[0] for n in FAKE.names)
        return [acc - lag, 0]

    def clear(self):
        raise AssertionError("steady path must not clear rx")


setup = {"pkt_stats": PktStats(), "cls_stats": {}}
row = B._measure_once(setup, RxTab(), None, 64, 0, 450000, 7, gen=g)
check("window_mode steady in the row", row["window_mode"] == "steady")
check("respinti_pct ~ 20%", abs(row["respinti_pct"] - 20.0) < 1.0, f"{row['respinti_pct']}")
check("loss_pct (total) ~ 20%", abs(row["loss_pct"] - 20.0) < 1.0, f"{row['loss_pct']}")
check("loss_dut_pct ~ 0 (within the in-flight queue)", row["loss_dut_pct"] < 0.1, f"{row['loss_dut_pct']}")
check("rx_pps = true capacity within 2%",
      abs(row["rx_pps"] - true_acc) / true_acc < 0.02, f"{row['rx_pps']}")

print("7. 150 ms suspension inside the second read: the read is redone")
FAKE = FakePG(["veth0@0", "veth0@1"], 1.25e6, 0.2)
g = make_gen("steady")
calls = {"n": 0}


def stalling_probe():
    calls["n"] += 1
    if calls["n"] == 2:
        time.sleep(0.15)
    return probe()


r = g.steady(64, 0, stalling_probe)
rate = r.tx / r.secs
check("TX/s = true rate within 2% despite the suspension",
      abs(rate - true_acc) / true_acc < 0.02,
      f"{rate:.0f}, reads {calls['n']}")

print(f"\n{sum(RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(RESULTS) else 1)
