#!/usr/bin/env python3
"""test_host_conditions_kernel.py -- host_conditions on the real kernel: apply,
read back, measure, restore, compare. Needs root.

    sudo python3 ipa/test/test_host_conditions_kernel.py [--bench]
"""
import argparse
import csv
import glob
import os
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.dirname(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import host_conditions as HC  # noqa: E402

RESULTS = []
UNITS = ("init.scope", "system.slice", "user.slice")


def check(name, cond, detail=""):
    RESULTS.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""), flush=True)


def rd(path):
    return HC.read_text(path)


# --- the snapshot: everything the conditioning can touch ---
def snapshot(topo):
    P = HC.Paths()
    s = {}
    for c in topo.online:
        for n in ("scaling_governor", "scaling_min_freq", "scaling_max_freq",
                  "energy_performance_preference"):
            s[f"cpu{c}/{n}"] = rd(P.cpu(f"cpu{c}", "cpufreq", n))
        for d in glob.glob(P.cpu(f"cpu{c}", "cpuidle", "state*")):
            s[f"cpu{c}/{os.path.basename(d)}"] = rd(os.path.join(d, "disable"))
    for d in glob.glob(P.cpu("intel_uncore_frequency", "*")):
        for n in ("min_freq_khz", "max_freq_khz"):
            s[f"uncore/{os.path.basename(d)}/{n}"] = rd(os.path.join(d, n))
    for f in glob.glob("/proc/irq/*/smp_affinity_list"):
        s[f] = rd(f)
    s["irq_default"] = rd("/proc/irq/default_smp_affinity")
    s["wq"] = rd(P.sys("devices", "virtual", "workqueue", "cpumask"))
    s["nmi"] = rd("/proc/sys/kernel/nmi_watchdog")
    s["platform_profile"] = rd(P.sys("firmware", "acpi", "platform_profile"))
    _, prof, _ = HC.run_cmd(["powerprofilesctl", "get"])
    s["ppd"] = prof.strip()
    for u in UNITS:
        _, v, _ = HC.run_cmd(["systemctl", "show", "-p", "AllowedCPUs",
                              "--value", u])
        s[f"unit/{u}"] = v.strip()
    for pid in kthreads():
        comm = rd(f"/proc/{pid}/comm") or ""
        if not comm.startswith("irq/"):
            s[f"kthread/{pid}/{comm}"] = cpus_allowed(pid)
    return s


def kthreads():
    out = []
    for d in glob.glob("/proc/[0-9]*"):
        st = rd(os.path.join(d, "stat"))
        if not st or ")" not in st:
            continue
        f = st.rsplit(")", 1)[1].split()
        flags = int(f[6]) if len(f) > 6 else 0
        if flags & HC.PF_KTHREAD and not flags & HC.PF_NO_SETAFFINITY:
            out.append(int(os.path.basename(d)))
    return sorted(out)


def cpus_allowed(pid):
    for line in (rd(f"/proc/{pid}/status") or "").splitlines():
        if line.startswith("Cpus_allowed_list:"):
            return line.split(":", 1)[1].strip()
    return None


def diff(a, b):
    keys = [k for k in set(a) | set(b)
            if not (k.startswith("kthread/") and (k not in a or k not in b))]
    return sorted(k for k in keys if a.get(k) != b.get(k))


def t_apply_measure_restore(topo, roles):
    print("[1] apply, and read back from the kernel")
    before = snapshot(topo)
    host = HC.HostConditioner(topo, roles["dut"], roles["gen"],
                              roles["egress"])
    host.apply()
    bench = host.bench
    try:
        P = HC.Paths()
        pinned = {c: (rd(P.cpu(f"cpu{c}", "cpufreq", "scaling_min_freq")),
                      rd(P.cpu(f"cpu{c}", "cpufreq", "scaling_max_freq")),
                      rd(P.cpu(f"cpu{c}", "cpufreq", "scaling_governor")))
                  for c in bench + host.siblings}
        check("performance governor and min = max on the bench CPUs and their "
              "siblings", all(g == "performance" and lo == hi
                              for lo, hi, g in pinned.values()),
              HC._uniform(pinned))
        check("in sysfs min = max = requested frequency",
              all(int(pinned[c][1]) == t
                  for c, t in host.requested_khz.items()),
              str(host.requested_khz))
        check("frequency measured at apply time on every bench core",
              set(host.target_khz) == set(host.requested_khz)
              and host.target_khz != {}, str(host.target_khz))
        deep = [(c, rd(os.path.join(d, "name")))
                for c in bench
                for d in glob.glob(P.cpu(f"cpu{c}", "cpuidle", "state*"))
                if int(rd(os.path.join(d, "latency")) or 0)
                > int(host.cstate_max_us or 0)
                and rd(os.path.join(d, "disable")) != "1"]
        check("deep idle states off on the bench CPUs",
              not deep, str(deep))
        check("NMI watchdog off", rd("/proc/sys/kernel/nmi_watchdog")
              == "0")
        hk = set(host.hk)
        cg = rd("/proc/self/cgroup") or ""
        check("the bench process is in ipa-bench.slice",
              HC.SCOPE_SLICE in cg, cg)
        ok_units = {}
        for u in UNITS:
            _, v, _ = HC.run_cmd(["systemctl", "show", "-p", "AllowedCPUs",
                                  "--value", u])
            ok_units[u] = set(HC.parse_cpu_list(v)) == hk
        check("AllowedCPUs of init/system/user = system CPUs (systemd)",
              all(ok_units.values()), str(ok_units))
        r = subprocess.run(
            ["systemd-run", "--quiet", "--wait", "--pipe", "--slice",
             "user.slice", "grep", "Cpus_allowed_list", "/proc/self/status"],
            capture_output=True, text=True)
        allowed = set(HC.parse_cpu_list(r.stdout.split(":", 1)[-1]))
        check("a new user.slice process runs only on the system "
              "CPUs", allowed and allowed <= hk,
              f"{HC.format_cpu_list(allowed)} (rc {r.returncode})")
        moved = [f for f in glob.glob("/proc/irq/*/smp_affinity_list")
                 if set(HC.parse_cpu_list(rd(f) or "")) <= hk]
        check("IRQs on the system CPUs (the movable ones)",
              len(moved) > 0, f"{len(moved)} IRQ")
        check("unbound workqueues on the system CPUs",
              set(HC.parse_cpu_mask(rd(P.sys("devices", "virtual",
                                             "workqueue", "cpumask"))))
              == hk)

        print("[2] measure: does the loaded DUT hold the fixed frequency?")
        dut = roles["dut"][0]
        mon = HC.HostMonitor(topo, bench, dut=dut,
                             target_khz=host.target_khz)
        check("MSRs readable (APERF/MPERF)", mon._fd is not None,
              mon.msr_note)
        a = mon.mark()
        subprocess.run([sys.executable, "-c",
                        "import time\nt=time.time()+1.5\n"
                        "while time.time()<t: pass"],
                       preexec_fn=lambda: os.sched_setaffinity(0, {dut}))
        cols = mon.delta(a, mon.mark())
        mon.close()
        tgt = host.target_khz.get(dut)
        req = host.requested_khz.get(dut)
        check("DUT busy during the load", (cols.get("host_dut_busy_pct")
                                           or 0) > 50, str(cols))
        if tgt:
            check(f"the DUT holds the frequency measured at apply time "
                  f"({tgt // 1000} MHz, +-5%): it is fixed",
                  cols.get("host_dut_mhz") is not None
                  and abs(cols["host_dut_mhz"] * 1000 - tgt) <= 0.05 * tgt,
                  f"{cols.get('host_dut_mhz')} MHz measured now, "
                  f"{(req or 0) // 1000} written in sysfs")
            check("the monitor does not mark the window as disturbed",
                  not cols.get("host_disturbed"), str(cols))
        check("no throttling nor powerclamp in the window",
              not cols.get("host_throttle_core")
              and not cols.get("host_throttle_pkg")
              and not cols.get("host_powerclamp"), str(cols))
        print(f"  temperature {cols.get('host_pkg_temp_c')} C, SMI "
              f"{cols.get('host_smi')}")
    finally:
        failed = host.restore()

    print("[3] restore, and read back from the kernel")
    after = snapshot(topo)
    d = diff(before, after)
    check("every value as it was before", not d and not failed,
          "; ".join(f"{k}: {before.get(k)} -> {after.get(k)}"
                    for k in d[:6]))
    check("state file deleted", not os.path.exists(HC.Paths().state))


CHILD = r"""
import os, sys, time
sys.path.insert(0, %(here)r)
import host_conditions as HC
topo = HC.Topology.read()
h = HC.HostConditioner(topo, %(dut)r, %(gen)r, %(egress)r)
h.apply()
print("APPLIED", flush=True)
time.sleep(60)
"""


def t_crash(topo, roles):
    print("[4] a run killed with SIGKILL while conditions are applied")
    before = snapshot(topo)
    src = CHILD % dict(here=HERE, dut=roles["dut"], gen=roles["gen"],
                       egress=roles["egress"])
    p = subprocess.Popen([sys.executable, "-c", src], stdout=subprocess.PIPE,
                         text=True)
    applied = False
    deadline = time.monotonic() + 60
    for line in p.stdout:
        if "APPLIED" in line:
            applied = True
            break
        if time.monotonic() > deadline:
            break
    changed = snapshot(topo) != before
    p.send_signal(signal.SIGKILL)
    p.wait()
    check("the child applied and the machine changed",
          applied and changed)
    check("after SIGKILL the state file remains",
          os.path.exists(HC.Paths().state))
    n = HC.recover_stale_state()
    after = snapshot(topo)
    d = diff(before, after)
    check(f"--restore brings everything back ({n} settings)", not d,
          "; ".join(f"{k}: {before.get(k)} -> {after.get(k)}"
                    for k in d[:6]))


def t_bench():
    print("[5] bench_load_curve for real: one short round")
    out = tempfile.mkdtemp(prefix="ipa_bitrate_kernel_")
    cmd = [sys.executable, os.path.join(HERE, "bench_load_curve.py"),
           "--method", "rxonly,baseline,template", "--rounds", "1",
           "--overhead-reps", "0", "--no-plot", "--out", out]
    rc = subprocess.call(cmd)
    path = os.path.join(out, "bitrate_raw.csv")
    rows = []
    if os.path.exists(path):
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
    check("bench_load_curve finished and wrote the windows",
          rc == 0 and rows, f"rc {rc}, {len(rows)} rows, {out}")
    if not rows:
        return
    check("every window has the machine columns",
          all(r.get("host_dut_mhz") not in (None, "") for r in rows))
    bad = [r for r in rows if r.get("host_disturbed") == "True"]
    check("no window with the machine disturbed", not bad,
          f"{len(bad)}/{len(rows)}")
    check("the per-second log exists",
          os.path.exists(os.path.join(out, "host_monitor.csv")))
    check("after the bench the machine has no applied state",
          not os.path.exists(HC.Paths().state))
    print(f"  results in {out}")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--bench", action="store_true",
                   help="also a short round of bench_load_curve (pktgen + XDP)")
    a = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("root needed: sudo python3 ipa/test/test_host_conditions_kernel.py")
    if os.path.exists(HC.Paths().state):
        sys.exit(f"{HC.Paths().state} exists: first sudo python3 "
                 f"ipa/test/host_conditions.py --restore")
    topo = HC.Topology.read()
    roles = HC.plan_roles(topo, want_egress=True)
    print(f"  {topo.summary()}\n  DUT {roles['dut']}, egress "
          f"{roles['egress']}, generator {roles['gen']}")
    t_apply_measure_restore(topo, roles)
    t_crash(topo, roles)
    if a.bench:
        t_bench()
    n, ok = len(RESULTS), sum(RESULTS)
    print(f"\n{ok}/{n} PASS")
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
