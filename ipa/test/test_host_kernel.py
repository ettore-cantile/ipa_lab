#!/usr/bin/env python3
"""host_conditions sul KERNEL VERO: applica, rilegge dal kernel, misura,
ripristina, confronta. Serve root; lascia la macchina com'era (e lo verifica).

test_host_conditions.py controlla la logica su un /sys finto. Questo controlla
che il kernel faccia davvero quello che la logica chiede:

  [1] applicare: governor, min = max, stati di idle, uncore, NMI watchdog,
      IRQ, workqueue riletti da sysfs/procfs dopo la scrittura; AllowedCPUs
      riletto da systemd; il processo del banco nello scope suo; un processo
      di user.slice che il kernel lascia girare SOLO sulle CPU del sistema
  [2] misurare: un ciclo a vuoto pinnato sul DUT, e la frequenza che il DUT
      ha tenuto davvero, da APERF/MPERF (deve essere quella fissata, +-5%);
      throttling e SMI nella finestra
  [3] ripristinare: ogni valore riletto e confrontato con la fotografia presa
      prima di cominciare
  [4] un run ucciso con SIGKILL a condizioni applicate: il file di stato
      resta, e il ripristino da li' riporta la macchina com'era
  [5] (--bench) bench_bitrate per davvero, un giro corto, e le colonne host_*
      nel CSV: nessuna finestra disturbata

    sudo python3 ipa/test/test_host_kernel.py
    sudo python3 ipa/test/test_host_kernel.py --bench     # + pktgen/XDP
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


# --------------------------------------------------------------------------
# la fotografia: tutto cio' che il condizionamento puo' toccare
# --------------------------------------------------------------------------
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
        # irq/*: affinita' effettiva dell'IRQ, la sceglie il kernel
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
    # un kthread nato o morto nel frattempo non e' una differenza
    keys = [k for k in set(a) | set(b)
            if not (k.startswith("kthread/") and (k not in a or k not in b))]
    return sorted(k for k in keys if a.get(k) != b.get(k))


# --------------------------------------------------------------------------
def t_apply_measure_restore(topo, roles):
    print("[1] applicare, e rileggere dal kernel")
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
        check("governor performance e min = max sulle CPU del banco e sui "
              "fratelli", all(g == "performance" and lo == hi
                              for lo, hi, g in pinned.values()),
              HC._uniform(pinned))
        check("nel sysfs min = max = frequenza chiesta",
              all(int(pinned[c][1]) == t
                  for c, t in host.requested_khz.items()),
              str(host.requested_khz))
        check("frequenza misurata all'applicazione su ogni core del banco",
              set(host.target_khz) == set(host.requested_khz)
              and host.target_khz != {}, str(host.target_khz))
        deep = [(c, rd(os.path.join(d, "name")))
                for c in bench
                for d in glob.glob(P.cpu(f"cpu{c}", "cpuidle", "state*"))
                if int(rd(os.path.join(d, "latency")) or 0)
                > int(host.cstate_max_us or 0)
                and rd(os.path.join(d, "disable")) != "1"]
        check("stati di idle profondi spenti sulle CPU del banco",
              not deep, str(deep))
        check("NMI watchdog spento", rd("/proc/sys/kernel/nmi_watchdog")
              == "0")
        hk = set(host.hk)
        cg = rd("/proc/self/cgroup") or ""
        check("il processo del banco e' in ipa-bench.slice",
              HC.SCOPE_SLICE in cg, cg)
        ok_units = {}
        for u in UNITS:
            _, v, _ = HC.run_cmd(["systemctl", "show", "-p", "AllowedCPUs",
                                  "--value", u])
            ok_units[u] = set(HC.parse_cpu_list(v)) == hk
        check("AllowedCPUs di init/system/user = CPU del sistema (systemd)",
              all(ok_units.values()), str(ok_units))
        # un processo nuovo in user.slice: dove lo lascia girare il kernel?
        r = subprocess.run(
            ["systemd-run", "--quiet", "--wait", "--pipe", "--slice",
             "user.slice", "grep", "Cpus_allowed_list", "/proc/self/status"],
            capture_output=True, text=True)
        allowed = set(HC.parse_cpu_list(r.stdout.split(":", 1)[-1]))
        check("un processo nuovo di user.slice gira solo sulle CPU del "
              "sistema", allowed and allowed <= hk,
              f"{HC.format_cpu_list(allowed)} (rc {r.returncode})")
        moved = [f for f in glob.glob("/proc/irq/*/smp_affinity_list")
                 if set(HC.parse_cpu_list(rd(f) or "")) <= hk]
        check("IRQ sulle CPU del sistema (quelli spostabili)",
              len(moved) > 0, f"{len(moved)} IRQ")
        check("workqueue unbound sulle CPU del sistema",
              set(HC.parse_cpu_mask(rd(P.sys("devices", "virtual",
                                             "workqueue", "cpumask"))))
              == hk)

        print("[2] misurare: il DUT sotto carico tiene la frequenza fissata?")
        dut = roles["dut"][0]
        mon = HC.HostMonitor(topo, bench, dut=dut,
                             target_khz=host.target_khz)
        check("MSR leggibili (APERF/MPERF)", mon._fd is not None,
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
        check("DUT occupato durante il carico", (cols.get("host_dut_busy_pct")
                                                 or 0) > 50, str(cols))
        if tgt:
            check(f"il DUT tiene la frequenza misurata all'applicazione "
                  f"({tgt // 1000} MHz, +-5%): e' fissata",
                  cols.get("host_dut_mhz") is not None
                  and abs(cols["host_dut_mhz"] * 1000 - tgt) <= 0.05 * tgt,
                  f"{cols.get('host_dut_mhz')} MHz misurati ora, "
                  f"{(req or 0) // 1000} scritti nel sysfs")
            check("il monitor non segna la finestra come disturbata",
                  not cols.get("host_disturbed"), str(cols))
        check("nessun throttling ne' powerclamp nella finestra",
              not cols.get("host_throttle_core")
              and not cols.get("host_throttle_pkg")
              and not cols.get("host_powerclamp"), str(cols))
        print(f"  temperatura {cols.get('host_pkg_temp_c')} C, SMI "
              f"{cols.get('host_smi')}")
    finally:
        failed = host.restore()

    print("[3] ripristinare, e rileggere dal kernel")
    after = snapshot(topo)
    d = diff(before, after)
    check("ogni valore com'era prima", not d and not failed,
          "; ".join(f"{k}: {before.get(k)} -> {after.get(k)}"
                    for k in d[:6]))
    check("file di stato cancellato", not os.path.exists(HC.Paths().state))


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
    print("[4] un run ucciso con SIGKILL a condizioni applicate")
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
    check("il figlio ha applicato e la macchina e' cambiata",
          applied and changed)
    check("dopo SIGKILL il file di stato resta",
          os.path.exists(HC.Paths().state))
    n = HC.recover_stale_state()
    after = snapshot(topo)
    d = diff(before, after)
    check(f"--restore riporta tutto com'era ({n} impostazioni)", not d,
          "; ".join(f"{k}: {before.get(k)} -> {after.get(k)}"
                    for k in d[:6]))


def t_bench():
    print("[5] bench_bitrate per davvero: un giro corto")
    out = tempfile.mkdtemp(prefix="ipa_bitrate_kernel_")
    cmd = [sys.executable, os.path.join(HERE, "bench_bitrate.py"),
           "--method", "rxonly,baseline,template", "--rounds", "1",
           "--overhead-reps", "0", "--no-plot", "--out", out]
    rc = subprocess.call(cmd)
    path = os.path.join(out, "bitrate_raw.csv")
    rows = []
    if os.path.exists(path):
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
    check("bench_bitrate e' terminato e ha scritto le finestre",
          rc == 0 and rows, f"rc {rc}, {len(rows)} righe, {out}")
    if not rows:
        return
    check("ogni finestra ha le colonne della macchina",
          all(r.get("host_dut_mhz") not in (None, "") for r in rows))
    bad = [r for r in rows if r.get("host_disturbed") == "True"]
    check("nessuna finestra con la macchina disturbata", not bad,
          f"{len(bad)}/{len(rows)}")
    check("il registro al secondo c'e'",
          os.path.exists(os.path.join(out, "host_monitor.csv")))
    check("dopo il banco la macchina non ha lo stato applicato",
          not os.path.exists(HC.Paths().state))
    print(f"  risultati in {out}")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--bench", action="store_true",
                   help="anche un giro corto di bench_bitrate (pktgen + XDP)")
    a = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("serve root: sudo python3 ipa/test/test_host_kernel.py")
    if os.path.exists(HC.Paths().state):
        sys.exit(f"{HC.Paths().state} esiste: prima sudo python3 "
                 f"ipa/test/host_conditions.py --restore")
    topo = HC.Topology.read()
    roles = HC.plan_roles(topo, want_egress=True)
    print(f"  {topo.summary()}\n  DUT {roles['dut']}, uscita "
          f"{roles['egress']}, generatore {roles['gen']}")
    t_apply_measure_restore(topo, roles)
    t_crash(topo, roles)
    if a.bench:
        t_bench()
    n, ok = len(RESULTS), sum(RESULTS)
    print(f"\n{ok}/{n} PASS")
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
