"""host_conditions, checked without root and without touching the machine.

The conditioner writes to sysfs, procfs and systemd; here every path points
into a fake tree that copies THIS laptop (Core Ultra 7 155H: P-cores 0-11 with
the real SMT pairs 0/5, 1/2, 3/4, 6/7, 8/9, 10/11, E-cores 12-19, LP E-cores
20-21 without L3), and systemctl / powerprofilesctl / busctl are a fake that
keeps their state. What can go wrong without anything crashing: the DUT on the
same physical core as the generator, the desktop confined onto the DUT's
sibling, a C-state disabled on the wrong CPU, and above all a restore that
leaves the machine different from how it was found -- so the central check
is that the tree comes back byte for byte, also after a simulated crash.

    python3 ipa/test/test_host_conditions.py
"""
import atexit
import os
import shutil
import signal
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.dirname(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import host_conditions as HC  # noqa: E402

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))


# --------------------------------------------------------------------------
# the fake machine
# --------------------------------------------------------------------------
MTL_PAIRS = [(0, 5), (1, 2), (3, 4), (6, 7), (8, 9), (10, 11)]
MTL_CORE_ID = {0: 16, 5: 16, 1: 8, 2: 8, 3: 12, 4: 12, 6: 20, 7: 20, 8: 24,
               9: 24, 10: 28, 11: 28, 12: 0, 13: 1, 14: 2, 15: 3, 16: 4,
               17: 5, 18: 6, 19: 7, 20: 32, 21: 33}
IDLE = (("POLL", 0), ("C1E", 1), ("C6", 140), ("C10", 310))
KTHREADS = {  # pid: (comm, flags)
    2: ("kthreadd", HC.PF_KTHREAD),
    15: ("rcu_preempt", HC.PF_KTHREAD),
    20: ("ksoftirqd/1", HC.PF_KTHREAD | HC.PF_NO_SETAFFINITY),
    30: ("napi/ipatg0-8193", HC.PF_KTHREAD),
    100: ("bash", 0x400000),
}
ME = 4242


def w(root, rel, value):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"{value}\n")


def build_mtl(root):
    c = "sys/devices/system/cpu"
    w(root, f"{c}/online", "0-21")
    w(root, "sys/devices/cpu_core/cpus", "0-11")
    w(root, "sys/devices/cpu_atom/cpus", "12-21")
    sib = {}
    for a, b in MTL_PAIRS:
        sib[a] = sib[b] = f"{a},{b}" if b != a + 1 else f"{a}-{b}"
    for n in range(22):
        d = f"{c}/cpu{n}"
        w(root, f"{d}/topology/thread_siblings_list", sib.get(n, str(n)))
        w(root, f"{d}/topology/core_id", MTL_CORE_ID[n])
        w(root, f"{d}/topology/physical_package_id", 0)
        if n < 20:
            w(root, f"{d}/cache/index3/shared_cpu_list", "0-19")
        if n in (1, 2, 3, 4):
            mx, base = 4800000, 1400000
        elif n < 12:
            mx, base = 4500000, 1400000
        elif n < 20:
            mx, base = 3800000, 900000
        else:
            mx, base = 2500000, 700000
        f = f"{d}/cpufreq"
        w(root, f"{f}/scaling_governor", "powersave")
        w(root, f"{f}/scaling_available_governors", "performance powersave")
        w(root, f"{f}/cpuinfo_min_freq", 400000)
        w(root, f"{f}/cpuinfo_max_freq", mx)
        w(root, f"{f}/base_frequency", base)
        w(root, f"{f}/scaling_min_freq", 400000)
        w(root, f"{f}/scaling_max_freq", mx)
        w(root, f"{f}/scaling_cur_freq", 1900000)
        w(root, f"{f}/energy_performance_preference", "balance_performance")
        for i, (name, lat) in enumerate(IDLE):
            w(root, f"{d}/cpuidle/state{i}/name", name)
            w(root, f"{d}/cpuidle/state{i}/latency", lat)
            w(root, f"{d}/cpuidle/state{i}/disable", 0)
        w(root, f"{d}/thermal_throttle/core_throttle_count",
          {1: 7251, 3: 12729, 6: 26}.get(n, 0))
        w(root, f"{d}/thermal_throttle/package_throttle_count", 1000 + n)
    w(root, f"{c}/intel_pstate/status", "active")
    w(root, f"{c}/intel_pstate/no_turbo", 0)
    u = f"{c}/intel_uncore_frequency/package_00_die_00"
    w(root, f"{u}/initial_min_freq_khz", 400000)
    w(root, f"{u}/initial_max_freq_khz", 3300000)
    w(root, f"{u}/min_freq_khz", 400000)
    w(root, f"{u}/max_freq_khz", 3300000)
    w(root, "sys/devices/virtual/workqueue/cpumask", "3fffff")
    w(root, "sys/firmware/acpi/platform_profile", "balanced")
    w(root, "sys/firmware/acpi/platform_profile_choices",
      "low-power balanced performance")
    w(root, "sys/class/power_supply/ACAD/type", "Mains")
    w(root, "sys/class/power_supply/ACAD/online", 1)
    w(root, "sys/class/power_supply/BAT1/type", "Battery")
    w(root, "sys/class/power_supply/BAT1/capacity", 81)
    w(root, "sys/class/thermal/thermal_zone8/type", "x86_pkg_temp")
    w(root, "sys/class/thermal/thermal_zone8/temp", 50000)
    w(root, "sys/class/thermal/cooling_device27/type", "intel_powerclamp")
    w(root, "sys/class/thermal/cooling_device27/cur_state", 0)
    w(root, "sys/class/thermal/cooling_device5/type", "Processor")
    w(root, "sys/class/thermal/cooling_device5/cur_state", 0)
    w(root, "sys/class/hwmon/hwmon5/name", "coretemp")
    for i, cid in enumerate(sorted(set(MTL_CORE_ID.values()))):
        w(root, f"sys/class/hwmon/hwmon5/temp{i + 2}_label", f"Core {cid}")
        w(root, f"sys/class/hwmon/hwmon5/temp{i + 2}_input", 45000 + cid)
    for k, v in (("sys_vendor", "LENOVO"), ("product_name", "83DA"),
                 ("product_version", "IdeaPad Slim 5 14IMH9"),
                 ("bios_version", "N7CN32WW")):
        w(root, f"sys/class/dmi/id/{k}", v)
    w(root, "proc/sys/kernel/nmi_watchdog", 1)
    w(root, "proc/cpuinfo", "processor\t: 0\nmicrocode\t: 0x25")
    for irq in range(6):
        w(root, f"proc/irq/{irq}/smp_affinity_list", "0-21")
    w(root, "proc/irq/7/smp_affinity_list", "0,5")        # gia' a posto
    w(root, "proc/irq/9/smp_affinity_list", "0-21")       # gestito dal kernel
    w(root, "proc/irq/default_smp_affinity", "3fffff")
    w(root, "proc/self/cgroup",
      "0::/user.slice/user-1000.slice/session-2.scope")
    os.makedirs(os.path.join(root, f"proc/self/task/{ME}"), exist_ok=True)
    for pid, (comm, flags) in KTHREADS.items():
        w(root, f"proc/{pid}/comm", comm)
        w(root, f"proc/{pid}/stat",
          f"{pid} ({comm}) S 2 0 0 0 -1 {flags} 0 0 0 0 0 0")
    os.makedirs(os.path.join(root, "run"), exist_ok=True)


def build_flat(root, n=4):
    """Una macchina piatta: n core, niente SMT, un tipo solo, niente
    cpufreq ne' cpuidle."""
    c = "sys/devices/system/cpu"
    w(root, f"{c}/online", f"0-{n - 1}")
    for i in range(n):
        w(root, f"{c}/cpu{i}/topology/thread_siblings_list", i)
        w(root, f"{c}/cpu{i}/topology/core_id", i)


def build_smt_server(root):
    """8 core / 16 thread non ibrido, fratelli (i, i+8)."""
    c = "sys/devices/system/cpu"
    w(root, f"{c}/online", "0-15")
    for i in range(16):
        w(root, f"{c}/cpu{i}/topology/thread_siblings_list",
          f"{i % 8},{i % 8 + 8}")
        w(root, f"{c}/cpu{i}/topology/core_id", i % 8)
        w(root, f"{c}/cpu{i}/cpufreq/cpuinfo_max_freq", 3600000)


def snapshot(root, skip=("proc/self/cgroup",)):
    out = {}
    for d, _, files in os.walk(root):
        for f in files:
            rel = os.path.relpath(os.path.join(d, f), root)
            if rel in skip or rel.startswith("run/"):
                continue
            with open(os.path.join(d, f), "rb") as fh:
                out[rel] = fh.read()
    return out


class FakeSystem:
    """systemctl / powerprofilesctl / busctl, con il loro stato."""

    def __init__(self, root):
        self.root = root
        self.profile = "balanced"
        self.allowed = {"init.scope": "", "system.slice": "",
                        "user.slice": "", "machine.slice": ""}
        self.active_units = {"init.scope", "system.slice", "user.slice"}
        self.calls = []

    def __call__(self, argv, timeout=15):
        self.calls.append(list(argv))
        if argv[:2] == ["systemctl", "is-active"]:
            return ((0, "active\n", "")
                    if argv[2] in ("power-profiles-daemon", "thermald")
                    else (3, "inactive\n", ""))
        if argv[:2] == ["powerprofilesctl", "get"]:
            return 0, self.profile + "\n", ""
        if argv[:2] == ["powerprofilesctl", "set"]:
            self.profile = argv[2]
            return 0, "", ""
        if argv[:1] == ["busctl"] and "StartTransientUnit" in argv:
            w(self.root, "proc/self/cgroup",
              f"0::/{HC.SCOPE_SLICE}/{argv[6]}")
            return 0, 'o "/org/freedesktop/systemd1/job/77"\n', ""
        if argv[:3] == ["systemctl", "show", "-p"]:
            unit = argv[5]
            if argv[3] == "ActiveState":
                return 0, ("active" if unit in self.active_units
                           else "inactive") + "\n", ""
            if argv[3] == "AllowedCPUs":
                return 0, self.allowed.get(unit, "") + "\n", ""
        if argv[:3] == ["systemctl", "set-property", "--runtime"]:
            prop, _, val = argv[4].partition("=")
            self.allowed[argv[3]] = val
            return 0, "", ""
        return 0, "", ""


class FakeAffinity:
    def __init__(self, online):
        self.aff = {pid: set(online) for pid in KTHREADS}
        self.aff[ME] = set(online)
        self.refuse = set()

    def get(self, pid):
        return set(self.aff.get(pid, set()))

    def set(self, pid, cpus):
        if pid in self.refuse:
            raise PermissionError("rifiutato")
        self.aff[pid] = set(cpus)


def conditioner(root, roles, fake, aff, **kw):
    topo = HC.Topology.read(HC.Paths(root))
    kw.setdefault("getpid", lambda: ME)
    return HC.HostConditioner(
        topo, roles["dut"], roles["gen"], roles["egress"],
        paths=HC.Paths(root), runner=fake, setaffinity=aff.set,
        getaffinity=aff.get, **kw)


def simulate_crash(c):
    """Il processo muore senza ripristinare: niente restore, niente atexit."""
    c.active = False
    atexit.unregister(c.restore)
    for s, h in c._handlers.items():
        signal.signal(s, h)
    c._handlers = {}


def cpu_file(root, cpu, *parts):
    return HC.read_text(os.path.join(root, "sys/devices/system/cpu",
                                     f"cpu{cpu}", *parts))


# --------------------------------------------------------------------------
# the checks
# --------------------------------------------------------------------------
def t_lists():
    print("[1] liste e maschere di CPU")
    check("parse: '0,5,12-21'",
          HC.parse_cpu_list("0,5,12-21") == [0, 5] + list(range(12, 22)))
    check("parse: spazi e a capo come separatori",
          HC.parse_cpu_list("0 5\n7-8") == [0, 5, 7, 8])
    check("format: ritorno", HC.format_cpu_list([21, 0, 5, 12, 13, 14, 15, 16,
                                                  17, 18, 19, 20])
          == "0,5,12-21")
    check("maschera di 22 CPU = 3fffff",
          HC.cpu_mask_hex(range(22)) == "3fffff")
    check("maschera oltre 32 CPU: gruppi da 32 bit",
          HC.cpu_mask_hex([0, 40]) == "100,00000001"
          and HC.parse_cpu_mask("100,00000001") == [0, 40])
    check("maschera vuota", HC.cpu_mask_hex([]) == "0")
    try:
        HC.parse_cpu_list("5-2")
        check("intervallo rovesciato rifiutato", False)
    except ValueError:
        check("intervallo rovesciato rifiutato", True)


def t_topology(root):
    print("[2] topologia di questo portatile")
    topo = HC.Topology.read(HC.Paths(root))
    kinds = {c: topo.kind(c) for c in topo.online}
    check("P 0-11, E 12-19, LP E 20-21 (senza L3)",
          all(kinds[c] == "P" for c in range(12))
          and all(kinds[c] == "E" for c in range(12, 20))
          and kinds[20] == kinds[21] == "LPE", str(kinds))
    check("ibrida e con SMT", topo.hybrid and topo.smt and topo.structured)
    check("i fratelli veri: 0 con 5, 1 con 2",
          topo.core(0) == (0, 5) and topo.core(5) == (0, 5)
          and topo.core(1) == (1, 2))
    check("6 core fisici P, 8 E, 2 LP E: 16 core",
          len(topo.cores()) == 16)
    check("etichetta", topo.label(6) == "cpu6 (P, fratello 7)",
          topo.label(6))
    check("riassunto", "LP E-core 20-21" in topo.summary()
          and "P-core 0-11 (SMT)" in topo.summary(), topo.summary())


def roles_ok(topo, r):
    used = r["dut"] + r["gen"] + ([r["egress"]] if r["egress"] is not None
                                  else [])
    cores = [topo.core(c) for c in used]
    hk = HC.housekeeping(topo, used)
    sib = HC.idle_siblings(topo, used)
    return (len(set(cores)) == len(cores)
            and not (set(hk) & (set(used) | set(sib)))
            and set(hk) | set(used) | set(sib) == set(topo.online))


def t_plan(root, flat, smt):
    print("[3] i ruoli")
    topo = HC.Topology.read(HC.Paths(root))
    r = HC.plan_roles(topo, want_egress=True)
    check("DUT su un P-core non preferito (turbo 4,5 GHz): cpu6",
          r["dut"] == [6], str(r))
    check("uscita cpu8, generatore cpu10, 1, 3", r["egress"] == 8
          and r["gen"] == [10, 1, 3], str(r))
    used = r["dut"] + r["gen"] + [r["egress"]]
    check("nessun ruolo sul core della CPU 0 (0 e 5)",
          not ({0, 5} & set(used)))
    check("un thread per core fisico, fratelli a riposo, il resto al "
          "sistema", roles_ok(topo, r))
    check("fratelli a riposo 2,4,7,9,11",
          HC.idle_siblings(topo, used) == [2, 4, 7, 9, 11])
    check("sistema 0,5,12-21",
          HC.format_cpu_list(HC.housekeeping(topo, used)) == "0,5,12-21")
    r = HC.plan_roles(topo)
    check("senza uscita: generatore 8, 10, 1", r["gen"] == [8, 10, 1]
          and r["egress"] is None, str(r))
    r = HC.plan_roles(topo, n_gen=4, want_egress=True)
    check("--threads 4 prima dell'uscita: 4 P-core al generatore, uscita "
          "no (e lo dice)", r["gen"] == [8, 10, 1, 3] and r["egress"] is None
          and any("uscita" in n for n in r["notes"]), str(r))
    r = HC.plan_roles(topo, n_gen=6)
    check("--threads 6: esteso sugli E-core (mai sui LP E), e lo dice",
          r["gen"] == [8, 10, 1, 3, 12, 13]
          and any("lenti" in n for n in r["notes"]), str(r))
    r = HC.plan_roles(topo, allow_cpu0=True)
    check("--allow-cpu0: il core 0/5 torna disponibile",
          0 in r["dut"] + r["gen"], str(r))

    ft = HC.Topology.read(HC.Paths(flat))
    check("macchina piatta: niente scelta da fare (structured falso)",
          not ft.structured)
    r = HC.plan_roles(ft, want_egress=True)
    check("piatta a 4 core: DUT 1, generatore 2,3, niente uscita",
          r["dut"] == [1] and r["gen"] == [2, 3] and r["egress"] is None,
          str(r))
    check("piatta: spare_core dopo gen 1,2 e DUT 3 = nessuno",
          HC.spare_core(ft, [1, 2, 3]) is None)

    st = HC.Topology.read(HC.Paths(smt))
    r = HC.plan_roles(st, want_egress=True)
    check("server SMT non ibrido: DUT 1, uscita 2, generatore 3,4,5",
          r["dut"] == [1] and r["egress"] == 2 and r["gen"] == [3, 4, 5],
          str(r))
    used = r["dut"] + r["gen"] + [r["egress"]]
    check("server SMT: fratelli 9-13 a riposo, sistema 0,6-8,14-15",
          HC.format_cpu_list(HC.idle_siblings(st, used)) == "9-13"
          and HC.format_cpu_list(HC.housekeeping(st, used)) == "0,6-8,14,15"
          .replace("14,15", "14-15"))
    check("server SMT: ruoli validi", roles_ok(st, r))


def t_apply_restore(root):
    print("[4] applicare e ripristinare, su un albero finto")
    before = snapshot(root)
    fake = FakeSystem(root)
    topo = HC.Topology.read(HC.Paths(root))
    aff = FakeAffinity(topo.online)
    aff_before = {k: set(v) for k, v in aff.aff.items()}
    irq9 = os.path.join(root, "proc/irq/9/smp_affinity_list")
    if os.geteuid() != 0:
        os.chmod(irq9, 0o444)           # un IRQ che il kernel non lascia
    aff.refuse.add(2)                   # un kthread che rifiuta
    r = HC.plan_roles(topo, want_egress=True)
    c = conditioner(root, r, fake, aff)
    c.apply()
    bench = [1, 3, 6, 8, 10]
    sibs = [2, 4, 7, 9, 11]
    check("governor performance e min = max = 3500 MHz su banco e fratelli",
          all(cpu_file(root, n, "cpufreq", "scaling_governor") == "performance"
              and cpu_file(root, n, "cpufreq", "scaling_min_freq") == "3500000"
              and cpu_file(root, n, "cpufreq", "scaling_max_freq") == "3500000"
              for n in bench + sibs))
    check("target per il monitor sulle CPU del banco",
          c.target_khz == {n: 3500000 for n in bench}, str(c.target_khz))
    check("CPU del sistema: tetto 2500 MHz, governor invariato",
          all(cpu_file(root, n, "cpufreq", "scaling_max_freq") == "2500000"
              and cpu_file(root, n, "cpufreq", "scaling_governor")
              == "powersave" for n in [0, 5] + list(range(12, 22))))
    check("idle: C6 e C10 spenti sulle CPU del banco, POLL e C1E no",
          all(cpu_file(root, n, "cpuidle", f"state{i}", "disable")
              == ("1" if i >= 2 else "0") for n in bench for i in range(4)))
    check("idle: i fratelli possono ancora dormire (C10 acceso)",
          all(cpu_file(root, n, "cpuidle", "state3", "disable") == "0"
              for n in sibs))
    unc = os.path.join(root, "sys/devices/system/cpu/intel_uncore_frequency/"
                             "package_00_die_00")
    check("uncore fissata al massimo",
          HC.read_text(os.path.join(unc, "min_freq_khz")) == "3300000"
          and HC.read_text(os.path.join(unc, "max_freq_khz")) == "3300000")
    check("profilo performance via power-profiles-daemon",
          fake.profile == "performance")
    check("user/system/init confinati su 0,5,12-21, machine.slice no",
          all(fake.allowed[u] == "0,5,12-21" for u in
              ("init.scope", "system.slice", "user.slice"))
          and fake.allowed["machine.slice"] == "")
    check("il banco in uno scope suo PRIMA del confinamento",
          [i for i, a in enumerate(fake.calls) if a[0] == "busctl"][0]
          < [i for i, a in enumerate(fake.calls)
             if a[:2] == ["systemctl", "set-property"]][0])
    check("i thread del banco sulle CPU del sistema",
          aff.aff[ME] == set(HC.housekeeping(topo, bench)))
    irqs = [HC.read_text(os.path.join(root, f"proc/irq/{i}/smp_affinity_list"))
            for i in range(6)]
    check("IRQ spostati", all(v == "0,5,12-21" for v in irqs), str(irqs))
    check("IRQ gia' a posto non toccato",
          HC.read_text(os.path.join(root, "proc/irq/7/smp_affinity_list"))
          == "0,5")
    if os.geteuid() != 0:
        check("IRQ rifiutato dal kernel: resta com'era e si dice",
              HC.read_text(irq9) == "0-21"
              and "1 non spostabili" in dict(c.facts)["isolamento_irq"],
              dict(c.facts).get("isolamento_irq"))
    hk_mask = HC.cpu_mask_hex(HC.housekeeping(topo, bench))
    check("default_smp_affinity e workqueue unbound = CPU del sistema",
          HC.read_text(os.path.join(root, "proc/irq/default_smp_affinity"))
          == hk_mask and HC.read_text(os.path.join(
              root, "sys/devices/virtual/workqueue/cpumask")) == hk_mask)
    check("kthread: rcu_preempt spostato; per-CPU, napi e processi no; "
          "rifiuto contato",
          aff.aff[15] == set(HC.housekeeping(topo, bench))
          and aff.aff[20] == set(topo.online)
          and aff.aff[30] == set(topo.online)
          and aff.aff[100] == set(topo.online) and aff.aff[2]
          == set(topo.online), str({k: HC.format_cpu_list(v)
                                    for k, v in aff.aff.items()}))
    check("NMI watchdog spento",
          HC.read_text(os.path.join(root, "proc/sys/kernel/nmi_watchdog"))
          == "0")
    state = HC.load_state(HC.Paths(root))
    check("stato salvato durante il run, con il pid",
          state and state["pid"] == ME
          and len(state["changes"]) == len(c.changes))
    check("EPP ricordato prima del governor (si ripristina dopo)",
          any(ch.get("new") is None and "energy_performance" in ch["path"]
              for ch in state["changes"]))
    env = dict(HC.env_pairs(HC.Roles(topo, r["dut"], r["gen"], r["egress"]),
                            host=c, paths=HC.Paths(root), runner=fake))
    check("env: ruoli, frequenza fissata, idle, condizionamento",
          env.get("ruolo_dut") == "cpu6 (P, fratello 7)"
          and "3500-3500 MHz" in env.get("frequenza_banco", "")
          and env.get("idle_banco") == "cpu 1,3,6,8,10: POLL,C1E"
          and env.get("condizionamento", "").startswith("applicato"),
          str({k: env.get(k) for k in ("ruolo_dut", "frequenza_banco",
                                       "idle_banco", "condizionamento")}))

    failed = c.restore()
    after = snapshot(root)
    diff = sorted(k for k in set(before) | set(after)
                  if before.get(k) != after.get(k))
    check("RIPRISTINO: albero identico byte per byte", not diff
          and not failed, f"{diff[:5]} {failed[:2]}")
    check("ripristino: profilo e AllowedCPUs come prima",
          fake.profile == "balanced"
          and all(v == "" for v in fake.allowed.values()))
    check("ripristino: affinita' dei kthread come prima",
          all(aff.aff[k] == aff_before[k] for k in KTHREADS))
    check("ripristino: file di stato cancellato",
          not os.path.exists(HC.Paths(root).state))
    check("ripristino idempotente", c.restore() == [])
    if os.geteuid() != 0:
        os.chmod(irq9, 0o644)


def t_crash(root):
    print("[5] un run ucciso senza ripristino")
    before = snapshot(root)
    fake = FakeSystem(root)
    topo = HC.Topology.read(HC.Paths(root))
    aff = FakeAffinity(topo.online)
    r = HC.plan_roles(topo, want_egress=True)
    c = conditioner(root, r, fake, aff)
    c.apply()
    simulate_crash(c)
    check("dopo il crash la macchina e' cambiata e lo stato e' su disco",
          snapshot(root) != before and os.path.exists(HC.Paths(root).state))
    c2 = conditioner(root, r, fake, aff, alive=lambda pid: True,
                     getpid=lambda: ME + 1)
    try:
        c2.apply()
        check("un altro banco vivo: si rifiuta", False)
        simulate_crash(c2)
    except RuntimeError:
        check("un altro banco vivo: si rifiuta", True)
    n = HC.recover_stale_state(HC.Paths(root), fake, alive=lambda pid: False,
                               me=1, setaffinity=aff.set)
    after = snapshot(root)
    diff = sorted(k for k in set(before) | set(after)
                  if before.get(k) != after.get(k))
    check("--restore riporta tutto com'era", n > 0 and not diff
          and fake.profile == "balanced", str(diff[:5]))
    c3 = conditioner(root, r, fake, aff, alive=lambda pid: False)
    c3.apply()
    simulate_crash(c3)
    c4 = conditioner(root, r, fake, aff, alive=lambda pid: False)
    c4.apply()                      # ripristina lo stato vecchio, poi applica
    c4.restore()
    after = snapshot(root)
    diff = sorted(k for k in set(before) | set(after)
                  if before.get(k) != after.get(k))
    check("il run dopo un crash ripristina prima di applicare", not diff,
          str(diff[:5]))


def t_knobs(root):
    print("[6] le manopole")
    before = snapshot(root)
    fake = FakeSystem(root)
    topo = HC.Topology.read(HC.Paths(root))
    aff = FakeAffinity(topo.online)
    r = HC.plan_roles(topo, want_egress=True)
    c = conditioner(root, r, fake, aff, freq="keep", system_max_mhz="keep",
                    uncore="keep", cstate_max_us=None, isolate=False,
                    profile="keep", nmi_off=False)
    c.apply()
    check("tutto keep: nessuna modifica", not c.changes
          and snapshot(root) == before and fake.profile == "balanced")
    c.restore()
    c = conditioner(root, r, fake, aff, freq="base", isolate=False,
                    profile="keep", system_max_mhz="keep")
    c.apply()
    check("--freq base: min = max = base_frequency (1400 MHz)",
          cpu_file(root, 6, "cpufreq", "scaling_max_freq") == "1400000"
          and cpu_file(root, 6, "cpufreq", "scaling_min_freq") == "1400000")
    c.restore()
    c = conditioner(root, r, fake, aff, freq="2000", isolate=False,
                    profile="keep", system_max_mhz="keep")
    c.apply()
    check("--freq 2000: min = max = 2000 MHz",
          cpu_file(root, 6, "cpufreq", "scaling_max_freq") == "2000000"
          and cpu_file(root, 6, "cpufreq", "scaling_min_freq") == "2000000")
    c.restore()
    c = conditioner(root, r, fake, aff, freq="9999", isolate=False,
                    profile="keep", system_max_mhz="keep")
    c.apply()
    check("--freq 9999: tagliata al massimo di ogni CPU",
          cpu_file(root, 6, "cpufreq", "scaling_max_freq") == "4500000"
          and cpu_file(root, 1, "cpufreq", "scaling_max_freq") == "4800000")
    c.restore()
    c = conditioner(root, r, fake, aff, freq="max", isolate=False,
                    profile="keep", system_max_mhz="keep", cstate_max_us=0)
    c.apply()
    check("--freq max: performance, minimo non toccato, nessun target",
          cpu_file(root, 6, "cpufreq", "scaling_governor") == "performance"
          and cpu_file(root, 6, "cpufreq", "scaling_min_freq") == "400000"
          and not c.target_khz)
    check("--cstate-max-us 0: resta solo POLL",
          [cpu_file(root, 6, "cpuidle", f"state{i}", "disable")
           for i in range(4)] == ["0", "1", "1", "1"])
    c.restore()
    check("dopo tutte le prove l'albero e' quello di partenza",
          snapshot(root) == before)

    class A:
        pass
    a = A()
    a.freq, a.system_max_mhz, a.uncore, a.cstate_max_us = "x", "1", "max", "1"
    try:
        HC.check_args(a)
        check("--freq non valida rifiutata", False)
    except SystemExit:
        check("--freq non valida rifiutata", True)
    check("--egress-cpu: auto, none, numero",
          HC.parse_egress("auto") == "auto" and HC.parse_egress("none") is None
          and HC.parse_egress("8") == 8 and HC.parse_egress(None) is None)


def t_monitor(root):
    print("[7] il monitor")
    GHZ = 1e9
    a = dict(t=0.0, core_thr={6: 26, 8: 0}, pkg_thr={6: 1006, 8: 1008},
             msr=(0, 0, 0), smi=3, pkg_temp_mc=50000, dut_temp_mc=48000,
             clamp=0, cooling=0, ac=True)
    # 0,5 s a TSC 3 GHz; DUT occupato al 60% a 1,4 GHz
    b = dict(a, t=0.5, msr=(int(0.5 * 0.6 * 1.4 * GHZ), int(0.5 * 0.6 * 3 * GHZ),
                            int(0.5 * 3 * GHZ)), smi=3, pkg_temp_mc=52000)
    h = HC.host_columns(a, b, 1400000)
    check("frequenza del DUT da APERF/MPERF: 1400 MHz, occupato 60%",
          h["host_dut_mhz"] == 1400 and h["host_dut_busy_pct"] == 60.0, str(h))
    check("condizioni rispettate: non disturbata",
          not h["host_disturbed"] and h["host_throttle_core"] == 0
          and h["host_smi"] == 0 and h["host_pkg_temp_c"] == 52.0)
    check("frequenza fuori target: disturbata",
          HC.host_columns(a, b, 2000000)["host_disturbed"])
    idle = dict(b, msr=(int(0.5 * 0.1 * 1.4 * GHZ), int(0.5 * 0.1 * 3 * GHZ),
                        int(0.5 * 3 * GHZ)))
    check("DUT quasi fermo: la frequenza non si giudica",
          not HC.host_columns(a, idle, 2000000)["host_off_target"])
    hot = dict(b, core_thr={6: 29, 8: 0})
    check("throttling di un core: disturbata, eventi contati",
          HC.host_columns(a, hot)["host_disturbed"]
          and HC.host_columns(a, hot)["host_throttle_core"] == 3)
    pk = dict(b, pkg_thr={6: 1006, 8: 1010})
    check("throttling del pacchetto: massimo fra le CPU",
          HC.host_columns(a, pk)["host_throttle_pkg"] == 2)
    check("a batteria: disturbata",
          HC.host_columns(a, dict(b, ac=False))["host_disturbed"])
    check("powerclamp attivo: disturbata",
          HC.host_columns(a, dict(b, clamp=50))["host_disturbed"])
    check("letture mancanti: nessuna colonna",
          HC.host_columns(None, b) == {})

    topo = HC.Topology.read(HC.Paths(root))
    m = HC.HostMonitor(topo, [6, 8, 10], dut=6, paths=HC.Paths(root),
                       target_khz={6: 1400000}, use_msr=False)
    x = m.mark()
    check("mark sul sysfs finto: temperature, throttling, rete",
          x["pkg_temp_mc"] == 50000 and x["dut_temp_mc"] == 45020
          and x["core_thr"][6] == 26 and x["ac"] is True, str(x))
    check("target del DUT dal dizionario", m.dut_target_khz == 1400000)
    log = os.path.join(root, "log.csv")
    HC.log_loop(log, [6, 8], period=0.01, paths=HC.Paths(root),
                max_samples=2)
    s = HC.summarise_log(log)
    check("registro: due campioni, temperatura, nessun throttling",
          s and s["samples"] == 2 and s["temp_max_c"] == 50.0
          and s["throttle_core"] == 0, str(s))
    with open(log) as f:
        head = f.readline().strip().split(",")
    check("registro: una colonna di frequenza per CPU osservata",
          head[-2:] == ["mhz_cpu6", "mhz_cpu8"], str(head))


def t_cli(root):
    print("[8] riga di comando")
    p = HC.argparse.ArgumentParser()
    p.add_argument("--run", action="store_true")
    HC.add_args(p)
    p.add_argument("cmd", nargs=HC.argparse.REMAINDER)
    a = p.parse_args(["--run", "--freq", "2000", "--", "python3",
                      "ipa/test/test_suite.py", "--only", "kernel"])
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    check("--run -- COMANDO: le opzioni del comando restano sue",
          a.run and a.freq == "2000"
          and cmd == ["python3", "ipa/test/test_suite.py", "--only",
                      "kernel"], str(a.cmd))
    rc = HC.show(HC.Paths(root))
    check("--show sull'albero finto", rc == 0)


def t_bench_plan(root, flat):
    print("[9] bench_throughput: piano CPU e code del DUT")
    import bench_throughput as B
    topo = HC.Topology.read(HC.Paths(root))
    p = B.plan_cpus(topo=topo, check_pktgen=False)
    check("senza liste, su questa macchina: DUT 6, generatore 8,10,1",
          p.dut == [6] and p.gen == [8, 10, 1] and p.egress is None
          and not p.shared, f"{p.dut} {p.gen} {p.egress}")
    check("la regola storica avrebbe dato 14 thread pktgen e il DUT sugli E",
          len(p.gen) == 3)
    p = B.plan_cpus(topo=topo, check_pktgen=False, egress_spec="auto")
    check("--egress-cpu auto: uscita 8, generatore 10,1,3",
          p.egress == 8 and p.gen == [10, 1, 3], f"{p.gen} {p.egress}")
    check("CPU lasciate al sistema = 0,5,12-21, fratelli a riposo a parte",
          HC.format_cpu_list(p.excluded) == "0,5,12-21"
          and p.idle_siblings == [2, 4, 7, 9, 11], f"{p.excluded}")
    p = B.plan_cpus(topo=topo, check_pktgen=False, egress_spec=8)
    check("--egress-cpu 8 esplicita: il piano lascia libero il suo core",
          p.egress == 8 and not ({8, 9} & set(p.gen + p.dut)),
          f"{p.dut} {p.gen} {p.egress}")
    p = B.plan_cpus(gen_spec="2", dut_spec="1", topo=topo,
                    check_pktgen=False)
    check("generatore sul fratello SMT del DUT: dichiarato condiviso",
          p.shared and any("SMT" in n for n in p.notes), str(p.notes))
    p = B.plan_cpus(gen_spec="8,10", dut_spec="6", topo=topo,
                    check_pktgen=False)
    check("liste esplicite: rispettate", p.gen == [8, 10] and p.dut == [6]
          and not p.shared)
    ft = HC.Topology.read(HC.Paths(flat))
    p = B.plan_cpus(threads=2, topo=ft, check_pktgen=False,
                    egress_spec="auto")
    check("piatta a 4 core: la regola semplice (generatore 1,2, DUT 3), "
          "niente uscita libera", p.gen == [1, 2] and p.dut == [3]
          and p.egress is None, f"{p.gen} {p.dut} {p.egress}")

    class P:
        gen, dut = [8, 10, 1], [6]
    old = B.DUT_QUEUES
    try:
        B.DUT_QUEUES = None
        check("code: storico, una per thread generatore",
              B.ingress_queues(P) == (3, 3))
        B.DUT_QUEUES = 1
        check("code: una sola, tutti i thread pktgen su quella",
              B.ingress_queues(P) == (1, 1))
        B.DUT_QUEUES = 4
        check("code: piu' del generatore, rx >= tx",
              B.ingress_queues(P) == (3, 4))
    finally:
        B.DUT_QUEUES = old
    check("--dut-queues auto = CPU del DUT, gen = storico, numero",
          B.parse_dut_queues("auto", P) == 1
          and B.parse_dut_queues("gen", P) is None
          and B.parse_dut_queues("2", P) == 2)


def main():
    tmp = tempfile.mkdtemp(prefix="ipa_hc_")
    try:
        mtl = os.path.join(tmp, "mtl")
        flat = os.path.join(tmp, "flat")
        smt = os.path.join(tmp, "smt")
        build_mtl(mtl)
        build_flat(flat)
        build_smt_server(smt)
        t_lists()
        t_topology(mtl)
        t_plan(mtl, flat, smt)
        t_apply_restore(mtl)
        t_crash(mtl)
        t_knobs(mtl)
        t_monitor(mtl)
        t_cli(mtl)
        t_bench_plan(mtl, flat)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n, ok = len(RESULTS), sum(RESULTS)
    print(f"\n{ok}/{n} PASS")
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
