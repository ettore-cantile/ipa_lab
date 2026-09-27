#!/usr/bin/env python3
"""
host_conditions.py -- le condizioni della macchina mentre i banchi misurano:
chi gira dove, a che frequenza, con quali stati di idle, e che cosa e'
successo alla macchina durante ogni finestra.

--------------------------------------------------------------------------
PERCHE'
--------------------------------------------------------------------------
Un banco che misura nanosecondi per pacchetto deve decidere su che core
gira, a che frequenza e che cosa gli gira accanto; lasciato al sistema, il
numero misura il sistema. Qui va deciso con cura, perche' la macchina di
laboratorio (Ubuntu 24.04) e' un portatile con un processore IBRIDO (Intel
Core Ultra 7 155H, Lenovo IdeaPad Slim 5):

  P-core   0-11   6 core fisici con SMT -- coppie 0/5, 1/2, 3/4, 6/7, 8/9,
                  10/11 -- base 1,4 GHz, turbo 4,5 GHz (4,8 su 1-4)
  E-core   12-19  8 core, base 0,9 GHz, turbo 3,8 GHz
  LP E     20-21  2 core fuori dalla L3, turbo 2,5 GHz

Lasciata a se' stessa, questa macchina mette il DUT dove capita (anche su un
E-core), fa girare desktop e browser sul fratello SMT del DUT, cambia
frequenza fra 0,4 e 4,8 GHz secondo carico e temperatura, e addormenta i
core in C10, da cui il risveglio costa 310 us: piu' di quanto il ring del
veth (256 descrittori) copra a 1 Mpps. E scalda: il 2026-09-27, a desktop
quasi fermo, un solo P-core salito a 4,5-4,8 GHz ha portato il pacchetto da
51 a 99 C in due secondi, e dopo 41 minuti di uptime i P-core 1 e 3 contavano
gia' 7 251 e 12 729 eventi di throttling termico.

--------------------------------------------------------------------------
COSA FA (tutto reversibile, tutto riportato in env.csv)
--------------------------------------------------------------------------
  ruoli       DUT, uscita e generatore su P-core fisici DISTINTI, un thread
              per core; il fratello SMT di ognuno resta a riposo; il core
              della CPU 0 resta al sistema (plan_roles).
  frequenza   sui core del banco e sui loro fratelli: governor performance e
              min = max, 3500 MHz per default (DEFAULT_FREQ: la piu' alta
              che il portatile regge per un run intero), e poi MISURATA con
              APERF/MPERF, perche' il numero nel sysfs non sempre e' la
              frequenza vera. --freq.
  sistema     le CPU del sistema (desktop, browser, il processo del banco)
              con un tetto di frequenza, default 2,5 GHz: il loro turbo
              scalderebbe il pacchetto fino al throttling, e il throttling
              del pacchetto rallenta anche i core del banco. --system-max-mhz.
  uncore      min = max (default il massimo): la L3 e l'anello, su cui i
              pacchetti passano dal generatore al DUT, non cambiano velocita'
              a meta' misura. --uncore.
  idle        sulle CPU del banco si spengono gli stati di idle con uscita
              piu' lenta di --cstate-max-us (default 1 us: restano POLL e
              C1E, la soglia del profilo latency-performance di tuned).
  isolamento  user.slice, system.slice e init.scope confinati sulle CPU del
              sistema (AllowedCPUs di systemd, --runtime); sulle stesse CPU
              gli IRQ, le workqueue unbound e i kernel thread spostabili. Il
              processo del banco passa prima in uno scope suo, fuori da
              user.slice: senza, il confinamento lo porterebbe via dalle CPU
              su cui deve pinnare i propri thread (xdp_gen).
  profilo     power-profiles-daemon su "performance" (limiti di potenza e
              ventole della piattaforma).
  watchdog    NMI watchdog spento: un NMI ogni ~10 s su ogni CPU.

Durante il run, HostMonitor legge: eventi di throttling termico (core e
pacchetto), temperatura, frequenza REALE del DUT da APERF/MPERF, SMI,
powerclamp, alimentazione. Per finestra (bench_bitrate, colonne host_*) e per
l'intero run (env.csv); in piu' un registro al secondo in host_monitor.csv,
scritto da un processo a parte perche' non contenda il GIL al banco.

NON fa: isolcpus / nohz_full / rcu_nocbs (parametri di boot, servono un
riavvio: vedi docs/testing.md), non tocca il turbo globale, non spegne SMT.

--------------------------------------------------------------------------
IL RIPRISTINO
--------------------------------------------------------------------------
Ogni valore si legge e si salva PRIMA di cambiarlo, in
/run/ipa-bench/host_state.json, riscritto a ogni modifica. A fine run --
anche con Ctrl-C, SIGTERM, SIGHUP o un'eccezione -- si riscrive tutto in
ordine inverso e il file si cancella. Un run ucciso con SIGKILL lascia il
file: il run successivo lo trova e ripristina per primo, oppure

    sudo python3 ipa/test/host_conditions.py --restore

/run sta in memoria: al riavvio sparisce il file e, comunque, ogni modifica
(sono tutte runtime).

--------------------------------------------------------------------------
USO
--------------------------------------------------------------------------
    python3 ipa/test/host_conditions.py --show        # niente root
    sudo python3 ipa/test/host_conditions.py --restore
    # un comando qualunque sul core del DUT, a condizioni applicate
    # (per esempio i banchi BPF_PROG_TEST_RUN, che girano nel processo):
    sudo python3 ipa/test/host_conditions.py --run -- \\
        python3 ipa/test/test_suite.py --only kernel

bench_throughput e bench_bitrate lo usano da soli; --no-tune non tocca la
macchina, ma le condizioni vengono lette e scritte in env.csv lo stesso.
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
    """print che non solleva: il ripristino gira anche quando il terminale
    e' gia' chiuso (SIGHUP), e un EIO su una print non deve fermarlo a meta'."""
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
# Le unita' di systemd che si confinano: tutto cio' che non e' kernel e non e'
# il banco. machine.slice c'e' solo se systemd-machined ha qualcosa avviato.
CONFINED_UNITS = ("init.scope", "system.slice", "user.slice", "machine.slice")

# La frequenza fissa dei core del banco. Scelta sul portatile di laboratorio
# (Core Ultra 7 155H) il 2026-09-27 con run completi di bench_bitrate, 5 giri,
# 6 metodi, circa 5 minuti: a 4000 MHz 11 finestre su 260 in throttling
# termico, DUT compreso, pacchetto fino a 98 C; a 3500 MHz 1 su 390 (2 eventi
# di pacchetto), massimo 85 C, dispersione fra i giri 0,4-2%. "base" (1400 nel
# sysfs) dava ~2000 MHz misurati: vedi _step_measure_freq. Oltre il massimo di
# un core, la frequenza si taglia al suo massimo.
DEFAULT_FREQ = "3500"
# Il tetto delle CPU del SISTEMA (desktop, browser, il processo del banco)
# durante il run. Misurato il 2026-09-27: un solo P-core che sale a 4,5-4,8
# GHz porta il pacchetto da 51 a 99 C in due secondi, con un centinaio di
# eventi di throttling. Il throttling del pacchetto rallenta anche i core del
# banco, che hanno la frequenza fissata ma stanno sullo stesso silicio. A 2,5
# GHz il desktop resta usabile e nessun core fa da punto caldo.
DEFAULT_SYSTEM_MAX_MHZ = 2500
DEFAULT_UNCORE = "max"
DEFAULT_CSTATE_MAX_US = 1
DEFAULT_PROFILE = "performance"
# Thread del generatore quando nessuno li chiede. Tre portano la sola
# ricezione in saturazione a 3,5 GHz (circa 6 Mpps offerti contro 4,4
# ricevuti); tutti i thread scrivono sulla stessa coda del DUT (vedi
# bench_throughput.ingress_queues).
DEFAULT_GEN_THREADS = 3
MIN_GEN_THREADS = 2
# Oltre questo scarto la frequenza misurata sul DUT non e' quella fissata.
FREQ_TOLERANCE = 0.05
# Sotto questa occupazione APERF/MPERF misura troppo poco lavoro per dire
# qualcosa sulla frequenza.
FREQ_CHECK_MIN_BUSY_PCT = 20.0
# Durata del carico con cui si misura la frequenza di ogni core del banco.
MEASURE_S = 0.3

MSR_TSC, MSR_MPERF, MSR_APERF, MSR_SMI_COUNT = 0x10, 0xE7, 0xE8, 0x34
PF_KTHREAD = 0x00200000
PF_NO_SETAFFINITY = 0x04000000

KIND_RANK = {"P": 0, "-": 0, "E": 1, "?": 1, "LPE": 2}
KIND_NAME = {"P": "P-core", "E": "E-core", "LPE": "LP E-core", "-": "core",
             "?": "core"}


# ==========================================================================
# LETTURA E SCRITTURA, rispetto a una radice
# ==========================================================================
class Paths:
    """Dove leggere e scrivere. La radice e' "/" sulla macchina; i test la
    puntano a un albero finto, per verificare applicazione e ripristino senza
    root e senza toccare niente di vero."""

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
    """(codice, stdout, stderr), mai un'eccezione: un comando assente e' un
    codice 127, come nella shell."""
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


# ==========================================================================
# LISTE DI CPU: i due formati del kernel
# ==========================================================================
def parse_cpu_list(spec):
    """"0,5,12-21" -> [0, 5, 12, ..., 21]. Stringa vuota o None -> []."""
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
                raise ValueError(f"intervallo rovesciato: {part!r}")
            out.update(range(lo, hi + 1))
        else:
            out.add(int(part))
    return sorted(out)


def format_cpu_list(cpus):
    """[0, 5, 12, 13, 14] -> "0,5,12-14": il formato di *_list nel kernel e
    di AllowedCPUs in systemd."""
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
    """Maschera esadecimale nel formato delle bitmap del kernel: gruppi da 32
    bit separati da virgole, il piu' significativo per primo."""
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


# ==========================================================================
# TOPOLOGIA
# ==========================================================================
class Topology:
    """Le CPU online, il core fisico di ognuna (i fratelli SMT), il tipo di
    core e le frequenze. Tutto dal sysfs, niente root.

    Tipo: "P" / "E" / "LPE" su un Intel ibrido (/sys/devices/cpu_core e
    cpu_atom, i due PMU), "-" su una macchina non ibrida. I LP E-core di
    Meteor Lake sono gli E-core senza L3: stanno sul tile SoC, fuori dalla
    cache condivisa con il resto."""

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
            if hybrid:
                if c in core_set:
                    kind = "P"
                elif c in atom_set:
                    kind = "LPE" if (some_l3 and not l3[c]) else "E"
                else:
                    kind = "?"
            else:
                kind = "-"
            cpus[c] = dict(core=sib, core_id=_int(rd("topology", "core_id"), c),
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
        """C'e' una scelta da fare: core di tipi diversi, o fratelli SMT.
        Su una macchina piatta (niente SMT, un tipo di core solo) no, e il
        piano semplice di bench_throughput resta quello giusto."""
        return self.hybrid or self.smt

    def core(self, cpu):
        return self.cpus[cpu]["core"] if cpu in self.cpus else (cpu,)

    def siblings(self, cpu):
        return [s for s in self.core(cpu) if s != cpu]

    def kind(self, cpu):
        return self.cpus.get(cpu, {}).get("kind", "?")

    def cores(self):
        """I core fisici, come tuple dei loro thread, per prima CPU."""
        return sorted({v["core"] for v in self.cpus.values()},
                      key=lambda t: t[0])

    def label(self, cpu):
        parts = []
        k = self.kind(cpu)
        if k not in ("-", "?"):
            parts.append(k)
        sib = self.siblings(cpu)
        if sib:
            parts.append("fratello " + ",".join(str(s) for s in sib))
        return f"cpu{cpu}" + (f" ({', '.join(parts)})" if parts else "")

    def summary(self):
        if not self.hybrid:
            return (f"{len(self.online)} CPU, "
                    + ("SMT" if self.smt else "niente SMT") + ", non ibrida")
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
        return "ibrida: " + "; ".join(parts)


# ==========================================================================
# I RUOLI
# ==========================================================================
def plan_roles(topo, n_gen=None, want_egress=False, allow_cpu0=False,
               exclude=()):
    """DUT, uscita e generatore su core fisici distinti.

    Regole, in ordine:
      1. si parte dai core fisici; quello della CPU 0 resta al sistema
         (timer, RCU, IRQ), con il suo fratello SMT;
      2. si usano i core del tipo piu' veloce presente (P-core); un thread per
         core, il fratello resta a riposo -- due thread sullo stesso core
         fisico si dividono pipeline, cache L1/L2 e banda, e il costo per
         pacchetto dell'uno dipenderebbe dal lavoro dell'altro;
      3. il DUT prende il primo;
      4. l'uscita (il nodo successivo) un core suo, se ne resta uno dopo aver
         garantito il generatore: MIN_GEN_THREADS, o i thread chiesti;
      5. il generatore i successivi, DEFAULT_GEN_THREADS se non si chiede
         altro; sugli E-core solo se i P-core non bastano, e lo si dice;
         mai sui LP E-core.

    Fra i P-core vengono prima quelli con il turbo PIU' BASSO. A frequenza
    fissata si equivalgono; in turbo no, e i "preferiti" (1-4 su questa
    macchina, 4,8 GHz invece di 4,5) sono quelli su cui lo scheduler mette i
    picchi e che vanno in throttling: il 2026-09-27, a desktop quasi fermo,
    migliaia di eventi su 1 e 3, 26 su 6, zero su 8 e 10. Il DUT, che e' cio'
    che si misura, va dove la macchina e' piu' calma.

    `exclude`: CPU gia' assegnate altrove (un --egress-cpu esplicito): il
    loro core fisico resta fuori.

    Restituisce dict(dut=[cpu], gen=[cpu...], egress=cpu|None, notes=[...])."""
    notes = []
    ex = set(exclude)
    cores = [c for c in topo.cores()
             if (allow_cpu0 or 0 not in c) and not (set(c) & ex)]
    if not cores:
        cores = [c for c in topo.cores() if not (set(c) & ex)] \
            or list(topo.cores())
        notes.append("nessun core fuori da quello della CPU 0: lo uso lo "
                     "stesso")

    def rank(core):
        return KIND_RANK.get(topo.kind(core[0]), 1)

    def turbo(core):
        return max((topo.cpus.get(c, {}).get("max_khz") or 0) for c in core)

    best = min(rank(c) for c in cores)
    fast = sorted((c for c in cores if rank(c) == best),
                  key=lambda c: (turbo(c), c[0]))
    slow = [c for c in cores if best < rank(c) < KIND_RANK["LPE"]]
    if best > KIND_RANK["P"]:
        notes.append("nessun P-core disponibile: il banco gira su core lenti")
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
            notes.append(f"nessun {KIND_NAME[topo.kind(dut[0])]} libero per "
                         f"l'uscita dopo DUT e generatore: l'uscita resta "
                         f"sulla CPU del DUT (softirq)")

    gen = list(rest[:want])
    if len(gen) < want and (explicit or len(gen) < MIN_GEN_THREADS):
        need = (want if explicit else MIN_GEN_THREADS) - len(gen)
        extra = slow[:need]
        if extra:
            gen += extra
            notes.append("generatore esteso su core lenti ("
                         + ", ".join(topo.label(c[0]) for c in extra)
                         + "): offrono meno pacchetti al secondo, e meno "
                           "regolari")
    if explicit and len(gen) < want:
        notes.append(f"chiesti {want} thread generatore, ci sono {len(gen)} "
                     f"core fisici liberi: ne uso {len(gen)}")
    if not gen:
        sib = tuple(s for s in dut if s != dut[0])
        gen = [sib] if sib else [dut]
        notes.append("nessun core libero per il generatore: condivide il "
                     "core fisico del DUT, e la cifra assoluta misura la "
                     "somma dei due")
    return dict(dut=[dut[0]], gen=[c[0] for c in gen],
                egress=(egress[0] if egress else None), notes=notes)


def spare_core(topo, used, allow_cpu0=False):
    """La prima CPU di un core fisico del tipo piu' veloce senza nessun thread
    in `used`, o None. Serve all'uscita automatica col piano storico."""
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


def idle_siblings(topo, used):
    """I fratelli SMT dei thread usati: restano a riposo, fuori da tutto."""
    used = set(used)
    return sorted({s for c in used for s in topo.core(c)} - used)


def housekeeping(topo, used):
    """Le CPU del sistema: tutte, meno quelle del banco e i loro fratelli."""
    busy = set(used) | set(idle_siblings(topo, used))
    return [c for c in topo.online if c not in busy]


class Roles:
    """I ruoli di un comando qualunque (--run): stessa forma di
    bench_throughput.CpuPlan per quello che serve qui."""

    def __init__(self, topo, dut, gen=(), egress=None):
        self.topo = topo
        self.dut = list(dut)
        self.gen = list(gen)
        self.egress = egress

    @property
    def used(self):
        return sorted(set(self.dut) | set(self.gen)
                      | ({self.egress} if self.egress is not None else set()))


# ==========================================================================
# LO STATO SALVATO, E IL RIPRISTINO
# ==========================================================================
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
    """Riscrive all'indietro. Ogni voce e' indipendente: un fallimento si
    conta e si va avanti, perche' un ripristino a meta' e' peggio di uno con
    una voce mancante. Restituisce [(voce, errore)]."""
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
                # Il pid puo' essere stato riusato: si ripristina solo se e'
                # ancora lo stesso thread (stesso nome).
                if _comm_of(paths, ch["pid"]) == ch.get("comm"):
                    setaffinity(int(ch["pid"]), set(parse_cpu_list(ch["old"])))
        except (OSError, ValueError, KeyError) as e:
            failed.append((ch, str(e)))
    return failed


def recover_stale_state(paths=None, runner=None, alive=None, me=None,
                        setaffinity=None):
    """Se un run precedente e' morto senza ripristinare, ripristina adesso.

    Solleva RuntimeError se il file appartiene a un processo ancora vivo: due
    banchi con le condizioni applicate contemporaneamente si ripristinerebbero
    a vicenda i valori sbagliati. Restituisce le voci ripristinate."""
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
            f"le condizioni della macchina sono gia' applicate dal processo "
            f"{pid} ({paths.state}). Se quel processo non e' un banco: sudo "
            f"python3 ipa/test/host_conditions.py --restore --force")
    changes = data.get("changes", [])
    warn(f"stato di un run interrotto senza ripristino (pid {pid}, "
         f"{data.get('started', '?')}): ripristino {len(changes)} "
         f"impostazioni prima di cominciare")
    failed = restore_changes(changes, runner, paths, setaffinity)
    for ch, err in failed:
        warn(f"non ripristinato: {_describe_change(ch)} -- {err}")
    os.remove(paths.state)
    return len(changes)


def _describe_change(ch):
    k = ch.get("kind")
    if k == "file":
        return f"{ch.get('path')} = {ch.get('old')}"
    if k == "unit":
        return f"{ch.get('unit')} {ch.get('prop')}={ch.get('old')}"
    if k == "profile":
        return f"profilo {ch.get('old')}"
    if k == "affinity":
        return f"affinita' di {ch.get('comm')} ({ch.get('pid')}) = {ch.get('old')}"
    return str(ch)


def _uniform(values, fmt=str):
    """{cpu: valore} -> "cpu 1,3,6: v" se tutti uguali, altrimenti per CPU."""
    vals = {c: v for c, v in values.items()}
    if not vals:
        return "n/d"
    distinct = set(vals.values())
    if len(distinct) == 1:
        return f"cpu {format_cpu_list(vals)}: {fmt(next(iter(distinct)))}"
    return "; ".join(f"cpu{c} {fmt(v)}" for c, v in sorted(vals.items()))


# ==========================================================================
# APPLICARE LE CONDIZIONI
# ==========================================================================
class HostConditioner:
    """Applica le condizioni del banco e le ripristina. Vedi la docstring del
    modulo per cosa e perche'; qui il come.

    Ogni modifica passa da _set_file / _record: il valore vecchio si salva
    nel file di stato PRIMA di scrivere quello nuovo, cosi' un'interruzione
    in qualunque punto lascia un ripristino completo."""

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
        self.egress = None if egress is None else int(egress)
        self.bench = sorted(set(self.dut) | set(self.gen)
                            | ({self.egress} if self.egress is not None
                               else set()))
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

    # -- stato -----------------------------------------------------------
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
        """None: il file non c'e'. False: scrittura rifiutata (il valore resta
        quello di prima). True: il file vale `new`."""
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
        """Salva il valore senza scriverlo: si riscrive al ripristino. Per
        l'EPP, che il governor performance forza da se' e che il ritorno a
        powersave deve ritrovare com'era."""
        old = read_text(path)
        if old is not None:
            self._record(dict(kind="file", path=path, old=old, new=None,
                              what=what))

    # -- ciclo di vita -----------------------------------------------------
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
        _say(f"{YELLOW} Condizioni della macchina (host_conditions){NC}")
        _say(f"{YELLOW}{'=' * 78}{NC}")
        try:
            self._check_power()
            self._step_profile()
            if self.isolate and not self.hk:
                warn("nessuna CPU resta al sistema: isolamento saltato")
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
        info(f"{len(self.changes)} impostazioni cambiate, salvate in "
             f"{self.paths.state}; si ripristinano a fine run")
        return self

    def restore(self):
        if not self.active:
            return []
        self.active = False
        # Un secondo Ctrl-C (o SIGTERM) durante il ripristino lo lascerebbe a
        # meta': per la sua durata i segnali si ignorano.
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
                # SIGTERM e SIGHUP tornano a com'erano prima di apply();
                # SIGINT a com'era prima del ripristino.
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
                warn(f"non ripristinato: {_describe_change(ch)} -- {err}")
        _say(f"  {GREY}condizioni della macchina ripristinate: {n - len(failed)}"
             f"/{n} impostazioni{NC}")
        return failed

    def __enter__(self):
        return self.apply()

    def __exit__(self, *exc):
        self.restore()

    def _install_signals(self):
        """SIGTERM e SIGHUP come Ctrl-C: risalgono come eccezione, e i
        `finally` del banco (fabric, pktgen, ripristino) girano."""
        def handler(signum, frame):
            raise KeyboardInterrupt(f"segnale {signum}")
        for s in (signal.SIGTERM, signal.SIGHUP):
            try:
                self._handlers[s] = signal.signal(s, handler)
            except (ValueError, OSError):
                pass            # non dal thread principale: resta atexit

    # -- i passi -----------------------------------------------------------
    def _check_power(self):
        on_ac, pct = power_source(self.paths)
        if on_ac is False:
            warn("il portatile e' a BATTERIA: limiti di potenza e profilo "
                 "cambiano, e power-profiles-daemon puo' cambiarli a meta' "
                 "run. Collega l'alimentatore.")
        self.facts.append(("alimentazione", _power_text(on_ac, pct)))

    def _ppd_active(self):
        rc, out, _ = self.run(["systemctl", "is-active",
                               "power-profiles-daemon"])
        return rc == 0 and out.strip() == "active"

    def _step_profile(self):
        target = self.profile
        if target in (None, "", "keep"):
            self.facts.append(("profilo", "non toccato"))
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
            self.facts.append(("profilo", f"{now.strip() or '?'} (era "
                                          f"{cur or '?'}, power-profiles-daemon)"))
            return
        path = self.paths.sys("firmware", "acpi", "platform_profile")
        choices = (read_text(self.paths.sys(
            "firmware", "acpi", "platform_profile_choices")) or "").split()
        old = read_text(path)
        if old is None:
            self.facts.append(("profilo", "platform_profile assente"))
            return
        if target not in choices:
            warn(f"profilo {target!r} non fra {choices}: resta {old}")
            self.facts.append(("profilo", old))
            return
        self._set_file(path, target, "platform_profile")
        self.facts.append(("profilo", f"{read_text(path)} (era {old})"))

    def _cgroup_of_self(self):
        return read_text(self.paths.proc("self", "cgroup")) or ""

    def _tids(self):
        try:
            return [int(t) for t in os.listdir(self.paths.proc("self", "task"))
                    if t.isdigit()]
        except OSError:
            return [self._getpid()]

    def _step_scope(self):
        """Il processo del banco in uno scope suo, sotto ipa-bench.slice.

        Con StartTransientUnit e PIDs=[noi], come fa `systemd-run --scope`,
        ma senza rilanciare il processo. Poi tutti i suoi thread sulle CPU
        del sistema: il banco legge contatori e scrive CSV, e non deve farlo
        sui core che misura. I thread che servono altrove (xdp_gen) si
        pinnano da soli, e fuori da user.slice possono ancora farlo."""
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
                warn("il processo del banco non e' passato in uno scope suo "
                     f"({err.strip() or 'busctl rc=' + str(rc)}): confinare "
                     "user.slice lo porterebbe via dalle CPU che deve usare. "
                     "Salto il confinamento dei processi; IRQ, workqueue e "
                     "kernel thread si spostano lo stesso.")
                self.facts.append(("isolamento_processi", "no (scope non "
                                                          "creato)"))
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
                warn(f"{unit}: AllowedCPUs rifiutato ({err.strip() or rc})")
                continue
            done.append(unit)
        self.facts.append(("isolamento_processi",
                           f"{', '.join(done)} -> cpu {hk}" if done
                           else "non applicato"))

    def _step_kthreads(self):
        """I kernel thread non legati a una CPU (rcu_preempt, kswapd,
        khugepaged, kcompactd, ...) sulle CPU del sistema. Quelli per-CPU hanno
        PF_NO_SETAFFINITY e restano dove sono; napi/* e kpktgend_* li pinna il
        banco."""
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
            # irq/*: il kernel li tiene sull'affinita' EFFETTIVA del loro
            # IRQ e la ricalcola da se' (visto il 2026-09-27: irq/167-iwlwifi
            # su cpu10, dopo il ripristino su cpu16). Si spostano con l'IRQ.
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
                           f"{moved} spostati sulle CPU del sistema"
                           + (f", {refused} rifiutati" if refused else "")))

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
                           f"{moved} IRQ su cpu {hk_list}"
                           + (f", {refused} non spostabili (affinita' gestita "
                              f"dal kernel)" if refused else "")))

    def _step_workqueue(self):
        path = self.paths.sys("devices", "virtual", "workqueue", "cpumask")
        r = self._set_file(path, cpu_mask_hex(self.hk), "workqueue unbound")
        self.facts.append(("isolamento_workqueue",
                           f"unbound su cpu {format_cpu_list(self.hk)}"
                           if r else "non applicato"))

    def _step_freq(self):
        if self.freq in (None, "", "keep"):
            self.facts.append(("frequenza", "non toccata"))
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
                # min al minimo, poi max, poi min: ogni scrittura resta
                # valida (min <= max) qualunque fosse il punto di partenza.
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
            self.facts.append(("frequenza", "cpufreq assente: non "
                                            "controllabile"))
            return
        # I limiti sono richieste di QoS: il kernel li applica alla policy in
        # modo asincrono, e una rilettura immediata puo' restituire quelli
        # vecchi (visto il 2026-09-27: "400-4800" subito dopo la scrittura,
        # 1400-1400 un attimo dopo). Si rilegge finche' non si assestano.
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
            self.facts.append(("frequenza", f"performance, turbo libero su "
                                            f"cpu {format_cpu_list(cpus)} "
                                            f"(non fissata)"))
        if unpinned:
            warn(f"base_frequency non esposta su cpu "
                 f"{format_cpu_list(unpinned)}: frequenza non fissata "
                 f"(usa --freq MHz)")
        if missing:
            warn(f"cpufreq assente su cpu {format_cpu_list(missing)}")
        bad = [c for c, (a, b) in pinned.items()
               if a != b or b != wanted.get(c)] if pinned else []
        if bad:
            warn(f"frequenza non fissata come chiesto su cpu "
                 f"{format_cpu_list(bad)}: " + _uniform(
                     {c: pinned[c] for c in bad},
                     lambda v: f"{(v[0] or 0) // 1000}-{(v[1] or 0) // 1000} "
                               f"MHz"))

    def _step_measure_freq(self):
        """La frequenza che i core del banco tengono DAVVERO, da APERF/MPERF,
        con un ciclo a vuoto di MEASURE_S secondi pinnato su ciascuno.

        Non ci si fida del numero scritto nel sysfs. Il 2026-09-27, su questo
        portatile (kernel 6.8, Core Ultra 7 155H), min = max = 1400000 kHz
        riletti dal kernel davano un DUT fisso a ~2 000 MHz misurati, stabile
        fra run (2006, 2004, 1997): la frequenza e' FISSATA, ma la
        corrispondenza fra kHz del sysfs e frequenza vera, sui P-core di
        questo processore ibrido, non e' quella dichiarata. Da qui in avanti
        il riferimento (target_khz, che il monitor confronta finestra per
        finestra) e' la frequenza misurata; quella chiesta resta in
        requested_khz e in env.csv."""
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
                                   f"non misurabile ({mon.msr_note})"))
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
            + f" (APERF/MPERF, {MEASURE_S} s a pieno carico; richiesta "
              + _uniform({c: v // 1000 for c, v in self.requested_khz.items()},
                         lambda v: f"{v} MHz") + ")"))
        if spread > FREQ_TOLERANCE:
            warn("i core del banco non tengono la stessa frequenza: "
                 + ", ".join(f"cpu{c} {v // 1000} MHz"
                             for c, v in sorted(measured.items())))
        off = {c: v for c, v in measured.items()
               if abs(v - self.requested_khz[c])
               > FREQ_TOLERANCE * self.requested_khz[c]}
        if off:
            info("frequenza reale diversa da quella scritta nel sysfs ("
                 + ", ".join(f"cpu{c}: {self.requested_khz[c] // 1000} "
                             f"chiesti, {v // 1000} misurati"
                             for c, v in sorted(off.items()))
                 + "): e' comunque fissa; il riferimento del monitor e' "
                   "quella misurata")

    def _step_system_cap(self):
        """Tetto di frequenza sulle CPU del sistema: niente turbo li', quindi
        niente punti caldi che mandino in throttling il pacchetto intero.
        Governor e minimo restano quelli di prima."""
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
                               f"cpu {format_cpu_list(capped)}: massimo "
                               f"{int(cap)} MHz (niente turbo durante il run)"))

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
                           else "non controllabile (intel_uncore_frequency "
                                "assente)"))

    def _step_cstates(self):
        lim = self.cstate_max_us
        if lim in (None, "", "keep"):
            self.facts.append(("idle", "non toccato"))
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
            self.facts.append(("idle", "cpuidle assente (driver none?): "
                                       "niente da limitare"))
            return
        self.facts.append(("idle", f"cpu {format_cpu_list(self.bench)}: "
                           + (("spenti " + ", ".join(
                               f"{n} ({l} us)" for n, l in off.items()))
                              if off else "nessuno stato sopra la soglia")
                           + ("; restano " + ", ".join(kept) if kept else "")))

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
        out = [("condizionamento", "applicato da host_conditions, "
                                   "ripristinato a fine run")]
        out += [(f"host_{k}", v) for k, v in self.facts]
        return out


# ==========================================================================
# IL MONITOR
# ==========================================================================
def power_source(paths=None):
    """(sulla rete: True/False/None, batteria %: int o None).

    Un caricatore USB-C compare come alimentatore "USB" (ucsi) accanto,
    o al posto, di quello "Mains" (ACAD): basta che uno dei due sia online."""
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
    src = {True: "rete (AC)", False: "BATTERIA", None: "sconosciuta"}[on_ac]
    return src + (f", batteria {pct}%" if pct is not None else "")


def _thermal_zone(paths, typ):
    for d in sorted(glob.glob(paths.sys("class", "thermal", "thermal_zone*"))):
        if read_text(os.path.join(d, "type")) == typ:
            return os.path.join(d, "temp")
    return None


def _coretemp_input(paths, topo, cpu):
    """Il tempN_input di coretemp per il core fisico di `cpu` (etichetta
    "Core <core_id>")."""
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
    """Le colonne host_* fra due letture del monitor. Funzione pura: i test la
    verificano senza MSR e senza sysfs.

      host_throttle_core  eventi di throttling termico dei core osservati
      host_throttle_pkg   eventi del pacchetto (il massimo fra le CPU: ognuna
                          li conta dal proprio punto di vista)
      host_dut_busy_pct   quota del tempo in C0 del DUT (MPERF / TSC)
      host_dut_mhz        frequenza media del DUT mentre lavorava:
                          TSC/s x APERF/MPERF, come Bzy_MHz di turbostat
      host_smi            System Management Interrupt (MSR 0x34): il firmware
                          ferma TUTTE le CPU, e il kernel non lo vede
      host_off_target     DUT occupato ma a una frequenza diversa da quella
                          fissata oltre FREQ_TOLERANCE
      host_disturbed      throttling, powerclamp, raffreddamento passivo,
                          batteria o frequenza fuori target: la finestra non
                          e' stata misurata nelle condizioni dichiarate"""
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
    """Letture della macchina attorno alle misure. mark() costa qualche
    lettura di sysfs e, se c'e' /dev/cpu/N/msr, tre di MSR sul DUT: ognuna e'
    un IPI verso il DUT, quindi si chiama FUORI dalla finestra (prima che
    pktgen parta e dopo che si e' fermato), mai durante."""

    def __init__(self, topo, watch, dut=None, paths=None, target_khz=None,
                 use_msr=True):
        self.topo = topo
        self.paths = paths or Paths()
        self.watch = sorted(set(int(c) for c in watch))
        self.dut = dut if dut is not None else (self.watch[0] if self.watch
                                                else None)
        self.target_khz = target_khz
        self._fd = None
        self.msr_note = "non chiesto"
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
            self.msr_note = f"assente ({e.strerror})"
            return
        try:
            os.pread(fd, 8, MSR_APERF)
        except OSError as e:
            os.close(fd)
            self.msr_note = f"illeggibile ({e.strerror})"
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

    # -- l'intero run -------------------------------------------------------
    def start_run(self):
        self._start = self.mark()
        return self._start

    def run_columns(self):
        return host_columns(self._start, self.mark(), self.dut_target_khz)

    def start_log(self, path, period=1.0):
        """Il registro al secondo, in un processo a parte: un thread qui
        contenderebbe il GIL alle letture a tempo del banco."""
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
            warn(f"registro della macchina non avviato: {e}")
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
    """Il corpo di `--log`: una riga ogni `period` secondi finche' il padre
    e' vivo. Solo sysfs, niente MSR (ogni lettura di MSR e' un IPI verso la
    CPU letta)."""
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
    """Massimi e differenze del registro: che cosa e' successo fra la prima
    e l'ultima riga."""
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


# ==========================================================================
# LE CONDIZIONI, LETTE (anche senza condizionamento)
# ==========================================================================
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
    """Le condizioni delle CPU del banco come sono ADESSO: governor, limiti di
    frequenza, EPP, stati di idle attivi, throttling cumulato dal boot."""
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
            idle[c] = ",".join(on) or "nessuno"
        ct = f("thermal_throttle", "core_throttle_count")
        if ct is not None:
            thr[c] = ct
    return dict(governor=gov, limiti=lim, epp=epp, idle=idle, throttle=thr)


def env_pairs(plan, host=None, monitor=None, paths=None, runner=None,
              log_summary=None):
    """Le righe di env.csv sulla macchina: chi fa cosa, e in che condizioni.

    `plan`: qualunque oggetto con topo, dut, gen, egress (CpuPlan di
    bench_throughput, Roles qui). `host`: il HostConditioner, se applicato.
    `monitor`: il HostMonitor del run, per le differenze dall'inizio."""
    paths = paths or Paths()
    runner = runner or run_cmd
    topo = getattr(plan, "topo", None) or Topology.read(paths)
    dut = list(getattr(plan, "dut", []) or [])
    gen = list(getattr(plan, "gen", []) or [])
    egress = getattr(plan, "egress", None)
    used = sorted(set(dut) | set(gen) | ({egress} if egress is not None
                                         else set()))
    env = []

    def add(k, v):
        env.append((k, "n/d" if v is None or v == "" else str(v)))

    add("macchina", _dmi(paths))
    add("topologia_cpu", topo.summary())
    add("microcode", _microcode(paths))
    if used:
        add("ruolo_dut", ", ".join(topo.label(c) for c in dut))
        add("ruolo_uscita", topo.label(egress) if egress is not None
            else "nessuna CPU sua (softirq sulla CPU del DUT)")
        add("ruolo_generatore", ", ".join(topo.label(c) for c in gen))
        add("fratelli_smt_a_riposo",
            format_cpu_list(idle_siblings(topo, used)) or "nessuno")
        add("cpu_sistema", format_cpu_list(housekeeping(topo, used)))
    add("intel_pstate", read_text(paths.cpu("intel_pstate", "status")))
    nt = read_text(paths.cpu("intel_pstate", "no_turbo"))
    add("turbo", {"0": "attivo", "1": "disattivo"}.get(nt, nt))
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
        add("condizionamento", "no (--no-tune): condizioni della macchina "
                               "lasciate com'erano, solo registrate")
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


# ==========================================================================
# PER I BANCHI: argomenti e costruzione
# ==========================================================================
def add_args(parser):
    g = parser.add_argument_group(
        "condizioni della macchina (host_conditions.py, tutte reversibili)")
    g.add_argument("--no-tune", action="store_true",
                   help="non toccare la macchina: niente frequenza fissa, "
                        "idle, isolamento, profilo. Le condizioni vengono "
                        "comunque lette e scritte in env.csv.")
    g.add_argument("--freq", default=DEFAULT_FREQ, metavar="F",
                   help=f"frequenza dei core del banco in MHz (default "
                        f"{DEFAULT_FREQ}: la piu' alta che il portatile di "
                        f"laboratorio regge per un run intero), base (quella "
                        f"garantita al TDP), max "
                        "(governor performance e turbo libero: piu' veloce, "
                        "meno ripetibile), keep, oppure MHz")
    g.add_argument("--system-max-mhz", default=str(DEFAULT_SYSTEM_MAX_MHZ),
                   metavar="MHZ",
                   help=f"tetto di frequenza delle CPU del sistema (desktop, "
                        f"browser, il processo del banco) durante il run "
                        f"(default {DEFAULT_SYSTEM_MAX_MHZ}): un core in turbo "
                        f"scalda il pacchetto fino al throttling. keep per "
                        f"non toccarle")
    g.add_argument("--uncore", default=DEFAULT_UNCORE, metavar="U",
                   help="frequenza della uncore (L3, anello): max (default), "
                        "keep, oppure MHz")
    g.add_argument("--cstate-max-us", default=str(DEFAULT_CSTATE_MAX_US),
                   metavar="US",
                   help="sulle CPU del banco spegne gli stati di idle con "
                        "uscita piu' lenta di US microsecondi (default 1: "
                        "restano POLL e C1E); 0 = solo POLL; keep")
    g.add_argument("--profile", default=DEFAULT_PROFILE, metavar="P",
                   help="profilo di power-profiles-daemon durante il run "
                        "(default performance), oppure keep")
    g.add_argument("--no-isolate", action="store_true",
                   help="non confinare processi, IRQ, workqueue e kernel "
                        "thread sulle CPU del sistema")
    g.add_argument("--keep-nmi-watchdog", action="store_true",
                   help="lascia acceso l'NMI watchdog")
    return g


def check_args(a):
    """Valida i valori che argparse non puo' validare da solo."""
    def num_or(v, words, what):
        if v in words:
            return v
        try:
            n = int(v)
        except (TypeError, ValueError):
            sys.exit(f"{what}: atteso {' | '.join(words)} oppure un numero, "
                     f"ricevuto {v!r}")
        if n < 0:
            sys.exit(f"{what}: serve un numero non negativo")
        return str(n)

    a.freq = num_or(a.freq, ("base", "max", "keep"), "--freq")
    a.system_max_mhz = num_or(a.system_max_mhz, ("keep",),
                              "--system-max-mhz")
    a.uncore = num_or(a.uncore, ("max", "keep"), "--uncore")
    a.cstate_max_us = num_or(a.cstate_max_us, ("keep",), "--cstate-max-us")
    return a


def from_args(a, plan, **kw):
    """Il HostConditioner per `plan`, o None con --no-tune. Non applica."""
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
    """--egress-cpu: "auto", "none" o un numero. None = nessuna CPU sua."""
    if spec is None:
        return None
    s = str(spec).strip().lower()
    if s in ("", "none", "no", "off"):
        return None
    if s == "auto":
        return "auto"
    try:
        return int(s)
    except ValueError:
        sys.exit(f"--egress-cpu: atteso auto, none o un numero di CPU, "
                 f"ricevuto {spec!r}")


# ==========================================================================
# DA RIGA DI COMANDO
# ==========================================================================
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
    """--show: la topologia, il piano che i banchi userebbero, e le
    condizioni attuali. Niente root, niente modifiche."""
    paths = paths or Paths()
    topo = Topology.read(paths)
    _say(f"\n{YELLOW}== topologia =={NC}")
    _say(f"  {topo.summary()}")
    _say(f"  {'cpu':>4s} {'tipo':5s} {'core':>9s} {'base':>6s} {'max':>6s} "
         f"{'governor':12s} {'min-max MHz':>12s} {'epp':22s} idle attivi"
         f"{'':3s}throttle")
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
    _say(f"\n{YELLOW}== piano automatico dei banchi =={NC}")
    _say(f"  DUT ........... {', '.join(topo.label(c) for c in r['dut'])}")
    _say(f"  uscita ........ " + (topo.label(r["egress"])
                                  if r["egress"] is not None else "nessuna"))
    _say(f"  generatore .... {', '.join(topo.label(c) for c in r['gen'])}")
    _say(f"  a riposo ...... {format_cpu_list(idle_siblings(topo, used))}"
         f"  (fratelli SMT)")
    _say(f"  sistema ....... {format_cpu_list(housekeeping(topo, used))}")
    for n in r["notes"]:
        warn(n)
    _say(f"\n{YELLOW}== condizioni attuali (delle CPU del piano) =={NC}")
    for k, v in env_pairs(Roles(topo, r["dut"], r["gen"], r["egress"]),
                          paths=paths):
        if k in ("topologia_cpu",) or k.startswith(("ruolo_", "fratelli_",
                                                    "cpu_sistema")):
            continue                    # gia' stampati sopra
        _say(f"  {GREY}{k:28s}{NC} {v}")
    if os.path.exists(paths.state):
        warn(f"{paths.state} esiste: un run e' in corso, o e' morto senza "
             f"ripristinare (sudo python3 {sys.argv[0]} --restore)")
    hints = _toolchain_hints()
    if hints:
        warn("manca per P1/P1.5 (oggetto AOT): sudo apt install "
             + " ".join(hints))
    return 0


def _run_command(a, cmd):
    """--run: condizioni applicate, `cmd` sul core del DUT, ripristino."""
    if os.geteuid() != 0:
        sys.exit("--run serve root: sudo python3 ipa/test/host_conditions.py "
                 "--run -- COMANDO")
    if not cmd:
        sys.exit("--run: manca il comando dopo --")
    topo = Topology.read()
    if a.cpu is not None:
        if a.cpu not in topo.online:
            sys.exit(f"--cpu {a.cpu}: CPU non online")
        dut = a.cpu
    else:
        dut = plan_roles(topo, allow_cpu0=a.allow_cpu0)["dut"][0]
    roles = Roles(topo, [dut])
    info(f"comando su {topo.label(dut)}: {' '.join(cmd)}")
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
        _say(f"\n{YELLOW} La macchina durante il comando{NC}")
        for k, v in cols.items():
            _say(f"  {GREY}{k:22s}{NC} {v}")
        if cols.get("host_disturbed"):
            warn("il comando NON ha girato nelle condizioni dichiarate "
                 "(throttling, powerclamp, batteria o frequenza fuori "
                 "target): vedi le righe sopra")
    return rc


def main(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__.strip().split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--show", action="store_true",
                   help="topologia, piano automatico e condizioni attuali "
                        "(niente root, niente modifiche)")
    p.add_argument("--restore", action="store_true",
                   help="ripristina le condizioni lasciate da un run ucciso")
    p.add_argument("--force", action="store_true",
                   help="con --restore: anche se il processo che le ha "
                        "applicate risulta vivo")
    p.add_argument("--run", action="store_true",
                   help="applica le condizioni, esegue il comando dopo -- sul "
                        "core del DUT, ripristina")
    p.add_argument("--cpu", type=int, default=None,
                   help="con --run: la CPU del comando (default: il DUT del "
                        "piano automatico)")
    p.add_argument("--allow-cpu0", action="store_true")
    p.add_argument("--log", default=None, help=argparse.SUPPRESS)
    p.add_argument("--watch", default="", help=argparse.SUPPRESS)
    p.add_argument("--period", type=float, default=1.0,
                   help=argparse.SUPPRESS)
    p.add_argument("--root", default="/", help=argparse.SUPPRESS)
    add_args(p)
    p.add_argument("cmd", nargs=argparse.REMAINDER,
                   help="con --run: il comando, dopo --")
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
            sys.exit("--restore serve root")
        data = load_state(paths)
        if data is None:
            info(f"niente da ripristinare ({paths.state} non c'e')")
            return 0
        alive = (lambda pid: False) if a.force else pid_alive
        n = recover_stale_state(paths, alive=alive, me=os.getpid())
        ok(f"ripristinate {n} impostazioni")
        return 0
    if a.run:
        check_args(a)
        return _run_command(a, cmd)
    return show(paths, a.allow_cpu0)


if __name__ == "__main__":
    sys.exit(main())
