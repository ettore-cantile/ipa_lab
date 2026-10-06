#!/usr/bin/env python3
"""hw_counters.py -- istruzioni, cicli e mancate per CPU, dai contatori
hardware (perf_event_open), letti nella stessa lettura dei contatori dei
pacchetti.

Perche'. Il tempo di CPU per pacchetto (bench_throughput, ns_cpu) dice quanto
costa un pacchetto, non perche'. Cicli per pacchetto e istruzioni per
pacchetto lo spezzano: cicli = istruzioni / IPC. A frequenza fissata i cicli
sono il tempo di CPU per la frequenza; le istruzioni dipendono dal codice e
non dal core; l'IPC dipende dal core. E' la grandezza che separa un P-core
(Redwood Cove) da un E-core (Crestmont) a parita' di frequenza.

Come. Un contatore per (CPU, evento), in tutta la CPU (pid = -1): conta il
thread NAPI, il programma XDP, gli interrupt e il resto del kernel che gira
li', cioe' esattamente cio' che il tempo di CPU attribuisce al pacchetto.
Utente e kernel insieme. Serve root (o CAP_PERFMON).

Sui processori ibridi gli eventi generici vanno aperti sul PMU del tipo di
core: cpu_core per i P-core, cpu_atom per E-core e LP E-core. Il tipo del PMU
va negli alti 32 bit di `config` (PERF_TYPE_HARDWARE esteso, kernel >= 5.13).

Istruzioni e cicli stanno nei contatori fissi; mancate di cache e di salto in
quelli generali. Con il watchdog NMI spento (host_conditions lo spegne) nessun
contatore e' multiplexato: lo si verifica comunque (time_running contro
time_enabled) e un evento multiplexato si scarta invece di stimarlo.

USO (dentro i banchi)

    hw = HwCounters(cpus=[6, 8]).open()      # None se non disponibile
    d0 = hw.read()                            # {"_hwins6": ..., "_hwcyc6": ...}
    ...
    cols = per_packet(delta, dut=[6], pkts=n, secs=s)

    sudo python3 ipa/test/hw_counters.py --cpu 6 --seconds 1   # prova a mano
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
# x86_64; le altre architetture non servono a questo banco.
SYS_PERF_EVENT_OPEN = {"x86_64": 298, "aarch64": 241}.get(os.uname().machine)

# (chiave breve, id generico, nome). La chiave breve entra nei nomi interni
# delle colonne (_hw<chiave><cpu>), che i banchi differenziano fra le letture.
EVENTS = (
    ("ins", PERF_COUNT_HW_INSTRUCTIONS, "instructions"),
    ("cyc", PERF_COUNT_HW_CPU_CYCLES, "cycles"),
    ("llc", PERF_COUNT_HW_CACHE_MISSES, "cache-misses"),
    ("brm", PERF_COUNT_HW_BRANCH_MISSES, "branch-misses"),
)
PMU_DIR = "/sys/bus/event_source/devices"


class PerfEventAttr(ctypes.Structure):
    """La parte fissa di perf_event_attr (PERF_ATTR_SIZE_VER0, 64 byte): il
    kernel accetta una struttura piu' corta della sua e azzera il resto."""
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


# bit di perf_event_attr.flags
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
    """{cpu: tipo del PMU} sui processori ibridi, {} altrove."""
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
    """"cpu_core", "cpu_atom" o "cpu": il PMU su cui un evento di `cpu` si
    apre. Va in env.csv, perche' i numeri dei due PMU non sono lo stesso
    contatore."""
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
    """Un contatore su tutta la CPU `cpu`. Restituisce il fd, o solleva
    OSError con l'errno del kernel."""
    if SYS_PERF_EVENT_OPEN is None:
        raise OSError(38, "perf_event_open: architettura non prevista")
    attr = PerfEventAttr()
    attr.type = PERF_TYPE_HARDWARE
    attr.size = ctypes.sizeof(PerfEventAttr)
    attr.config = hw_id | ((pmu_type or 0) << PERF_TYPE_SHIFT)
    attr.read_format = (PERF_FORMAT_TOTAL_TIME_ENABLED
                        | PERF_FORMAT_TOTAL_TIME_RUNNING)
    # Abilitato subito, in tutta la CPU, utente + kernel. Pinned: se il PMU
    # non lo puo' tenere sempre acceso, l'evento va in errore invece di
    # essere multiplexato in silenzio.
    attr.flags = FLAG_PINNED | FLAG_EXCLUDE_HV
    fd = _syscall()(SYS_PERF_EVENT_OPEN, ctypes.byref(attr), -1, cpu, -1,
                    PERF_FLAG_FD_CLOEXEC)
    if fd < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return fd


class HwCounters:
    """I contatori di un gruppo di CPU. `open()` restituisce self, oppure
    None se non si possono aprire (niente root, niente PMU, macchina
    virtuale): i banchi in quel caso lasciano le colonne vuote e lo dicono,
    non le stimano."""

    def __init__(self, cpus, events=EVENTS):
        self.cpus = sorted(set(int(c) for c in cpus))
        self.events = list(events)
        self.fds = {}           # (chiave, cpu) -> fd
        self.why = None
        self.dropped = []       # eventi non apribili, con il motivo

    def open(self):
        pmus = hybrid_pmus()
        for key, hw_id, name in self.events:
            for c in self.cpus:
                try:
                    fd = perf_open(c, hw_id, pmus.get(c))
                except OSError as e:
                    if pmus.get(c) is not None and e.errno in (2, 22, 95):
                        # kernel senza il tipo esteso: il PMU lo sceglie lui
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
            self.why = ("contatori hardware non disponibili ("
                        + ("; ".join(self.dropped[:3]) or "nessun evento")
                        + ")")
            self.close()
            return None
        return self

    def read(self):
        """{"_hw<chiave><cpu>": valore}. Un evento multiplexato o in errore
        (time_running < time_enabled, lettura vuota) non compare: la
        differenza fra due letture resterebbe una stima."""
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
        """Una riga per env.csv."""
        ev = sorted({k for k, _ in self.fds}, key=[e[0] for e in EVENTS].index)
        names = [n for k, _, n in EVENTS if k in ev]
        return (", ".join(names) + " su cpu "
                + ",".join(f"{c} ({pmu_name(c)})" for c in self.cpus)
                + " (perf_event_open, utente + kernel, pinned)"
                + (f"; non aperti: {'; '.join(self.dropped)}"
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
    """Le colonne di una finestra dalle DIFFERENZE dei contatori `d`.

    dut: le CPU del nodo; pkts: i pacchetti che il nodo ha elaborato nella
    finestra; secs: la durata. egress: le CPU dell'uscita, se ce ne sono di
    proprie (il loro costo per pacchetto inoltrato).

      instr_pkt        istruzioni per pacchetto sui core del nodo
      cycles_pkt       cicli per pacchetto (non fermi: C1E e oltre non
                       contano), cioe' ns di CPU x GHz a frequenza fissa
      ipc              istruzioni per ciclo
      llc_miss_pkt     mancate dell'ultimo livello di cache per pacchetto
      br_miss_pkt      salti previsti male per pacchetto
      dut_ghz_busy     cicli / (durata x core): la frequenza x l'occupazione;
                       al 100% e' la frequenza vera del core, ed e' la
                       controprova di APERF/MPERF
      egress_cycles_pkt  cicli dell'uscita per pacchetto elaborato

    Vuoto se i contatori non c'erano: niente stime."""
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


# Le colonne di per_packet, nell'ordine in cui si stampano.
COLUMNS = ("instr_pkt", "cycles_pkt", "ipc", "llc_miss_pkt", "br_miss_pkt",
           "dut_ghz_busy", "egress_cycles_pkt", "egress_ipc")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="prova dei contatori hardware "
                                             "su una o piu' CPU")
    ap.add_argument("--cpu", default="0", help="lista di CPU, es. 6,12,20")
    ap.add_argument("--seconds", type=float, default=1.0)
    a = ap.parse_args(argv)
    cpus = _cpu_list(a.cpu)
    hw = HwCounters(cpus).open()
    if hw is None:
        sys.exit("contatori non disponibili (serve root?)")
    print(hw.describe())
    r0 = hw.read()
    time.sleep(a.seconds)
    r1 = hw.read()
    d = {k: r1[k] - r0.get(k, 0) for k in r1}
    for c in cpus:
        ins, cyc = d.get(f"_hwins{c}"), d.get(f"_hwcyc{c}")
        ipc = f"{ins / cyc:.3f}" if ins is not None and cyc else "-"
        print(f"cpu{c:<3d} {pmu_name(c):9s} istruzioni {ins}  cicli {cyc}  "
              f"IPC {ipc}  cicli/s {cyc / a.seconds / 1e9 if cyc else 0:.3f} G")
    hw.close()


if __name__ == "__main__":
    main()
