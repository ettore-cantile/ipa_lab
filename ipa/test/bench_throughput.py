#!/usr/bin/env python3
"""
bench_throughput.py -- throughput END-TO-END misurato, non stimato.

Ogni altra cifra di throughput in questo progetto e' `1 / latenza` sotto
BPF_PROG_TEST_RUN: un ciclo sullo stesso buffer, senza scheda di rete, senza
driver, senza un pacchetto che arrivi davvero da qualche parte. E' un PICCO
TEORICO. Questo script genera traffico vero con pktgen, lo fa attraversare la
pipeline, e conta quanti pacchetti escono dall'altra parte.

La differenza fra i due numeri e' il punto dell'esperimento.

--------------------------------------------------------------------------
IL BANCO, E CHE COSA MISURA DAVVERO
--------------------------------------------------------------------------
    TG (pktgen)          DUT (la pipeline)           RX (contatore)
    ipa_in_peer  --veth-->  ipa_in                --veth-->  ipa<N>p
        TX              XDP: inferenza + redirect        XDP_DROP + contatore

TG, DUT e RX stanno sulla STESSA macchina e condividono le stesse CPU, perche'
e' la macchina che c'e'. Va detto prima dei numeri:

    questo NON misura "il throughput di P2". Misura il throughput del percorso
    veth di QUESTA macchina con P2 in mezzo, mentre pktgen le ruba CPU.

Resta un esperimento che vale: da' perdita di pacchetti vera invece di
1/latenza, e il confronto RELATIVO fra pipeline regge perche' il generatore e'
identico per tutte. Se il collo di bottiglia e' il generatore la cosa si vede
nei dati (tutte le pipeline allo stesso rate, perdita zero) e va riportata.

--------------------------------------------------------------------------
CHI E' IL COLLO DI BOTTIGLIA
--------------------------------------------------------------------------
Misurato: a `delay 0` e frame da 64 byte questa macchina fa circa 780 kpps con
la pipeline hardcoded e ZERO perdita. Il picco teorico di quella pipeline e'
~14 Mpps, quindi a saturare non e' lei: e' il generatore.

E c'e' una ragione strutturale, non solo di potenza. Su veth la RICEZIONE del
peer avviene nel softirq della STESSA CPU che trasmette: TG e DUT non sono solo
sulla stessa macchina, sono sullo stesso core, per costruzione. Aggiungere
thread al generatore non li separa.

Questo non rende la misura inutile, ma cambia la grandezza che misura:

    a delay 0 un core fa {genera + inferisce + redirige}. Il tempo per
    pacchetto e' t_gen + t_pipeline, e t_gen e' IDENTICO per tutte e tre le
    pipeline. La differenza fra le loro cifre e' quindi attribuibile alla
    pipeline, anche se il valore assoluto no.

Conseguenza da riportare e non nascondere: finche' il generatore satura per
primo, "throughput massimo" e "throughput a perdita nulla" coincidono, perche'
la perdita non compare mai. Sono due numeri diversi solo quando a saturare e'
il sistema sotto test.

`--clone-skb N` fa riusare a pktgen lo stesso buffer N volte invece di
allocarne uno per pacchetto, e alza parecchio il rate offerto. Va usato
sapendo che cambia cosa si misura: sparisce il costo di allocazione dal lato
generatore, e il datapath puo' dover prendere una copia privata del buffer
prima di riscrivere il TTL. Il default e' 0, cioe' un buffer per pacchetto,
che e' la condizione piu' vicina al traffico vero.

--------------------------------------------------------------------------
TRE PUNTI DI CONTEGGIO, PERCHE' "PERSI" NON BASTA
--------------------------------------------------------------------------
  TX   quanti pktgen ne ha trasmessi          (dai suoi contatori)
  HIT  quanti la pipeline ne ha elaborati     (pkt_stats[0])
  RX   quanti sono arrivati a destinazione    (il contatore XDP sull'uscita)

TX - HIT e' quello che non e' nemmeno arrivato al programma (coda del veth,
softirq). HIT - RX e' quello che il programma ha elaborato ma non e' uscito
(redirect fallito, oppure la classe scelta era DROP). Un solo numero di
"perdita" confonderebbe cose diverse.

--------------------------------------------------------------------------
IL BYTE CHE FA FALLIRE TUTTO IN SILENZIO
--------------------------------------------------------------------------
pktgen scrive la PROPRIA intestazione subito dopo UDP (magic 0xbe9be955), e il
primo byte di quel payload e' esattamente dove il dispatcher legge
`ipa->model_id`. Vale quindi 190, non 0: senza il modello registrato anche su
190 ogni pacchetto diventa MISS, il programma restituisce XDP_PASS e il test
misurerebbe il costo di NON fare inferenza.

Il modello viene percio' registrato su model_id 0 E 190, e una sonda da un
pacchetto verifica HIT prima di misurare qualunque cosa. Se la sonda fallisce
lo script si ferma invece di produrre numeri privi di senso.

--------------------------------------------------------------------------
USO
--------------------------------------------------------------------------
    sudo python3 ipa/test/bench_throughput.py                  # tutte
    sudo python3 ipa/test/bench_throughput.py --method modular
    sudo python3 ipa/test/bench_throughput.py --frames 64,512,1514
    sudo python3 ipa/test/bench_throughput.py --out result/
    sudo python3 ipa/test/bench_throughput.py --cleanup        # se resta sporco

Serve Linux, root, BCC e il modulo pktgen (`sudo modprobe pktgen`).
"""
import os
import re
import sys
import csv
import time
import argparse
import subprocess
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")

PKTGEN_DIR = "/proc/net/pktgen"
PKTGEN_MAGIC_MODEL_ID = 0xBE      # vedi la docstring

# Quante volte riusare lo stesso buffer quando il generatore satura per primo e
# bisogna spingere piu' forte. 100000 e' abbastanza da togliere di mezzo il
# costo di allocazione senza che il conteggio dei pacchetti ne risenta.
ESCALATE_CLONE = 100000

# Frame sizes. 64 e' il minimo Ethernet; 1514 il massimo senza jumbo. Il frame
# IPA minimo di questo progetto e' 63 byte, quindi 64 li contiene tutti.
DEFAULT_FRAMES = [64, 128, 256, 512, 1024, 1514]

# Ritardi fissi, usati solo se il chiamante li chiede con --delays. Il default
# e' la ricerca del ginocchio (find_knee), che costa meno punti e centra la
# risposta invece di avvicinarla.
DEFAULT_DELAYS = [0, 200, 500, 1000, 2000, 5000, 10000]

METHODS = ("hardcoded", "template", "modular")

# Contatore sull'uscita: XDP_DROP, cosi' il conteggio non paga lo stack di rete
# e non falsa la misura con il costo di consegnare a un socket.
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


# ==========================================================================
# pktgen
# ==========================================================================
def pg_write(path, cmd):
    """Write one pktgen command, and say which one if it fails.

    os.open(O_WRONLY) rather than open(path, "w"): the builtin adds O_TRUNC,
    and a procfs file with no truncate handler answers that with
    `OSError: [Errno 95] Operation not supported` -- an error about the OPEN
    that reads like an error about pktgen.

    The failure is wrapped because the bare OSError names neither the command
    nor the file, and pktgen has a dozen commands per configuration: without
    this the message says only "Operation not supported"."""
    try:
        fd = os.open(path, os.O_WRONLY)
    except OSError as e:
        raise RuntimeError(
            f"pktgen: non posso aprire {path} ({e.strerror}). "
            f"Se il file non esiste, `add_device` non ha avuto effetto.") from e
    try:
        os.write(fd, (cmd + "\n").encode())
    except OSError as e:
        raise RuntimeError(
            f"pktgen: comando '{cmd}' rifiutato da {path} "
            f"({e.strerror}). Questo kernel potrebbe non supportarlo.") from e
    finally:
        os.close(fd)


def pg_available():
    return os.path.isdir(PKTGEN_DIR)


def pg_reset():
    pg_write(f"{PKTGEN_DIR}/pgctrl", "reset")


def pg_clear_threads(n):
    """Detach every device from the first `n` generator threads."""
    for i in range(n):
        try:
            pg_write(f"{PKTGEN_DIR}/kpktgend_{i}", "rem_device_all")
        except RuntimeError:
            break                   # fewer threads than CPUs: nothing to clear


def pg_configure(dev, pkt_size, count, delay, dst_ip, dst_mac, clone=0,
                 thread=0):
    """Put one device on one generator thread and configure it.

    One thread per device, one device per thread. pktgen threads are pinned to
    a CPU each, so N devices on N threads is N generator cores -- which is the
    only way to raise the offered load on this bench, clone_skb being refused
    by veth (it modifies the skb, so it cannot advertise IFF_TX_SKB_SHARING)."""
    pg_write(f"{PKTGEN_DIR}/kpktgend_{thread}", f"add_device {dev}")
    d = f"{PKTGEN_DIR}/{dev}"
    # add_device creates this entry, and a failed add leaves it missing. Saying
    # so here beats an ENOENT from the first pgset, which points at the wrong
    # step.
    if not os.path.exists(d):
        raise RuntimeError(
            f"pktgen: {d} non esiste dopo `add_device {dev}`. "
            f"L'interfaccia esiste ed e' UP? `ip link show {dev}`")
    if clone:
        # Optional by design: clone_skb is the escalation knob, not part of the
        # reference condition. A kernel that refuses it costs one experiment,
        # not the whole run -- so it is tried separately and its failure is
        # reported rather than raised.
        try:
            pg_write(d, f"clone_skb {clone}")
        except RuntimeError as e:
            warn(f"clone_skb non accettato, proseguo senza: {e}")
    for cmd in (f"count {count}",
                f"pkt_size {pkt_size}",
                f"delay {delay}",
                f"dst {dst_ip}",
                f"dst_mac {dst_mac}",
                "udp_src_min 1234", "udp_src_max 1234",
                "udp_dst_min 9999", "udp_dst_max 9999"):
        pg_write(d, cmd)


# pktgen's device file after a run looks like:
#
#   Result: OK: 1234567(c1234000+d567) usec, 200000 (64byte,0frags)
#     162000pps 82Mb/sec (82944000bps) errors: 0
#   Current:
#     pkts-sofar: 200000  errors: 0
#
# `pkts-sofar` is the count, the number inside Result's parentheses is the
# elapsed microseconds, and `pps` is pktgen's own rate. Taking the duration
# from pktgen rather than from a wall clock here matters: the write to pgctrl
# blocks, but it also covers thread startup and teardown, which at small
# packet counts is a large share of the wall time.
_SOFAR_RE = re.compile(r"pkts-sofar:\s*(\d+)")
_USEC_RE = re.compile(r"Result: OK:\s*(\d+)\(")
_PPS_RE = re.compile(r"(\d+)pps")


def pg_run_and_read(devs):
    """Start every configured thread, wait, and sum what they sent.

    `pgctrl start` runs ALL threads at once and blocks until the last one
    finishes, so one call drives the whole generator. TX is the sum over
    devices; the duration is the LONGEST of them, because the offered rate is
    what the slowest thread finished in -- taking the shortest would inflate
    every pps in the table."""
    if isinstance(devs, str):
        devs = [devs]
    wall0 = time.time()
    pg_write(f"{PKTGEN_DIR}/pgctrl", "start")     # blocks until all are done
    wall = time.time() - wall0

    sent = pps = 0
    secs = 0.0
    for dev in devs:
        with open(f"{PKTGEN_DIR}/{dev}") as f:
            text = f.read()
        m = _SOFAR_RE.search(text)
        sent += int(m.group(1)) if m else 0
        m = _USEC_RE.search(text)
        if m:
            secs = max(secs, int(m.group(1)) / 1e6)
        m = _PPS_RE.search(text)
        pps += int(m.group(1)) if m else 0
    secs = secs or wall
    pps = pps or (int(sent / secs) if secs else 0)
    if sent == 0:
        # Nothing parsed usually means the device was never added, or pktgen
        # refused the config. Hand the raw text over rather than reporting a
        # silent zero that looks like 100% loss.
        raise RuntimeError(
            f"pktgen non riporta pacchetti per {devs}. Uscita grezza:\n"
            + text[:600])
    return sent, pps, secs


# ==========================================================================
# RX counter
# ==========================================================================
def _percpu_sum(table, key=0):
    vals = table[ct.c_int(key)]
    return sum(int(v) for v in vals)


# ==========================================================================
# one measurement point
# ==========================================================================
def _read_u64(table, key):
    try:
        return int(table[ct.c_int(key)].value)
    except Exception:
        return 0


def _zero_counters(setup, rx_tab, n_out):
    for c in range(n_out):
        try:
            setup["cls_stats"][ct.c_int(c)] = ct.c_ulonglong(0)
        except Exception:
            break
    for k in range(len(setup["pkt_stats"])):
        setup["pkt_stats"][ct.c_int(k)] = ct.c_ulonglong(0)
    rx_tab.clear()


def measure_point(setup, rx_tab, fab, frame, delay, count, n_out, clone=0,
                  tg_devs=None):
    """One (frame size, offered rate) point. Returns a dict of counters.

    `count` is per generator thread, so the offered load scales with the number
    of threads and the per-thread duration stays comparable."""
    devs = tg_devs or [fab.ingress_peer]
    _zero_counters(setup, rx_tab, n_out)
    pg_clear_threads(len(devs))
    for i, dev in enumerate(devs):
        pg_configure(dev, frame, count, delay,
                     dst_ip="10.0.0.2", dst_mac="02:00:00:00:00:02",
                     clone=clone, thread=i)
    tx, tx_pps, elapsed = pg_run_and_read(devs)
    hit = _read_u64(setup["pkt_stats"], 0)
    miss = _read_u64(setup["pkt_stats"], 1)
    drop = _read_u64(setup["pkt_stats"], 2)
    rx = _percpu_sum(rx_tab)
    secs = elapsed if elapsed > 0 else 1e-9
    return dict(frame=frame, delay=delay, secs=round(secs, 3),
                tx=tx, tx_pps=tx_pps or int(tx / secs),
                hit=hit, miss=miss, drop=drop, rx=rx,
                rx_pps=int(rx / secs),
                # Throughput on the wire counts the frame, not the payload.
                rx_mbps=round(rx * frame * 8 / secs / 1e6, 2),
                lost_before=max(0, tx - hit),
                lost_after=max(0, hit - rx),
                loss_pct=round(100.0 * (tx - rx) / tx, 3) if tx else 0.0)


# ==========================================================================
# extra ingress links: one generator core each
# ==========================================================================
TG_PREFIX = "ipatg"


def _ip(*args, check=True):
    return subprocess.run(["ip", *args], capture_output=True, text=True,
                          check=check)


def make_tg_links(n):
    """`n` extra veth pairs, each the ingress of one more generator thread.

    Why this exists: clone_skb is refused by veth, so a single pktgen thread
    cannot be made faster. What CAN be added is threads -- pktgen pins one per
    CPU -- and each needs its own device. All of them feed the SAME XDP
    program, so the offered load scales with cores while the thing under test
    stays one program with one set of maps.

    That is also what makes the result interesting rather than just bigger:
    pkt_stats and cls_stats are shared BPF_ARRAYs incremented with
    __sync_fetch_and_add, so several cores hammering them contend on the same
    cache line. Whether that shows up is the question this can answer and the
    single-core measurement cannot.

    Returns [(rx_dev, tx_dev, rx_ifindex), ...]."""
    made = []
    for i in range(n):
        rx, tx = f"{TG_PREFIX}{i}", f"{TG_PREFIX}{i}p"
        _ip("link", "del", rx, check=False)          # leftovers from a crash
        _ip("link", "add", rx, "type", "veth", "peer", tx)
        for dev in (rx, tx):
            _ip("link", "set", dev, "up")
            # IPv6 autoconf would put router solicitations on the same wire and
            # they would be counted as traffic that nobody generated.
            subprocess.run(["sysctl", "-qw",
                            f"net.ipv6.conf.{dev}.disable_ipv6=1"],
                           capture_output=True, check=False)
        idx = int(_ip("-o", "link", "show", rx).stdout.split(":")[0])
        made.append((rx, tx, idx))
    return made


def del_tg_links(n):
    for i in range(n):
        _ip("link", "del", f"{TG_PREFIX}{i}", check=False)


# ==========================================================================
# setup
# ==========================================================================
def class_semantics():
    """The declared class semantics, resolved the same way test_fabric does."""
    import model_meta as mm
    meta_path = os.path.join(SHARED_DIR, "weights.json")
    n_out = mm.derive_shape(
        mm.load_model_meta(meta_path),
        topology_config=mm.load_topology_config())["n_out"]
    return mm.load_class_semantics(meta_path, n_out), n_out


def build_pipeline(method, model_path, fab, sem):
    """Load the pipeline, point it at THIS fabric, and make it answer to the
    model_id pktgen actually puts on the wire.

    The three map writes below are the same ones test_fabric makes, done by
    hand rather than through common.install_*: those helpers resolve the node
    and the ports from a node configuration, and here both come from the
    fabric that was just built."""
    import verify_prog_run as V
    import test_fabric as TF

    setup = getattr(V, TF._SETUP[method])(0, model_path)
    b, pl = setup["b"], setup["pipeline"]

    TF._install_fabric_mac_table(b, TF._MAC_NAME[pl], fab, sem.logical_ports)
    b[TF._INGRESS_NAME[pl]][ct.c_uint32(fab.ingress_ifindex)] = \
        ct.c_uint32(TF.FABRIC_INGRESS_SLOT)
    b[TF._NODEID_NAME[pl]][ct.c_uint32(0)] = \
        ct.c_uint32(TF.FABRIC_NODE_INDEX)

    # The model under the id pktgen writes. See the docstring: this is the
    # difference between measuring inference and measuring XDP_PASS.
    _register_alias(method, setup, PKTGEN_MAGIC_MODEL_ID)
    return setup


def _register_alias(method, setup, model_id):
    b, w, scale = setup["b"], setup["weights"], setup["scale"]
    if method == "hardcoded":
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(setup["fn"].fd)
    elif method == "template":
        from ebpf_template_arch import load_arch_weights
        load_arch_weights(b, w, model_id=model_id, scale=scale)
    else:
        from ebpf_modular import load_modular_weights
        load_modular_weights(b, w, model_id=model_id, scale=scale,
                             layer_dims=[(65, 4), (4, 4), (4, 7)])


def attach_rx_counter(fab):
    """Replace the fabric's XDP_PASS stubs with a counting XDP_DROP.

    The stubs exist so that bpf_redirect into a veth works at all
    (veth_xdp_xmit needs the receiving peer to have a program). Counting there
    instead of passing keeps the packet out of the network stack, so the
    number measured is delivery by the datapath and not the cost of handing
    frames to a socket."""
    from bcc import BPF
    from common import attach_xdp
    b = BPF(text=RX_COUNTER_SRC)
    fn = b.load_func("xdp_rx_count", BPF.XDP)
    attached = []
    for port, peer in fab.peer_of.items():
        try:
            attach_xdp(b, fn, peer)
            attached.append(peer)
        except Exception as e:
            warn(f"contatore non agganciato a {peer}: {e}")
    return b, b["rx_count"], attached


# ==========================================================================
def run_method(method, model_path, frames, delays, count, out_rows,
               clone=0, threads=1):
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} {method} -- throughput end-to-end, TG e DUT sulla stessa "
          f"macchina{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")

    sem, n_out = class_semantics()
    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        rx_b, rx_tab, attached = attach_rx_counter(fab)
        info(f"contatore RX su {len(attached)} peer d'uscita (XDP_DROP)")

        setup = build_pipeline(method, model_path, fab, sem)
        attach_xdp(setup["b"], setup["disp"], fab.ingress)
        info(f"pipeline agganciata a {fab.ingress} (ifindex "
             f"{fab.ingress_ifindex})")

        # Thread 0 uses the fabric's own ingress; the rest get their own veth.
        tg_devs = [fab.ingress_peer]
        extra = []
        if threads > 1:
            import test_fabric as TF
            extra = make_tg_links(threads - 1)
            ing_map = setup["b"][TF._INGRESS_NAME[setup["pipeline"]]]
            for rx, tx, idx in extra:
                attach_xdp(setup["b"], setup["disp"], rx)
                # Same logical port as the fabric ingress: these are extra
                # generator cores feeding one node, not extra node ports.
                ing_map[ct.c_uint32(idx)] = ct.c_uint32(TF.FABRIC_INGRESS_SLOT)
                tg_devs.append(tx)
            info(f"{threads} core generatori: {', '.join(tg_devs)}")

        # -- sonda: un pacchetto solo, per sapere se stiamo misurando
        #    inferenza o XDP_PASS.
        probe = measure_point(setup, rx_tab, fab, 64, 0, 1, n_out, clone,
                              tg_devs)
        if probe["hit"] == 0:
            warn(f"la sonda non ha prodotto nessun HIT "
                 f"(tx={probe['tx']} miss={probe['miss']}).")
            warn("Il dispatcher scarta i pacchetti: probabilmente il byte "
                 "model_id sul filo non e' ne' 0 ne' 190.")
            warn("Misurare adesso darebbe il costo di NON fare inferenza. "
                 "Mi fermo.")
            return 1
        ok(f"sonda: {probe['hit']} HIT su {probe['tx']} inviato -- si sta "
           f"misurando inferenza vera")

        hdr = (f"  {'frame':>5s} {'delay':>6s} {'TX':>9s} {'HIT':>9s} "
               f"{'RX':>9s} {'TX pps':>9s} {'RX pps':>9s} {'Mb/s':>8s} "
               f"{'perdita':>8s}")
        print(f"\n{hdr}")
        print("  " + "-" * (len(hdr) - 2))
        def printer(r):
            mark = GREEN if r["loss_pct"] == 0 else (
                RED if r["loss_pct"] > 1 else YELLOW)
            print(f"  {r['frame']:5d} {r['delay']:6d} {r['tx']:9d} "
                  f"{r['hit']:9d} {r['rx']:9d} {r['tx_pps']:9d} "
                  f"{r['rx_pps']:9d} {r['rx_mbps']:8.1f} "
                  f"{mark}{r['loss_pct']:7.2f}%{NC}")

        for frame in frames:
            if delays:
                # Manual sweep: the caller asked for specific rates.
                for delay in delays:
                    r = measure_point(setup, rx_tab, fab, frame, delay, count,
                                      n_out, clone, tg_devs)
                    r["clone_skb"], r["method"] = clone, method
                    r["threads"] = threads
                    out_rows.append(r)
                    printer(r)
            else:
                find_knee(setup, rx_tab, fab, frame, count, n_out, clone,
                          out_rows, method, printer, tg_devs=tg_devs,
                          threads=threads)
            _summarise(method, frame, out_rows)

        pg_reset()
        del_tg_links(threads - 1)
        for peer in attached:
            subprocess.run(["ip", "link", "set", "dev", peer, "xdp", "off"],
                           check=False, capture_output=True)
        del rx_b
    return 0


def find_knee(setup, rx_tab, fab, frame, count, n_out, clone, out_rows,
              method, printer, max_delay=20000, steps=6, tg_devs=None,
              threads=1):
    """Find the fastest rate this pipeline takes without losing a packet.

    A fixed list of delays spends most of its time at the slow end, where the
    answer is always "no loss", and still misses the knee unless one of the
    values happens to land on it. This walks to the knee instead:

      1. offer everything the generator has (delay 0);
      2. if nothing is lost, the GENERATOR saturated first -- there is no knee
         to find, and saying so is the result;
      3. otherwise bisect the delay to the smallest one that loses nothing,
         which is the no-loss throughput.

    Returns (peak_row, clean_row_or_None). Costs about `steps` measurements
    instead of one per delay, and lands on the answer rather than near it."""
    full = measure_point(setup, rx_tab, fab, frame, 0, count, n_out, clone,
                         tg_devs)
    full["method"], full["clone_skb"], full["delay"] = method, clone, 0
    full["threads"] = threads
    out_rows.append(full)
    printer(full)

    if full["loss_pct"] == 0.0 and clone == 0:
        # Nothing lost at the generator's best effort. Before concluding that
        # the pipeline has headroom, PUSH HARDER: with clone_skb pktgen reuses
        # one buffer instead of allocating per packet, which removes the cost
        # that dominates it here and can multiply the offered rate.
        #
        # This is an escalation, not the default condition: clone_skb changes
        # what is measured (no allocation on the generator side, and the
        # datapath may take a private copy before rewriting the TTL). It is
        # used only to answer "does this pipeline EVER saturate", and the rows
        # it produces carry clone_skb != 0 so they stay distinguishable.
        hard = measure_point(setup, rx_tab, fab, frame, 0, count, n_out,
                             ESCALATE_CLONE, tg_devs)
        hard["method"], hard["clone_skb"], hard["delay"] = \
            method, ESCALATE_CLONE, 0
        hard["threads"] = threads
        out_rows.append(hard)
        printer(hard)
        if hard["loss_pct"] > 0.0:
            print(f"  {GREY}con clone_skb={ESCALATE_CLONE} la pipeline perde: "
                  f"il ginocchio esiste, lo cerco{NC}")
            return find_knee(setup, rx_tab, fab, frame, count, n_out,
                             ESCALATE_CLONE, out_rows, method, printer,
                             max_delay, steps, tg_devs, threads)
        print(f"  {GREY}nemmeno con clone_skb={ESCALATE_CLONE}: su questa "
              f"macchina satura il generatore, non la pipeline{NC}")
        return (hard if hard["rx_pps"] > full["rx_pps"] else full), hard

    if full["loss_pct"] == 0.0:
        return full, full          # generator-bound: peak IS the no-loss rate

    lo, hi = 0, max_delay           # lo loses, hi is assumed clean
    best_clean = None
    for _ in range(steps):
        mid = (lo + hi) // 2
        if mid in (lo, hi):
            break
        r = measure_point(setup, rx_tab, fab, frame, mid, count, n_out,
                          clone, tg_devs)
        r["method"], r["clone_skb"], r["threads"] = method, clone, threads
        out_rows.append(r)
        printer(r)
        if r["loss_pct"] == 0.0:
            best_clean = r if (best_clean is None or
                               r["rx_pps"] > best_clean["rx_pps"]) else best_clean
            hi = mid                # clean: try to go faster
        else:
            lo = mid                # still losing: slow down
    return full, best_clean


def _summarise(method, frame, rows):
    """The two numbers the question is asked in: the peak, and the peak that
    loses nothing. They are different, and reporting only the first is the
    usual way to overstate a datapath."""
    pts = [r for r in rows if r["method"] == method and r["frame"] == frame]
    if not pts:
        return
    peak = max(pts, key=lambda r: r["rx_pps"])
    clean = [r for r in pts if r["loss_pct"] == 0.0]
    best_clean = max(clean, key=lambda r: r["rx_pps"]) if clean else None
    print(f"  {GREY}frame {frame}: massimo {peak['rx_pps']} pps "
          f"({peak['rx_mbps']} Mb/s, perdita {peak['loss_pct']}%)", end="")
    if best_clean:
        print(f" | a perdita nulla {best_clean['rx_pps']} pps "
              f"({best_clean['rx_mbps']} Mb/s){NC}")
    else:
        print(f" | {RED}nessun punto a perdita nulla{GREY} in questo sweep{NC}")


# ==========================================================================
def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("USO")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--method", choices=list(METHODS) + ["all"], default="all")
    p.add_argument("--frames", default=",".join(map(str, DEFAULT_FRAMES)))
    p.add_argument("--delays", default="",
                   help="ritardi fissi in ns, separati da virgola. Vuoto (il "
                        "default) cerca il ginocchio invece di spazzolare: "
                        "meno punti e centra la risposta")
    p.add_argument("--count", type=int, default=200000,
                   help="pacchetti per punto di misura")
    p.add_argument("--threads", type=int, default=1, metavar="N",
                   help="core generatori: N veth d'ingresso, N thread pktgen, "
                        "tutti sullo stesso programma XDP. E' l'unico modo di "
                        "alzare il carico offerto, visto che veth rifiuta "
                        "clone_skb.")
    p.add_argument("--clone-skb", type=int, default=0, metavar="N",
                   help="riusa lo stesso skb N volte invece di allocarne uno "
                        "per pacchetto: alza molto il rate offerto. "
                        "Cambia cosa si misura -- vedi la docstring.")
    p.add_argument("--out", default=None, help="dove scrivere il CSV")
    p.add_argument("--cleanup", action="store_true",
                   help="rimuovi un fabric rimasto da un run interrotto")
    a = p.parse_args()

    if sys.platform != "linux":
        sys.exit(f"serve Linux, non {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("serve root: sudo python3 ipa/test/bench_throughput.py")

    os.chdir(SHARED_DIR)
    if a.cleanup:
        from netns_fabric import cleanup
        cleanup()
        del_tg_links(16)
        if pg_available():
            pg_reset()
        return 0

    if not pg_available():
        sys.exit(f"{PKTGEN_DIR} non c'e': `sudo modprobe pktgen` e riprova.")
    pg_reset()

    import model_meta as mm
    model_path = mm.default_checkpoint()
    frames = [int(x) for x in a.frames.split(",") if x.strip()]
    delays = [int(x) for x in a.delays.split(",") if x.strip()]
    methods = list(METHODS) if a.method == "all" else [a.method]

    rows = []
    rc = 0
    for m in methods:
        rc |= run_method(m, model_path, frames, delays, a.count, rows,
                         a.clone_skb, a.threads)

    if a.out and rows:
        os.makedirs(a.out, exist_ok=True)
        path = os.path.join(a.out, "throughput.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        uid = os.environ.get("SUDO_UID")
        if uid:
            try:
                os.chown(a.out, int(uid), int(os.environ.get("SUDO_GID", uid)))
                os.chown(path, int(uid), int(os.environ.get("SUDO_GID", uid)))
            except OSError:
                pass
        print(f"\n  {GREEN}scritto{NC} {path}  ({len(rows)} righe)")

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(" Da ricordare leggendo questi numeri: TG, DUT e contatore stanno")
    print(" sulla STESSA macchina e condividono le stesse CPU. E' throughput")
    print(" del percorso veth di questa VM con la pipeline in mezzo, non della")
    print(" pipeline. Il confronto fra pipeline regge; le cifre assolute no.")
    print(f"{YELLOW}{'=' * 78}{NC}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
