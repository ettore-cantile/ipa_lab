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

Confronto equo (questo e' quello da citare in tesi): un solo fabric, tutte le
pipeline compilate PRIMA di misurare, e misura a giri con la mediana fra i giri.
Riporta il tempo arrivo-partenza, non solo la portata.

    sudo python3 ipa/test/bench_throughput.py --latency --rounds 5 --out result/
    sudo python3 ipa/test/bench_throughput.py --latency --frames 64,512,1514 \
        --rounds 5 --out result/

Scrive due file: latency.csv (mediana fra i giri) e latency_raw.csv (ogni giro).
Il secondo serve a leggere la dispersione, che e' cio' che dice se la mediana
significa qualcosa: su questa VM la latenza varia di pochi ns fra i giri, la
portata a pieno rate anche del 137%.

Serve Linux, root, BCC e il modulo pktgen (`sudo modprobe pktgen`).
"""
import io
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

class PktgenEmptyRun(RuntimeError):
    """Un run che non ha trasmesso nulla. Segnalato al chiamante, non fatale."""


PKTGEN_DIR = "/proc/net/pktgen"
PKTGEN_MAGIC_MODEL_ID = 0xBE      # vedi la docstring

# Quante volte riusare lo stesso buffer quando il generatore satura per primo e
# bisogna spingere piu' forte. 100000 e' abbastanza da togliere di mezzo il
# costo di allocazione senza che il conteggio dei pacchetti ne risenta.
ESCALATE_CLONE = 100000

# --------------------------------------------------------------------------
# DOVE VA IL TEMPO PER PACCHETTO, E LE TRE MANOPOLE CHE LO TOCCANO
# --------------------------------------------------------------------------
# A ~550 kpps per core il costo per pacchetto e' ~1800 ns, e l'inferenza ne
# spiega 60 (P1). Il resto e' il banco, e si divide in tre pezzi che si possono
# aggredire separatamente.
#
# 1. LA COPIA PER HEADROOM. XDP su veth pretende XDP_PACKET_HEADROOM (256 byte)
#    davanti al pacchetto; gli skb di pktgen ne hanno NET_SKB_PAD (64). Quindi
#    veth_xdp_rcv_skb ne fa una copia PER OGNI PACCHETTO prima di eseguire il
#    programma. E' il costo noto di "XDP su veth alimentato da un mittente non
#    XDP" e non si toglie con una manopola di pktgen: si toglie cambiando modo
#    di iniezione (punto 3).
#
# 2. IL SECONDO SALTO VETH. Ogni pacchetto rediretto attraversa un ALTRO veth e
#    ci trova un ALTRO programma XDP (il contatore). Sono due traversate e due
#    invocazioni XDP per pacchetto, mentre su un nodo vero il redirect va su una
#    NIC. Il contatore serve -- e' cio' che ha mostrato che la perdita e' in
#    uscita -- ma va saputo che sta dentro la cifra.
#
# 3. IL MODO DI INIEZIONE. `xmit_mode netif_receive` fa iniettare a pktgen i
#    pacchetti direttamente nel percorso RX del device, saltando veth_xmit, la
#    NAPI del peer e la conversione skb->xdp. E' il modo documentato per
#    misurare l'elaborazione in ricezione. ATTENZIONE: si entra a
#    netif_receive_skb, quindi XDP gira in modo GENERIC, non native -- i numeri
#    non sono confrontabili con quelli in modo native, e la colonna xmit_mode
#    del CSV serve a non mescolarli.
#
# `burst N` chiede a pktgen di consegnare N pacchetti per chiamata (xmit_more).
# Come clone_skb puo' essere rifiutato da veth; come clone_skb, il rifiuto e' un
# esperimento in meno e non un run perso.
XMIT_MODES = ("start_xmit", "netif_receive", "queue_xmit")
_BURST_SUPPORTED = True

# veth non espone IFF_TX_SKB_SHARING -- consegna l'skb alla RX del peer, dove
# XDP lo riscrive -- quindi pktgen rifiuta clone_skb. Una volta saputo, non si
# riprova: altrimenti ogni punto di misura stampa lo stesso avviso per ogni
# device, e a tre thread sono sei righe di rumore per misura.
_CLONE_SUPPORTED = True

# Frame sizes. 64 e' il minimo Ethernet; 1514 il massimo senza jumbo. Il frame
# IPA minimo di questo progetto e' 63 byte, quindi 64 li contiene tutti.
DEFAULT_FRAMES = [64, 128, 256, 512, 1024, 1514]

# Sotto questa percentuale la perdita e' considerata rumore della macchina e non
# saturazione del datapath. Vedi find_knee per la misura che ha imposto questa
# scelta. Zero stretto resta riportato a parte.
DEFAULT_LOSS_THRESHOLD = 0.1

# Quante volte ripetere ogni punto. Non e' prudenza generica: tre misure della
# stessa identica configurazione hanno dato 0.06%, 19.52% e 0.00% di perdita.
# Vedi measure_point.
DEFAULT_REPEAT = 3

# Giri completi: in ogni giro si misurano TUTTI i metodi, poi si prende la
# mediana. Serve a togliere l'ordine dei metodi dalla misura -- vedi run_fair.
DEFAULT_ROUNDS = 3

# Oltre questa dispersione fra le ripetizioni il punto non e' utilizzabile.
# Misurato: hardcoded ha dato +-75% fra tre misure della stessa cosa, e la
# baseline e' uscita il 26% PIU' LENTA di una pipeline che fa strettamente piu'
# lavoro -- cioe' il run misurava il carico della macchina, non il datapath.
MAX_SPREAD_PCT = 25.0

# Sotto questa differenza relativa due pipeline non sono distinguibili su questo
# banco, e un'inversione non e' un difetto del run. Vedi check_validity.
VALID_TOL = 0.10

# Ritardi fissi, usati solo se il chiamante li chiede con --delays. Il default
# e' la ricerca del ginocchio (find_knee), che costa meno punti e centra la
# risposta invece di avvicinarla.
DEFAULT_DELAYS = [0, 200, 500, 1000, 2000, 5000, 10000]

# Cinque gradini, e i due estremi servono a leggere i tre in mezzo.
#
#   baseline   XDP che parsa, decrementa il TTL e redirige su una classe FISSA.
#              Nessuna inferenza. E' il TETTO DEL BANCO: se satura anche lei a
#              X pacchetti/s, allora X e' il limite del veth e delle CPU, non
#              della pipeline, e ogni cifra sotto va letta rispetto a quello.
#              Senza questa colonna non si sa se si sta misurando il datapath o
#              la macchina.
#   p1_static  pesi E indice del nodo compilati dentro: un binario per nodo.
#   hardcoded  pesi compilati, nodo da mappa (la "P1.5").
#   template   solo i soffitti compilati.
#   modular    anche la profondita' a runtime.
METHODS = ("baseline", "p1_static", "hardcoded", "template", "modular")

# Il nodo che la P1 specializzata si porta dentro. Lo stesso che installa
# test_fabric, cosi' le due misure parlano dello stesso nodo.
STATIC_NODE = 7

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
    """Is pktgen loaded -- and if not, load it.

    The module unloads between sessions (a reboot, an autoclean), and the
    script already runs as root, so sending the user off to find `modprobe`
    is a stop for something it can do itself. Only the failure is worth
    reporting."""
    if os.path.isdir(PKTGEN_DIR):
        return True
    subprocess.run(["modprobe", "pktgen"], check=False, capture_output=True)
    if os.path.isdir(PKTGEN_DIR):
        info("modulo pktgen caricato")
        return True
    return False


def pg_reset():
    pg_write(f"{PKTGEN_DIR}/pgctrl", "reset")


def probe_clone_support(dev):
    """Chiedi UNA volta se questo device accetta clone_skb, prima di misurare.

    Il rifiuto costa una misura: il tentativo mancato lascia il device in uno
    stato da cui `start` non parte -- pktgen riporta `pkts-sofar: 0` e
    `started: 0us` -- e quella misura andava a zero pacchetti in mezzo allo
    sweep. Scoprirlo prima, su un device gia' configurato per essere buttato,
    toglie il problema alla radice invece di gestirne le conseguenze."""
    global _CLONE_SUPPORTED
    if not os.path.exists(f"{PKTGEN_DIR}/{dev}"):
        return _CLONE_SUPPORTED
    try:
        pg_write(f"{PKTGEN_DIR}/{dev}", "clone_skb 1")
        pg_write(f"{PKTGEN_DIR}/{dev}", "clone_skb 0")
    except RuntimeError:
        _CLONE_SUPPORTED = False
        info("clone_skb non supportato su questo device (veth consegna l'skb "
             "alla RX del peer e non puo' condividerlo): niente escalation")
    return _CLONE_SUPPORTED


def pg_clear_threads(n):
    """Detach every device from the first `n` generator threads."""
    for i in range(n):
        try:
            pg_write(f"{PKTGEN_DIR}/kpktgend_{i}", "rem_device_all")
        except RuntimeError:
            break                   # fewer threads than CPUs: nothing to clear


def pg_ensure_device(dev, thread=0):
    """Attacca `dev` se pktgen non lo conosce (piu'). Idempotente."""
    if os.path.exists(f"{PKTGEN_DIR}/{dev}"):
        return f"{PKTGEN_DIR}/{dev}"
    return pg_add_device(dev, thread)


def pg_add_device(dev, thread=0):
    """Attacca `dev` al thread generatore `thread` e verifica che ci sia."""
    pg_write(f"{PKTGEN_DIR}/kpktgend_{thread}", f"add_device {dev}")
    d = f"{PKTGEN_DIR}/{dev}"
    if not os.path.exists(d):
        raise RuntimeError(
            f"pktgen: {d} non esiste dopo `add_device {dev}`. "
            f"L'interfaccia esiste ed e' UP? `ip link show {dev}`")
    return d


def pg_set_params(dev, pkt_size, count, delay, dst_ip="10.0.0.2",
                  dst_mac="02:00:00:00:00:02"):
    """Cambia i parametri di un device GIA' attaccato, senza staccarlo.

    Separato da pg_configure perche' rimuovere e riaggiungere il device a ogni
    punto di misura faceva fallire `add_device` con EBUSY -- la rimozione non e'
    sincrona e il thread lo teneva ancora. Cambiare i parametri e' quello che
    serviva fin dall'inizio."""
    d = f"{PKTGEN_DIR}/{dev}"
    for cmd in (f"count {count}", f"pkt_size {pkt_size}", f"delay {delay}",
                f"dst {dst_ip}", f"dst_mac {dst_mac}",
                "udp_src_min 1234", "udp_src_max 1234",
                "udp_dst_min 9999", "udp_dst_max 9999"):
        pg_write(d, cmd)


def pg_configure(dev, pkt_size, count, delay, dst_ip, dst_mac, clone=0,
                 thread=0, burst=0, xmit_mode="start_xmit"):
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
    global _CLONE_SUPPORTED, _BURST_SUPPORTED
    if xmit_mode != "start_xmit":
        # Set before anything else: it changes which path the packets take, and
        # some settings are only meaningful on one of them.
        pg_write(d, f"xmit_mode {xmit_mode}")
    if burst and _BURST_SUPPORTED:
        try:
            pg_write(d, f"burst {burst}")
        except RuntimeError:
            _BURST_SUPPORTED = False
            warn("burst rifiutato da questo device, proseguo senza.")
    if clone and _CLONE_SUPPORTED:
        # Optional by design: clone_skb is the escalation knob, not part of the
        # reference condition. A kernel that refuses it costs one experiment,
        # not the whole run -- so it is tried separately, reported ONCE, and
        # never attempted again.
        try:
            pg_write(d, f"clone_skb {clone}")
        except RuntimeError:
            _CLONE_SUPPORTED = False
            warn("clone_skb rifiutato da questo device: veth consegna l'skb "
                 "alla RX del peer e non puo' condividerlo. Proseguo senza, "
                 "e non ci riprovo.")
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
        try:
            with open(f"{PKTGEN_DIR}/{dev}") as f:
                text = f.read()
        except FileNotFoundError:
            # pktgen ha smesso di conoscere questo device fra la
            # configurazione e la lettura. Succede quando il fabric viene
            # ricostruito fra un metodo e l'altro: l'interfaccia ha lo stesso
            # NOME ma e' un'altra, e lo stato di pktgen non sopravvive al giro.
            # Costa un punto di misura, non il run: il chiamante lo salta e
            # riaggancia il device al giro dopo.
            raise PktgenEmptyRun(
                f"pktgen non conosce piu' {dev} (fabric ricostruito?)")
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
        # Non fatale: un punto che non si misura e' un punto che non si
        # misura, non la fine dell'esperimento. Alzare qui buttava via anche
        # le misure gia' riuscite dello stesso run.
        # Nothing parsed usually means the device was never added, or pktgen
        # refused the config. Hand the raw text over rather than reporting a
        # silent zero that looks like 100% loss.
        raise PktgenEmptyRun(
            f"pktgen non riporta pacchetti per {devs}")
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
                  tg_devs=None, repeat=DEFAULT_REPEAT, burst=0,
                  xmit_mode="start_xmit"):
    """`repeat` runs of the same point; returns the median by rx_pps, carrying
    the WORST loss seen across them.

    Single samples are not usable here. Measured on this bench, three runs of
    one identical configuration -- same pipeline, same rate, same frame,
    clone_skb already known refused -- gave 0.06%, 19.52% and 0.00% loss. A
    knee search reading one of those decides on noise: the 19.52% made it
    conclude the datapath was saturating and restart the search.

    Median for the RATE, because a slow outlier is a busy machine and not the
    datapath. Worst for the LOSS, because a rate that drops packets on one run
    out of three is not a rate this datapath sustains, and calling it clean
    would be the optimistic lie this whole script exists to avoid."""
    runs = []
    for _ in range(max(1, repeat)):
        try:
            r = _measure_once(setup, rx_tab, fab, frame, delay, count,
                              n_out, clone, tg_devs, burst, xmit_mode)
        except PktgenEmptyRun as e:
            warn(f"misura scartata: {e}")
            continue
        # HIT > 0 e RX == 0 non e' "perdita del 100%": e' il contatore che non
        # ha visto niente mentre il programma elaborava tutto. E' un guasto
        # della strumentazione, e tenerlo faceva comparire righe con
        # TX == HIT == RX == 200000 marcate 100.00%, perche' la perdita
        # PEGGIORE delle tre ripetizioni veniva da una misura rotta.
        if r["hit"] > 0 and r["rx"] == 0:
            warn(f"misura scartata: {r['hit']} elaborati e 0 contati in "
                 f"uscita -- contatore RX non aggiornato, non perdita")
            continue
        runs.append(r)
    if not runs:
        return None
    runs.sort(key=lambda r: r["rx_pps"])
    med = runs[len(runs) // 2]
    med["repeat"] = len(runs)
    med["loss_worst"] = max(r["loss_pct"] for r in runs)
    med["loss_best"] = min(r["loss_pct"] for r in runs)
    med["rx_pps_min"] = runs[0]["rx_pps"]
    med["rx_pps_max"] = runs[-1]["rx_pps"]
    med["burst"] = burst
    med["xmit_mode"] = xmit_mode
    lo, hi = med["rx_pps_min"], med["rx_pps_max"]
    med["spread_pct"] = round(100.0 * (hi - lo) / lo, 1) if lo else None
    # Una mediana su misure che oscillano del 75% non e' una misura: e' il
    # carico della macchina in tre momenti diversi. Marcarla e' l'unica cosa
    # onesta da farne.
    med["unreliable"] = bool(med["spread_pct"] is not None
                             and med["spread_pct"] > MAX_SPREAD_PCT)
    return med


def _measure_once(setup, rx_tab, fab, frame, delay, count, n_out, clone=0,
                  tg_devs=None, burst=0, xmit_mode="start_xmit"):
    """One (frame size, offered rate) point. Returns a dict of counters.

    `count` is per generator thread, so the offered load scales with the number
    of threads and the per-thread duration stays comparable."""
    devs = tg_devs or [fab.ingress_peer]
    _zero_counters(setup, rx_tab, n_out)
    pg_clear_threads(len(devs))
    for i, dev in enumerate(devs):
        pg_configure(dev, frame, count, delay,
                     dst_ip="10.0.0.2", dst_mac="02:00:00:00:00:02",
                     clone=clone, thread=i, burst=burst,
                     xmit_mode=xmit_mode)
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
# LATENZA ARRIVO -> RIPARTENZA, su traffico vero
# ==========================================================================
# E' l'unica voce dell'elenco che nessun'altra misura di questo progetto da'.
#
# test_suite cronometra il PROGRAMMA: dall'ingresso alla sua return. Non ci
# sono dentro ne' la consegna del pacchetto al programma, ne' la trasmissione
# vera, perche' bpf_redirect non spedisce -- accoda, e il pacchetto parte dopo
# che il programma e' finito. Il generatore, dall'altra parte, misura pacchetti
# al secondo e perdita, non il tempo di attraversamento.
#
# Qui si misura la cosa che interessa a un nodo che inoltra: quanto passa fra
# l'arrivo e il momento in cui il pacchetto e' davvero uscito.
#
# COME. Il dispatcher segna bpf_ktime_get_ns() in una cella PER-CPU; il
# programma d'uscita rilegge quella cella e fa la differenza. La cella per-CPU
# regge perche' il redirect avviene sullo stesso core, in modo sincrono: fra la
# scrittura e la lettura non si cambia CPU.
#
# PERCHE' IN UN OGGETTO SOLO. Due oggetti BPF distinti non condividono mappe
# (servirebbe il pinning su bpffs). Il programma d'uscita viene quindi compilato
# INSIEME alla pipeline, ed e' la ragione per cui questa modalita' ricostruisce
# il sorgente invece di riusare verify_prog_run.setup_*.
#
# IL PREZZO, DICHIARATO. E' una BUILD STRUMENTATA: la scrittura del timestamp
# non c'e' nel datapath di produzione. Aggiunge una scrittura di mappa per
# pacchetto, quindi la latenza misurata qui e' leggermente SUPERIORE a quella
# vera, e il throughput leggermente inferiore. Stessa scelta gia' fatta per il
# contatore dei lookup in test_suite, e per lo stesso motivo: una misura che
# non esiste vale piu' di una misura perfetta impossibile.

# Le DICHIARAZIONI vanno inserite prima del dispatcher che le usa: in C non si
# usa un simbolo prima di dichiararlo, e appendendo tutto in fondo al sorgente
# il dispatcher vedeva `ts_in` non dichiarata e clang si fermava -- errore che
# BCC riporta solo come "Failed to compile BPF module".
#
# Vanno anche DOPO gli #include della pipeline, perche' servono i tipi del
# kernel: il punto giusto e' quindi immediatamente sopra il dispatcher, cioe'
# lo stesso anchor usato per il timestamp.
LAT_DECLS_SRC = r"""
BPF_PERCPU_ARRAY(ts_in, __u64, 1);
/* 0 = quanti, 1 = somma ns, 2 = minimo, 3 = massimo */
BPF_PERCPU_ARRAY(lat_acc, __u64, 4);
/* Istogramma logaritmico: la cella i raccoglie [2^i, 2^(i+1)) ns. Serve per i
 * PERCENTILI, perche' media e massimo su una VM non dicono niente -- misurato:
 * media ~2000 ns con minimo 250 e massimo 10,6 ms, cioe' un singolo valore
 * enorme che trascina la media. */
BPF_PERCPU_ARRAY(lat_hist, __u64, LAT_BUCKETS);   /* log2: [2^i, 2^(i+1)) */
"""

LAT_COUNTER_SRC = r"""
int xdp_lat_count(struct xdp_md *ctx) {
    int z = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *t0 = ts_in.lookup(&z);
    if (t0 && *t0 && now > *t0) {
        __u64 d = now - *t0;
        __u32 bk = bpf_log2l(d);
        if (bk >= LAT_BUCKETS) bk = LAT_BUCKETS - 1;
        int bi = (int)bk;
        __u64 *hb = lat_hist.lookup(&bi); if (hb) *hb += 1;
        int k = 0;
        __u64 *n = lat_acc.lookup(&k); if (n) *n += 1;
        k = 1; __u64 *sm = lat_acc.lookup(&k); if (sm) *sm += d;
        k = 2; __u64 *mn = lat_acc.lookup(&k);
        if (mn && (*mn == 0 || d < *mn)) *mn = d;
        k = 3; __u64 *mx = lat_acc.lookup(&k); if (mx && d > *mx) *mx = d;
    }
    return XDP_DROP;
}
"""

# Iniettata subito dopo la graffa del dispatcher: il primo istante in cui il
# programma ha il pacchetto in mano.
LAT_STAMP = ("\n    { int _lz = 0; __u64 _lt = bpf_ktime_get_ns();\n"
             "      ts_in.update(&_lz, &_lt); }\n")

# Nome della funzione d'ingresso XDP per ciascun metodo: e' quella in cui
# infilare il timestamp, ed e' quella che si attacca all'interfaccia.
# Istogramma LOGARITMICO, 40 celle: la cella i raccoglie [2^i, 2^(i+1)) ns,
# quindi si copre da 1 ns a ~18 minuti.
#
# Il primo tentativo erano 256 celle lineari da 16 ns, scelte per separare 228
# da 243 da 267 -- le differenze fra le pipeline sono di quell'ordine. Sbagliato
# per la ragione opposta: quella finestra copre 4 us, e sotto carico p90 e p99
# stanno molto piu' in alto, quindi venivano riportati come ">4us", cioe' non
# riportati.
#
# La distinzione fine fra pipeline sta nel MINIMO, che e' esatto e non passa per
# l'istogramma. I percentili servono a descrivere la coda sotto carico, e la'
# la risoluzione logaritmica (1-2 us, 2-4 us, ...) e' quella giusta.
LAT_BUCKETS = 40

LAT_ENTRY = {
    "baseline": "xdp_baseline",
    "p1_static": "ipa_switch_hardcoded",
    "hardcoded": "ipa_switch_hardcoded",
    "template": "ipa_switch_template",
    "modular": "modular_dispatcher",
}


def _instrumented_source(method, model_path, node=STATIC_NODE):
    """(sorgente, pesi, scale) della pipeline col timestamp e il contatore."""
    import verify_prog_run as V
    weights, scale = V.load_weights(model_path)

    if method == "baseline":
        src = V.EBPF_BASELINE
    elif method in ("hardcoded", "p1_static"):
        from ebpf_program import build_combined_hardcoded_source
        src = build_combined_hardcoded_source(
            [(0, weights, scale)],
            static_node=(node if method == "p1_static" else None))
    elif method == "template":
        from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                        EBPF_ARCH_GENERIC_2LAYER)
        src = ("#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
               + "\n" + EBPF_ARCH_GENERIC_2LAYER)
    else:
        from ebpf_modular import EBPF_MODULAR_FULL
        src = EBPF_MODULAR_FULL

    anchor = f"int {LAT_ENTRY[method]}(struct xdp_md *ctx) {{"
    if src.count(anchor) != 1:
        raise RuntimeError(
            f"non trovo il punto d'ingresso '{anchor}' nel sorgente di "
            f"{method} (trovato {src.count(anchor)} volte). E' cambiata la "
            f"firma del dispatcher?")
    defines = f"#define LAT_BUCKETS {LAT_BUCKETS}\n"
    src = src.replace(anchor,
                      defines + LAT_DECLS_SRC + "\n" + anchor + LAT_STAMP)
    return src + "\n" + LAT_COUNTER_SRC, weights, scale


def _load_instrumented(method, model_path, fab, sem, node=STATIC_NODE):
    """Compila tutto insieme, carica, e caba la pipeline su questo fabric."""
    from bcc import BPF
    import verify_prog_run as V
    import test_fabric as TF

    src, weights, scale = _instrumented_source(method, model_path, node)
    try:
        b = BPF(text=src)
    except Exception as e:
        # BCC riporta solo "Failed to compile BPF module": la diagnostica di
        # clang l'ha gia' stampata su stderr, SOPRA questa riga.
        raise RuntimeError(
            f"la build strumentata di {method} non compila. L'errore di clang "
            f"e' nelle righe SOPRA questa. ({e})") from e
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

    # tail call / pesi, come fa il setup di produzione
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


def _read_lat(b):
    """Statistiche di latenza, sommando le celle per-CPU.

    Restituisce un dizionario con min, p50, p90, p99, media, max e quanti
    campioni hanno sforato l'istogramma. I percentili vengono dai bucket;
    minimo e massimo sono esatti.

    La MEDIA e' riportata ma non va usata per concludere: su questa VM un
    singolo valore da 10 ms fra 100 000 campioni la sposta di piu' di quanto la
    differenza fra due pipeline. I percentili no."""
    acc = b["lat_acc"]
    n = sum(int(v) for v in acc[ct.c_int(0)])
    if not n:
        return None
    tot = sum(int(v) for v in acc[ct.c_int(1)])
    mins = [int(v) for v in acc[ct.c_int(2)] if int(v) > 0]
    maxs = [int(v) for v in acc[ct.c_int(3)]]

    hist = b["lat_hist"]
    buckets = [sum(int(v) for v in hist[ct.c_int(i)])
               for i in range(LAT_BUCKETS)]
    over = buckets[-1]          # oltre 2^39 ns: praticamente mai

    def pct(q):
        """Il bordo SUPERIORE del bucket log2 in cui cade il quantile q.

        Un bucket i copre [2^i, 2^(i+1)), quindi il valore riportato e' un
        limite superiore: "il 99% sta sotto questa cifra". E' il modo in cui un
        percentile da istogramma si legge, e va detto perche' il numero non e'
        il percentile esatto ma il bordo che lo contiene."""
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


def run_latency(method, model_path, frames, delays, count, threads,
                threaded_napi=True):
    """Latenza arrivo -> ripartenza, a piu' dimensioni di frame e piu' rate."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} {method} -- latenza arrivo->ripartenza E throughput "
          f"(build strumentata){NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")

    sem, n_out = class_semantics()
    rows = []
    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        setup, lat_fn = _load_instrumented(method, model_path, fab, sem)
        b = setup["b"]
        for peer in fab.peer_of.values():
            try:
                attach_xdp(b, lat_fn, peer)
            except Exception as e:
                warn(f"contatore latenza non agganciato a {peer}: {e}")
        attach_xdp(b, setup["disp"], fab.ingress)
        info("un oggetto BPF solo: ingresso e uscita condividono le mappe")

        napi_devs = []
        if threaded_napi:
            napi_devs = [fab.ingress]
            if enable_threaded_napi(napi_devs, threads, os.cpu_count() or 1):
                info("NAPI in thread: generatore e DUT su core separati")

        # Throughput E latenza nella stessa riga, perche' vengono dallo
        # STESSO pacchetto: il programma d'uscita conta e cronometra insieme,
        # quindi `campioni` e' esattamente RX. Riportarli separati avrebbe
        # significato due run e due stati della macchina per due numeri che
        # descrivono lo stesso evento.
        # Aggiunto una volta per tutto il run: vedi pg_set_params.
        pg_clear_threads(1)
        pg_add_device(fab.ingress_peer, thread=0)
        hdr = (f"  {'frame':>5s} {'delay':>6s} {'TX':>8s} {'RX':>8s} "
               f"{'RX pps':>9s} {'Mb/s':>7s} {'perdita':>8s} "
               f"{'min':>6s} {'p50':>6s} {'p90':>6s} {'p99':>7s}")
        print(f"\n{hdr}")
        print("  " + "-" * (len(hdr) - 2))
        for frame in frames:
            for delay in delays:
                b["lat_acc"].clear()
                b["lat_hist"].clear()
                # Il device si aggiunge UNA volta (sopra) e poi si cambiano
                # solo i parametri. Rimuoverlo e riaggiungerlo a ogni punto
                # faceva fallire `add_device` con EBUSY: la rimozione non e'
                # istantanea e il thread lo teneva ancora.
                # Idempotente: se il device e' ancora agganciato non fa
                # nulla, se e' sparito lo riaggancia. Costa una `stat` per
                # punto e toglie un'intera classe di fallimenti.
                pg_ensure_device(fab.ingress_peer, thread=0)
                pg_set_params(fab.ingress_peer, frame, count, delay)
                try:
                    tx, tx_pps, secs = pg_run_and_read([fab.ingress_peer])
                except PktgenEmptyRun as e:
                    warn(f"punto scartato: {e}")
                    continue
                st = _read_lat(b)
                if st is None:
                    warn(f"frame {frame} delay {delay}: nessun campione -- il "
                         f"pacchetto non e' arrivato all'uscita")
                    continue

                rx = st["n"]
                secs = secs or 1e-9
                rx_pps = int(rx / secs)
                # Il throughput sul filo conta il frame intero, non il payload.
                mbps = round(rx * frame * 8 / secs / 1e6, 1)
                # RX > TX non e' una perdita negativa: sono pacchetti
                # arrivati all'uscita che questo punto non ha trasmesso --
                # residui in volo dal punto precedente, o traffico del kernel.
                # Misurato: 100 256 contati su 100 000 inviati dopo un punto
                # scartato. Riportarlo come -0,26% dava un numero senza senso.
                excess = max(0, rx - tx)
                loss = round(100.0 * max(0, tx - rx) / tx, 3) if tx else 0.0

                def _f(v):
                    return f"{v:5d}n" if v is not None else "  >4us"
                mark = GREEN if loss <= 0.1 else (RED if loss > 1 else YELLOW)
                tag = f" {GREY}+{excess}{NC}" if excess else ""
                print(f"  {frame:5d} {delay:6d} {tx:8d} {rx:8d} "
                      f"{rx_pps:9d} {mbps:7.1f} {mark}{loss:7.2f}%{NC}{tag} "
                      f"{_f(st['lat_min_ns'])} {_f(st['lat_p50_ns'])} "
                      f"{_f(st['lat_p90_ns'])} {_f(st['lat_p99_ns'])}")
                rows.append(dict(method=method, frame=frame, delay=delay,
                                 tx=tx, rx=rx, tx_pps=tx_pps, rx_pps=rx_pps,
                                 rx_mbps=mbps, loss_pct=loss,
                                 excess_rx=excess, samples=rx, **{
                                     k: st[k] for k in
                                     ("lat_min_ns", "lat_p50_ns",
                                      "lat_p90_ns", "lat_p99_ns",
                                      "lat_avg_ns", "lat_max_ns")},
                                 over_4us=st["over"]))
        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
    print(f"\n  {GREY}Latenza dal primo istante in cui il programma ha il "
          f"pacchetto al momento in cui e' uscito. Include la trasmissione, "
          f"che test_suite non misura, e la scrittura del timestamp, che il "
          f"datapath di produzione non fa.{NC}")
    print(f"  {GREY}Leggi il MINIMO e i percentili. La media resta nel CSV "
          f"per completezza, ma su questa VM un singolo campione da "
          f"millisecondi la sposta piu' della differenza fra due pipeline.{NC}")
    print(f"  {GREY}Il throughput qui e' della build STRUMENTATA, che paga una "
          f"scrittura di mappa per pacchetto in piu': e' quindi un limite "
          f"INFERIORE di quello di produzione, non lo stesso numero. Per il "
          f"throughput da citare usa il run senza --latency.{NC}")
    return rows



# ==========================================================================
# CONFRONTO EQUO: stesse condizioni per tutte le pipeline
# ==========================================================================
# Tre cose differivano fra un metodo e l'altro, e ognuna e' bastata da sola a
# rovinare un run:
#
# 1. OGNI METODO RICOSTRUIVA IL FABRIC. Veth nuove, ifindex nuovi, e lo stato di
#    pktgen che non sopravvive al giro -- da cui il device che spariva a meta'
#    sweep. Qui il fabric si costruisce UNA volta e lo usano tutti.
#
# 2. OGNI METODO CHIAMAVA CLANG SUBITO PRIMA DI MISURARE. template e modular
#    bruciano secondi di CPU che baseline non brucia, e la misura partiva su una
#    macchina in stati diversi. Qui si compila e si carica TUTTO prima, e durante
#    le misure nessun compilatore gira.
#
# 3. I METODI GIRAVANO IN SEQUENZA, una volta ciascuno. Qualunque deriva della
#    macchina -- pagine, frequenza, un processo che si sveglia -- si mappava
#    sull'ORDINE dei metodi, ed e' cosi' che la baseline e' uscita il 26% piu'
#    lenta di una pipeline che fa strettamente piu' lavoro. Qui si misura a
#    GIRI: in ogni giro tutti i metodi, e di ogni metodo si tiene la mediana fra
#    i giri. Una deriva colpisce allora tutti allo stesso modo invece di
#    premiare chi capita per primo.
#
# Resta quello che non si puo' togliere: TG e DUT sulla stessa macchina. Ma
# adesso e' l'unica differenza rimasta fra le colonne, non una delle quattro.


class _quiet:
    """Zittisce stdout. attach_xdp stampa una riga per interfaccia, e nel
    confronto a giri sono 6 interfacce x 5 pipeline x N giri: novanta righe di
    rumore in cui la tabella dei risultati si perde. La prima attaccatura resta
    visibile, le successive no."""

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


def run_fair(methods, model_path, frames, delays, count, threads,
             threaded_napi=True, repeat=DEFAULT_REPEAT, rounds=DEFAULT_ROUNDS):
    """Tutte le pipeline sullo stesso fabric, compilate prima, misurate a giri."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    sem, n_out = class_semantics()
    raw = []

    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        # --- fase 1: compila e carica tutto. Qui gira clang, una volta sola,
        #     e nessuna misura e' ancora partita.
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Fase 1: compilo e carico {len(methods)} pipeline "
              f"(nessuna misura in corso){NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        loaded = {}
        for m in methods:
            try:
                setup, lat_fn = _load_instrumented(m, model_path, fab, sem)
                loaded[m] = (setup, lat_fn)
                info(f"{m}: caricata")
            except Exception as e:
                warn(f"{m}: non caricata, la salto -- {type(e).__name__}: {e}")
        if not loaded:
            warn("nessuna pipeline caricata")
            return []

        pg_clear_threads(1)
        pg_add_device(fab.ingress_peer, thread=0)
        napi_devs = []

        # --- fase 2: misura a giri, tutti i metodi in ogni giro
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Fase 2: {rounds} giri x {len(loaded)} pipeline, "
              f"stesso fabric, nessuna compilazione{NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        hdr = (f"  {'giro':>4s} {'pipeline':10s} {'frame':>5s} {'delay':>6s} "
               f"{'RX pps':>9s} {'Mb/s':>7s} {'perdita':>8s} "
               f"{'min':>6s} {'p50':>6s} {'p99':>7s}")
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))

        first = True
        for rnd in range(1, rounds + 1):
            for m, (setup, lat_fn) in loaded.items():
                b = setup["b"]
                # SOSTITUISCE il programma, non lo stacca: attach_xdp non passa
                # UPDATE_IF_NOEXIST, quindi un attach su un'interfaccia che ne
                # ha gia' uno lo rimpiazza. Staccare avrebbe smontato la NAPI, e
                # con lei la modalita' a thread -- che e' esattamente perche' al
                # run precedente `threaded` veniva rifiutato.
                ctx = (lambda: _quiet()) if not first else (lambda: _noop())
                with ctx():
                    for peer in fab.peer_of.values():
                        try:
                            attach_xdp(b, lat_fn, peer)
                        except Exception:
                            pass
                    attach_xdp(b, setup["disp"], fab.ingress)
                if first:
                    # SOLO ORA la NAPI esiste: veth la usa quando c'e' un
                    # programma XDP attaccato. Abilitarla prima -- com'era --
                    # otteneva "Operation not supported", perche' non c'era
                    # nulla da mettere in thread.
                    if threaded_napi:
                        napi_devs = [fab.ingress]
                        if enable_threaded_napi(napi_devs, threads,
                                                os.cpu_count() or 1):
                            info("NAPI in thread: generatore e DUT su core "
                                 "separati")
                        else:
                            napi_devs = []
                    first = False
                # Scaldata scartata: la prima raffica paga cache fredde e la
                # prima allocazione, e non descrive il regime.
                try:
                    pg_ensure_device(fab.ingress_peer, thread=0)
                    pg_set_params(fab.ingress_peer, 64, 2000, 0)
                    pg_run_and_read([fab.ingress_peer])
                except PktgenEmptyRun:
                    pass
                for frame in frames:
                    for delay in delays:
                        r = _one_fair_point(b, fab, frame, delay, count)
                        if r is None:
                            continue
                        r.update(method=m, round=rnd, threads=threads)
                        raw.append(r)
                        print(f"  {rnd:4d} {m:10s} {frame:5d} {delay:6d} "
                              f"{r['rx_pps']:9d} {r['rx_mbps']:7.1f} "
                              f"{r['loss_pct']:7.2f}% "
                              f"{_fmt_ns(r['lat_min_ns'])} "
                              f"{_fmt_ns(r['lat_p50_ns'])} "
                              f"{_fmt_ns(r['lat_p99_ns'])}")

        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        _detach(fab.ingress)
        for peer in fab.peer_of.values():
            _detach(peer)
    return raw


def _noop():
    class _N:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    return _N()


def _fmt_ns(v):
    return f"{v:5d}n" if v is not None else "  n/d"


def _one_fair_point(b, fab, frame, delay, count):
    """Un punto: throughput e latenza dallo stesso pacchetto."""
    b["lat_acc"].clear()
    b["lat_hist"].clear()
    try:
        pg_ensure_device(fab.ingress_peer, thread=0)
        pg_set_params(fab.ingress_peer, frame, count, delay)
        tx, tx_pps, secs = pg_run_and_read([fab.ingress_peer])
    except PktgenEmptyRun as e:
        warn(f"punto scartato: {e}")
        return None
    st = _read_lat(b)
    if st is None:
        return None
    rx, secs = st["n"], (secs or 1e-9)
    return dict(frame=frame, delay=delay, tx=tx, rx=rx, tx_pps=tx_pps,
                rx_pps=int(rx / secs), rx_mbps=round(rx * frame * 8 / secs / 1e6, 1),
                loss_pct=round(100.0 * max(0, tx - rx) / tx, 3) if tx else 0.0,
                excess_rx=max(0, rx - tx),
                **{k: st[k] for k in ("lat_min_ns", "lat_p50_ns", "lat_p90_ns",
                                      "lat_p99_ns", "lat_avg_ns",
                                      "lat_max_ns")})


def _give_back(*paths):
    """Ridai i file all'utente che ha lanciato il sudo.

    Senza questo i CSV restano di root: il run dopo non puo' sovrascriverli e
    nemmeno il plotter puo' leggerli comodamente."""
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
    """La latenza regge anche dove il throughput no: dirlo esplicitamente.

    Sullo stesso identico run, a pieno rate: il throughput di una pipeline
    varia del 137% fra i giri, la sua latenza minima di meno dell'1%. Sono due
    misure con due affidabilita' diverse e vanno riportate come tali, invece di
    lasciare che il lettore prenda la tabella per buona tutta insieme."""
    lat = [r for r in rows if r.get("lat_spread_pct") is not None]
    if not lat:
        return
    worst = max(lat, key=lambda r: r["lat_spread_pct"])
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Latenza: quanto e' riproducibile{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    if worst["lat_spread_pct"] <= 5.0:
        print(f"  {GREEN}[PASS]{NC} la latenza minima varia al massimo del "
              f"{worst['lat_spread_pct']:.1f}% fra i giri "
              f"({worst['method']}, frame {worst['frame']}, delay "
              f"{worst['delay']}).")
        print(f"  {GREY}E' la misura da citare: riproducibile anche dove il "
              f"throughput non lo e'.{NC}")
    else:
        print(f"  {RED}[FAIL]{NC} la latenza minima varia fino al "
              f"{worst['lat_spread_pct']:.1f}% fra i giri "
              f"({worst['method']}): alza --rounds.")


def summarise_fair(raw, methods):
    """Mediana fra i giri, per metodo e configurazione."""
    import statistics as stats
    if not raw:
        return []
    keys = sorted({(r["method"], r["frame"], r["delay"]) for r in raw})
    out = []
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Riepilogo: mediana fra i giri{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    hdr = (f"  {'pipeline':10s} {'frame':>5s} {'delay':>6s} {'giri':>4s} "
           f"{'RX pps':>9s} {'Mb/s':>7s} {'perdita':>8s} "
           f"{'min':>6s} {'p50':>6s} {'p99':>7s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for m, frame, delay in keys:
        pts = [r for r in raw if (r["method"], r["frame"], r["delay"])
               == (m, frame, delay)]
        med = {k: stats.median([r[k] for r in pts if r[k] is not None] or [0])
               for k in ("rx_pps", "rx_mbps", "loss_pct", "lat_min_ns",
                         "lat_p50_ns", "lat_p99_ns")}
        # Dispersione FRA I GIRI, non dentro un punto. E' la cosa che dice se
        # la mediana significa qualcosa: misurato, hardcoded a pieno rate ha
        # dato 2,78 / 1,17 / 1,46 Mpps in tre giri -- 137% -- e la sua mediana
        # e' finita SOTTO template, che fa molto piu' lavoro. Una mediana su
        # misure cosi' non e' un risultato, ed e' il numero che va marcato.
        pps = [r["rx_pps"] for r in pts if r["rx_pps"]]
        spread = (100.0 * (max(pps) - min(pps)) / min(pps)) if pps else 0.0
        # La latenza ha la sua dispersione, e nei fatti e' un altro mondo:
        # pochi ns su tre giri contro decine di punti percentuali.
        lats = [r["lat_min_ns"] for r in pts if r["lat_min_ns"]]
        lat_spread = (100.0 * (max(lats) - min(lats)) / min(lats)) if lats else 0.0
        bad = spread > MAX_SPREAD_PCT
        row = dict(method=m, frame=frame, delay=delay, rounds=len(pts),
                   pps_spread_pct=round(spread, 1),
                   lat_spread_pct=round(lat_spread, 1), unreliable=bad, **med)
        out.append(row)
        flag = f" {RED}pps +-{spread:.0f}%{NC}" if bad else ""
        print(f"  {m:10s} {frame:5d} {delay:6d} {len(pts):4d} "
              f"{int(med['rx_pps']):9d} {med['rx_mbps']:7.1f} "
              f"{med['loss_pct']:7.2f}% "
              f"{int(med['lat_min_ns']):5d}n {int(med['lat_p50_ns']):5d}n "
              f"{int(med['lat_p99_ns']):6d}n{flag}")
    return out


# ==========================================================================
# THREADED NAPI: separare davvero il generatore dal DUT
# ==========================================================================
# Questo e' il pezzo che rende il banco un banco TG/DUT invece di una misura
# della somma dei due.
#
# In modalita' softirq la RX di un veth gira sulla CPU che ha trasmesso: il
# generatore e la pipeline finiscono sullo stesso core, e il tempo per pacchetto
# e' t_gen + t_pipeline. Cosi' il generatore satura sempre per primo e la
# pipeline non arriva mai al suo limite -- il risultato e' che "throughput
# massimo" e "throughput a perdita nulla" coincidono, che e' un non-risultato.
#
# Dal kernel 5.12 /sys/class/net/<dev>/threaded sposta il poll NAPI in un
# KERNEL THREAD dedicato (`napi/<dev>-<id>`), che lo scheduler puo' mettere
# altrove e che si puo' pinnare a mano. Pinnando i thread NAPI sulle CPU che
# pktgen NON usa, generatore e DUT stanno davvero su core diversi:
#
#     CPU 0..T-1   pktgen genera
#     CPU T..N-1   napi/<dev>-*  esegue XDP, cioe' l'inferenza
#
# Da quel momento la domanda "a che rate la pipeline comincia a perdere" ha una
# risposta, perche' il generatore non le ruba piu' il core.
#
# Non e' gratis e va detto: i pacchetti attraversano una frontiera di cache fra
# il core che genera e quello che elabora, quindi il costo per pacchetto in
# assoluto puo' salire. In cambio diventa attribuibile, che e' il punto.


def _napi_threads(dev):
    """I PID dei kernel thread NAPI di `dev`. Vuoto se non e' in modo thread."""
    out = subprocess.run(["ps", "-eo", "pid,comm"], capture_output=True,
                         text=True, check=False).stdout
    pids = []
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].strip().startswith(f"napi/{dev}-"):
            pids.append(parts[0].strip())
    return pids


def enable_threaded_napi(devs, first_cpu, ncpu):
    """Metti in modo thread la NAPI di `devs` e pinna i thread da `first_cpu`.

    Restituisce [(dev, pid, cpu), ...] per quello che e' andato a posto. Un
    device che non supporta `threaded` non e' un errore: si riporta e si
    proseguec in softirq, perche' meglio una misura dichiarata su un core solo
    che nessuna misura."""
    placed = []
    cpu = first_cpu
    for dev in devs:
        # ONE CPU per device, not one per NAPI thread. A multi-queue veth has a
        # NAPI thread per queue, so pinning them round-robin scattered one
        # device's work over every DUT core and, with two ingress devices and
        # five egress counters, put ten threads on two CPUs -- measured: the
        # generator offered 4.17 Mpps and the datapath delivered 118 k, a
        # collapse rather than saturation. A device is one DUT core.
        path = f"/sys/class/net/{dev}/threaded"
        if not os.path.exists(path):
            warn(f"{dev}: /sys/.../threaded non c'e', resto in softirq "
                 f"(kernel < 5.12?)")
            continue
        try:
            with open(path, "w") as f:
                f.write("1\n")
        except OSError as e:
            warn(f"{dev}: threaded rifiutato ({e.strerror}), resto in softirq")
            continue
        if cpu >= ncpu:
            cpu = first_cpu              # piu' device che CPU libere: gira
        pids = _napi_threads(dev)
        for pid in pids:
            subprocess.run(["taskset", "-pc", str(cpu), pid],
                           capture_output=True, check=False)
        if pids:
            placed.append((dev, len(pids), cpu))
        cpu += 1
    return placed


def disable_threaded_napi(devs):
    for dev in devs:
        path = f"/sys/class/net/{dev}/threaded"
        if os.path.exists(path):
            try:
                with open(path, "w") as f:
                    f.write("0\n")
            except OSError:
                pass


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
        # One queue per CPU on both sides: with a single queue every
        # generator thread funnels through one NAPI instance, which caps the
        # aggregate before any pipeline does.
        ncpu = str(os.cpu_count() or 1)
        _ip("link", "add", rx, "numrxqueues", ncpu, "numtxqueues", ncpu,
            "type", "veth", "peer", tx,
            "numrxqueues", ncpu, "numtxqueues", ncpu)
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
def setup_p1_static(model_id, model_path, node=STATIC_NODE):
    """setup_hardcoded, ma con l'indice del nodo congelato nel sorgente.

    Non e' in verify_prog_run perche' la specializzazione e' nata qui: lo
    switch a n_nodi casi sulla one-hot del nodo sparisce e con lui la lettura
    della mappa node_id, restando n_h1 costanti che clang piega
    nell'accumulatore. Vedi _gen_feature_onehot_node in ebpf_program.py, e
    `bench_scaling.py --verify` per la prova che decide come la P1.5."""
    from bcc import BPF
    from ebpf_program import build_combined_hardcoded_source
    import verify_prog_run as V

    weights, scale = V.load_weights(model_path)
    src = build_combined_hardcoded_source(
        [(model_id, weights, scale)], static_node=node)
    b = BPF(text=src)
    model_fn = b.load_func(f"model_{model_id}", BPF.XDP)
    disp = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ct.c_int(model_id)] = ct.c_int(model_fn.fd)
    V._seed_link_state(b, 1)
    V._install_mac_table(b, "mac_table")
    return {
        "b": b, "fn": model_fn, "disp": disp,
        "weights": weights, "scale": scale,
        "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"],
        "pipeline": 1, "static_node": node,
        "progs": {"ipa_switch_hardcoded": disp.fd,
                  f"model_{model_id}": model_fn.fd},
    }


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

    if method == "baseline":
        setup = V.setup_baseline(0, model_path)
    elif method == "p1_static":
        setup = setup_p1_static(0, model_path)
    else:
        setup = getattr(V, TF._SETUP[method])(0, model_path)
    b, pl = setup["b"], setup["pipeline"]

    # mac_table serve a tutte: e' la catena porta logica -> ifindex, ed e' cio'
    # che fa uscire il pacchetto dal veth giusto. La baseline redirige su una
    # classe fissa, quindi le basta la porta 0, ma installarle tutte non costa.
    mac_name = "mac_table" if pl in (0, 1) else TF._MAC_NAME[pl]
    TF._install_fabric_mac_table(b, mac_name, fab, sem.logical_ports)

    if method == "baseline":
        # Nessuna feature: non c'e' ingress_port, non c'e' node_id, e il
        # programma non legge nemmeno ipa->model_id. Niente da cablare, ed e'
        # esattamente cio' che la rende il tetto del banco.
        return setup

    b[TF._INGRESS_NAME[pl]][ct.c_uint32(fab.ingress_ifindex)] = \
        ct.c_uint32(TF.FABRIC_INGRESS_SLOT)
    if method != "p1_static":
        # La specializzata ha l'indice del nodo compilato dentro: la mappa e'
        # ancora dichiarata nell'header condiviso ma nessuno la legge, e
        # scriverci darebbe l'impressione sbagliata che serva.
        b[TF._NODEID_NAME[pl]][ct.c_uint32(0)] = \
            ct.c_uint32(TF.FABRIC_NODE_INDEX)

    # The model under the id pktgen writes. See the docstring: this is the
    # difference between measuring inference and measuring XDP_PASS.
    _register_alias(method, setup, PKTGEN_MAGIC_MODEL_ID)
    return setup


def _register_alias(method, setup, model_id):
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
               clone=0, threads=1, threshold=DEFAULT_LOSS_THRESHOLD,
               repeat=DEFAULT_REPEAT, burst=0, xmit_mode="start_xmit",
               threaded_napi=True):
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} {method} -- throughput end-to-end, TG e DUT sulla stessa "
          f"macchina{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")

    sem, n_out = class_semantics()
    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        rx_side = (xmit_mode == "netif_receive")
        rx_b, rx_tab, attached = attach_rx_counter(fab)
        info(f"contatore RX su {len(attached)} peer d'uscita (XDP_DROP)")

        setup = build_pipeline(method, model_path, fab, sem)
        # netif_receive injects at netif_receive_skb, which is PAST the native
        # XDP hook: veth's native program runs in veth_poll, earlier. Attaching
        # native and injecting there means no program runs at all -- neither
        # HIT nor MISS, which is exactly what the probe reported. The generic
        # hook is the one on that path, so that is where the program has to go.
        xdp_mode = "generic" if xmit_mode == "netif_receive" else None
        attach_xdp(setup["b"], setup["disp"], fab.ingress, mode=xdp_mode)
        info(f"pipeline agganciata a {fab.ingress} (ifindex "
             f"{fab.ingress_ifindex})")

        # (rx_side is set above, before the pipeline is attached, because
        # it decides the XDP mode as well as the device.)
        # WHICH device pktgen is pointed at depends on the injection mode.
        #
        #   start_xmit / queue_xmit : pktgen TRANSMITS, so it takes the PEER of
        #       the DUT's ingress; the packet crosses the veth and arrives on
        #       the ingress, where the pipeline's XDP runs.
        #   netif_receive : pktgen injects straight into a device's RECEIVE
        #       path, so it takes the INGRESS itself. No veth crossing, no
        #       peer NAPI, no skb->xdp conversion -- and XDP runs generic.
        #
        # Getting this backwards would send every packet somewhere the pipeline
        # is not, and the probe would catch it, but the message would blame the
        # model_id byte.
        tg_devs = [fab.ingress if rx_side else fab.ingress_peer]
        extra = []
        if threads > 1:
            import test_fabric as TF
            extra = make_tg_links(threads - 1)
            ing_map = setup["b"][TF._INGRESS_NAME[setup["pipeline"]]]
            for rx, tx, idx in extra:
                attach_xdp(setup["b"], setup["disp"], rx, mode=xdp_mode)
                # Same logical port as the fabric ingress: these are extra
                # generator cores feeding one node, not extra node ports.
                ing_map[ct.c_uint32(idx)] = ct.c_uint32(TF.FABRIC_INGRESS_SLOT)
                tg_devs.append(rx if rx_side else tx)
            info(f"{threads} core generatori: {', '.join(tg_devs)}")
        if rx_side:
            info("xmit_mode netif_receive: XDP gira in modo GENERIC, non "
                 "native -- non confrontabile con gli altri run")

        # Separazione vera fra generatore e DUT: i thread NAPI che eseguono
        # l'inferenza vanno sulle CPU che pktgen non usa.
        napi_devs = []
        if threaded_napi and not rx_side:
            ncpu = os.cpu_count() or 1
            # pktgen usa kpktgend_0..threads-1, cioe' le CPU 0..threads-1.
            # SOLO gli ingressi. I peer d'uscita portano il contatore, che
            # e' strumentazione e non il DUT: lasciarli in softirq li fa girare
            # sul core che ha elaborato il pacchetto, come farebbe l'uscita di
            # un nodo vero. Metterli in thread su CPU proprie li ha messi in
            # concorrenza con l'inferenza sulle stesse due CPU.
            napi_devs = [fab.ingress] + [e[0] for e in extra]
            placed = enable_threaded_napi(napi_devs, threads, ncpu)
            if placed:
                where = ", ".join(f"{d}({n} code)->cpu{c}"
                                  for d, n, c in placed)
                info(f"NAPI in thread, pinnata: {where}")
                info(f"pktgen su cpu 0-{threads - 1}, inferenza sulle altre: "
                     f"generatore e DUT su core separati")
            else:
                warn("nessun thread NAPI pinnato: generatore e pipeline "
                     "restano sullo stesso core, e le cifre misurano la somma")

        # -- sonda: un pacchetto solo, per sapere se stiamo misurando
        #    inferenza o XDP_PASS.
        probe = measure_point(setup, rx_tab, fab, 64, 0, 1, n_out, clone,
                              tg_devs, repeat=1, burst=burst,
                              xmit_mode=xmit_mode)
        probe_clone_support(tg_devs[0])
        if probe is None:
            warn("la sonda non ha trasmesso nulla: pktgen non e' partito.")
            return 1
        if probe["hit"] == 0 and method == "baseline":
            warn("la baseline non ha prodotto HIT: non legge model_id, quindi "
                 "il problema e' a monte (il pacchetto non arriva o mac_table "
                 "e' vuota). Mi fermo.")
            return 1
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
            spread = ""
            if r.get("spread_pct") is not None:
                col = RED if r.get("unreliable") else GREY
                flag = " INAFFIDABILE" if r.get("unreliable") else ""
                spread = (f" {col}(x{r['repeat']}, +-{r['spread_pct']:.0f}%"
                          f"{flag}){NC}")
            print(f"  {r['frame']:5d} {r['delay']:6d} {r['tx']:9d} "
                  f"{r['hit']:9d} {r['rx']:9d} {r['tx_pps']:9d} "
                  f"{r['rx_pps']:9d} {r['rx_mbps']:8.1f} "
                  f"{mark}{r['loss_worst']:7.2f}%{NC}{spread}")

        for frame in frames:
            if delays:
                # Manual sweep: the caller asked for specific rates.
                for delay in delays:
                    r = measure_point(setup, rx_tab, fab, frame, delay, count,
                                      n_out, clone, tg_devs, repeat, burst,
                                      xmit_mode)
                    if r is None:
                        continue
                    r["clone_skb"], r["method"] = clone, method
                    r["threads"] = threads
                    out_rows.append(r)
                    printer(r)
            else:
                find_knee(setup, rx_tab, fab, frame, count, n_out, clone,
                          out_rows, method, printer, tg_devs=tg_devs,
                          threads=threads, threshold=threshold,
                          repeat=repeat, burst=burst, xmit_mode=xmit_mode)
            _summarise(method, frame, out_rows, threshold)

        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        del_tg_links(threads - 1)
        for peer in attached:
            subprocess.run(["ip", "link", "set", "dev", peer, "xdp", "off"],
                           check=False, capture_output=True)
        del rx_b
    return 0


def find_knee(setup, rx_tab, fab, frame, count, n_out, clone, out_rows,
              method, printer, max_delay=20000, steps=6, tg_devs=None,
              threads=1, threshold=DEFAULT_LOSS_THRESHOLD,
              repeat=DEFAULT_REPEAT, burst=0, xmit_mode="start_xmit"):
    """Find the fastest rate this pipeline takes without losing packets.

      1. offer everything the generator has (delay 0);
      2. if nothing is lost, the GENERATOR saturated first -- there is no knee
         to find, and saying so is the result;
      3. otherwise bisect the delay down to the fastest rate that stays under
         `threshold`.

    `threshold` is not a convenience. Measured on this bench: at three
    generator cores the loss along one frame size went 0.00, 0.00, 0.10, 0.01,
    0.12, 0.02, 0.21 percent as the rate ROSE -- tens to hundreds of packets
    out of 300 000, scattered, not monotone. That is a busy VM losing the odd
    packet, not a datapath saturating. A bisection that treats any loss > 0 as
    "too fast" converges on whichever slow point happened to come out clean,
    and reports it as the no-loss throughput: here it returned 600 kpps while
    1.2 Mpps had run at 0.02%.

    So the search uses a DECLARED threshold, and the summary reports both the
    threshold figure and whether any point was strictly lossless. RFC 2544
    asks for zero, and on hardware that can hold still zero is the right bar;
    on a shared VM it measures the neighbours.

    Returns (peak_row, clean_row_or_None)."""
    full = measure_point(setup, rx_tab, fab, frame, 0, count, n_out, clone,
                         tg_devs, repeat, burst, xmit_mode)
    if full is None:
        warn(f"frame {frame}: nessuna misura utilizzabile a pieno rate")
        return None, None
    full["method"], full["clone_skb"], full["delay"] = method, clone, 0
    full["threads"] = threads
    out_rows.append(full)
    printer(full)

    if full["loss_worst"] <= threshold and clone == 0 and _CLONE_SUPPORTED:
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
                             ESCALATE_CLONE, tg_devs, repeat, burst,
                             xmit_mode)
        if hard is None:
            return full, full
        hard["method"], hard["clone_skb"], hard["delay"] = \
            method, ESCALATE_CLONE, 0
        hard["threads"] = threads
        out_rows.append(hard)
        printer(hard)
        if hard["loss_worst"] > threshold:
            print(f"  {GREY}con clone_skb={ESCALATE_CLONE} la pipeline perde: "
                  f"il ginocchio esiste, lo cerco{NC}")
            return find_knee(setup, rx_tab, fab, frame, count, n_out,
                             ESCALATE_CLONE, out_rows, method, printer,
                             max_delay, steps, tg_devs, threads,
                             threshold, repeat, burst, xmit_mode)
        print(f"  {GREY}nemmeno con clone_skb={ESCALATE_CLONE}: su questa "
              f"macchina satura il generatore, non la pipeline{NC}")
        return (hard if hard["rx_pps"] > full["rx_pps"] else full), hard

    if full["loss_worst"] <= threshold:
        return full, full          # generator-bound: peak IS the no-loss rate

    lo, hi = 0, max_delay           # lo loses, hi is assumed clean
    best_clean = None
    for _ in range(steps):
        mid = (lo + hi) // 2
        if mid in (lo, hi):
            break
        r = measure_point(setup, rx_tab, fab, frame, mid, count, n_out,
                          clone, tg_devs, repeat, burst, xmit_mode)
        if r is None:
            break
        r["method"], r["clone_skb"], r["threads"] = method, clone, threads
        out_rows.append(r)
        printer(r)
        if r["loss_worst"] <= threshold:
            best_clean = r if (best_clean is None or
                               r["rx_pps"] > best_clean["rx_pps"]) else best_clean
            hi = mid                # under threshold: try to go faster
        else:
            lo = mid                # still losing: slow down
    # Is the loss actually driven by the rate? If a point LOSES at a rate
    # lower than one that stayed clean, it is not: on this bench the sequence
    # ran 0.00% at 343 kpps, 0.58% at 356 k, 0.57% at 369 k, 0.20% at 400 k and
    # 0.43% at 600 k -- scattered, with repeat=3 and worst-of-three already
    # applied. Reporting the fastest clean point as "the no-loss throughput"
    # would publish whichever rate happened to come out clean three times in a
    # row, which is a lottery ticket, not a measurement.
    if best_clean is not None:
        dirty_below = [r for r in out_rows
                       if r.get("method") == method and r["frame"] == frame
                       and r["loss_worst"] > threshold
                       and r["rx_pps"] < best_clean["rx_pps"]]
        if dirty_below:
            worst = min(dirty_below, key=lambda r: r["rx_pps"])
            print(f"  {RED}la perdita non dipende dal rate{NC}{GREY}: "
                  f"{worst['loss_worst']:.2f}% a {worst['rx_pps']} pps, "
                  f"pulito a {best_clean['rx_pps']}. Sotto saturazione qui "
                  f"si perde per ragioni della macchina, non del datapath: "
                  f"un rate 'a perdita nulla' non e' determinabile.{NC}")
            best_clean = None
    return full, best_clean


def _summarise(method, frame, rows, threshold=DEFAULT_LOSS_THRESHOLD):
    """Three numbers, because two would hide the thing that matters.

    The peak alone overstates a datapath. The peak plus a "no loss" figure is
    the usual pair -- but on a machine that drops the odd packet for reasons of
    its own, strict zero is a lottery. So: the peak, the fastest rate under the
    declared threshold, and whether ANY point was strictly lossless."""
    pts = [r for r in rows if r["method"] == method and r["frame"] == frame]
    if not pts:
        return
    peak = max(pts, key=lambda r: r["rx_pps"])
    under = [r for r in pts if r["loss_worst"] <= threshold]
    strict = [r for r in pts if r["loss_worst"] == 0.0]
    best = max(under, key=lambda r: r["rx_pps"]) if under else None
    print(f"  {GREY}frame {frame}: massimo {peak['rx_pps']} pps "
          f"({peak['rx_mbps']} Mb/s, perdita {peak['loss_pct']}%)")
    # WHERE the loss happens decides what the number means. Measured here at
    # three generator cores: 8.5% lost with TX == HIT, i.e. the program saw and
    # processed every packet and the drops were all on the way OUT. Reporting
    # only the total would read as "the datapath loses 8.5%", which is the
    # opposite of what happened.
    if peak["lost_before"] or peak["lost_after"]:
        if peak["lost_after"] > peak["lost_before"]:
            print(f"  {GREY}  la perdita e' DOPO l'inferenza: "
                  f"{peak['lost_after']} pacchetti elaborati e non usciti "
                  f"({peak['lost_before']} non erano nemmeno arrivati). "
                  f"A saturare e' l'uscita, non la pipeline.{NC}")
        else:
            print(f"  {GREY}  la perdita e' PRIMA dell'inferenza: "
                  f"{peak['lost_before']} pacchetti mai arrivati al programma "
                  f"({peak['lost_after']} elaborati e non usciti). "
                  f"A saturare e' l'ingresso.{NC}")
    # Same guard as in find_knee, applied to whatever set of points exists:
    # a clean point is only meaningful if nothing SLOWER lost.
    if best and any(r["loss_worst"] > threshold and r["rx_pps"] < best["rx_pps"]
                    for r in pts):
        print(f"  {GREY}  nessun rate a perdita nulla determinabile: si perde "
              f"anche a rate piu' bassi di quelli puliti, quindi la perdita "
              f"sotto saturazione e' rumore della macchina{NC}")
        best = None
    if best:
        print(f"  {GREY}  sotto {threshold}% di perdita: {best['rx_pps']} pps "
              f"({best['rx_mbps']} Mb/s, perdita {best['loss_pct']}%)")
    if strict and best:
        b0 = max(strict, key=lambda r: r["rx_pps"])
        print(f"  {GREY}  a perdita esattamente zero: {b0['rx_pps']} pps "
              f"({b0['rx_mbps']} Mb/s){NC}")
    else:
        print(f"  {GREY}  nessun punto a perdita esattamente zero{NC}")


# ==========================================================================
def check_validity(rows):
    """La baseline deve essere la piu' veloce. Se non lo e', il run e' sporco.

    Non e' una convenzione: la baseline parsa, decrementa il TTL e redirige su
    una classe FISSA. Fa strettamente MENO lavoro di qualunque pipeline, quindi
    non puo' consegnare meno pacchetti. Se lo fa, la differenza fra le colonne
    e' il carico della macchina in momenti diversi e non il costo
    dell'inferenza, e pubblicare quella classifica sarebbe pubblicare rumore
    ordinato.

    Questo controllo esiste perche' e' successo: baseline 2 658 k contro
    p1_static 3 342 k, con dispersioni fino al 75%."""
    best = {}
    for r in rows:
        m = r.get("method")
        if m and (m not in best or r["rx_pps"] > best[m]["rx_pps"]):
            best[m] = r
    if "baseline" not in best or len(best) < 2:
        return 0
    base = best["baseline"]["rx_pps"]
    # Tolleranza: un'inversione ENTRO questa soglia non e' contaminazione, e'
    # rumore fra due pipeline che il banco non riesce a distinguere. Misurato:
    # baseline 1 377 k contro hardcoded 1 423 k, cioe' il 3% -- entrambe
    # limitate dal generatore, quindi il throughput non le separa. Chiamarlo
    # "run contaminato" avrebbe buttato via una misura che invece dice una cosa
    # vera: che sono indistinguibili.
    faster = {m: r["rx_pps"] for m, r in best.items()
              if m != "baseline" and r["rx_pps"] > base * (1 + VALID_TOL)}
    close = {m: r["rx_pps"] for m, r in best.items()
             if m != "baseline" and base < r["rx_pps"] <= base * (1 + VALID_TOL)}
    noisy = sorted({m for m, r in best.items() if r.get("unreliable")})

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Controllo di validita'{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    if not faster and not noisy:
        print(f"  {GREEN}[PASS]{NC} la baseline ({base} pps) e' la piu' veloce "
              f"entro {VALID_TOL:.0%}, come deve essere: fa strettamente meno "
              f"lavoro.")
        if close:
            det = ", ".join(f"{m} {v}" for m, v in sorted(close.items()))
            print(f"  {GREY}Indistinguibili da lei entro il rumore: {det}. "
                  f"Sono limitate dal generatore, non da se stesse: il "
                  f"throughput non le separa, la latenza si'.{NC}")
        print(f"  {GREY}Le differenze oltre la tolleranza sono attribuibili "
              f"alle pipeline.{NC}")
        return 0
    if faster:
        det = ", ".join(f"{m} {v}" for m, v in sorted(faster.items()))
        print(f"  {RED}[FAIL]{NC} la baseline ({base} pps) NON e' la piu' "
              f"veloce: {det}.")
        print(f"  {GREY}La baseline fa strettamente meno lavoro, quindi non "
              f"puo' consegnare meno. Questo run misura il carico della "
              f"macchina, non il datapath: le cifre non sono confrontabili "
              f"fra metodi.{NC}")
    if noisy:
        print(f"  {RED}[FAIL]{NC} dispersione fra i giri oltre "
              f"{MAX_SPREAD_PCT:.0f}% su: {', '.join(noisy)}.")
        print(f"  {GREY}Una mediana su misure che oscillano cosi' non e' una "
              f"portata: e' il carico della macchina in momenti diversi. "
              f"Misurato: una pipeline ha dato 2,78 / 1,17 / 1,46 Mpps in tre "
              f"giri, e la sua mediana e' finita SOTTO una che fa piu' lavoro. "
              f"Il throughput di queste righe non e' un risultato.{NC}")
        print(f"  {GREY}La latenza delle stesse righe e' un'altra misura con "
              f"un'altra dispersione -- vedi il verdetto qui sotto. Un "
              f"throughput inutilizzabile non la invalida.{NC}")
    print(f"\n  {YELLOW}Che fare{NC}: chiudi tutto il resto, poi rilancia con "
          f"--rounds 7. Se la dispersione resta, questa VM non e' un banco di "
          f"misura per il throughput assoluto, e cio' che resta valido e' la "
          f"latenza piu' il confronto dentro un singolo metodo.")
    return 1


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
    p.add_argument("--no-threaded-napi", action="store_true",
                   help="lascia la RX in softirq sulla CPU che trasmette, "
                        "cioe' generatore e pipeline sullo stesso core. Serve "
                        "per riprodurre le misure vecchie, non per farne di "
                        "nuove.")
    p.add_argument("--burst", type=int, default=0, metavar="N",
                   help="consegna N pacchetti per chiamata (xmit_more). Come "
                        "clone_skb puo' essere rifiutato da veth.")
    p.add_argument("--xmit-mode", choices=XMIT_MODES, default="start_xmit",
                   help="netif_receive inietta nel percorso RX saltando la "
                        "traversata veth, ma XDP gira GENERIC: numeri non "
                        "confrontabili con gli altri modi.")
    p.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, metavar="N",
                   help="giri completi: in ogni giro si misurano TUTTE le "
                        "pipeline, poi si tiene la mediana. Toglie l'ordine "
                        "dei metodi dalla misura.")
    p.add_argument("--repeat", type=int, default=DEFAULT_REPEAT, metavar="R",
                   help="misure per punto; si tiene la mediana del rate e la "
                        "PEGGIORE delle perdite")
    p.add_argument("--loss-threshold", type=float,
                   default=DEFAULT_LOSS_THRESHOLD, metavar="PCT",
                   help="sotto questa percentuale la perdita e' considerata "
                        "rumore della macchina, non saturazione. Zero stretto "
                        "resta riportato a parte.")
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
    p.add_argument("--latency", action="store_true",
                   help="misura la latenza arrivo->ripartenza invece del "
                        "throughput. Usa una build strumentata: vedi "
                        "run_latency.")
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
        sys.exit(f"{PKTGEN_DIR} non c'e' e `modprobe pktgen` non l'ha "
                 f"creato: questo kernel non ha il modulo.")
    pg_reset()

    import model_meta as mm
    model_path = mm.default_checkpoint()
    frames = [int(x) for x in a.frames.split(",") if x.strip()]
    delays = [int(x) for x in a.delays.split(",") if x.strip()]
    methods = list(METHODS) if a.method == "all" else [a.method]

    rows = []
    rc = 0
    if a.latency:
        lat_delays = delays or [0, 5000, 20000]
        raw = run_fair(methods, model_path, frames, lat_delays, a.count,
                       a.threads, not a.no_threaded_napi, a.repeat, a.rounds)
        rows = summarise_fair(raw, methods)
        rc |= check_validity([dict(method=r["method"], rx_pps=r["rx_pps"],
                                   unreliable=r["unreliable"]) for r in rows])
        _latency_verdict(rows)
        if a.out and rows:
            os.makedirs(a.out, exist_ok=True)
            # Anche i punti grezzi, non solo la mediana: la dispersione fra i
            # giri si legge solo da questi, ed e' cio' che dice se la mediana
            # significa qualcosa.
            for name, data in (("latency.csv", rows),
                               ("latency_raw.csv", raw)):
                if not data:
                    continue
                path = os.path.join(a.out, name)
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
                    w.writeheader()
                    w.writerows(data)
                print(f"  {GREEN}scritto{NC} {path}  ({len(data)} righe)")
            _give_back(a.out)
        # Il codice di uscita e' quello del controllo: un run in cui la
        # baseline non e' la piu' veloce, o in cui la dispersione sfonda, non
        # deve uscire 0 solo perche' il CSV e' stato scritto.
        return rc

    for m in methods:
        rc |= run_method(m, model_path, frames, delays, a.count, rows,
                         a.clone_skb, a.threads, a.loss_threshold,
                         a.repeat, a.burst, a.xmit_mode,
                         not a.no_threaded_napi)

    rc |= check_validity(rows)

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
