#!/usr/bin/env python3
"""
bench_bitrate.py -- il test al crescere del BIT RATE offerto: ritardo
end-to-end, pacchetti che il programma XDP riceve, pacchetti che rilancia, e
dove comincia la perdita.

--------------------------------------------------------------------------
LA DOMANDA
--------------------------------------------------------------------------
Richiesta del relatore: grafico in funzione del bit rate inviato. La coda si
riempie, il tempo end-to-end cresce fino a una perdita. Se si perde all'uscita
del programma il collo di bottiglia e' trasmissivo, se si perde all'ingresso
e' il programma eBPF. Contare quanti pacchetti il programma riceve e quanti ne
rilancia: due programmi eBPF sullo stesso XDP, uno conta soltanto, l'altro
contiene la pipeline.

Come si legge su XDP. Il programma gira dall'inizio alla fine su ogni
pacchetto, dentro il poll NAPI (run-to-completion): non ha una coda sua, e ogni
pacchetto che entra esce con un verdetto. Se il programma e' lento si riempie
la coda che sta DAVANTI a lui -- il ring di ricezione dell'interfaccia; su
veth il ptr_ring, 256 descrittori per coda -- e quindi, al crescere del rate:

  1. il ritardo end-to-end cresce (attesa in quella coda);
  2. poi la coda trabocca e i pacchetti si perdono PRIMA di XDP.

  perdita prima di XDP  -> collo di bottiglia del programma. Oppure della
                           ricezione che glielo porta: per separarli c'e' il
                           riferimento `rxonly`, il solo contatore allo stesso
                           rate. Se il solo contatore non perde e la pipeline
                           si', la differenza e' il programma.
  perdita dopo XDP      -> il programma ha deciso l'inoltro ma il pacchetto
                           non arriva al nodo successivo: redirect o coda
                           d'uscita, cioe' collo di bottiglia trasmissivo.

"Il programma riceve ma non riesce a rilanciare" non esiste come coda interna:
fra ricevuti e rilanciati ci sono solo le DECISIONI del modello (classe DROP,
MISS) e i fallimenti dell'uscita, e il test li conta separatamente.

--------------------------------------------------------------------------
IL BANCO: quello di bench_throughput, non uno nuovo
--------------------------------------------------------------------------
Stesso fabric veth (netns_fabric), stesso generatore (pktgen su CPU dedicate,
`delay` per istanza), stessa finestra stazionaria (Generator.steady), stesse
pipeline caricate da build_pipeline -- gli oggetti di produzione, NON le build
strumentate di `--mode rates`: nessuna riga del loro codice cambia. Il modulo
usa bench_throughput come libreria e non lo modifica.

    pktgen (cpu gen) --veth ipatg0p->ipatg0--> [XDP: contatore -> pipeline]
        --bpf_redirect--> ipaN --veth--> ipaNp [XDP: contatore d'uscita]

--------------------------------------------------------------------------
I DUE PROGRAMMI SULLO STESSO HOOK
--------------------------------------------------------------------------
Un'interfaccia porta UN programma XDP (modo nativo). Due programmi sullo
stesso hook si ottengono in catena, con la tail call che il progetto usa gia'
(P1 dispatcher -> modello, P2 -> architettura, P3 -> strati):

  programma 1  xdp_ing_count, attaccato all'hook. ing_count[0] += 1 su una
               mappa PER-CPU (niente atomiche, niente contesa), poi
               bpf_tail_call(ing_next[0]). Se la tail call non parte,
               ing_count[1] += 1 e XDP_DROP: un contatore che non deve mai
               muoversi, e che si controlla a ogni finestra.
  programma 2  la pipeline, cioe' il suo programma d'ingresso (dispatcher)
               messo in ing_next[0]. Stesso ctx: ingress_ifindex, pacchetto e
               metadati sono quelli che avrebbe visto attaccata da sola.

La tail call richiede programmi compatibili: stesso tipo, stesso JIT e, nei
kernel recenti, stesso expected_attach_type -- che BCC lascia a 0 e libbpf
mette a BPF_XDP. Il contatore viene percio' caricato dallo STESSO caricatore
della pipeline che precede:

  baseline, P2, P3   oggetto BCC a parte (ING_COUNTER_BCC)
  P1, P1.5           dentro lo stesso oggetto AOT (ING_COUNTER_LIBBPF,
                     aggiunto in coda al sorgente, come fa gia' la build
                     strumentata _instrument_aot_latency): stesso clang, stesso
                     loader_aot, stessi attributi. I programmi della pipeline
                     nell'oggetto restano quelli di produzione.
  rxonly             il contatore da solo, slot vuoto: conta e scarta. E' il
                     tetto della ricezione allo stesso rate.

Il costo del contatore non si suppone: la fase finale misura ogni pipeline a
rate massimo con e senza catena (bitrate_overhead.csv).

--------------------------------------------------------------------------
DOVE SI CONTA, E COME SI LEGGE
--------------------------------------------------------------------------
  inviati     pktgen: pkts-sofar (accettati dal veth) + errors (respinti a
              coda d'ingresso piena). Letti dal file /proc/net/pktgen/<ist>.
  RX XDP      ing_count[0], programma 1, somma sulle CPU.
  decisioni   pkt_stats[0..2] della pipeline (HIT = inoltro deciso, MISS,
              DROP), i contatori che la pipeline ha gia'.
  inoltrati   rx_count sul nodo successivo: il programma d'uscita
              (xdp_rx_lat, al posto dello stub XDP_PASS del fabric) conta ogni
              pacchetto che ARRIVA. bpf_redirect da solo non garantisce la
              trasmissione: si conta dopo.

Tutti i contatori sono cumulativi e non si azzerano. Ogni punto e' UNA
finestra stazionaria: pktgen parte, si aspetta che tutte le istanze
trasmettano, si leggono TUTTI i contatori (lettura sotto i 3 ms, rifatta se
piu' lunga), si aspettano `--duration` secondi, si rileggono, si ferma pktgen.
I valori della riga sono le DIFFERENZE fra le due letture, e la durata e'
l'intervallo fra i loro istanti medi (duration_s). Avvio, assestamento e coda
finale restano fuori per costruzione.

--------------------------------------------------------------------------
PERDITE (in pacchetti; le percentuali sono sugli INVIATI e si sommano)
--------------------------------------------------------------------------
  loss_before_xdp  = inviati - RX_XDP
                   = respinti (errors di pktgen) + persi fra veth e XDP
  loss_in_pipeline = RX_XDP - inoltrati
                   = decisioni (MISS + DROP)
                   + perdita all'uscita (HIT - inoltrati)
                   + residuo (RX_XDP - HIT - MISS - DROP, atteso ~0)
  packets_lost     = inviati - inoltrati = le due sopra

Il residuo non e' zero esatto perche' i contatori si leggono uno dopo
l'altro: lo sfasamento si annulla fra le due letture ma non del tutto.

--------------------------------------------------------------------------
BIT RATE
--------------------------------------------------------------------------
  bitrate_sent_bps = inviati / duration_s * frame * 8

`frame` e' il pkt_size di pktgen, cioe' il frame senza FCS: sono i byte che
attraversano il veth (L2). bitrate_sent_l1_gbps aggiunge i 24 byte che una
Ethernet vera spende per frame (FCS 4, preambolo 8, IFG 12), solo come
riferimento. Il rate CHIESTO fissa il `delay` di pktgen; l'asse dei grafici e'
quello MISURATO, perche' sopra il tetto del generatore i due divergono
(gen_limited).

Senza --bitrates si usano i punti in pps della scala a 64 byte anche per le
altre taglie: il costo del nodo e' per pacchetto, non per byte.

--------------------------------------------------------------------------
LATENZA END-TO-END
--------------------------------------------------------------------------
pktgen scrive gia' in ogni pacchetto, subito dopo l'intestazione UDP, la sua
intestazione (magic 0xbe9be955, seq, tv_sec, tv_usec): l'istante in cui ha
costruito il pacchetto, CLOCK_REALTIME in microsecondi. Il programma d'uscita
lo legge e lo confronta con il proprio orologio:

  lat_us = floor((bpf_ktime_get_ns() + off) / 1000) - (tv_sec*1e6 + tv_usec)

  off  = CLOCK_REALTIME - CLOCK_MONOTONIC, letto da Python prima di ogni
         punto e scritto in lat_ctl[1] (bpf_ktime_get_ns e' il monotono)
  risoluzione 1 us: entrambi gli istanti sono troncati al microsecondo, quindi
  l'errore su un campione sta in (-1, +1) us e sulla media si annulla

Il percorso misurato e' tutto il nodo: accodamento sul veth d'ingresso,
ATTESA IN CODA, i due programmi, redirect, accodamento d'uscita, ricezione del
nodo successivo. E' la cifra che cresce quando la coda si riempie; T3-T1 di
`--mode rates` parte invece dall'ingresso del programma e l'attesa in coda non
la vede.

La correzione che serve. pktgen timbra il pacchetto e POI aspetta il momento
di trasmetterlo (spin() fino a next_tx, net/core/pktgen.c): il timbro precede
la trasmissione di quell'attesa, che a rate basso e' quasi tutto il `delay`
(~10 us a 0,2 Mpps). pktgen la accumula nel suo contatore `idle`; la media per
pacchetto, Delta(idle) / inviati nella finestra, si sottrae da ogni statistica
(e2e_spin_correction_us). I valori non corretti restano nel CSV
(e2e_latency_p50_raw_us).

Campionamento: si cronometra un pacchetto ogni `mask+1`, scelti col seq di
pktgen, con mask = potenza di 2 tale da restare vicino a --lat-samples campioni
per finestra: ad alto rate il costo sul percorso misurato e' ~1/64 di pacchetto.
Il contatore dei pacchetti invece conta tutto, sempre. I campioni si registrano
solo fra le due letture della finestra (lat_ctl[0], aperto alla prima lettura,
chiuso alla seconda); l'istogramma (1 us per cella fino a 4096 us, piu' una
cella di trabocco) si azzera prima di ogni punto.

--------------------------------------------------------------------------
USCITE (in --out)
--------------------------------------------------------------------------
  bitrate_raw.csv       una riga per (pipeline, rate, giro): tutti i conteggi
  bitrate.csv           mediana fra i giri, collo di bottiglia per riga
  bitrate_overhead.csv  costo del contatore per pipeline: ns con e senza
                        catena, e la differenza (le finestre in *_raw.csv)
  env.csv               condizioni della macchina e del run
  bitrate_*.png/.pdf    i grafici (plot_bitrate.py, se c'e' matplotlib)

--------------------------------------------------------------------------
USO
--------------------------------------------------------------------------
    sudo python3 ipa/test/bench_bitrate.py --out results/bitrate
    sudo python3 ipa/test/bench_bitrate.py --bitrates 0.5,1,1.5,2,2.5 \\
        --method rxonly,baseline,p1_static,template --rounds 5 --out results/bitrate
    python3 ipa/test/plot_bitrate.py results/bitrate      # i grafici, anche altrove

Serve Linux, root, BCC, clang (per P1/P1.5) e il modulo pktgen.
"""
import argparse
import contextlib
import ctypes as ct
import os
import re
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SHARED = os.path.dirname(HERE)
for _p in (SHARED, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")

# Scala di default, in Gbit/s a 64 byte: da ben sotto la capacita' di P3
# (~0,9 Gbit/s su questa VM) a sopra quella della baseline (~2 Gbit/s) e fino
# al tetto del generatore a due thread (~3 Gbit/s).
DEFAULT_BITRATES_GBPS = (0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0,
                         2.5, 3.0)
DEFAULT_FRAME = 64
ETH_L1_OVERHEAD = 24            # FCS 4 + preambolo/SFD 8 + IFG 12
DEFAULT_ROUNDS = 3
# Soglia per dire "qui si perde", in punti percentuali degli inviati. Non
# 0,1: su questa VM anche il solo contatore respinge l'1-2% sotto capacita'
# (claims.md, "Il pavimento dei respinti"), e quel pavimento varia fra run.
# Si confronta la pipeline con rxonly allo stesso rate e si chiede che la
# differenza superi la soglia.
DEFAULT_LOSS_THRESHOLD = 1.0
GEN_LIMITED_FRACTION = 0.95     # sotto il 95% del chiesto: tetto del generatore

LAT_US_BUCKETS = 4096           # celle da 1 us; la 4096 e' il trabocco
LAT_TARGET_SAMPLES = 20000      # campioni di latenza per finestra, circa
PKTGEN_HDR_OFF = 14 + 20 + 8    # eth + IPv4 senza opzioni + UDP
OVERHEAD_REPS = 3
SANITY_PPS = 100_000
SANITY_S = 0.1
DRAIN_S = 0.05

REFERENCE = "rxonly"
PIPELINES = ("baseline", "p1_static", "hardcoded", "template", "modular")
AOT_METHODS = ("p1_static", "hardcoded")

LABEL_NONE = "nessuna"
LABEL_PROG = "ingresso: programma eBPF"
LABEL_IN_UNSPLIT = "ingresso: programma o ricezione (manca rxonly)"
LABEL_OUT = "uscita: trasmissivo"
LABEL_REF = "riferimento"

# ==========================================================================
# I PROGRAMMI
# ==========================================================================
# Programma 1, dialetto BCC: precede baseline, P2, P3 e fa da rxonly.
ING_COUNTER_BCC = r"""
#include <uapi/linux/bpf.h>
/* 0 = pacchetti entrati in XDP, 1 = tail call non partita (atteso 0) */
BPF_PERCPU_ARRAY(ing_count, __u64, 2);
BPF_PROG_ARRAY(ing_next, 1);

int xdp_ing_count(struct xdp_md *ctx) {
    int k = 0;
    __u64 *v = ing_count.lookup(&k);
    if (v)
        *v += 1;
    ing_next.call(ctx, 0);
    /* qui solo se la tail call non e' partita: slot vuoto (rxonly) o
     * programma incompatibile */
    int km = 1;
    __u64 *m = ing_count.lookup(&km);
    if (m)
        *m += 1;
    return XDP_DROP;
}
"""

# Programma 1, dialetto libbpf: aggiunto IN CODA al sorgente AOT di P1/P1.5,
# che include gia' linux/bpf.h e bpf/bpf_helpers.h. Stesso testo, stesse
# mappe, stessi nomi: il lettore Python non distingue i due.
ING_COUNTER_LIBBPF = r"""
/* ---- bench_bitrate: programma 1 della coppia, il contatore d'ingresso ---- */
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 2);
         __type(key, __u32); __type(value, __u64); } ing_count SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 1);
         __type(key, __u32); __type(value, __u32); } ing_next SEC(".maps");

SEC("xdp")
int xdp_ing_count(struct xdp_md *ctx) {
    __u32 k = 0;
    __u64 *v = bpf_map_lookup_elem(&ing_count, &k);
    if (v)
        *v += 1;
    bpf_tail_call(ctx, &ing_next, 0);
    k = 1;
    v = bpf_map_lookup_elem(&ing_count, &k);
    if (v)
        *v += 1;
    return XDP_DROP;
}
"""

# Il nodo successivo: conta ogni arrivo e, fra le due letture della finestra,
# cronometra un pacchetto ogni mask+1 con il timbro di pktgen.
EGRESS_LAT_BCC = r"""
#include <uapi/linux/bpf.h>

#define LAT_US_BUCKETS %(buckets)d
#define PG_OFF %(off)d

BPF_PERCPU_ARRAY(rx_count, __u64, 1);
/* 0 = cancello (1 = registra), 1 = CLOCK_REALTIME - CLOCK_MONOTONIC in ns,
 * 2 = maschera di campionamento sul seq di pktgen */
BPF_ARRAY(lat_ctl, __u64, 3);
/* 0 campioni, 1 somma us, 2 minimo us + 1 (0 = nessuno), 3 massimo us,
 * 4 timbro nel futuro (orologi disallineati), 5 senza intestazione pktgen */
BPF_PERCPU_ARRAY(lat_acc, __u64, 6);
/* cella i = latenza di i us; cella LAT_US_BUCKETS = oltre */
BPF_PERCPU_ARRAY(lat_hist, __u64, LAT_US_BUCKETS + 1);

int xdp_rx_lat(struct xdp_md *ctx) {
    int z = 0;
    __u64 *cnt = rx_count.lookup(&z);
    if (cnt)
        *cnt += 1;

    __u64 *gate = lat_ctl.lookup(&z);
    if (!gate || *gate == 0)
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *p = data;
    int k_nostamp = 5;
    if ((void *)(p + PG_OFF + 16) > data_end) {
        __u64 *e = lat_acc.lookup(&k_nostamp);
        if (e)
            *e += 1;
        return XDP_DROP;
    }
    __u8 *h = p + PG_OFF;
    if (h[0] != 0xbe || h[1] != 0x9b || h[2] != 0xe9 || h[3] != 0x55) {
        __u64 *e = lat_acc.lookup(&k_nostamp);
        if (e)
            *e += 1;
        return XDP_DROP;
    }
    __u32 seq = ((__u32)h[4] << 24) | ((__u32)h[5] << 16) |
                ((__u32)h[6] << 8) | (__u32)h[7];
    int k_mask = 2;
    __u64 *mask = lat_ctl.lookup(&k_mask);
    if (!mask || (seq & *mask))
        return XDP_DROP;
    __u64 sec = ((__u32)h[8] << 24) | ((__u32)h[9] << 16) |
                ((__u32)h[10] << 8) | (__u32)h[11];
    __u64 usec = ((__u32)h[12] << 24) | ((__u32)h[13] << 16) |
                 ((__u32)h[14] << 8) | (__u32)h[15];
    int k_off = 1;
    __u64 *off = lat_ctl.lookup(&k_off);
    if (!off)
        return XDP_DROP;
    __u64 now_us = (bpf_ktime_get_ns() + *off) / 1000;
    __u64 stamp_us = sec * 1000000ULL + usec;
    if (now_us < stamp_us) {
        int k_neg = 4;
        __u64 *e = lat_acc.lookup(&k_neg);
        if (e)
            *e += 1;
        return XDP_DROP;
    }
    __u64 d = now_us - stamp_us;
    int bi = d < LAT_US_BUCKETS ? (int)d : LAT_US_BUCKETS;
    __u64 *hb = lat_hist.lookup(&bi);
    if (hb)
        *hb += 1;
    int k0 = 0, k1 = 1, k2 = 2, k3 = 3;
    __u64 *n = lat_acc.lookup(&k0);
    if (n)
        *n += 1;
    __u64 *sum = lat_acc.lookup(&k1);
    if (sum)
        *sum += d;
    __u64 *mn = lat_acc.lookup(&k2);
    if (mn && (*mn == 0 || d + 1 < *mn))
        *mn = d + 1;
    __u64 *mx = lat_acc.lookup(&k3);
    if (mx && d > *mx)
        *mx = d;
    return XDP_DROP;
}
""" % {"buckets": LAT_US_BUCKETS, "off": PKTGEN_HDR_OFF}


# ==========================================================================
# CONTI (funzioni pure: test_bitrate_math.py le verifica senza kernel)
# ==========================================================================
def pps_for_gbps(gbps, frame):
    """Pacchetti al secondo che fanno `gbps` Gbit/s di frame da `frame` byte."""
    return gbps * 1e9 / (frame * 8)


def gbps_of(pps, frame, l1=False):
    """Gbit/s di `pps` frame da `frame` byte; l1 aggiunge FCS, preambolo, IFG."""
    return pps * (frame + (ETH_L1_OVERHEAD if l1 else 0)) * 8 / 1e9


def sample_mask(rate_pps, window_s, target=LAT_TARGET_SAMPLES):
    """Maschera sul seq di pktgen: si cronometra un pacchetto ogni mask+1.

    Potenza di 2 perche' il filtro nel programma e' un AND; la piu' piccola
    che non superi di molto `target` campioni nella finestra. Zero = tutti."""
    expected = max(0.0, float(rate_pps) * float(window_s))
    if target <= 0 or expected <= target:
        return 0
    step = 1
    while step * target < expected:
        step <<= 1
    return step - 1


def pct(part, whole):
    return round(100.0 * part / whole, 3) if whole else None


def hist_percentile(hist, q):
    """Il quantile q dall'istogramma a celle da 1 us (l'ultima e' il
    trabocco). Restituisce (valore_us, tagliato): tagliato vero se il
    quantile cade oltre l'istogramma, e allora il valore e' il suo bordo."""
    n = sum(hist)
    if n <= 0:
        return None, False
    target = q * n
    run = 0
    for i, c in enumerate(hist):
        run += c
        if run >= target:
            if i == len(hist) - 1:
                return float(i), True
            return float(i), False
    return float(len(hist) - 1), True


def spin_per_packet_us(idle_us, attempts):
    """Attesa media di pktgen fra timbro e trasmissione, per pacchetto."""
    if idle_us is None or not attempts:
        return None
    return max(0.0, float(idle_us) / float(attempts))


def latency_stats(lat, spin_us, mask):
    """Statistiche della latenza end-to-end di UNA finestra, corrette per
    l'attesa di pktgen. `lat`: n, total_us, min_us, max_us, neg, nostamp,
    hist (le celle, trabocco compreso)."""
    hist = lat.get("hist") or []
    n = int(lat.get("n") or 0)
    out = dict(e2e_samples=n, e2e_sample_every=int(mask) + 1,
               e2e_spin_correction_us=(round(spin_us, 3)
                                       if spin_us is not None else None),
               e2e_over_range=(hist[-1] if hist else 0),
               e2e_negative=int(lat.get("neg") or 0),
               e2e_no_stamp=int(lat.get("nostamp") or 0),
               e2e_percentile_clipped=False)
    keys = ("e2e_latency_p50_us", "e2e_latency_p90_us", "e2e_latency_p99_us",
            "e2e_latency_mean_us", "e2e_latency_min_us",
            "e2e_latency_max_us", "e2e_latency_p50_raw_us")
    if n <= 0 or not hist:
        out.update({k: None for k in keys})
        return out
    corr = spin_us or 0.0

    def c(v):
        return None if v is None else round(max(0.0, float(v) - corr), 2)

    p = {}
    for q in (0.50, 0.90, 0.99):
        v, clipped = hist_percentile(hist, q)
        p[q] = v
        out["e2e_percentile_clipped"] |= clipped
    out.update(e2e_latency_p50_us=c(p[0.50]), e2e_latency_p90_us=c(p[0.90]),
               e2e_latency_p99_us=c(p[0.99]),
               e2e_latency_mean_us=c(float(lat["total_us"]) / n),
               e2e_latency_min_us=c(lat.get("min_us")),
               e2e_latency_max_us=c(lat.get("max_us")),
               e2e_latency_p50_raw_us=p[0.50])
    return out


def window_row(method, frame, rnd, rate_req_pps, delay_ns, gen_threads, secs,
               wall_s, tx, rejected, d, lat, mask, idle_ok=True):
    """Una finestra stazionaria -> una riga. `d` sono le DIFFERENZE dei
    contatori fra le due letture: rx_xdp, tail_miss, fwd, idle_us e, per le
    pipeline, hit/miss/drop. Il riferimento rxonly non ha pipeline ne'
    uscita: i suoi campi di inoltro restano vuoti invece di valere zero."""
    secs = secs if secs and secs > 0 else 1e-9
    sent = int(tx) + int(rejected)
    rx = int(d["rx_xdp"])
    ref = "hit" not in d
    row = dict(
        method=method, frame=frame, round=rnd,
        rate_requested_pps=int(rate_req_pps),
        bitrate_requested_gbps=round(gbps_of(rate_req_pps, frame), 4),
        delay_ns=delay_ns, gen_threads=gen_threads,
        duration_s=round(secs, 4), point_wall_s=round(wall_s, 3),
        packets_sent=sent, packets_accepted_by_veth=int(tx),
        rejected_by_ingress_queue=int(rejected),
        packets_received_by_xdp=rx, tail_call_miss=int(d.get("tail_miss", 0)),
        sent_pps=int(sent / secs), rx_pps=int(rx / secs),
        bitrate_sent_bps=int(sent / secs * frame * 8),
        bitrate_sent_gbps=round(gbps_of(sent / secs, frame), 4),
        bitrate_sent_l1_gbps=round(gbps_of(sent / secs, frame, l1=True), 4),
        rx_gbps=round(gbps_of(rx / secs, frame), 4),
        loss_before_xdp=sent - rx,
        lost_between_veth_and_xdp=int(tx) - rx,
        loss_before_xdp_pct=pct(sent - rx, sent),
        rejected_pct=pct(int(rejected), sent),
        reference=ref)
    row["gen_limited"] = bool(rate_req_pps and
                              row["sent_pps"] < GEN_LIMITED_FRACTION
                              * rate_req_pps)
    if ref:
        for k in ("packets_forwarded", "forwarded_pps", "forwarded_gbps",
                  "packets_lost", "loss_in_pipeline", "loss_in_pipeline_pct",
                  "loss_total_pct", "pipeline_hit", "pipeline_miss",
                  "pipeline_drop", "not_forwarded_by_decision",
                  "decision_pct", "loss_after_xdp", "loss_after_xdp_pct",
                  "unaccounted_in_pipeline"):
            row[k] = None
    else:
        fwd = int(d["fwd"])
        hit, miss, drop = int(d["hit"]), int(d["miss"]), int(d["drop"])
        row.update(
            packets_forwarded=fwd, forwarded_pps=int(fwd / secs),
            forwarded_gbps=round(gbps_of(fwd / secs, frame), 4),
            packets_lost=sent - fwd,
            loss_in_pipeline=rx - fwd,
            loss_in_pipeline_pct=pct(rx - fwd, sent),
            loss_total_pct=pct(sent - fwd, sent),
            pipeline_hit=hit, pipeline_miss=miss, pipeline_drop=drop,
            not_forwarded_by_decision=miss + drop,
            decision_pct=pct(miss + drop, sent),
            loss_after_xdp=hit - fwd,
            loss_after_xdp_pct=pct(hit - fwd, sent),
            unaccounted_in_pipeline=rx - (hit + miss + drop))
    spin = spin_per_packet_us(d.get("idle_us"), sent) if idle_ok else None
    if ref:
        # nessun pacchetto arriva all'uscita: niente latenza end-to-end
        row.update(latency_stats({}, spin, mask))
    else:
        row.update(latency_stats(lat, spin, mask))
    return row


# Le colonne che la sintesi porta come mediana fra i giri.
MEDIAN_KEYS = (
    "bitrate_requested_gbps", "bitrate_sent_gbps", "bitrate_sent_l1_gbps",
    "sent_pps", "rx_pps", "forwarded_pps", "rx_gbps", "forwarded_gbps",
    "packets_sent", "packets_received_by_xdp", "packets_forwarded",
    "packets_lost", "loss_before_xdp", "loss_in_pipeline",
    "rejected_by_ingress_queue", "lost_between_veth_and_xdp",
    "not_forwarded_by_decision", "loss_after_xdp", "unaccounted_in_pipeline",
    "tail_call_miss", "loss_before_xdp_pct", "rejected_pct",
    "loss_in_pipeline_pct", "decision_pct", "loss_after_xdp_pct",
    "loss_total_pct", "e2e_latency_p50_us", "e2e_latency_p90_us",
    "e2e_latency_p99_us", "e2e_latency_mean_us", "e2e_latency_min_us",
    "e2e_latency_max_us", "e2e_latency_p50_raw_us", "e2e_samples",
    "e2e_spin_correction_us", "duration_s", "point_wall_s")
SPREAD_KEYS = ("sent_pps", "rx_pps", "forwarded_pps", "bitrate_sent_gbps",
               "e2e_latency_p50_us", "e2e_latency_p99_us")


def _median(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


def classify(row, floor_pct, threshold=DEFAULT_LOSS_THRESHOLD):
    """Il collo di bottiglia di UNA riga di sintesi, secondo la regola del
    relatore, con il pavimento della ricezione tolto.

    floor_pct: la perdita prima di XDP del solo contatore (rxonly) allo stesso
    rate, o None se rxonly non e' stato misurato."""
    if row.get("reference"):
        return LABEL_REF
    before = row.get("loss_before_xdp_pct") or 0.0
    after = row.get("loss_after_xdp_pct") or 0.0
    excess = before - (floor_pct or 0.0)
    if excess <= threshold and after <= threshold:
        return LABEL_NONE
    if after > threshold and after > excess:
        return LABEL_OUT
    return LABEL_PROG if floor_pct is not None else LABEL_IN_UNSPLIT


def summarise(rows, threshold=DEFAULT_LOSS_THRESHOLD):
    """Mediana fra i giri per (pipeline, frame, rate chiesto), poi il collo
    di bottiglia di ogni riga contro rxonly allo stesso rate."""
    groups = {}
    for r in rows:
        groups.setdefault((r["method"], r["frame"], r["rate_requested_pps"]),
                          []).append(r)
    out = []
    for (m, frame, rate), rs in groups.items():
        s = dict(method=m, frame=frame, rate_requested_pps=rate,
                 rounds=len(rs), reference=bool(rs[0].get("reference")),
                 gen_limited=any(r.get("gen_limited") for r in rs),
                 e2e_percentile_clipped=any(r.get("e2e_percentile_clipped")
                                            for r in rs))
        for k in MEDIAN_KEYS:
            v = _median([r.get(k) for r in rs])
            s[k] = round(v, 4) if isinstance(v, float) else v
        for k in SPREAD_KEYS:
            vals = [r.get(k) for r in rs if r.get(k) is not None]
            s[f"{k}_min"] = min(vals) if vals else None
            s[f"{k}_max"] = max(vals) if vals else None
        out.append(s)
    floors = {(s["frame"], s["rate_requested_pps"]): s.get("loss_before_xdp_pct")
              for s in out if s["method"] == REFERENCE}
    for s in out:
        floor = floors.get((s["frame"], s["rate_requested_pps"]))
        s["rxonly_loss_before_xdp_pct"] = floor
        s["excess_loss_before_xdp_pct"] = (
            None if s["reference"] or s.get("loss_before_xdp_pct") is None
            else round(s["loss_before_xdp_pct"] - (floor or 0.0), 3))
        s["bottleneck"] = classify(s, floor, threshold)
    order = {m: i for i, m in enumerate((REFERENCE,) + PIPELINES)}
    out.sort(key=lambda s: (s["frame"], order.get(s["method"], 99),
                            s["rate_requested_pps"]))
    return out


def onsets(summary):
    """Per pipeline e frame: l'ultimo rate senza perdita attribuibile, il
    primo con, e il collo che ce l'ha. Il riferimento resta fuori."""
    per = {}
    for s in summary:
        if s["reference"]:
            continue
        per.setdefault((s["method"], s["frame"]), []).append(s)
    out = []
    for (m, frame), rs in per.items():
        rs = sorted(rs, key=lambda s: s["rate_requested_pps"])
        first = next((s for s in rs if s["bottleneck"] != LABEL_NONE), None)
        clean = [s for s in rs if s["bottleneck"] == LABEL_NONE
                 and (first is None or s["rate_requested_pps"]
                      < first["rate_requested_pps"])]
        last_clean = clean[-1] if clean else None
        fwd = [s.get("forwarded_pps") for s in rs
               if s.get("forwarded_pps") is not None]
        out.append(dict(method=m, frame=frame,
                        last_clean=last_clean, first_loss=first,
                        lowest=rs[0] if rs else None,
                        highest=rs[-1] if rs else None,
                        max_forwarded_pps=max(fwd) if fwd else None))
    return out


class Probe:
    """La lettura che Generator.steady fa alle due marcature della finestra.

    Oltre a restituire i contatori cumulativi apre il cancello della latenza
    alla prima chiamata e lo chiude alla prima chiamata che arriva dopo meta'
    finestra: le letture lente si rifanno (Generator._snapshot), e le rifatte
    della prima marcatura non devono chiuderlo."""

    def __init__(self, read_counters, set_gate, window_s, clock=time.monotonic):
        self.read = read_counters
        self.set_gate = set_gate
        self.half = float(window_s) / 2.0
        self.clock = clock
        self.t_open = None
        self.t_close = None

    def __call__(self):
        now = self.clock()
        if self.t_open is None:
            self.set_gate(1)
            self.t_open = now
        elif self.t_close is None and now - self.t_open >= self.half:
            self.set_gate(0)
            self.t_close = now
        return self.read()


_IDLE_RE = re.compile(r"idle:\s*(\d+)us")


def parse_idle_us(text):
    """Il contatore `idle` (us) dalla sezione Current di un device pktgen."""
    m = _IDLE_RE.search(text)
    return int(m.group(1)) if m else None


def realtime_minus_monotonic_ns(tries=7):
    """(CLOCK_REALTIME - CLOCK_MONOTONIC in ns, incertezza in ns): la lettura
    col panino piu' stretto fra `tries`."""
    best = None
    for _ in range(tries):
        m1 = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        r = time.clock_gettime_ns(time.CLOCK_REALTIME)
        m2 = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        if best is None or m2 - m1 < best[1]:
            best = (r - (m1 + m2) // 2, m2 - m1)
    return best


def _percpu_total(tab, key):
    """Somma sulle CPU di una cella per-CPU, BCC o mappa fissata (AOT)."""
    v = tab[ct.c_int(key)]
    if isinstance(v, int):
        return v
    try:
        return sum(int(x) for x in v)
    except TypeError:
        return int(getattr(v, "value", v))


# ==========================================================================
# CARICAMENTO
# ==========================================================================
def _bcc_counter(target_fd):
    """Il programma 1 in un oggetto BCC suo, con la pipeline nello slot."""
    from bcc import BPF
    b = BPF(text=ING_COUNTER_BCC)
    fn = b.load_func("xdp_ing_count", BPF.XDP)
    if target_fd is not None:
        try:
            b["ing_next"][ct.c_int(0)] = ct.c_int(target_fd)
        except Exception as e:
            raise RuntimeError(
                f"il kernel rifiuta la pipeline come destinazione della tail "
                f"call ({e}): tipo, JIT o expected_attach_type diversi fra "
                f"contatore e pipeline") from e
    return b, fn


@contextlib.contextmanager
def _counter_in_aot_object():
    """build_pipeline carica P1/P1.5 con p1_aot.load_p1, che compila
    p1_source(...): per la durata del blocco il sorgente porta in coda il
    programma 1. Tutto il resto -- compilazione, loader_aot, mappe fissate,
    cablaggio sul fabric, alias del model_id di pktgen -- resta quello di
    build_pipeline, riga per riga."""
    import p1_aot
    orig = p1_aot.p1_source

    def with_counter(*a, **k):
        return orig(*a, **k) + "\n" + ING_COUNTER_LIBBPF

    p1_aot.p1_source = with_counter
    try:
        yield
    finally:
        p1_aot.p1_source = orig


def load_method(B, method, model_path, fab, sem):
    """(setup della pipeline o None, contatore d'ingresso) per un metodo."""
    if method == REFERENCE:
        b, fn = _bcc_counter(None)
        return None, dict(b=b, fn=fn, tab=b["ing_count"], kind="bcc")
    if method in AOT_METHODS:
        with _counter_in_aot_object():
            setup = B.build_pipeline(method, model_path, fab, sem)
        owner = setup.get("owner")
        fn = getattr(owner, "progs", {}).get("xdp_ing_count")
        if fn is None:
            raise RuntimeError(
                f"{method}: l'oggetto AOT non contiene xdp_ing_count -- il "
                f"sorgente non e' passato da p1_aot.p1_source?")
        setup["b"]["ing_next"][ct.c_int(0)] = ct.c_int(setup["disp"].fd)
        return setup, dict(b=setup["b"], fn=fn, tab=setup["b"]["ing_count"],
                           kind="aot")
    setup = B.build_pipeline(method, model_path, fab, sem)
    b, fn = _bcc_counter(setup["disp"].fd)
    return setup, dict(b=b, fn=fn, tab=b["ing_count"], kind="bcc")


def attach_egress(B, fab):
    """Il programma d'uscita su ogni peer, al posto dello stub XDP_PASS: e'
    anche cio' che rende possibile il redirect nel veth (vedi netns_fabric)."""
    from bcc import BPF
    from common import attach_xdp
    b = BPF(text=EGRESS_LAT_BCC)
    fn = b.load_func("xdp_rx_lat", BPF.XDP)
    attached = []
    for peer in fab.peer_of.values():
        try:
            B.raise_veth_ring(peer)
            with B._quiet():
                attach_xdp(b, fn, peer)
            attached.append(peer)
        except Exception as e:
            B.warn(f"contatore d'uscita non agganciato a {peer}: {e}")
    return b, attached


def read_latency(acc, hist_tab):
    cells = [[int(x) for x in acc[ct.c_int(i)]] for i in range(6)]
    mins = [c - 1 for c in cells[2] if c > 0]
    hist = [sum(int(x) for x in hist_tab[ct.c_int(i)])
            for i in range(LAT_US_BUCKETS + 1)]
    n = sum(cells[0])
    return dict(n=n, total_us=sum(cells[1]),
                min_us=(min(mins) if mins else None),
                max_us=(max(cells[3]) if n else None),
                neg=sum(cells[4]), nostamp=sum(cells[5]), hist=hist)


def zero_latency(acc, hist_tab, lat=None):
    """Azzera accumulatori e istogramma. Delle celle dell'istogramma solo
    quelle lette diverse da zero: le altre lo sono gia'."""
    for i in range(6):
        del acc[ct.c_int(i)]
    idx = (range(LAT_US_BUCKETS + 1) if lat is None else
           [i for i, c in enumerate(lat["hist"]) if c])
    for i in idx:
        del hist_tab[ct.c_int(i)]


def pktgen_idle_us(B, names):
    tot = 0
    for n in names:
        with open(B.pg_dev_path(n)) as f:
            v = parse_idle_us(f.read())
        if v is None:
            return None
        tot += v
    return tot


# ==========================================================================
# IL RUN
# ==========================================================================
def run_bitrate(B, methods, model_path, frames, rates_of, plan, rounds,
                window_s, lat_target=LAT_TARGET_SAMPLES, egress_cpu=None,
                overhead_reps=OVERHEAD_REPS):
    """Tutte le pipeline, stesso fabric e stesso generatore, a rate crescente.
    Restituisce (righe grezze, righe del costo del contatore, note)."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    sem, n_out = B.class_semantics()
    raw, over, notes = [], [], {}
    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        eg_b, peers = attach_egress(B, fab)
        if not peers:
            raise RuntimeError("nessun contatore d'uscita agganciato: senza, "
                               "gli inoltrati non si contano")
        ctl, acc, hist_tab = eg_b["lat_ctl"], eg_b["lat_acc"], eg_b["lat_hist"]
        rx_tab = eg_b["rx_count"]
        B.info(f"programma d'uscita (conta + latenza) su {len(peers)} peer")

        print(f"\n{YELLOW} Fase 1: carico pipeline e contatori d'ingresso "
              f"(nessuna misura in corso){NC}")
        loaded = {}
        for m in methods:
            try:
                loaded[m] = load_method(B, m, model_path, fab, sem)
                kind = loaded[m][1]["kind"]
                B.info(f"{m}: " + ("solo contatore (riferimento)"
                                   if m == REFERENCE else
                                   f"contatore -> tail call -> pipeline "
                                   f"({'stesso oggetto AOT' if kind == 'aot' else 'BCC'})"))
            except Exception as e:
                B.warn(f"{m}: non caricata, la salto -- "
                       f"{type(e).__name__}: {e}")
        if not loaded:
            return raw, over, notes

        ing = B.build_ingress(fab, plan, "shared", False)
        gen, napi_devs, egress_napi = None, [], []

        def set_ctl(i, v):
            ctl[ct.c_int(i)] = ct.c_ulonglong(int(v))

        def use(m, direct=False):
            setup, cnt = loaded[m]
            with B._quiet():
                for dev in ing.dut_devs:
                    if direct:
                        attach_xdp(setup["b"], setup["disp"], dev)
                    else:
                        attach_xdp(cnt["b"], cnt["fn"], dev)

        idle_ok = [True]

        def reader(m, direct=False):
            setup, cnt = loaded[m]

            def read():
                d = dict(fwd=_percpu_total(rx_tab, 0))
                idle = pktgen_idle_us(B, gen.names) if idle_ok[0] else 0
                d["idle_us"] = idle or 0
                if not direct:
                    d["rx_xdp"] = _percpu_total(cnt["tab"], 0)
                    d["tail_miss"] = _percpu_total(cnt["tab"], 1)
                if setup is not None:
                    ps = setup["pkt_stats"]
                    d.update(hit=B._read_u64(ps, 0), miss=B._read_u64(ps, 1),
                             drop=B._read_u64(ps, 2))
                return d
            return read

        def window(m, frame, rate, mask, seconds=None, direct=False,
                   timed=True):
            """Una finestra stazionaria: (run, latenza, durata totale).
            timed=False lascia chiuso il cancello: nessun pacchetto
            cronometrato, il programma d'uscita conta e basta."""
            off, _ = realtime_minus_monotonic_ns()
            set_ctl(0, 0)
            set_ctl(1, off)
            set_ctl(2, mask)
            gate = (lambda v: set_ctl(0, v)) if timed else (lambda v: None)
            probe = Probe(reader(m, direct), gate, seconds or window_s)
            t0 = time.monotonic()
            try:
                run = gen.steady(frame, gen.delay_for(rate) if rate else 0,
                                 probe, seconds=seconds)
            except Exception:
                # Finestra scartata: i campioni gia' registrati non devono
                # finire in quella dopo.
                set_ctl(0, 0)
                time.sleep(DRAIN_S)
                zero_latency(acc, hist_tab)
                raise
            finally:
                set_ctl(0, 0)
            wall = time.monotonic() - t0
            time.sleep(DRAIN_S)
            lat = read_latency(acc, hist_tab)
            zero_latency(acc, hist_tab, lat)
            return run, lat, wall

        try:
            for setup, _ in loaded.values():
                if setup is not None:
                    B._map_extra_ingress(setup, ing.ifindexes)
            gen = B.Generator(ing.gen_devs[:1], plan, window_s=window_s,
                              warmup_s=0.0, window_mode="steady").attach()
            if pktgen_idle_us(B, gen.names) is None:
                idle_ok[0] = False
                B.warn("pktgen non espone `idle` in /proc/net/pktgen: la "
                       "latenza NON e' corretta per l'attesa fra timbro e "
                       "trasmissione, e a rate basso e' sovrastimata di "
                       "circa il delay")
            notes["idle_correction"] = idle_ok[0]

            # Il primo attach crea la NAPI; solo dopo si mette in thread.
            use(next(iter(loaded)))
            napi_devs = list(ing.dut_devs)
            placed = B.enable_threaded_napi(napi_devs, plan)
            if placed:
                B.info("NAPI d'ingresso in thread: " + ", ".join(
                    f"{dv}({nt})->cpu{','.join(map(str, cs))}"
                    for dv, nt, cs in placed))
            else:
                napi_devs = []
                B.warn("nessun thread NAPI pinnato: generatore e DUT restano "
                       "sullo stesso core")
            if egress_cpu is not None:
                eplan = B.CpuPlan([], [egress_cpu], B.online_cpus(), [])
                placed_e = B.enable_threaded_napi(list(peers), eplan)
                egress_napi = [dv for dv, _, _ in placed_e]
                B.info(f"uscita in thread su cpu{egress_cpu}: "
                       f"{len(egress_napi)} veth")

            # --- sonda: la catena funziona? il timbro c'e'?
            print(f"\n{YELLOW} Sonda a {SANITY_PPS // 1000} kpps{NC}")
            alive = []
            f0 = frames[0]
            for m in loaded:
                use(m)
                try:
                    run, lat, _ = window(m, f0, SANITY_PPS,
                                         sample_mask(SANITY_PPS, SANITY_S,
                                                     lat_target),
                                         seconds=SANITY_S)
                except B.PktgenEmptyRun as e:
                    B.warn(f"{m}: sonda senza traffico ({e}), la escludo")
                    continue
                d = run.dut
                problems = []
                if d["rx_xdp"] <= 0:
                    problems.append("il contatore d'ingresso non conta")
                if m != REFERENCE:
                    if d["tail_miss"]:
                        problems.append(f"{d['tail_miss']} tail call non "
                                        f"partite")
                    if d["hit"] + d["drop"] <= 0:
                        problems.append("la pipeline non decide (nessun "
                                        "HIT/DROP)")
                    if d["fwd"] <= 0:
                        problems.append("niente arriva al nodo successivo")
                if problems:
                    B.warn(f"{m}: " + "; ".join(problems) + " -- esclusa")
                    continue
                if m != REFERENCE and not lat["n"]:
                    B.warn(f"{m}: nessun campione di latenza (timbri senza "
                           f"intestazione pktgen: {lat['nostamp']}, nel "
                           f"futuro: {lat['neg']}): conteggi validi, latenza "
                           f"assente")
                B.ok(f"{m}: RX {d['rx_xdp']}, inoltrati {d['fwd']}, "
                     f"campioni di latenza {lat['n']}")
                alive.append(m)
            if not alive:
                B.warn("nessun metodo ha superato la sonda")
                return raw, over, notes

            # --- lo sweep
            npts = rounds * sum(len(rates_of(f)) for f in frames) * len(alive)
            print(f"\n{YELLOW}{'=' * 78}{NC}")
            print(f"{YELLOW} Fase 2: {rounds} giri x {len(alive)} metodi x "
                  f"rate crescente, frame {frames} -- {npts} finestre da "
                  f"{window_s}s{NC}")
            print(f"{YELLOW}{'=' * 78}{NC}")
            print(f"  {'giro':>4s} {'chiesto':>8s} {'metodo':10s} "
                  f"{'inviati':>9s} {'RX XDP':>9s} {'inoltr.':>9s} "
                  f"{'prima%':>7s} {'pipe%':>7s} {'p50us':>7s} {'p99us':>7s}")
            t_run = time.monotonic()
            done = 0
            for rnd in range(1, rounds + 1):
                seq = alive if rnd % 2 else list(reversed(alive))
                for frame in frames:
                    for rate in rates_of(frame):
                        mask = sample_mask(rate, window_s, lat_target)
                        for m in seq:
                            use(m)
                            done += 1
                            try:
                                run, lat, wall = window(m, frame, rate, mask)
                            except B.PktgenEmptyRun as e:
                                B.warn(f"giro {rnd} {m} "
                                       f"{gbps_of(rate, frame):.2f} Gbit/s: "
                                       f"finestra scartata -- {e}")
                                continue
                            row = window_row(
                                m, frame, rnd, rate,
                                gen.delay_for(rate) if rate else 0,
                                gen.n_inst, run.window, wall, run.tx,
                                getattr(run, "errors", 0), run.dut, lat, mask,
                                idle_ok=idle_ok[0])
                            raw.append(row)
                            _print_point(row, done, npts, t_run)
                            if m != REFERENCE and row["tail_call_miss"]:
                                B.warn(f"{m}: {row['tail_call_miss']} tail "
                                       f"call non partite in questa finestra")

            # --- quanto costa il contatore
            pipes = [m for m in alive if m != REFERENCE]
            if overhead_reps > 0 and pipes:
                print(f"\n{YELLOW} Fase 3: costo del contatore, rate massimo, "
                      f"{overhead_reps} ripetizioni, con e senza catena{NC}")
                for rep in range(overhead_reps):
                    for m in pipes:
                        variants = (False, True) if rep % 2 == 0 else (True,
                                                                      False)
                        for direct in variants:
                            use(m, direct=direct)
                            try:
                                run, _, _ = window(m, frames[0], 0, 0,
                                                   direct=direct, timed=False)
                            except B.PktgenEmptyRun as e:
                                B.warn(f"{m}: finestra scartata ({e})")
                                continue
                            d = run.dut
                            proc = d["hit"] + d["miss"] + d["drop"]
                            pps = proc / run.window if run.window > 0 else 0
                            over.append(dict(
                                method=m, variant=("diretta" if direct
                                                   else "catena"),
                                rep=rep + 1, frame=frames[0],
                                duration_s=round(run.window, 4),
                                processed=proc, processed_pps=int(pps),
                                cost_ns=round(1e9 / pps, 2) if pps else None))
                            print(f"  {rep + 1:2d} {m:10s} "
                                  f"{('diretta' if direct else 'catena'):8s} "
                                  f"{pps / 1e6:6.3f} Mpps elaborati  "
                                  f"{(1e9 / pps if pps else 0):7.1f} ns")
        finally:
            if gen is not None:
                gen.detach()
            try:
                if os.path.isdir(B.PKTGEN_DIR):
                    B.pg_reset()
            except RuntimeError:
                pass
            if napi_devs:
                B.disable_threaded_napi(napi_devs)
            if egress_napi:
                B.disable_threaded_napi(egress_napi)
            for dev in ing.dut_devs:
                B._detach(dev)
            ing.cleanup()
            for peer in peers:
                B._detach(peer)
    return raw, over, notes


def _print_point(r, done, total, t0):
    def f(v, spec):
        return format(v, spec) if v is not None else "n/d"

    el = time.monotonic() - t0
    eta = el / done * (total - done) if done else 0
    print(f"  {r['round']:4d} {r['bitrate_requested_gbps']:6.2f}G "
          f"{r['method']:10s} {r['sent_pps'] / 1e6:8.3f}M "
          f"{r['rx_pps'] / 1e6:8.3f}M "
          f"{f(r['forwarded_pps'] and r['forwarded_pps'] / 1e6, '8.3f'):>8s}M "
          f"{f(r['loss_before_xdp_pct'], '7.2f'):>7s} "
          f"{f(r['loss_in_pipeline_pct'], '7.2f'):>7s} "
          f"{f(r['e2e_latency_p50_us'], '7.1f'):>7s} "
          f"{f(r['e2e_latency_p99_us'], '7.1f'):>7s}"
          f"  {GREY}[{done}/{total}, ~{eta / 60:.0f} min]{NC}")


def summarise_overhead(over):
    per = {}
    for r in over:
        per.setdefault(r["method"], {}).setdefault(r["variant"], []).append(
            r["cost_ns"])
    out = []
    for m, v in per.items():
        chain, direct = _median(v.get("catena", [])), _median(
            v.get("diretta", []))
        out.append(dict(method=m, cost_chain_ns=chain, cost_direct_ns=direct,
                        overhead_ns=(round(chain - direct, 2)
                                     if chain is not None
                                     and direct is not None else None)))
    return out


def print_summary(summary, ons, over_sum, threshold):
    def f(v, spec):
        return format(v, spec) if v is not None else "n/d"

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Mediana fra i giri. Perdite in % degli inviati; collo "
          f"di bottiglia con soglia {threshold}% oltre rxonly{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    last = None
    for s in summary:
        key = (s["method"], s["frame"])
        if key != last:
            last = key
            print(f"\n  {s['method']} ({s['frame']} B)")
            print(f"    {'Gbit/s inv.':>11s} {'inviati':>8s} {'RX XDP':>8s} "
                  f"{'inoltr.':>8s} {'prima%':>7s} {'pipe%':>7s} "
                  f"{'p50us':>7s} {'p99us':>7s}  collo")
        gl = " (gen)" if s["gen_limited"] else ""
        print(f"    {f(s['bitrate_sent_gbps'], '11.3f')} "
              f"{f(s['sent_pps'] and s['sent_pps'] / 1e6, '8.3f')} "
              f"{f(s['rx_pps'] and s['rx_pps'] / 1e6, '8.3f')} "
              f"{f(s['forwarded_pps'] and s['forwarded_pps'] / 1e6, '8.3f'):>8s} "
              f"{f(s['loss_before_xdp_pct'], '7.2f'):>7s} "
              f"{f(s['loss_in_pipeline_pct'], '7.2f'):>7s} "
              f"{f(s['e2e_latency_p50_us'], '7.1f'):>7s} "
              f"{f(s['e2e_latency_p99_us'], '7.1f'):>7s}  "
              f"{s['bottleneck']}{gl}")
    if ons:
        print(f"\n{YELLOW} Dove comincia la perdita{NC}")
        for o in ons:
            lc, fl, lo = o["last_clean"], o["first_loss"], o["lowest"]
            hi = o["highest"]
            cap = o["max_forwarded_pps"]
            head = f"  {o['method']:10s} ({o['frame']} B): "
            if fl is None:
                print(head + f"nessuna perdita attribuibile fino a "
                      f"{f(hi['bitrate_sent_gbps'] if hi else None, '.3f')}"
                      f" Gbit/s inviati, il rate piu' alto misurato; "
                      f"inoltrati al massimo {f(cap and cap / 1e6, '.3f')} "
                      f"Mpps")
                continue
            print(head + f"pulita fino a "
                  f"{f(lc['bitrate_sent_gbps'] if lc else None, '.3f')} "
                  f"Gbit/s, perde da {f(fl['bitrate_sent_gbps'], '.3f')} "
                  f"Gbit/s ({f(fl['sent_pps'] / 1e6, '.3f')} Mpps inviati) "
                  f"-> {fl['bottleneck']}. Latenza p50 "
                  f"{f(lo['e2e_latency_p50_us'], '.1f')} us al rate piu' "
                  f"basso, {f(lc['e2e_latency_p50_us'] if lc else None, '.1f')}"
                  f" us all'ultimo pulito, "
                  f"{f(fl['e2e_latency_p50_us'], '.1f')} us al primo con "
                  f"perdita. Inoltrati al massimo "
                  f"{f(cap and cap / 1e6, '.3f')} Mpps")
    if over_sum:
        print(f"\n{YELLOW} Costo del contatore (mediana, rate massimo){NC}")
        for o in over_sum:
            print(f"  {o['method']:10s} catena {f(o['cost_chain_ns'], '.1f')} "
                  f"ns, diretta {f(o['cost_direct_ns'], '.1f')} ns, "
                  f"differenza {f(o['overhead_ns'], '+.1f')} ns/pacchetto")


def _parse_list(spec, what):
    try:
        vals = [float(x) for x in spec.split(",") if x.strip()]
    except ValueError:
        sys.exit(f"{what}: attesi numeri separati da virgola, ricevuto "
                 f"{spec!r}")
    if not vals or min(vals) <= 0:
        sys.exit(f"{what}: servono valori positivi")
    return sorted(vals)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(
        description=__doc__.strip().split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--method", default="all",
                   help="all (default: rxonly e le cinque pipeline) oppure "
                        "una lista, es. rxonly,baseline,p1_static")
    r = p.add_mutually_exclusive_group()
    r.add_argument("--bitrates", default=None, metavar="LISTA",
                   help="bit rate da offrire in Gbit/s (L2, byte del frame), "
                        "separati da virgola. Default: "
                        + ",".join(str(x) for x in DEFAULT_BITRATES_GBPS)
                        + " a 64 byte")
    r.add_argument("--rates", default=None, metavar="LISTA",
                   help="in alternativa, rate in Mpps")
    p.add_argument("--frames", default=str(DEFAULT_FRAME),
                   help="taglie di frame in byte (pkt_size di pktgen, senza "
                        "FCS), default 64")
    p.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS,
                   help="giri completi: ogni giro misura tutti i metodi a "
                        "tutti i rate; si riporta la mediana")
    p.add_argument("--duration", type=float, default=None, metavar="S",
                   help="durata della finestra stazionaria (default quella "
                        "di bench_throughput, 0.3 s)")
    p.add_argument("--lat-samples", type=int, default=LAT_TARGET_SAMPLES,
                   help="campioni di latenza per finestra, circa (0 = ogni "
                        "pacchetto)")
    p.add_argument("--loss-threshold", type=float,
                   default=DEFAULT_LOSS_THRESHOLD, metavar="PCT",
                   help="perdita in punti %% degli inviati, oltre quella di "
                        "rxonly allo stesso rate, da cui una riga si dice "
                        "'in perdita'")
    p.add_argument("--overhead-reps", type=int, default=OVERHEAD_REPS,
                   help="ripetizioni della misura del costo del contatore "
                        "(0 la salta)")
    p.add_argument("--gen-cpus", default=None, metavar="LISTA")
    p.add_argument("--dut-cpus", default=None, metavar="LISTA")
    p.add_argument("--threads", type=int, default=None, metavar="N")
    p.add_argument("--allow-cpu0", action="store_true")
    p.add_argument("--egress-cpu", type=int, default=None, metavar="N",
                   help="NAPI dei veth d'uscita in thread sulla CPU N. Senza, "
                        "la ricezione del nodo successivo gira sulla CPU del "
                        "DUT (come in --mode rates)")
    p.add_argument("--out", default=None, help="cartella dei risultati")
    p.add_argument("--no-plot", action="store_true",
                   help="non disegnare i grafici a fine run")
    p.add_argument("--cleanup", action="store_true",
                   help="rimuovi un fabric rimasto da un run interrotto")
    a = p.parse_args(argv)

    if sys.platform != "linux":
        sys.exit(f"serve Linux, non {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("serve root: sudo python3 ipa/test/bench_bitrate.py")
    import bench_throughput as B
    os.chdir(B.SHARED_DIR)
    if a.cleanup:
        from netns_fabric import cleanup
        cleanup()
        B.del_tg_links(16)
        if B.pg_available():
            B.pg_stop()
            B.pg_reset()
        return 0
    if not B.pg_available():
        sys.exit(f"{B.PKTGEN_DIR} non c'e' e `modprobe pktgen` non l'ha "
                 f"creato: questo kernel non ha il modulo.")
    B.pg_reset()

    methods = ([REFERENCE] + list(PIPELINES) if a.method == "all"
               else [m.strip() for m in a.method.split(",") if m.strip()])
    bad = [m for m in methods if m not in (REFERENCE,) + PIPELINES]
    if bad:
        sys.exit(f"--method: sconosciuti {bad}; validi: all, {REFERENCE}, "
                 f"{', '.join(PIPELINES)}")
    frames = [int(x) for x in _parse_list(a.frames, "--frames")]
    if a.bitrates:
        gbps = _parse_list(a.bitrates, "--bitrates")

        def rates_of(frame):
            return [int(pps_for_gbps(g, frame)) for g in gbps]
    else:
        mpps = (_parse_list(a.rates, "--rates") if a.rates else
                [pps_for_gbps(g, DEFAULT_FRAME) / 1e6
                 for g in DEFAULT_BITRATES_GBPS])

        def rates_of(frame):
            return [int(x * 1e6) for x in mpps]
    window_s = a.duration or B.WINDOW_S

    plan = B.plan_cpus(a.gen_cpus, a.dut_cpus, a.threads, a.allow_cpu0)
    plan.describe()
    if a.egress_cpu is not None:
        if a.egress_cpu in plan.dut or a.egress_cpu in plan.gen:
            sys.exit(f"--egress-cpu {a.egress_cpu} e' gia' del generatore o "
                     f"del DUT")
        if a.egress_cpu not in B.online_cpus():
            sys.exit(f"--egress-cpu {a.egress_cpu}: CPU non online")

    import model_meta as mm
    model_path = mm.default_checkpoint()
    envargs = argparse.Namespace(
        mode="bitrate", no_threaded_napi=False, gen_topology="shared",
        xmit_mode="start_xmit", duration=window_s, window="steady",
        generator="pktgen", ttl_mix=None, egress_cpu=a.egress_cpu,
        warmup=0.0, repeat=1, rounds=a.rounds,
        loss_threshold=a.loss_threshold, clone_skb=0, burst=0)

    def env_now(extra=()):
        env = B.capture_env(envargs, plan, methods, frames)
        env += [("bitrate_gbps_richiesti" if a.bitrates else "rate_mpps",
                 a.bitrates or a.rates or ",".join(
                     f"{pps_for_gbps(g, DEFAULT_FRAME) / 1e6:.4f}"
                     for g in DEFAULT_BITRATES_GBPS)),
                ("latenza", "timbro pktgen -> contatore del nodo successivo, "
                            "celle da 1 us, corretta per l'attesa di pktgen"),
                ("latenza_campioni_per_finestra", a.lat_samples),
                ("contatore_ingresso", "programma 1 (per-CPU) -> tail call -> "
                                       "pipeline di produzione")]
        env += list(extra)
        return env

    B.print_env(env_now())
    t0 = time.monotonic()
    raw, over, notes = run_bitrate(
        B, methods, model_path, frames, rates_of, plan, a.rounds, window_s,
        lat_target=a.lat_samples, egress_cpu=a.egress_cpu,
        overhead_reps=a.overhead_reps)
    summary = summarise(raw, a.loss_threshold)
    ons = onsets(summary)
    over_sum = summarise_overhead(over)
    print_summary(summary, ons, over_sum, a.loss_threshold)
    print(f"\n  durata del run: {(time.monotonic() - t0) / 60:.1f} min")
    rc = 0 if raw else 1
    if any(r["tail_call_miss"] for r in raw if not r["reference"]):
        B.warn("tail call non partite in qualche finestra: quei pacchetti "
               "sono entrati nel contatore e non nella pipeline")
        rc = 1
    if a.out and raw:
        os.makedirs(a.out, exist_ok=True)
        B._write_csv(os.path.join(a.out, "bitrate_raw.csv"), raw)
        B._write_csv(os.path.join(a.out, "bitrate.csv"), summary)
        if over:
            B._write_csv(os.path.join(a.out, "bitrate_overhead_raw.csv"),
                         over)
            B._write_csv(os.path.join(a.out, "bitrate_overhead.csv"),
                         over_sum)
        B.write_env(a.out, env_now([
            ("correzione_attesa_pktgen",
             "si" if notes.get("idle_correction") else "NO: idle assente"),
            ("durata_run_min", round((time.monotonic() - t0) / 60, 1))]))
        if not a.no_plot:
            try:
                import plot_bitrate
                plot_bitrate.plot_all(a.out)
            except ImportError as e:
                B.warn(f"grafici non disegnati ({e}): "
                       f"python3 ipa/test/plot_bitrate.py {a.out}")
        B._give_back(a.out)
    return rc


if __name__ == "__main__":
    sys.exit(main())
