"""bench_bitrate's arithmetic, checked without a kernel.

What can go wrong without anything crashing: a loss attributed to the wrong
side (the professor's rule inverted), percentages that do not add up, the
latency not corrected for pktgen's pacing wait, a percentile off by a bucket,
the latency gate closed by a retried first read, and the AOT counter compiled
into the object but never pinned (so P1 would run without program 1).

    python3 ipa/test/test_bitrate_math.py

BENCH_BITRATE_PATH=<file> runs the same checks against another copy of the
module (the mutation runs use it).
"""
import importlib.util
import inspect
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.dirname(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_path = os.environ.get("BENCH_BITRATE_PATH")
if _path:
    _spec = importlib.util.spec_from_file_location("bench_bitrate", _path)
    BB = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(BB)
else:
    import bench_bitrate as BB  # noqa: E402

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))


def close(a, b, tol=1e-6):
    return a is not None and b is not None and abs(a - b) <= tol


def t_bitrate():
    print("[1] bit rate <-> pps")
    check("1 Gbit/s di frame da 64 B = 1 953 125 pps",
          close(BB.pps_for_gbps(1.0, 64), 1_953_125))
    check("andata e ritorno a 512 B",
          close(BB.gbps_of(BB.pps_for_gbps(2.5, 512), 512), 2.5, 1e-9))
    # 60 B senza FCS + 24 = 84 B sul filo: 1,488 Mpps riempiono 1 GbE
    check("L1: 1 488 095 pps di frame da 60 B = 1 Gbit/s Ethernet",
          close(BB.gbps_of(1_488_095, 60, l1=True), 1.0, 1e-3))


def t_mask():
    print("[2] maschera di campionamento")
    check("sotto il bersaglio: tutti i pacchetti",
          BB.sample_mask(100_000, 0.1, 20000) == 0)
    check("58 600 attesi -> uno ogni 4", BB.sample_mask(195_312, 0.3, 20000) == 3)
    check("1,2 M attesi -> uno ogni 64", BB.sample_mask(4e6, 0.3, 20000) == 63)
    check("bersaglio 0 = ogni pacchetto", BB.sample_mask(4e6, 0.3, 0) == 0)
    ok = True
    for rate in (2e5, 7e5, 1.3e6, 3.9e6, 5.9e6):
        m = BB.sample_mask(rate, 0.3, 20000)
        got = rate * 0.3 / (m + 1)
        ok &= ((m + 1) & m) == 0 and 10000 < got <= 20000
    check("potenza di 2, fra meta' bersaglio e bersaglio", ok)


def _hist(pairs):
    h = [0] * (BB.LAT_CELLS + 1)
    for us, c in pairs:
        h[BB.lat_cell(us)] += c
    return h


def t_percentile():
    print("[3] percentili dall'istogramma a celle da 1 us")
    check("una cella sola", BB.hist_percentile(_hist([(1, 10)]), 0.5) == (1.0, False))
    h = _hist([(5, 100), (100, 1)])
    check("p99 di 100 x 5us + 1 x 100us = 5", BB.hist_percentile(h, 0.99)[0] == 5.0)
    h = _hist([(5, 100), (100, 2)])
    check("p99 di 100 x 5us + 2 x 100us = 100",
          BB.hist_percentile(h, 0.99)[0] == 100.0)
    v, clipped = BB.hist_percentile([0, 0, 0, 0, 10], 0.5)
    check("oltre l'istogramma: bordo e segnalato", v == 4.0 and clipped)
    check("vuoto", BB.hist_percentile([0, 0, 0], 0.5) == (None, False))
    # due passi: 1 us fino a 1024, poi 64 us fino a 65 536, poi trabocco
    check("celle fini fino a 1023 us",
          BB.lat_cell(0) == 0 and BB.lat_cell(1023) == 1023)
    check("celle da 64 us da 1024",
          BB.lat_cell(1024) == 1024 and BB.lat_cell(1087) == 1024
          and BB.lat_cell(1088) == 1025)
    check("ultima cella grossa e trabocco",
          BB.lat_cell(65535) == BB.LAT_CELLS - 1
          and BB.lat_cell(65536) == BB.LAT_CELLS
          and BB.lat_cell(10 ** 7) == BB.LAT_CELLS)
    check("valore di una cella grossa = il suo centro",
          BB.lat_cell_value(1025) == 1024 + 64 + 32)
    check("il centro ricade nella sua cella",
          all(BB.lat_cell(BB.lat_cell_value(i)) == i
              for i in range(BB.LAT_CELLS)))
    h = _hist([(10, 90), (3000, 10)])
    v, clipped = BB.hist_percentile(h, 0.99)
    check("p99 a 3 ms entro 32 us, non tagliato",
          abs(v - 3000) <= 32 and not clipped, str(v))
    h = _hist([(10, 90), (70_000, 10)])
    v, clipped = BB.hist_percentile(h, 0.99)
    check("oltre 65,5 ms: tagliato al bordo",
          v == float(BB.LAT_MAX_US) and clipped)


def t_latency():
    print("[4] latenza corretta per l'attesa di pktgen")
    check("attesa per pacchetto = idle / inviati",
          close(BB.spin_per_packet_us(576_000, 60_000), 9.6))
    check("senza idle niente correzione", BB.spin_per_packet_us(None, 10) is None)
    lat = dict(n=100, total_us=1500, min_us=10, max_us=20, neg=0, nostamp=0,
               hist=_hist([(10, 50), (20, 50)]))
    s = BB.latency_stats(lat, 2.5, 3)
    check("p50 10 - 2,5", s["e2e_latency_p50_us"] == 7.5)
    check("p90 20 - 2,5", s["e2e_latency_p90_us"] == 17.5)
    check("media 15 - 2,5", s["e2e_latency_mean_us"] == 12.5)
    check("minimo e massimo corretti",
          s["e2e_latency_min_us"] == 7.5 and s["e2e_latency_max_us"] == 17.5)
    check("il valore grezzo resta", s["e2e_latency_p50_raw_us"] == 10.0)
    check("un campione ogni mask+1", s["e2e_sample_every"] == 4)
    s0 = BB.latency_stats(dict(n=0, hist=_hist([])), 2.5, 0)
    check("nessun campione -> campi vuoti, non zero",
          s0["e2e_latency_p50_us"] is None and s0["e2e_samples"] == 0)
    s1 = BB.latency_stats(dict(n=3, total_us=3, min_us=1, max_us=1, neg=0,
                               nostamp=0, hist=_hist([(1, 3)])), 5.0, 0)
    check("la correzione non va sotto zero", s1["e2e_latency_p50_us"] == 0.0)


def _row(tx, rej, rx, fwd=None, hit=None, miss=0, drop=0, secs=0.01,
         rate=1_000_000, method="baseline", lat=None, idle=0):
    d = dict(rx_xdp=rx, tail_miss=0, fwd=fwd or 0, idle_us=idle)
    if hit is not None:
        d.update(hit=hit, miss=miss, drop=drop)
    return BB.window_row(method, 64, 1, rate, 1000, 2, secs, 0.6, tx, rej, d,
                         lat or dict(n=0, hist=_hist([])), 0)


def t_losses():
    print("[5] perdite e collo di bottiglia (la regola del relatore)")
    # caso B della richiesta: 10 inviati, 8 al programma, 8 rilanciati
    b = _row(tx=8000, rej=2000, rx=8000, fwd=8000, hit=8000)
    check("B: perdita prima di XDP = inviati - RX",
          b["loss_before_xdp"] == 2000 and b["loss_before_xdp_pct"] == 20.0)
    check("B: nessuna perdita nella pipeline", b["loss_in_pipeline"] == 0)
    check("B: col solo contatore pulito -> programma eBPF",
          BB.classify(b, 0.0) == BB.LABEL_PROG)
    check("B: senza rxonly non si separa programma da ricezione",
          BB.classify(b, None) == BB.LABEL_IN_UNSPLIT)
    # caso A: 10 inviati, 10 al programma, 8 escono
    a = _row(tx=10000, rej=0, rx=10000, fwd=8000, hit=10000)
    check("A: perdita all'uscita = HIT - inoltrati",
          a["loss_after_xdp"] == 2000 and a["loss_after_xdp_pct"] == 20.0)
    check("A: -> trasmissivo", BB.classify(a, 0.0) == BB.LABEL_OUT)
    # classe DROP: rilanciati meno dei ricevuti, ma e' una DECISIONE
    dd = _row(tx=10000, rej=0, rx=10000, fwd=8000, hit=8000, drop=2000)
    check("DROP del modello: loss_in_pipeline conta i non inoltrati",
          dd["loss_in_pipeline"] == 2000
          and dd["not_forwarded_by_decision"] == 2000)
    check("DROP del modello non e' un collo di bottiglia",
          BB.classify(dd, 0.0) == BB.LABEL_NONE)
    # pavimento del trasporto: la pipeline perde quanto il solo contatore
    fl = _row(tx=9700, rej=300, rx=9700, fwd=9700, hit=9700)
    check("3% prima di XDP con rxonly al 2,5% -> nessuna",
          BB.classify(fl, 2.5) == BB.LABEL_NONE)
    check("3% prima di XDP con rxonly a 0 -> programma",
          BB.classify(fl, 0.0) == BB.LABEL_PROG)
    # le percentuali si sommano, la scomposizione torna
    m = _row(tx=9000, rej=1000, rx=8900, fwd=8000, hit=8500, miss=100,
             drop=250)
    check("prima + pipeline = totale (in % degli inviati)",
          close(m["loss_before_xdp_pct"] + m["loss_in_pipeline_pct"],
                m["loss_total_pct"], 1e-3))
    check("decisioni + uscita + residuo = pipeline",
          m["not_forwarded_by_decision"] + m["loss_after_xdp"]
          + m["unaccounted_in_pipeline"] == m["loss_in_pipeline"])
    check("persi fra veth e XDP = accettati - RX",
          m["lost_between_veth_and_xdp"] == 100)
    check("packets_lost = inviati - inoltrati", m["packets_lost"] == 2000)


def t_rates():
    print("[6] rate e bit rate della riga")
    r = _row(tx=10000, rej=0, rx=10000, fwd=10000, hit=10000, secs=0.01)
    check("inviati/s", r["sent_pps"] == 1_000_000)
    check("bit rate inviato = pps x 64 x 8",
          r["bitrate_sent_bps"] == 512_000_000
          and r["bitrate_sent_gbps"] == 0.512)
    check("L1 = pps x 88 x 8", r["bitrate_sent_l1_gbps"] == 0.704)
    g = _row(tx=2000, rej=0, rx=2000, fwd=2000, hit=2000, secs=0.01,
             rate=1_000_000)
    check("inviato sotto il 95% del chiesto -> tetto del generatore",
          g["gen_limited"])
    check("al chiesto -> non limitato", not r["gen_limited"])
    bu = _row(tx=12000, rej=0, rx=12000, fwd=12000, hit=12000, secs=0.01,
              rate=1_000_000)
    check("inviato oltre il 105% del chiesto -> raffica di recupero",
          bu["gen_burst"] and not bu["gen_limited"])
    check("al chiesto -> nessuna raffica", not r["gen_burst"])
    ref = _row(tx=10000, rej=0, rx=10000, method="rxonly")
    check("rxonly: niente inoltro, niente latenza (vuoti, non zero)",
          ref["reference"] and ref["packets_forwarded"] is None
          and ref["loss_in_pipeline"] is None
          and ref["e2e_latency_p50_us"] is None)
    lat = dict(n=10, total_us=100, min_us=10, max_us=10, neg=0, nostamp=0,
               hist=_hist([(10, 10)]))
    c = _row(tx=10000, rej=0, rx=10000, fwd=10000, hit=10000, lat=lat,
             idle=20000)
    check("la riga corregge con idle/inviati (2 us)",
          c["e2e_spin_correction_us"] == 2.0
          and c["e2e_latency_p50_us"] == 8.0)
    # pktgen aspetta anche prima dei tentativi respinti: si divide per tutti
    # i tentativi, non per i soli accettati (sarebbero 2,5 us)
    cr = _row(tx=8000, rej=2000, rx=8000, fwd=8000, hit=8000, lat=lat,
              idle=20000)
    check("idle diviso per i tentativi, respinti compresi",
          cr["e2e_spin_correction_us"] == 2.0)
    c2 = BB.window_row("baseline", 64, 1, 1e6, 1000, 2, 0.01, 0.6, 10000, 0,
                       dict(rx_xdp=10000, tail_miss=0, fwd=10000,
                            idle_us=20000, hit=10000, miss=0, drop=0),
                       lat, 0, idle_ok=False)
    check("idle assente: nessuna correzione, e lo dice",
          c2["e2e_spin_correction_us"] is None
          and c2["e2e_latency_p50_us"] == 10.0)


def t_summary():
    print("[7] sintesi fra i giri e inizio della perdita")
    rows = []
    for rnd, (f1, f2) in enumerate(((9950, 5000), (9900, 5200), (9990, 4800)), 1):
        for rate, tx, rej in ((1_000_000, 10000, 0), (2_000_000, 20000, 0),
                              (4_000_000, 25000, 15000)):
            d = dict(rx_xdp=tx, tail_miss=0, fwd=0, idle_us=0)
            rows.append(BB.window_row("rxonly", 64, rnd, rate, 0, 2, 0.01, 0.6,
                                      tx, rej, d, dict(n=0, hist=[0]), 0))
        for rate, tx, rej, fwd in ((1_000_000, 10000, 0, f1),
                                   (2_000_000, 20000, 0, 19900),
                                   (4_000_000, 20000, 20000, 20000)):
            d = dict(rx_xdp=tx, tail_miss=0, fwd=fwd, idle_us=0, hit=tx,
                     miss=0, drop=0)
            rows.append(BB.window_row("baseline", 64, rnd, rate, 0, 2, 0.01,
                                      0.6, tx, rej, d, dict(n=0, hist=[0]), 0))
    s = BB.summarise(rows, 1.0)
    base = {x["rate_requested_pps"]: x for x in s if x["method"] == "baseline"}
    check("mediana fra tre giri",
          base[1_000_000]["packets_forwarded"] == 9950)
    check("min/max fra i giri",
          base[1_000_000]["forwarded_pps_min"] == 990_000
          and base[1_000_000]["forwarded_pps_max"] == 999_000)
    check("il pavimento viene da rxonly allo stesso rate",
          base[4_000_000]["rxonly_loss_before_xdp_pct"] == 37.5)
    check("50% prima di XDP contro 37,5% di rxonly -> programma",
          base[4_000_000]["bottleneck"] == BB.LABEL_PROG
          and base[4_000_000]["excess_loss_before_xdp_pct"] == 12.5)
    check("righe pulite -> nessuna",
          base[1_000_000]["bottleneck"] == BB.LABEL_NONE
          and base[2_000_000]["bottleneck"] == BB.LABEL_NONE)
    on = [o for o in BB.onsets(s) if o["method"] == "baseline"][0]
    check("ultima pulita 2 Mpps, prima in perdita 4 Mpps",
          on["last_clean"]["rate_requested_pps"] == 2_000_000
          and on["first_loss"]["rate_requested_pps"] == 4_000_000)
    check("rxonly non entra negli inizi",
          all(o["method"] != "rxonly" for o in BB.onsets(s)))

    # una riga in perdita seguita da righe pulite: sporadica, non l'inizio
    def srow(rate, label):
        return dict(method="modular", frame=64, rate_requested_pps=rate,
                    reference=False, bottleneck=label, forwarded_pps=rate,
                    loss_in_pipeline_pct=0.0)
    noisy = [srow(1, BB.LABEL_NONE), srow(2, BB.LABEL_PROG),
             srow(3, BB.LABEL_NONE), srow(4, BB.LABEL_PROG),
             srow(5, BB.LABEL_PROG)]
    o = BB.onsets(noisy)[0]
    check("inizio = da dove perdono tutti i rate piu' alti (4, non 2)",
          o["first_loss"]["rate_requested_pps"] == 4
          and o["last_clean"]["rate_requested_pps"] == 3)
    check("la riga isolata e' sporadica",
          [x["rate_requested_pps"] for x in o["sporadic"]] == [2])
    tail = [srow(1, BB.LABEL_NONE), srow(2, BB.LABEL_PROG),
            srow(3, BB.LABEL_NONE)]
    check("perdita non persistente fino all'ultimo rate -> nessun inizio",
          BB.onsets(tail)[0]["first_loss"] is None)


def t_probe():
    print("[8] il cancello della latenza")
    events = []
    p = BB.Probe(lambda: {"x": 1}, events.append)
    out = [p() for _ in range(5)]       # A, rifatte di A, B, rifatta di B
    check("aperto alla prima lettura, una volta sola", events == [1])
    check("la sonda non lo chiude (lo chiude chi ferma pktgen)",
          0 not in events)
    check("restituisce i contatori", out[-1] == {"x": 1})


def t_idle_parse():
    print("[9] il contatore idle di pktgen")
    text = ("Current:\n     pkts-sofar: 1000  errors: 5\n"
            "     started: 123456us  stopped: 123999us idle: 789us\n")
    check("idle letto", BB.parse_idle_us(text) == 789)
    check("assente -> None", BB.parse_idle_us("pkts-sofar: 1") is None)


def t_overhead():
    print("[11] costo del contatore")
    check("ns per esecuzione fra due letture di fdinfo",
          BB.per_run_ns((1000, 10), (6000, 110)) == 50.0)
    check("contatori fermi (statistiche spente) -> None",
          BB.per_run_ns((1000, 10), (1000, 10)) is None
          and BB.per_run_ns((None, None), (5, 5)) is None)
    over = []
    for rep, (pc, pd, cc, cd) in enumerate(((180.0, 170.0, 500.0, 430.0),
                                            (181.0, 171.0, 420.0, 460.0),
                                            (182.0, 170.0, 800.0, 440.0))):
        for var, prog, cost in (("catena", pc, cc), ("diretta", pd, cd)):
            over.append(dict(method="baseline", variant=var, rep=rep + 1,
                             prog_ns=prog, cost_ns=cost))
    o = BB.summarise_overhead(over)[0]
    check("contatore dal tempo del programma: mediana 181 - 170 = 11 ns",
          o["prog_overhead_ns"] == 11.0 and o["reps"] == 3)
    check("dal throughput resta anche lo scarto fra le finestre",
          o["cost_overhead_ns"] == 60.0
          and o["cost_spread_chain_ns"] == 380.0)


def t_sources():
    print("[10] i programmi (controlli statici: qui non c'e' un compilatore)")
    import p1_aot
    import bench_throughput as B
    check("il contatore AOT viene fissato in bpffs (p1_aot._PROG_RE lo vede)",
          p1_aot._PROG_RE.findall(BB.ING_COUNTER_LIBBPF) == ["xdp_ing_count"])
    for name, src in (("BCC d'ingresso", BB.ING_COUNTER_BCC),
                      ("libbpf d'ingresso", BB.ING_COUNTER_LIBBPF),
                      ("d'uscita", BB.EGRESS_LAT_BCC)):
        check(f"graffe e parentesi bilanciate ({name})",
              src.count("{") == src.count("}")
              and src.count("(") == src.count(")"))
    eg = BB.EGRESS_LAT_BCC
    check("uscita: parametri sostituiti",
          f"#define LAT_CELLS {BB.LAT_CELLS}" in eg
          and "#define LAT_FINE_US 1024" in eg
          and "#define LAT_STEP_SHIFT 6" in eg
          and "#define PG_OFF 42" in eg and "%(" not in eg)
    check("uscita: si campiona sul contatore degli arrivi PRIMA di leggere "
          "il pacchetto", 0 <= eg.find("(*cnt & *mask)") < eg.find("h[0]"))
    check("uscita: magic di pktgen 0xbe9be955 byte per byte",
          "h[0] != 0xbe" in eg and "h[1] != 0x9b" in eg
          and "h[2] != 0xe9" in eg and "h[3] != 0x55" in eg)
    check("uscita: lettura entro il controllo dei limiti (42 + 16)",
          "PG_OFF + 16" in eg and "h[15]" in eg and "h[16]" not in eg)
    check("il magic coincide con il model_id che il banco registra",
          B.PKTGEN_MAGIC_MODEL_ID == 0xBE)
    orig = p1_aot.p1_source
    try:
        p1_aot.p1_source = lambda *a, **k: "SRC"
        with BB._counter_in_aot_object():
            out = p1_aot.p1_source()
        check("nel blocco il sorgente AOT porta il contatore in coda",
              out.startswith("SRC") and "xdp_ing_count" in out)
        check("fuori dal blocco torna quello di prima", p1_aot.p1_source() == "SRC")
    finally:
        p1_aot.p1_source = orig
    check("load_p1 compila p1_source(...) per nome (la sostituzione vale)",
          "p1_source(models" in inspect.getsource(p1_aot.load_p1))
    check("setup_p1_static passa da p1_aot.load_p1",
          "p1_aot.load_p1" in inspect.getsource(B.setup_p1_static))


def main():
    for t in (t_bitrate, t_mask, t_percentile, t_latency, t_losses, t_rates,
              t_summary, t_probe, t_idle_parse, t_sources, t_overhead):
        t()
    n, ok = len(RESULTS), sum(RESULTS)
    print(f"\n{ok}/{n} PASS")
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
