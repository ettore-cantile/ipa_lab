"""test_load_curve_math.py -- the arithmetic of bench_load_curve (rates, loss
attribution, percentiles), checked without a kernel. No root.

    python3 ipa/test/test_load_curve_math.py
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
    _spec = importlib.util.spec_from_file_location("bench_load_curve", _path)
    BB = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(BB)
else:
    import bench_load_curve as BB  # noqa: E402

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
    check("round trip at 512 B",
          close(BB.gbps_of(BB.pps_for_gbps(2.5, 512), 512), 2.5, 1e-9))
    check("L1: 1 488 095 pps di frame da 60 B = 1 Gbit/s Ethernet",
          close(BB.gbps_of(1_488_095, 60, l1=True), 1.0, 1e-3))


def t_mask():
    print("[2] sampling mask")
    check("below the target: every packet",
          BB.sample_mask(100_000, 0.1, 20000) == 0)
    check("58 600 expected -> one every 4", BB.sample_mask(195_312, 0.3, 20000) == 3)
    check("1.2 M expected -> one every 64", BB.sample_mask(4e6, 0.3, 20000) == 63)
    check("target 0 = every packet", BB.sample_mask(4e6, 0.3, 0) == 0)
    ok = True
    for rate in (2e5, 7e5, 1.3e6, 3.9e6, 5.9e6):
        m = BB.sample_mask(rate, 0.3, 20000)
        got = rate * 0.3 / (m + 1)
        ok &= ((m + 1) & m) == 0 and 10000 < got <= 20000
    check("power of 2, between half the target and the target", ok)


def _hist(pairs):
    h = [0] * (BB.LAT_CELLS + 1)
    for us, c in pairs:
        h[BB.lat_cell(us)] += c
    return h


def t_percentile():
    print("[3] percentiles from the 1 us-cell histogram")
    check("a single cell", BB.hist_percentile(_hist([(1, 10)]), 0.5) == (1.0, False))
    h = _hist([(5, 100), (100, 1)])
    check("p99 di 100 x 5us + 1 x 100us = 5", BB.hist_percentile(h, 0.99)[0] == 5.0)
    h = _hist([(5, 100), (100, 2)])
    check("p99 di 100 x 5us + 2 x 100us = 100",
          BB.hist_percentile(h, 0.99)[0] == 100.0)
    v, clipped = BB.hist_percentile([0, 0, 0, 0, 10], 0.5)
    check("beyond the histogram: edge, and flagged", v == 4.0 and clipped)
    check("empty", BB.hist_percentile([0, 0, 0], 0.5) == (None, False))
    check("fine cells up to 1023 us",
          BB.lat_cell(0) == 0 and BB.lat_cell(1023) == 1023)
    check("64 us cells from 1024",
          BB.lat_cell(1024) == 1024 and BB.lat_cell(1087) == 1024
          and BB.lat_cell(1088) == 1025)
    check("last coarse cell and overflow",
          BB.lat_cell(65535) == BB.LAT_CELLS - 1
          and BB.lat_cell(65536) == BB.LAT_CELLS
          and BB.lat_cell(10 ** 7) == BB.LAT_CELLS)
    check("value of a coarse cell = its centre",
          BB.lat_cell_value(1025) == 1024 + 64 + 32)
    check("the centre falls in its own cell",
          all(BB.lat_cell(BB.lat_cell_value(i)) == i
              for i in range(BB.LAT_CELLS)))
    h = _hist([(10, 90), (3000, 10)])
    v, clipped = BB.hist_percentile(h, 0.99)
    check("p99 at 3 ms within 32 us, not clipped",
          abs(v - 3000) <= 32 and not clipped, str(v))
    h = _hist([(10, 90), (70_000, 10)])
    v, clipped = BB.hist_percentile(h, 0.99)
    check("beyond 65.5 ms: clipped at the edge",
          v == float(BB.LAT_MAX_US) and clipped)


def t_latency():
    print("[4] latency corrected for pktgen's wait")
    check("wait per packet = idle / sent",
          close(BB.spin_per_packet_us(576_000, 60_000), 9.6))
    check("without idle no correction", BB.spin_per_packet_us(None, 10) is None)
    lat = dict(n=100, total_us=1500, min_us=10, max_us=20, neg=0, nostamp=0,
               hist=_hist([(10, 50), (20, 50)]))
    s = BB.latency_stats(lat, 2.5, 3)
    check("p50 10 - 2,5", s["e2e_latency_p50_us"] == 7.5)
    check("p90 20 - 2,5", s["e2e_latency_p90_us"] == 17.5)
    check("media 15 - 2,5", s["e2e_latency_mean_us"] == 12.5)
    check("minimum and maximum corrected",
          s["e2e_latency_min_us"] == 7.5 and s["e2e_latency_max_us"] == 17.5)
    check("the raw value is kept", s["e2e_latency_p50_raw_us"] == 10.0)
    check("one sample every mask+1", s["e2e_sample_every"] == 4)
    s0 = BB.latency_stats(dict(n=0, hist=_hist([])), 2.5, 0)
    check("no sample -> empty fields, not zero",
          s0["e2e_latency_p50_us"] is None and s0["e2e_samples"] == 0)
    s1 = BB.latency_stats(dict(n=3, total_us=3, min_us=1, max_us=1, neg=0,
                               nostamp=0, hist=_hist([(1, 3)])), 5.0, 0)
    check("the correction does not go below zero", s1["e2e_latency_p50_us"] == 0.0)


def _row(tx, rej, rx, fwd=None, hit=None, miss=0, drop=0, secs=0.01,
         rate=1_000_000, method="baseline", lat=None, idle=0):
    d = dict(rx_xdp=rx, tail_miss=0, fwd=fwd or 0, idle_us=idle)
    if hit is not None:
        d.update(hit=hit, miss=miss, drop=drop)
    return BB.window_row(method, 64, 1, rate, 1000, 2, secs, 0.6, tx, rej, d,
                         lat or dict(n=0, hist=_hist([])), 0)


def t_losses():
    print("[5] losses and bottleneck (the ingress/egress rule)")
    b = _row(tx=8000, rej=2000, rx=8000, fwd=8000, hit=8000)
    check("B: loss before XDP = sent - RX",
          b["loss_before_xdp"] == 2000 and b["loss_before_xdp_pct"] == 20.0)
    check("B: no loss in the pipeline", b["loss_in_pipeline"] == 0)
    check("B: with a clean counter-only reference -> eBPF program",
          BB.classify(b, 0.0) == BB.LABEL_PROG)
    check("B: without rxonly program and reception cannot be separated",
          BB.classify(b, None) == BB.LABEL_IN_UNSPLIT)
    a = _row(tx=10000, rej=0, rx=10000, fwd=8000, hit=10000)
    check("A: loss at egress = HIT - forwarded",
          a["loss_after_xdp"] == 2000 and a["loss_after_xdp_pct"] == 20.0)
    check("A: -> transmission", BB.classify(a, 0.0) == BB.LABEL_OUT)
    dd = _row(tx=10000, rej=0, rx=10000, fwd=8000, hit=8000, drop=2000)
    check("model DROP: loss_in_pipeline counts the non-forwarded",
          dd["loss_in_pipeline"] == 2000
          and dd["not_forwarded_by_decision"] == 2000)
    check("model DROP is not a bottleneck",
          BB.classify(dd, 0.0) == BB.LABEL_NONE)
    fl = _row(tx=9700, rej=300, rx=9700, fwd=9700, hit=9700)
    check("threshold raised by hand (1): 3% before XDP with rxonly at 2.5% -> "
          "none", BB.classify(fl, 2.5, 1.0) == BB.LABEL_NONE)
    check("default threshold (0.1): the same 0.5 points above rxonly -> "
          "program", BB.classify(fl, 2.5) == BB.LABEL_PROG)
    check("3% before XDP with rxonly at 0 -> program",
          BB.classify(fl, 0.0) == BB.LABEL_PROG)
    idle = dict(fl, napi_run_pct=60.0)
    check("loss before XDP with the node at 60% -> bench, not program",
          BB.classify(idle, 0.0) == BB.LABEL_BENCH)
    check("with the node at 99.8% -> program",
          BB.classify(dict(fl, napi_run_pct=99.8), 0.0) == BB.LABEL_PROG)
    m = _row(tx=9000, rej=1000, rx=8900, fwd=8000, hit=8500, miss=100,
             drop=250)
    check("before + pipeline = total (in % of sent)",
          close(m["loss_before_xdp_pct"] + m["loss_in_pipeline_pct"],
                m["loss_total_pct"], 1e-3))
    check("decisions + egress + residual = pipeline",
          m["not_forwarded_by_decision"] + m["loss_after_xdp"]
          + m["unaccounted_in_pipeline"] == m["loss_in_pipeline"])
    check("lost between veth and XDP = accepted - RX",
          m["lost_between_veth_and_xdp"] == 100)
    check("packets_lost = sent - forwarded", m["packets_lost"] == 2000)


def t_rates():
    print("[6] rate e bit rate della riga")
    r = _row(tx=10000, rej=0, rx=10000, fwd=10000, hit=10000, secs=0.01)
    check("sent/s", r["sent_pps"] == 1_000_000)
    check("sent bit rate = pps x 64 x 8",
          r["bitrate_sent_bps"] == 512_000_000
          and r["bitrate_sent_gbps"] == 0.512)
    check("L1 = pps x 88 x 8", r["bitrate_sent_l1_gbps"] == 0.704)
    g = _row(tx=2000, rej=0, rx=2000, fwd=2000, hit=2000, secs=0.01,
             rate=1_000_000)
    check("sent below 95% of requested -> generator ceiling",
          g["gen_limited"])
    check("at the requested rate -> not limited", not r["gen_limited"])
    bu = _row(tx=12000, rej=0, rx=12000, fwd=12000, hit=12000, secs=0.01,
              rate=1_000_000)
    check("sent above 105% of requested -> catch-up burst",
          bu["gen_burst"] and not bu["gen_limited"])
    check("at the requested rate -> no burst", not r["gen_burst"])
    ref = _row(tx=10000, rej=0, rx=10000, method="rxonly")
    check("rxonly: no forwarding, no latency (empty, not zero)",
          ref["reference"] and ref["packets_forwarded"] is None
          and ref["loss_in_pipeline"] is None
          and ref["e2e_latency_p50_us"] is None)
    lat = dict(n=10, total_us=100, min_us=10, max_us=10, neg=0, nostamp=0,
               hist=_hist([(10, 10)]))
    c = _row(tx=10000, rej=0, rx=10000, fwd=10000, hit=10000, lat=lat,
             idle=20000)
    check("the row corrects with idle/sent (2 us)",
          c["e2e_spin_correction_us"] == 2.0
          and c["e2e_latency_p50_us"] == 8.0)
    cr = _row(tx=8000, rej=2000, rx=8000, fwd=8000, hit=8000, lat=lat,
              idle=20000)
    check("idle divided by attempts, rejected included",
          cr["e2e_spin_correction_us"] == 2.0)
    c2 = BB.window_row("baseline", 64, 1, 1e6, 1000, 2, 0.01, 0.6, 10000, 0,
                       dict(rx_xdp=10000, tail_miss=0, fwd=10000,
                            idle_us=20000, hit=10000, miss=0, drop=0),
                       lat, 0, idle_ok=False)
    check("idle missing: no correction, and it says so",
          c2["e2e_spin_correction_us"] is None
          and c2["e2e_latency_p50_us"] == 10.0)


def t_summary():
    print("[7] summary over rounds and loss onset")
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
    check("median over three rounds",
          base[1_000_000]["packets_forwarded"] == 9950)
    check("min/max over rounds",
          base[1_000_000]["forwarded_pps_min"] == 990_000
          and base[1_000_000]["forwarded_pps_max"] == 999_000)
    check("the floor comes from rxonly at the same rate",
          base[4_000_000]["rxonly_loss_before_xdp_pct"] == 37.5)
    check("50% before XDP against 37.5% for rxonly -> program",
          base[4_000_000]["bottleneck"] == BB.LABEL_PROG
          and base[4_000_000]["excess_loss_before_xdp_pct"] == 12.5)
    check("clean rows -> none",
          base[1_000_000]["bottleneck"] == BB.LABEL_NONE
          and base[2_000_000]["bottleneck"] == BB.LABEL_NONE)
    on = [o for o in BB.onsets(s) if o["method"] == "baseline"][0]
    check("last clean 2 Mpps, first with loss 4 Mpps",
          on["last_clean"]["rate_requested_pps"] == 2_000_000
          and on["first_loss"]["rate_requested_pps"] == 4_000_000)
    check("rxonly is not part of the onsets",
          all(o["method"] != "rxonly" for o in BB.onsets(s)))

    def srow(rate, label):
        return dict(method="modular", frame=64, rate_requested_pps=rate,
                    reference=False, bottleneck=label, forwarded_pps=rate,
                    loss_in_pipeline_pct=0.0)
    noisy = [srow(1, BB.LABEL_NONE), srow(2, BB.LABEL_PROG),
             srow(3, BB.LABEL_NONE), srow(4, BB.LABEL_PROG),
             srow(5, BB.LABEL_PROG)]
    o = BB.onsets(noisy)[0]
    check("onset = where every higher rate loses (4, not 2)",
          o["first_loss"]["rate_requested_pps"] == 4
          and o["last_clean"]["rate_requested_pps"] == 3)
    check("the isolated row is sporadic",
          [x["rate_requested_pps"] for x in o["sporadic"]] == [2])
    tail = [srow(1, BB.LABEL_NONE), srow(2, BB.LABEL_PROG),
            srow(3, BB.LABEL_NONE)]
    check("loss not persistent up to the last rate -> no onset",
          BB.onsets(tail)[0]["first_loss"] is None)


def t_probe():
    print("[8] the latency gate")
    events = []
    p = BB.Probe(lambda: {"x": 1}, events.append)
    out = [p() for _ in range(5)]
    check("opened at the first read, only once", events == [1])
    check("the probe does not close it (whoever stops pktgen does)",
          0 not in events)
    check("returns the counters", out[-1] == {"x": 1})


def t_idle_parse():
    print("[9] pktgen's idle counter")
    text = ("Current:\n     pkts-sofar: 1000  errors: 5\n"
            "     started: 123456us  stopped: 123999us idle: 789us\n")
    check("idle read", BB.parse_idle_us(text) == 789)
    check("missing -> None", BB.parse_idle_us("pkts-sofar: 1") is None)


def t_overhead():
    print("[11] cost of the counter")
    check("ns per run between two fdinfo reads",
          BB.per_run_ns((1000, 10), (6000, 110)) == 50.0)
    check("counters still (statistics off) -> None",
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
    check("counter from the program time: median 181 - 170 = 11 ns",
          o["prog_overhead_ns"] == 11.0 and o["reps"] == 3)
    check("from throughput the spread between windows remains too",
          o["cost_overhead_ns"] == 60.0
          and o["cost_spread_chain_ns"] == 380.0)


def t_report():
    print("[12] --report: from the CSVs to the summary")
    import contextlib
    import io
    import tempfile
    import bench_capacity as B
    rows = []
    for rnd in (1, 2, 3):
        for m, fwd in (("rxonly", 0), ("baseline", 9000)):
            d = dict(rx_xdp=9500, tail_miss=9500 if m == "rxonly" else 0,
                     fwd=fwd, idle_us=0)
            if m != "rxonly":
                d.update(hit=9500, miss=0, drop=0)
            rows.append(BB.window_row(m, 64, rnd, 1_000_000, 1000, 2, 0.01,
                                      0.6, 9500, 500, d,
                                      dict(n=0, hist=_hist([])), 0))
    direct = BB.summarise(rows, 1.0)
    with tempfile.TemporaryDirectory() as d:
        with contextlib.redirect_stdout(io.StringIO()):
            B._write_csv(os.path.join(d, "bitrate_raw.csv"), rows)
        from plot_load_curve import read_summary
        back = BB.summarise(read_summary(os.path.join(d, "bitrate_raw.csv")),
                            1.0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = BB.report_from_csv(d, 1.0)
    key = lambda s: (s["method"], s["rate_requested_pps"])  # noqa: E731
    same = all(a[k] == b[k] for a, b in zip(sorted(direct, key=key),
                                            sorted(back, key=key))
               for k in ("reference", "packets_forwarded",
                         "loss_before_xdp_pct", "bottleneck"))
    check("the re-read CSVs give the same summary (types and booleans)", same)
    check("the summary prints again (rc 0, baseline row)",
          rc == 0 and "baseline (64 B)" in out.getvalue())
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "bitrate_raw.csv")
        BB.save_csv(path, rows[:2])
        BB.save_csv(path, rows)
        back = read_summary(path)
        left = os.listdir(d)
    check("save_csv: rewrites every row, no .tmp left behind",
          len(back) == len(rows) and left == ["bitrate_raw.csv"]
          and back[-1]["packets_sent"] == rows[-1]["packets_sent"])


def t_sources():
    print("[10] the programs (static checks: there is no compiler here)")
    import p1_aot
    import bench_capacity as B
    check("the AOT counter is pinned in bpffs (p1_aot._PROG_RE sees it)",
          p1_aot._PROG_RE.findall(BB.ING_COUNTER_LIBBPF) == ["xdp_ing_count"])
    for name, src in (("BCC ingress", BB.ING_COUNTER_BCC),
                      ("libbpf ingress", BB.ING_COUNTER_LIBBPF),
                      ("egress", BB.EGRESS_LAT_BCC)):
        check(f"balanced braces and parentheses ({name})",
              src.count("{") == src.count("}")
              and src.count("(") == src.count(")"))
    eg = BB.EGRESS_LAT_BCC
    check("egress: parameters substituted",
          f"#define LAT_CELLS {BB.LAT_CELLS}" in eg
          and "#define LAT_FINE_US 1024" in eg
          and "#define LAT_STEP_SHIFT 6" in eg
          and "#define PG_OFF 42" in eg and "%(" not in eg)
    check("egress: sampling on the arrival counter BEFORE reading "
          "the packet", 0 <= eg.find("(*cnt & *mask)") < eg.find("h[0]"))
    check("egress: pktgen magic 0xbe9be955 byte by byte",
          "h[0] != 0xbe" in eg and "h[1] != 0x9b" in eg
          and "h[2] != 0xe9" in eg and "h[3] != 0x55" in eg)
    check("egress: read within the bounds check (42 + 16)",
          "PG_OFF + 16" in eg and "h[15]" in eg and "h[16]" not in eg)
    check("the magic matches the model_id the bench registers",
          B.PKTGEN_MAGIC_MODEL_ID == 0xBE)
    orig = p1_aot.p1_source
    try:
        p1_aot.p1_source = lambda *a, **k: "SRC"
        with BB._counter_in_aot_object():
            out = p1_aot.p1_source()
        check("inside the block the AOT source carries the counter at the end",
              out.startswith("SRC") and "xdp_ing_count" in out)
        check("outside the block the previous one comes back", p1_aot.p1_source() == "SRC")
    finally:
        p1_aot.p1_source = orig
    check("load_p1 compiles p1_source(...) by name (the substitution holds)",
          "p1_source(models" in inspect.getsource(p1_aot.load_p1))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "check_pipelines.py"), encoding="utf-8") as f:
        v_src = f.read()
    v_p1s = v_src.split("def setup_p1_static(", 1)[1].split("\ndef ", 1)[0]
    check("setup_p1_static goes through p1_aot.load_p1",
          "V.setup_p1_static" in inspect.getsource(B.setup_p1_static)
          and "p1_aot.load_p1" in v_p1s)


def t_scale_and_host():
    print("[13] calibrated scale and machine columns")
    r = BB.auto_rates(2_000_000, 6_000_000)
    check("fractions of the reception ceiling, rounded to kpps",
          r == [100_000, 200_000, 400_000, 600_000, 800_000, 1_000_000,
                1_200_000, 1_400_000, 1_600_000, 1_800_000, 2_000_000,
                2_200_000, 2_500_000], str(r))
    r = BB.auto_rates(2_000_000, 2_100_000)
    check("above the generator ceiling: stop at its 95%, no duplicates",
          r[-1] == 1_995_000 and r[-2] == 1_800_000
          and len(r) == len(set(r)) == 11, str(r))
    check("zero ceiling: no scale", BB.auto_rates(0, 5e6) == [])
    host = dict(host_throttle_core=0, host_dut_mhz=3500, host_disturbed=False)
    d = dict(rx_xdp=300000, tail_miss=0, fwd=300000, idle_us=0, hit=300000,
             miss=0, drop=0)
    rows = [BB.window_row("baseline", 64, rnd, 1e6, 1000, 3, 0.3, 0.6,
                          300000, 0, d, dict(n=0, hist=_hist([])), 0,
                          host=dict(host, host_disturbed=(rnd == 2),
                                    host_dut_mhz=3500 + rnd))
            for rnd in (1, 2, 3)]
    check("the row carries the host_* columns", rows[0]["host_dut_mhz"] == 3501)
    s = BB.summarise(rows)[0]
    check("summary: rounds with the machine disturbed are counted, not dropped",
          s["host_disturbed_rounds"] == 1 and s["rounds"] == 3)
    check("summary: DUT frequency as median over rounds",
          s["host_dut_mhz"] == 3502)
    old = _row(tx=10000, rej=0, rx=10000, fwd=10000, hit=10000)
    check("row without monitor: no host_* column",
          not any(k.startswith("host_") for k in old))


def main():
    for t in (t_bitrate, t_mask, t_percentile, t_latency, t_losses, t_rates,
              t_summary, t_probe, t_idle_parse, t_sources, t_overhead,
              t_report, t_scale_and_host):
        t()
    n, ok = len(RESULTS), sum(RESULTS)
    print(f"\n{ok}/{n} PASS")
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
