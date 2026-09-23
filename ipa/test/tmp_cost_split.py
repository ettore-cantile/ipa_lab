#!/usr/bin/env python3
"""TEMPORANEO (2026-09-23) -- da cancellare dopo l'esperimento.

Scompone il costo per pacchetto della baseline e di P1 sul banco reale
(generatore XDP, uscita su un'altra CPU), con tre gradini in piu' fra
rxonly e baseline e con il tempo del solo programma letto dal kernel:

  rxonly     conta e scarta, NON legge il pacchetto        (gia' nel banco)
  rxread     + legge le righe di cache delle intestazioni (byte 0 e 62)
  rxtouch    + le scrive (MAC e TTL), come fa la baseline
  base_drop  la baseline intera, ma XDP_DROP invece di bpf_redirect
  baseline   parse, TTL, MAC, bpf_redirect                (gia' nel banco)
  p1_static, hardcoded  (e con --all template, modular)

Differenze lette:
  rxread  - rxonly     primo accesso ai dati scritti dal generatore su un'altra CPU
  rxtouch - rxread     scriverli
  base_drop - rxtouch  il resto del lavoro della baseline (parse, lookup, atomiche)
  baseline - base_drop redirect + accodamento, MENO la restituzione della pagina
                       (che con il DROP avviene sulla CPU del nodo, con
                       l'inoltro sulla CPU d'uscita)

Fase B: kernel.bpf_stats_enabled=1, e da /proc/self/fdinfo del programma
attaccato run_time_ns / run_cnt = tempo medio del SOLO programma XDP sotto
questo carico (tail call incluse: girano dentro l'invocazione del
dispatcher). Le statistiche aggiungono due letture dell'orologio per
invocazione, uguali per tutti: rxonly ne da' il pavimento.

  sudo python3 ipa/test/tmp_cost_split.py [--rounds 5] [--all]
"""
import argparse
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import bench_throughput as B        # noqa: E402

RXREAD_SRC = r"""
#include <uapi/linux/bpf.h>
BPF_ARRAY(pkt_stats, __u64, 3);
BPF_ARRAY(cls_stats, __u64, 8);
int xdp_rxread(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *d = data;
    if ((void *)(d + 63) > data_end) {
        int m = 1; __u64 *mv = pkt_stats.lookup(&m);
        if (mv) __sync_fetch_and_add(mv, 1);
        return XDP_DROP;
    }
    /* Il valore finisce in una mappa, cosi' clang non puo' togliere i load. */
    int s = 7; __u64 *sv = cls_stats.lookup(&s);
    if (sv) *sv = d[0] + d[62];
    TOUCH
    int k = 0; __u64 *v = pkt_stats.lookup(&k);
    if (v) __sync_fetch_and_add(v, 1);
    return XDP_DROP;
}
"""
READ_ONLY = ""
# MAC sorgente e TTL: le stesse righe che la baseline riscrive.
WRITE = "d[6] = d[0]; d[11] = d[5]; d[22] = d[22] - 1;"

EXTRA = ("rxread", "rxtouch", "base_drop")


def _setup_src(src, fn_name):
    from bcc import BPF
    b = BPF(text=src)
    fn = b.load_func(fn_name, BPF.XDP)
    return {"b": b, "fn": fn, "disp": fn, "pipeline": 0, "rx_is_hit": True,
            "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"],
            "progs": {fn_name: fn.fd}}


def build(method, model_path, fab, sem):
    if method == "rxread":
        return _setup_src(RXREAD_SRC.replace("TOUCH", READ_ONLY), "xdp_rxread")
    if method == "rxtouch":
        return _setup_src(RXREAD_SRC.replace("TOUCH", WRITE), "xdp_rxread")
    if method == "base_drop":
        import verify_prog_run as V
        import test_fabric as TF
        a = "return bpf_redirect(action->ifindex, 0);"
        assert V.EBPF_BASELINE.count(a) == 1, "baseline cambiata: patch non valida"
        setup = _setup_src(V.EBPF_BASELINE.replace(a, "return XDP_DROP;"),
                           "xdp_baseline")
        TF._install_fabric_mac_table(setup["b"], "mac_table", fab,
                                     sem.logical_ports)
        return setup
    return B.build_pipeline(method, model_path, fab, sem)


def prog_stats(fd):
    t = c = None
    try:
        with open(f"/proc/self/fdinfo/{fd}") as f:
            for line in f:
                k, _, v = line.partition(":")
                if k.strip() == "run_time_ns":
                    t = int(v)
                elif k.strip() == "run_cnt":
                    c = int(v)
    except OSError:
        pass
    return t, c


STATS_KNOB = "/proc/sys/kernel/bpf_stats_enabled"


def set_stats(val):
    with open(STATS_KNOB) as f:
        old = f.read().strip()
    with open(STATS_KNOB, "w") as f:
        f.write(str(val))
    return old


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--stats-rounds", type=int, default=3)
    p.add_argument("--repeat", type=int, default=B.DEFAULT_REPEAT)
    p.add_argument("--threads", type=int, default=2)
    p.add_argument("--egress-cpu", type=int, default=0)
    p.add_argument("--all", action="store_true",
                   help="anche template e modular")
    a = p.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    import model_meta as mm
    from netns_fabric import NetnsFabric
    from common import attach_xdp
    from xdp_gen import XdpGen

    methods = [B.RX_ONLY, "rxread", "rxtouch", "base_drop", "baseline",
               "p1_static", "hardcoded"]
    if a.all:
        methods += ["template", "modular"]
    model_path = mm.default_checkpoint()
    plan = B.plan_cpus(threads=a.threads)
    print(f"CPU: generatore {plan.gen}, DUT {plan.dut}, uscita "
          f"cpu{a.egress_cpu}")
    sem, n_out = B.class_semantics()
    cost = {m: [] for m in methods}
    prog = {m: [] for m in methods}
    cost_st = {m: [] for m in methods}
    old_knob = None

    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        rx_b, rx_tab, attached = B.attach_rx_counter(fab)
        loaded = {}
        for m in methods:
            try:
                loaded[m] = build(m, model_path, fab, sem)
                B.info(f"{m}: caricata")
            except Exception as e:
                B.warn(f"{m}: non caricata -- {type(e).__name__}: {e}")
        ing = B.build_ingress(fab, plan, "shared", False)
        for s in loaded.values():
            B._map_extra_ingress(s, ing.ifindexes)
        gen = XdpGen(ing.gen_devs[0], plan, window_s=B.WINDOW_S).attach()

        def use(m):
            s = loaded[m]
            with B._quiet():
                for dev in ing.dut_devs:
                    attach_xdp(s["b"], s["disp"], dev)
            return s

        use(next(iter(loaded)))
        napi_devs = list(ing.dut_devs)
        placed = B.enable_threaded_napi(napi_devs, plan)
        B.info(f"NAPI DUT: {placed}")
        eplan = B.CpuPlan([], [a.egress_cpu], B.online_cpus(), [])
        placed_e = B.enable_threaded_napi(list(attached), eplan)
        egress_napi = [d for d, _, _ in placed_e]
        B.info(f"NAPI uscita: {placed_e}")

        alive = []
        for m in list(loaded):
            s = use(m)
            r = B.measure_point(s, rx_tab, fab, 64, 0, 1, n_out, gen.clone,
                                repeat=1, burst=gen.burst, gen=gen,
                                warmup=False, plan=plan, steady=False)
            if r is None or r["hit"] + r.get("drop", 0) == 0:
                B.warn(f"{m}: la sonda non produce HIT, esclusa")
                continue
            alive.append(m)
        full = gen.window_count(gen.rate_estimate or 3_000_000)

        def point(m, reps):
            s = use(m)
            return s, B.measure_point(s, rx_tab, fab, 64, 0, full, n_out,
                                      gen.clone, repeat=reps, burst=gen.burst,
                                      gen=gen, plan=plan)

        try:
            print(f"\nFase A: {a.rounds} giri, statistiche BPF spente. "
                  f"costo = 1e9 / elaborati al secondo")
            for rnd in range(1, a.rounds + 1):
                for m in alive:
                    _, r = point(m, a.repeat)
                    if r is None or not r.get("proc_pps"):
                        continue
                    c = 1e9 / r["proc_pps"]
                    cost[m].append(c)
                    print(f"  {rnd:2d} {m:10s} {r['proc_pps']:9d} pps "
                          f"{c:7.1f} ns  respinti "
                          f"{r.get('respinti_pct', 0.0):5.1f}%")

            old_knob = set_stats(1)
            print(f"\nFase B: {a.stats_rounds} giri, bpf_stats_enabled=1. "
                  f"prog = run_time_ns / run_cnt del programma attaccato")
            for rnd in range(1, a.stats_rounds + 1):
                for m in alive:
                    fd = loaded[m]["disp"].fd
                    t0, c0 = prog_stats(fd)
                    _, r = point(m, 1)
                    t1, c1 = prog_stats(fd)
                    if None in (t0, c0, t1, c1) or c1 <= c0:
                        print(f"  {rnd:2d} {m:10s} run_time_ns/run_cnt non "
                              f"disponibili in fdinfo")
                        continue
                    pn = (t1 - t0) / (c1 - c0)
                    prog[m].append(pn)
                    cs = 1e9 / r["proc_pps"] if r and r.get("proc_pps") else 0
                    if cs:
                        cost_st[m].append(cs)
                    print(f"  {rnd:2d} {m:10s} prog {pn:7.1f} ns  "
                          f"(costo nodo con stats {cs:7.1f} ns, "
                          f"{c1 - c0} invocazioni)")
        finally:
            if old_knob is not None:
                set_stats(old_knob)
            gen.detach()
            B.pg_reset()
            B.disable_threaded_napi(napi_devs)
            if egress_napi:
                B.disable_threaded_napi(egress_napi)
            for dev in ing.dut_devs:
                B._detach(dev)
            ing.cleanup()
            for peer in attached:
                B._detach(peer)
            del rx_b

    med = {m: st.median(v) for m, v in cost.items() if v}
    pmed = {m: st.median(v) for m, v in prog.items() if v}
    print("\nRiepilogo (mediana [min-max] fra i giri)")
    print(f"  {'metodo':10s} {'nodo ns':>9s} {'min':>7s} {'max':>7s} "
          f"{'prog ns':>9s} {'nodo con stats':>15s}")
    for m in alive:
        if m not in med:
            continue
        pm = f"{pmed[m]:9.1f}" if m in pmed else f"{'n/d':>9s}"
        cs = (f"{st.median(cost_st[m]):15.1f}" if cost_st[m]
              else f"{'n/d':>15s}")
        print(f"  {m:10s} {med[m]:9.1f} {min(cost[m]):7.1f} "
              f"{max(cost[m]):7.1f} {pm} {cs}")

    def d(x, y, label, tab):
        if x in tab and y in tab:
            print(f"  {x:>10s} - {y:<10s} {tab[x] - tab[y]:+7.1f} ns  {label}")

    print("\nScomposizione, costo del nodo (fase A)")
    d("rxread", B.RX_ONLY, "leggere le intestazioni scritte da un'altra CPU", med)
    d("rxtouch", "rxread", "scriverle", med)
    d("base_drop", "rxtouch", "resto del programma baseline", med)
    d("baseline", "base_drop", "redirect+accodamento - restituzione pagina", med)
    d("p1_static", "baseline", "P1 statica sopra la baseline", med)
    d("hardcoded", "baseline", "P1.5 sopra la baseline", med)
    d("template", "baseline", "P2 sopra la baseline", med)
    d("modular", "baseline", "P3 sopra la baseline", med)
    print("\nSolo programma (fase B, run_time_ns / run_cnt)")
    d("baseline", B.RX_ONLY, "programma baseline sopra il pavimento", pmed)
    d("p1_static", "baseline", "rete P1 statica, tempo del programma", pmed)
    d("hardcoded", "baseline", "rete P1.5, tempo del programma", pmed)
    d("template", "baseline", "P2, tempo del programma", pmed)
    d("modular", "baseline", "P3, tempo del programma", pmed)


if __name__ == "__main__":
    main()
