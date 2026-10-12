#!/usr/bin/env python3
"""
popolazione.py -- le cifre delle slide "Inferenza di una rete neurale nel
kernel Linux con eBPF XDP", calcolate su una campagna di popolazione.

    python3 docs/slides_src/popolazione.py results/popolazione_2026-10           # cifre
    python3 docs/slides_src/popolazione.py results/popolazione_2026-10 --pptx    # e slide

Nessuna cifra e' di un modello solo: ogni numero e' una mediana, un
intervallo [minimo–massimo] o una legge stimata sulla popolazione, letta con
population_report.Campaign (stesse esclusioni: misure disturbate o bocciate
fuori). Senza --pptx stampa le cifre in JSON, che servono anche a scrivere
spiegazione_inferenza.txt e il capitolo del september_notebook. Con --pptx
riscrive i grafici, le schede e i testi del .pptx (lo stile resta quello del
file: si sostituiscono i dati, non i grafici).
"""
import json
import math
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "ipa", "test"))
sys.path.insert(0, os.path.join(ROOT, "ipa"))

import population_report as PR  # noqa: E402
import campaign_report as CR  # noqa: E402

PIPES = PR.PIPES                       # p1_static, hardcoded, template, modular
ALL = ("baseline",) + PIPES
LAB = {"rxonly": "solo ricezione", "baseline": "baseline",
       "p1_static": "P1 statica", "hardcoded": "P1.5", "template": "P2",
       "modular": "P3"}
SHORT = {"baseline": "baseline", "p1_static": "P1", "hardcoded": "P1.5",
         "template": "P2", "modular": "P3"}
DENSE = ("base", "replica", "imbuto")  # le famiglie della legge di costo


# --------------------------------------------------------------------------
# statistica
# --------------------------------------------------------------------------
def clean(xs):
    return [x for x in xs if x is not None and not (isinstance(x, float)
                                                    and math.isnan(x))]


def med(xs):
    xs = clean(xs)
    return st.median(xs) if xs else None


def rng(xs):
    xs = clean(xs)
    return (min(xs), max(xs)) if xs else (None, None)


def summ(xs):
    """{'n', 'med', 'min', 'max'} di una lista."""
    xs = clean(xs)
    if not xs:
        return None
    return dict(n=len(xs), med=st.median(xs), min=min(xs), max=max(xs))


def num(v):
    return PR.num(v)


# --------------------------------------------------------------------------
# le cifre
# --------------------------------------------------------------------------
class Pop:
    def __init__(self, base):
        self.c = PR.Campaign(base)
        if not self.c.models:
            sys.exit(f"{base}: nessuna popolazione")
        self.base = base
        self.ids = sorted(self.c.models)

    def m(self, i, k):
        return self.c.models[i].get(k)

    def ids_of(self, families=None, sub=None):
        out = []
        for i in self.ids:
            if families and self.m(i, "family") not in families:
                continue
            if sub and self.m(i, f"sub_{sub}") != "1":
                continue
            out.append(i)
        return out

    def val(self, k, i, m, key):
        return self.c.val(k, i, m, key)

    def nn(self, k, i, m, key="ns"):
        return self.c.nn(k, i, m, key)

    # -- tetti senza modello ----------------------------------------------
    def reference(self):
        out = {}
        for k in ("P", "E", "L"):
            s = CR.saturation(PR.read_csv(os.path.join(
                self.base, f"rif_{k}core", "compare.csv")))
            for m in ("rxonly", "baseline"):
                if m in s:
                    r = s[m]
                    out[f"{m}_{k}"] = dict(
                        ns=num(r.get("ns_cpu")), mpps=CR.node_mpps(r),
                        instr=num(r.get("instr_pkt")), ipc=num(r.get("ipc")),
                        cycles=num(r.get("cycles_pkt")),
                        busy=num(r.get("dut_busy_pct")))
        return out

    # -- per pipeline, per core, su tutta la popolazione --------------------
    def per_pipe(self, k, key, ids=None, nn=False):
        ids = ids or self.ids
        f = self.nn if nn else self.val
        return {m: summ([f(k, i, m, key) for i in ids]) for m in ALL
                if not (nn and m == "baseline")}

    def ratio(self, k1, k0, key, ids=None, nn=False):
        """k1/k0 modello per modello (stesso modello, due core)."""
        ids = ids or self.ids
        f = self.nn if nn else self.val
        out = {}
        for m in ALL:
            if nn and m == "baseline":
                continue
            v = []
            for i in ids:
                a, b = f(k1, i, m, key), f(k0, i, m, key)
                if a is not None and b:
                    v.append(a / b)
            out[m] = summ(v)
        return out

    def pipe_ratio(self, k, a, b, key="ns"):
        """pipeline a / pipeline b sulla rete neurale, modello per modello."""
        v = []
        for i in self.ids:
            x, y = self.nn(k, i, a, key), self.nn(k, i, b, key)
            if x is not None and y:
                v.append(x / y)
        return summ(v)

    # -- curve al crescere del rate, normalizzate alla capacita' -----------
    def load_curves(self, grid=(0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0)):
        """Per core e pipeline: mediana sui modelli di inoltrati/capacita' a
        offerto/capacita' = grid (interpolazione lineare sulla curva di ogni
        modello). Cosi' le curve di modelli diversi si sovrappongono."""
        out, knees = {}, {}
        for k in ("P", "E"):
            root = os.path.join(self.base, f"carico_{k}core")
            if not os.path.isdir(root):
                continue
            for mid in sorted(os.listdir(root)):
                br = self.c.read_bitrate(os.path.join(root, mid))
                for m in PIPES:
                    cap = self.val(k, mid, m, "mpps")
                    pts = sorted((num(r["rate_requested_pps"]) / 1e6,
                                  (num(r.get("forwarded_pps")) or 0) / 1e6)
                                 for r in br if r.get("method") == m)
                    if not pts or not cap:
                        continue
                    kn, mx, _ = CR.knee(br, m)
                    knees.setdefault(k, []).append(mx / cap)
                    xs = [p[0] / cap for p in pts]
                    ys = [p[1] / cap for p in pts]
                    for g in grid:
                        if g < xs[0] or g > xs[-1]:
                            continue
                        j = next(j for j in range(len(xs)) if xs[j] >= g)
                        if xs[j] == g or j == 0:
                            y = ys[j]
                        else:
                            t = (g - xs[j - 1]) / (xs[j] - xs[j - 1])
                            y = ys[j - 1] + t * (ys[j] - ys[j - 1])
                        out.setdefault((k, m, g), []).append(y)
        curves = {k: {m: [med(out.get((k, m, g), [])) for g in grid]
                      for m in PIPES} for k in ("P", "E")}
        return dict(grid=list(grid), curves=curves,
                    knee_over_cap={k: summ(v) for k, v in knees.items()})

    # -- due core ------------------------------------------------------------
    def two_cores(self):
        out = {}
        for k in ("P", "E"):
            root = os.path.join(self.base, f"core2_{k}core")
            if not os.path.isdir(root):
                continue
            one, two, pct = {}, {}, {}
            for mid in sorted(os.listdir(root)):
                s = CR.saturation(self.c.read(os.path.join(root, mid),
                                              "compare.csv"))
                for m in ALL:
                    a = self.val(k, mid, m, "mpps")
                    if m in s and a:
                        b = CR.node_mpps(s[m])
                        one.setdefault(m, []).append(a)
                        two.setdefault(m, []).append(b)
                        pct.setdefault(m, []).append(b / a / 2 * 100)
            out[k] = dict(one={m: med(v) for m, v in one.items()},
                          two={m: med(v) for m, v in two.items()},
                          pct={m: summ(v) for m, v in pct.items()},
                          pct_all=summ([x for v in pct.values() for x in v]),
                          n=len(os.listdir(root)))
        return out

    # -- tre orologi ---------------------------------------------------------
    def clocks(self):
        """T2-T1 (programma intero, baseline compresa) e T3-T2 minimi:
        mediana sui modelli. E il rapporto traffico leggero / nodo saturo
        della sola rete."""
        prog, xport, light, minavg = {}, {}, {}, {}
        for k in ("P", "E"):
            for m in ALL:
                prog[(k, m)] = summ([self.c.t2.get((k, i), {}).get(m, (None,))[0]
                                     for i in self.ids])
                xport[(k, m)] = summ([self.c.xport.get((k, i), {}).get(
                    m, (None,))[0] for i in self.ids])
                if m == "baseline":
                    continue
                v, w = [], []
                for i in self.ids:
                    a, s = self.c.nn_t2(k, i, m), self.nn(k, i, m)
                    if a is not None and s:
                        v.append(a / s)
                    lo, av = self.c.nn_t2(k, i, m, 0), self.c.nn_t2(k, i, m)
                    if lo is not None and av:
                        w.append(lo / av)
                light[(k, m)] = summ(v)
                minavg[(k, m)] = summ(w)
        return dict(prog=prog, xport=xport, light=light, minavg=minavg)

    # -- taglie, classi, TTL misti ------------------------------------------
    def frames(self):
        root = os.path.join(self.base, "taglie")
        by, var = {}, []
        for mid in sorted(os.listdir(root)):
            rows = [r for r in self.c.read(os.path.join(root, mid),
                                           "compare.csv")
                    if r.get("phase") == "saturazione"]
            for m in ALL:
                v = {}
                for r in rows:
                    if r["method"] == m and num(r.get("ns_cpu")):
                        v[int(num(r["frame"]))] = num(r["ns_cpu"])
                for f, x in v.items():
                    by.setdefault((m, f), []).append(x)
                if len(v) >= 2:
                    var.append((max(v.values()) / min(v.values()) - 1) * 100)
        sizes = sorted({f for _, f in by})
        return dict(sizes=sizes,
                    ns={f: {m: med(by.get((m, f), [])) for m in ALL}
                        for f in sizes},
                    var=summ(var), n=len(os.listdir(root)))

    def classes(self):
        root = os.path.join(self.base, "classi")
        fw, dr, spread, extra = {}, {}, [], []
        for mid in sorted(os.listdir(root)):
            pc = [r for r in self.c.read(os.path.join(root, mid),
                                         "per_class.csv")
                  if r.get("phase") == "saturazione"]
            for m in ALL:
                f = [num(r["ns_cpu"]) for r in pc if r["method"] == m
                     and r.get("scenario_action") == "FORWARD"
                     and num(r.get("ns_cpu"))]
                d = [num(r["ns_cpu"]) for r in pc if r["method"] == m
                     and r.get("scenario_action") == "DROP"
                     and num(r.get("ns_cpu"))]
                if f:
                    fw.setdefault(m, []).append(st.median(f))
                    if m != "baseline":
                        spread.append((max(f) / min(f) - 1) * 100)
                if f and d:
                    dr.setdefault(m, []).append(st.median(d))
                    if m != "baseline":
                        extra.append(st.median(d) - st.median(f))
        return dict(fwd={m: med(v) for m, v in fw.items()},
                    drop={m: med(v) for m, v in dr.items()},
                    spread=summ(spread), extra=summ(extra),
                    n=len(os.listdir(root)))

    def mix(self):
        root = os.path.join(self.base, "mix")
        rel = []
        for mid in sorted(os.listdir(root)):
            s = CR.saturation(self.c.read(os.path.join(root, mid),
                                          "compare.csv"))
            for m in PIPES:
                fixed = self.val("P", mid, m, "ns")
                if m in s and fixed:
                    rel.append((num(s[m].get("ns_cpu")) / fixed - 1) * 100)
        return dict(rel=summ(rel), n=len(os.listdir(root)))

    # -- la forma: profondita', larghezza, pari pesi, sparsita' -------------
    def by_group(self, k, key, group, ids, nn=True, stat=None):
        """{pipeline: {valore del gruppo: mediana}} sui modelli `ids`."""
        out = {}
        for m in (PIPES if nn else ALL):
            g = {}
            for i in ids:
                v = stat(k, i, m) if stat else (self.nn(k, i, m, key) if nn
                                                else self.val(k, i, m, key))
                if v is not None:
                    g.setdefault(int(num(self.m(i, group))), []).append(v)
            out[m] = {x: med(v) for x, v in sorted(g.items())}
        return out

    def laws(self):
        """Le leggi di population_report: a + b*MAC eseguite + c*strati."""
        out = {}
        for k in ("P", "E"):
            for key in ("ns", "instr"):
                _, laws = PR._fit_rows(self.c, k, key, families=DENSE)
                for m, d in laws.items():
                    lab = "MAC eseguite + strati"
                    if lab in d:
                        beta, r2, e50, n = d[lab]
                        shape = d.get("MAC dalla forma + strati")
                        out[(k, key, m)] = dict(
                            a=beta[0], b=beta[1], c=beta[2], r2=r2, err50=e50,
                            n=n, r2_shape=shape[1] if shape else None)

        def loaded(k, i, m, key):
            return self.c.size.get(i, {}).get(m)
        _, laws = PR._fit_rows(self.c, None, None, stat=loaded,
                               families=DENSE)
        for m, d in laws.items():
            beta, r2, e50, n = d["MAC eseguite + strati"]
            out[("size", m)] = dict(a=beta[0], b=beta[1], c=beta[2], r2=r2,
                                    n=n)
        return out

    def law_shares(self, laws):
        """Quanto pesa ogni termine della legge sul costo previsto, modello
        per modello (modelli densi, P-core): {pipeline: (fisso, MAC, strati)}
        come summ() di frazioni. Dice dove va il tempo: nell'aritmetica (b)
        o nella struttura, cioe' tail call e letture di tabella (a, c)."""
        out = {}
        for m in PIPES:
            law = laws.get(("P", "ns", m))
            if not law:
                continue
            fa, fb, fc = [], [], []
            for i in self.ids_of(DENSE):
                if self.nn("P", i, m) is None:
                    continue
                mac = num(self.m(i, "mac_exec"))
                nl = num(self.m(i, "n_layers"))
                tot = self.predict(law, i)
                fa.append(law["a"] / tot)
                fb.append(law["b"] * mac / tot)
                fc.append(law["c"] * nl / tot)
            out[m] = (summ(fa), summ(fb), summ(fc))
        return out

    def predict(self, law, i):
        return (law["a"] + law["b"] * num(self.m(i, "mac_exec"))
                + law["c"] * num(self.m(i, "n_layers")))

    def nodes(self, laws):
        """Slide 19: costo misurato meno la legge, per numero di nodi della
        rete (one-hot dell'identita' del nodo). Solo le composizioni che
        hanno la feature del nodo. E la pendenza in ns per nodo."""
        import model_population as MP
        n_nodes = {}
        for lay, (fs, topo) in MP.LAYOUTS.items():
            feats = fs().features
            if any(f.name == "node" for f in feats):
                n_nodes[lay] = topo["n_nodes"]
        res, slope = {}, {}
        ids = [i for i in self.ids_of(DENSE) if self.m(i, "layout") in n_nodes]
        for m in PIPES:
            law = laws.get(("P", "ns", m))
            pts = []
            for i in ids:
                y = self.nn("P", i, m)
                if y is None or not law:
                    continue
                pts.append((n_nodes[self.m(i, "layout")],
                            y - self.predict(law, i)))
            g = {}
            for x, r in pts:
                g.setdefault(x, []).append(r)
            res[m] = {x: med(v) for x, v in sorted(g.items())}
            if len(pts) > 3:
                f = CR._fit([p[0] for p in pts], [p[1] for p in pts])
                slope[m] = f[0]
        return dict(sizes=sorted(set(n_nodes.values())), residual=res,
                    ns_per_node=slope, n=len(ids))

    def sparsity(self, laws):
        """Slide 23: misurato / previsto dalla legge densa, per frazione di
        pesi a zero; e la dimensione caricata contro il gemello denso."""
        out, size = {}, {}
        for m in PIPES:
            law = laws.get(("P", "ns", m))
            g = {}
            for i in self.ids:
                y = self.nn("P", i, m)
                if y is None or not law:
                    continue
                sp = round(num(self.m(i, "sparsity")) or 0, 1)
                if self.m(i, "family") not in ("sparsita",) + DENSE:
                    continue
                g.setdefault(sp, []).append(y / self.predict(law, i))
            out[m] = {x: summ(v) for x, v in sorted(g.items())}
        # dimensione: modello sparso contro il modello denso con la stessa
        # forma e composizione (famiglia base o replica)
        for i in self.ids_of(("sparsita",)):
            twin = [j for j in self.ids_of(("base", "replica"))
                    if self.m(j, "shape") == self.m(i, "shape")
                    and self.m(j, "layout") == self.m(i, "layout")]
            if not twin:
                continue
            sp = round(num(self.m(i, "sparsity")), 1)
            for m in PIPES:
                a = self.c.size.get(i, {}).get(m)
                b = med([self.c.size.get(j, {}).get(m) for j in twin])
                if a and b:
                    size.setdefault((m, sp), []).append(a / b)
        return dict(ratio=out,
                    size={f"{m}@{sp}": summ(v) for (m, sp), v in size.items()})

    def isoparam(self):
        ids = self.ids_of(("imbuto",))
        res = {k: self.by_group(k, "ns", "depth", ids) for k in ("P", "E")}
        slopes = {}
        for m in PIPES:
            for lay in sorted({self.m(i, "layout") for i in ids}):
                pts = [(int(num(self.m(i, "depth"))), self.nn("P", i, m))
                       for i in ids if self.m(i, "layout") == lay]
                pts = [p for p in pts if p[1] is not None]
                if len(pts) >= 3:
                    slopes.setdefault(m, []).append(
                        CR._fit([p[0] for p in pts], [p[1] for p in pts])[0])
        rise = {}
        for m in PIPES:
            v = []
            for lay in sorted({self.m(i, "layout") for i in ids}):
                d = {int(num(self.m(i, "depth"))): self.nn("P", i, m)
                     for i in ids if self.m(i, "layout") == lay}
                if d.get(1) and d.get(5):
                    v.append((d[5] / d[1] - 1) * 100)
            rise[m] = summ(v)
        return dict(nn=res, slope={m: summ(v) for m, v in slopes.items()},
                    rise=rise, n=len(ids),
                    total={k: self.by_group(k, "ns", "depth", ids, nn=False)
                           for k in ("P", "E")})

    def replicas(self):
        groups = {}
        for i in self.ids:
            g = self.m(i, "group")
            if g:
                groups.setdefault(g, []).append(i)
        out = {}
        for m in PIPES:
            v = []
            for ids in groups.values():
                x = clean([self.nn("P", i, m) for i in ids])
                if len(x) >= 2:
                    v.append((max(x) / min(x) - 1) * 100)
            out[m] = summ(v)
        return dict(spread=out, groups=len(groups))

    # -- il programma da solo, il cambio di modello (bench_solo.py) ----------
    def solo(self):
        """Letture di tabella, salti, tempi per installare un modello e per
        compilare, su ogni modello; e la sola rete a nodo saturo divisa per
        quella da sola a chiamate singole. Solo le misure che hanno inoltrato
        (la strada del traffico), come in population_report."""
        rows, comp = {}, {}
        for i in self.ids:
            d = os.path.join(self.base, "solo", i)
            for r in self.c.read(d, "solo.csv"):
                if r.get("esito") == "OK" and (num(r.get("fwd_pct")) or 0) >= 99:
                    rows.setdefault(i, {})[r["method"]] = r
            for r in PR.read_csv(os.path.join(self.base, "compila", i,
                                              "compila.csv")):
                comp.setdefault(r["method"], []).append(
                    num(r["generate_ms"]) + num(r["compile_ms"]))

        def col(m, key):
            return summ([num(rows[i][m].get(key)) for i in rows
                         if m in rows[i]])
        out = {k: {m: col(m, k) for m in ALL}
               for k in ("lookups", "n_tail", "update_ms", "build_ms")}
        out["compile_p1"] = {m: summ(v) for m, v in comp.items()}
        ratio = {}
        for m in PIPES:
            v = []
            for i in rows:
                if m in rows[i] and "baseline" in rows[i]:
                    solo = num(rows[i][m]["lat_ns"]) - \
                        num(rows[i]["baseline"]["lat_ns"])
                    sat = self.nn("P", i, m)
                    if solo and sat is not None:
                        v.append(sat / solo)
            ratio[m] = summ(v)
        out["sat_over_single"] = ratio
        pts = [(num(self.m(i, "n_layers")),
                num(rows[i]["modular"]["lookups"]),
                num(rows[i]["modular"]["n_tail"]))
               for i in rows if "modular" in rows[i]]
        if len(pts) > 3:
            out["p3_lookups_per_layer"] = CR._fit([p[0] for p in pts],
                                                  [p[1] for p in pts])[0]
            out["p3_tail_eq_layers"] = (sum(1 for p in pts if p[2] == p[0]),
                                        len(pts))
        out["n"] = len(rows)
        return out

    # -- tutto ---------------------------------------------------------------
    def facts(self):
        laws = self.laws()
        dense = self.ids_of(DENSE)
        f = dict(
            n_models=len(self.ids),
            families={fam: len(self.ids_of((fam,)))
                      for fam in ("base", "replica", "sparsita", "imbuto")},
            ranges={k: rng([num(self.m(i, k)) for i in self.ids])
                    for k in ("n_in", "depth", "width_max", "n_out",
                              "weights", "mac_exec")},
            excluded=len(self.c.excluded), seen=len(self.c.seen),
            ref=self.reference(),
            ns={k: self.per_pipe(k, "ns") for k in ("P", "E")},
            nn={k: self.per_pipe(k, "ns", nn=True) for k in ("P", "E")},
            mpps={k: self.per_pipe(k, "mpps") for k in ("P", "E")},
            instr={k: self.per_pipe(k, "instr") for k in ("P", "E")},
            nn_instr=self.per_pipe("P", "instr", nn=True),
            cycles={k: self.per_pipe(k, "cycles") for k in ("P", "E")},
            nn_cycles={k: self.per_pipe(k, "cycles", nn=True)
                       for k in ("P", "E")},
            ipc={k: self.per_pipe(k, "ipc") for k in ("P", "E")},
            loaded={m: summ([self.c.size.get(i, {}).get(m) for i in self.ids])
                    for m in ALL},
            cap_E_P=self.ratio("E", "P", "mpps"),
            cycles_E_P=self.ratio("E", "P", "cycles"),
            nn_cycles_E_P=self.ratio("E", "P", "cycles", nn=True),
            instr_E_P=self.ratio("E", "P", "instr"),
            ipc_E_P=self.ratio("E", "P", "ipc"),
            order=None,
            p2_over_p1=self.pipe_ratio("P", "template", "p1_static"),
            p3_over_p1=self.pipe_ratio("P", "modular", "p1_static"),
            p3_over_p2=self.pipe_ratio("P", "modular", "template"),
            p15_over_p1=self.pipe_ratio("P", "hardcoded", "p1_static"),
        )
        lpe = [i for i in self.ids if ("L", i) in self.c.sat]
        f["lpe"] = dict(
            n=len(lpe),
            mpps={k: self.per_pipe(k, "mpps", ids=lpe) for k in "PEL"},
            ns={k: self.per_pipe(k, "ns", ids=lpe) for k in "PEL"},
            cycles={k: self.per_pipe(k, "cycles", ids=lpe) for k in "PEL"},
            ipc={k: self.per_pipe(k, "ipc", ids=lpe) for k in "PEL"},
            llc={k: self.per_pipe(k, "llc", ids=lpe) for k in "PEL"},
            cap_L_P=self.ratio("L", "P", "mpps", ids=lpe),
            instr_L_P=self.ratio("L", "P", "instr", ids=lpe))
        f["load"] = self.load_curves()
        f["two"] = self.two_cores()
        f["clocks"] = self.clocks()
        f["frames"] = self.frames()
        f["classes"] = self.classes()
        f["mix"] = self.mix()
        f["laws"] = laws
        f["depth"] = {k: self.by_group(k, "ns", "depth", dense)
                      for k in ("P", "E")}
        f["depth_total"] = {k: self.by_group(k, "ns", "depth", dense, nn=False)
                            for k in ("P", "E")}
        f["depth_instr"] = self.by_group("P", "instr", "depth", dense,
                                         nn=False)
        f["depth_size"] = self.by_group(
            "P", None, "depth", dense,
            stat=lambda k, i, m: self.c.size.get(i, {}).get(m))
        f["width"] = {k: self.by_group(k, "ns", "width_max", dense)
                      for k in ("P", "E")}
        f["width_total"] = {k: self.by_group(k, "ns", "width_max", dense,
                                             nn=False) for k in ("P", "E")}
        # la sola rete a traffico leggero, minimo e media di T2-T1
        light = {}
        for which, lab in ((0, "min"), (1, "avg")):
            light[lab] = self.by_group(
                "P", None, "depth", dense,
                stat=lambda k, i, m, w=which: self.c.nn_t2(k, i, m, w))
        f["depth_light"] = light
        f["law_shares"] = self.law_shares(laws)
        f["solo"] = self.solo()
        f["nodes"] = self.nodes(laws)
        f["sparsity"] = self.sparsity(laws)
        f["isoparam"] = self.isoparam()
        f["replicas"] = self.replicas()
        order = []
        for i in self.ids:
            v = [self.nn("P", i, m) for m in ("p1_static", "template",
                                              "modular")]
            if all(x is not None for x in v):
                order.append(v[0] <= v[1] <= v[2])
        f["order"] = (sum(order), len(order))
        both = []
        for i in self.ids:
            s = self.c.size.get(i, {})
            a, b = self.nn("P", i, "template", "instr"), \
                self.nn("P", i, "modular", "instr")
            if s.get("template") and s.get("modular") and a and b:
                both.append(s["template"] > s["modular"] and b > a)
        f["p2_bigger_p3_works"] = (sum(both), len(both))
        return f


# --------------------------------------------------------------------------
# JSON: le chiavi tuple diventano stringhe
# --------------------------------------------------------------------------
def _jsonable(o):
    if isinstance(o, dict):
        return {("|".join(map(str, k)) if isinstance(k, tuple) else str(k)):
                _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonable(v) for v in o]
    if isinstance(o, float):
        return round(o, 4)
    return o


def main(argv):
    if not argv:
        sys.exit(__doc__.split("\n\n")[1])
    pop = Pop(argv[0])
    facts = pop.facts()
    if "--pptx" in argv:
        import popolazione_pptx as PX
        PX.build(pop, facts)
    else:
        print(json.dumps(_jsonable(facts), indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1:])
