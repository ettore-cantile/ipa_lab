#!/usr/bin/env python3
"""report_population_facts.py -- the summary figures of a population campaign.

    python3 ipa/test/report_population_facts.py results/popolazione_2026-10            # figures, JSON
    python3 ipa/test/report_population_facts.py results/popolazione_2026-10 --figura   # the cost-law chart

Medians, ranges and laws over the population (same exclusions as
report_population.py); --figura redraws docs/figures/popolazione_legge.pdf.
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
FIGURE = os.path.join(ROOT, "docs", "figures", "popolazione_legge.pdf")

import report_population as PR  # noqa: E402
import table_helpers as CR  # noqa: E402

PIPES = PR.PIPES
ALL = ("baseline",) + PIPES
LAB = {"rxonly": "receive only", "baseline": "baseline",
       "p1_static": "P1 static", "hardcoded": "P1.5", "template": "P2",
       "modular": "P3"}
SHORT = {"baseline": "baseline", "p1_static": "P1", "hardcoded": "P1.5",
         "template": "P2", "modular": "P3"}
DENSE = ("base", "replica", "imbuto")


# --- statistics ---
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
    """{'n', 'med', 'min', 'max'} of a list."""
    xs = clean(xs)
    if not xs:
        return None
    return dict(n=len(xs), med=st.median(xs), min=min(xs), max=max(xs))


def num(v):
    return PR.num(v)


# --- the figures ---
class Pop:
    def __init__(self, base):
        self.c = PR.Campaign(base)
        if not self.c.models:
            sys.exit(f"{base}: no population")
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

    def per_pipe(self, k, key, ids=None, nn=False):
        ids = ids or self.ids
        f = self.nn if nn else self.val
        return {m: summ([f(k, i, m, key) for i in ids]) for m in ALL
                if not (nn and m == "baseline")}

    def ratio(self, k1, k0, key, ids=None, nn=False):
        """k1/k0 model by model (same model, two cores)."""
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
        """pipeline a / pipeline b on the neural network, model by model."""
        v = []
        for i in self.ids:
            x, y = self.nn(k, i, a, key), self.nn(k, i, b, key)
            if x is not None and y:
                v.append(x / y)
        return summ(v)

    def load_curves(self, grid=(0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0)):
        """Per core and pipeline."""
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

    def load_examples(self, k="P"):
        """Three models of the load test -- the lightest, the middle one and
        the heaviest by P3 cost -- with the measured curves (offered,
        forwarded, in million packets/s) and the capacity measured
        separately, per pipeline."""
        root = os.path.join(self.base, f"carico_{k}core")
        mids = [i for i in sorted(os.listdir(root))
                if self.nn(k, i, "modular") is not None]
        mids.sort(key=lambda i: self.nn(k, i, "modular"))
        out = []
        for mid in (mids[0], mids[(len(mids) - 1) // 2], mids[-1]):
            br = self.c.read_bitrate(os.path.join(root, mid))
            pts, caps = {}, {}
            for m in PIPES:
                pts[m] = sorted((num(r["rate_requested_pps"]) / 1e6,
                                 (num(r.get("forwarded_pps")) or 0) / 1e6)
                                for r in br if r.get("method") == m)
                caps[m] = self.val(k, mid, m, "mpps")
            out.append(dict(id=mid, shape=self.m(mid, "shape"),
                            layers=int(num(self.m(mid, "depth"))),
                            mac=num(self.m(mid, "mac_exec")),
                            p3_ns=self.nn(k, mid, "modular"),
                            pts=pts, caps=caps))
        return out

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

    def clocks(self):
        """Minimum T2-T1 (whole program, baseline included) and T3-T2."""
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

    def by_group(self, k, key, group, ids, nn=True, stat=None):
        """{pipeline: {group value: median}} over the models `ids`."""
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

    def strati(self, laws):
        """The "strati" family (model_population.py): 1 to 6 hidden layers at
        constant multiplications on three input layouts. Raw measurements,
        median of the three layouts per depth (instructions per packet do not
        depend on the core: where the P-core measurement is excluded the
        E-core one is used). Then the cost of a layer following the code
        (fixed per layer, per neuron of the layers after the first) and the
        error of the law on these models, which the law has not seen."""
        ids = self.ids_of(("strati",))
        if not ids:
            return None
        depths = sorted({int(num(self.m(i, "depth"))) for i in ids})
        lays = sorted({self.m(i, "layout") for i in ids})

        def instr(i, m):
            return self.val("P", i, m, "instr") or self.val("E", i, m, "instr")

        def table(get):
            out = {}
            for m in PIPES:
                g = {}
                for i in ids:
                    v = get(i, m)
                    if v is not None:
                        g.setdefault(int(num(self.m(i, "depth"))), []).append(v)
                out[m] = {d: med(v) for d, v in sorted(g.items())}
            return out

        def step(get, m):
            """Mean rise per layer, layout by layout."""
            st_ = []
            for lay in lays:
                byd = {int(num(self.m(i, "depth"))): get(i, m) for i in ids
                       if self.m(i, "layout") == lay}
                lo, hi = byd.get(depths[0]), byd.get(depths[-1])
                if lo and hi:
                    st_.append((hi - lo) / (depths[-1] - depths[0]))
            return summ(st_)
        ins = table(instr)
        ns = {k: table(lambda i, m, k=k: self.nn(k, i, m)) for k in ("P", "E")}
        steps = {m: step(instr, m) for m in PIPES}
        steps_ns = {k: {m: step(lambda i, m_, k=k: self.nn(k, i, m_), m)
                        for m in ("template", "modular")} for k in ("P", "E")}
        macs = [num(self.m(i, "mac_exec")) for i in ids]
        import numpy as np
        fit_ids = self.ids_of(DENSE + ("strati",))

        def shape_terms(i):
            hid = [int(x) for x in self.m(i, "hidden").split("-")]
            n_out = int(num(self.m(i, "n_out")))
            later = list(zip(hid, hid[1:] + [n_out]))
            mac = num(self.m(i, "mac_exec"))
            mac_later = sum(a * b for a, b in later)
            return [mac - mac_later, mac_later, len(hid) + 1, hid[0],
                    sum(b for _, b in later)]
        all_lays = sorted({self.m(i, "layout") for i in fit_ids})
        code = {}
        for m in ("template", "modular"):
            rows = [(i, instr(i, m)) for i in fit_ids]
            rows = [(i, v) for i, v in rows if v]
            X = np.array([[1.0] + [1.0 if self.m(i, "layout") == l_ else 0.0
                                   for l_ in all_lays[1:]] + shape_terms(i)
                          for i, _ in rows])
            y = np.array([v for _, v in rows])
            beta = np.linalg.lstsq(X, y, rcond=None)[0]
            errs = []
            for k in range(len(y)):
                keep = np.arange(len(y)) != k
                b = np.linalg.lstsq(X[keep], y[keep], rcond=None)[0]
                errs.append(abs(X[k] @ b - y[k]) / y[k] * 100)
            code[m] = dict(per_layer=beta[-3], per_neuron=beta[-1],
                           per_mac_later=beta[-4], n=len(y),
                           err50=med(errs))
        law_err = {}
        for k in ("P", "E"):
            for m in PIPES:
                law = laws.get((k, "ns", m))
                e = [abs(self.predict(law, i) / self.nn(k, i, m) - 1) * 100
                     for i in ids if law and self.nn(k, i, m)]
                law_err[(k, m)] = summ(e)
        return dict(ids=ids, n=len(ids), depths=depths, layouts=lays,
                    instr=ins, ns=ns, step=steps, step_ns=steps_ns,
                    mac=(min(macs), max(macs)), code=code, law_err=law_err)

    def laws(self):
        """The laws of report_population."""
        out = {}
        for k in ("P", "E"):
            for key in ("ns", "instr"):
                _, laws = PR._fit_rows(self.c, k, key, families=DENSE)
                for m, d in laws.items():
                    lab = "executed MACs + layers"
                    if lab in d:
                        beta, r2, e50, n = d[lab]
                        shape = d.get("shape MACs + layers")
                        out[(k, key, m)] = dict(
                            a=beta[0], b=beta[1], c=beta[2], r2=r2, err50=e50,
                            n=n, r2_shape=shape[1] if shape else None)

        def loaded(k, i, m, key):
            return self.c.size.get(i, {}).get(m)
        _, laws = PR._fit_rows(self.c, None, None, stat=loaded,
                               families=DENSE)
        for m, d in laws.items():
            beta, r2, e50, n = d["executed MACs + layers"]
            out[("size", m)] = dict(a=beta[0], b=beta[1], c=beta[2], r2=r2,
                                    n=n)
        return out

    def law_shares(self, laws):
        """How much each term of the law weighs on the predicted cost, model
        by model (dense models, P-core)."""
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
        """Measured cost minus the law, per number of network nodes (node
        identity one-hot), only for the layouts that have the node feature;
        and the slope in ns per node."""
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
        """Measured / predicted by the dense law, per fraction of zero
        weights; and the loaded size against the dense twin."""
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
        lays = sorted({self.m(i, "layout") for i in ids})
        wts = {lay: [int(num(self.m(i, "weights"))) for i in ids
                     if self.m(i, "layout") == lay] for lay in lays}
        mac_rise = []
        for lay in lays:
            mac = {int(num(self.m(i, "depth"))): num(self.m(i, "mac_exec"))
                   for i in ids if self.m(i, "layout") == lay}
            mac_rise += [mac[d] / mac[1] - 1 for d in mac if d >= 4]
        return dict(nn=res, slope={m: summ(v) for m, v in slopes.items()},
                    rise=rise, n=len(ids),
                    total={k: self.by_group(k, "ns", "depth", ids, nn=False)
                           for k in ("P", "E")},
                    instr=self.by_group("P", "instr", "depth", ids, nn=False),
                    size=self.by_group(
                        "P", None, "depth", ids, nn=False,
                        stat=lambda k, i, m: self.c.size.get(i, {}).get(m)),
                    weights={lay: (min(w), max(w)) for lay, w in wts.items()},
                    mac_rise=(min(mac_rise), max(mac_rise)))

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

    def solo(self):
        """Table lookups, tail calls, times to install a model and to
        compile, on every model."""
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

    def facts(self):
        laws = self.laws()
        dense = self.ids_of(DENSE)
        f = dict(
            n_models=len(self.ids),
            families={fam: len(self.ids_of((fam,)))
                      for fam in ("base", "replica", "sparsita", "imbuto", "strati")},
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
        f["depth_instr"] = self.by_group("P", "instr", "depth", dense,
                                         nn=False)
        f["depth_size"] = self.by_group(
            "P", None, "depth", dense,
            stat=lambda k, i, m: self.c.size.get(i, {}).get(m))
        f["width"] = {k: self.by_group(k, "ns", "width_max", dense)
                      for k in ("P", "E")}
        f["width_total"] = {k: self.by_group(k, "ns", "width_max", dense,
                                             nn=False) for k in ("P", "E")}
        light = {}
        for which, lab in ((0, "min"), (1, "avg")):
            light[lab] = self.by_group(
                "P", None, "depth", dense,
                stat=lambda k, i, m, w=which: self.c.nn_t2(k, i, m, w))
        f["depth_light"] = light
        f["law_shares"] = self.law_shares(laws)
        nz = PR.noise(self.c)
        f["noise"] = dict(
            same_med=PR.quant(nz["same"], .5), same_p90=PR.quant(nz["same"], .9),
            same_max=max(nz["same"]) if nz["same"] else None,
            within_med=PR.quant(nz["within"], .5),
            base_P_max=max(nz["base"].get("P", [0])))
        f["solo"] = self.solo()
        f["nodes"] = self.nodes(laws)
        f["sparsity"] = self.sparsity(laws)
        f["isoparam"] = self.isoparam()
        f["strati"] = self.strati(laws)
        f["load_examples"] = self.load_examples()
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


# --- cost-law figure (docs/figures/popolazione_legge.pdf) ---
COLOR = {"p1_static": "#C8551E", "hardcoded": "#F09A3E",
         "template": "#2E9C8F", "modular": "#1F5F8B"}


def it(x, d=0):
    """1234.5 -> '1 234,5' (space for thousands, decimal comma)."""
    s = f"{x:,.{d}f}"
    return s.replace(",", " ").replace(".", ",")


def law_figure(pop, facts, path):
    """Network cost minus c x layers against executed MACs, one point per
    dense model."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ink, ink2, grid = "#222B36", "#5B6676", "#E3E7EC"
    marker = {"p1_static": "o", "hardcoded": "s", "template": "D",
              "modular": "^"}
    name = {"p1_static": "P1 static", "hardcoded": "P1.5", "template": "P2",
            "modular": "P3"}
    fig, ax = plt.subplots(figsize=(6.4, 4.0), dpi=200)
    ax.set_facecolor("white")
    ids = pop.ids_of(DENSE)
    xmax = max(num(pop.m(i, "mac_exec")) for i in ids)
    for m in PIPES:
        law = facts["laws"][("P", "ns", m)]
        xs, ys = [], []
        for i in ids:
            y = pop.nn("P", i, m)
            if y is None:
                continue
            xs.append(num(pop.m(i, "mac_exec")))
            ys.append(y - law["c"] * num(pop.m(i, "n_layers")))
        ax.scatter(xs, ys, s=16, marker=marker[m], color=COLOR[m],
                   alpha=0.75, linewidths=0.6, edgecolors="white",
                   label=f"{name[m]}: {it(law['b'], 2)} ns per "
                         f"multiplication", zorder=3)
        ax.plot([0, xmax * 1.03], [law["a"], law["a"] + law["b"] * xmax * 1.03],
                color=COLOR[m], linewidth=2, zorder=2)
        dy = {"hardcoded": 9, "p1_static": -9}.get(m, 0)
        ax.annotate(name[m], (xmax * 1.035,
                              law["a"] + law["b"] * xmax * 1.03 + dy),
                    color=ink, fontsize=8, va="center")
    ax.set_xlim(0, xmax * 1.16)
    ax.set_ylim(bottom=0)
    ax.set_xlabel("multiplications executed per packet", color=ink2,
                  fontsize=8)
    ax.set_ylabel("ns of neural network, minus the per-layer part", color=ink2,
                  fontsize=8)
    ax.grid(True, color=grid, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(grid)
    ax.tick_params(colors=ink2, labelsize=7)
    ax.legend(fontsize=8, frameon=False, loc="upper left",
              labelcolor=ink, markerscale=1.4)
    fig.tight_layout()
    fig.savefig(path, facecolor="white")
    plt.close(fig)


# --- JSON: tuple keys become strings ---
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
    if "--figura" in argv:
        law_figure(pop, facts, FIGURE)
    else:
        print(json.dumps(_jsonable(facts), indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1:])
