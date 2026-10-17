#!/usr/bin/env python3
"""report_population.py -- the conclusions of a population campaign, in markdown.

Every row is a range over the models, a cost law fitted on all of them, or a
claim with the number of models it holds on. Measurements disturbed by the
machine are left out (or kept without the disturbed rounds).

    python3 ipa/test/report_population.py results/popolazione_2026-10 > sintesi.md
"""
import csv
import json
import math
import os
import re
import statistics as st
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_SHARED = os.path.dirname(_TEST_DIR)
for _p in (_SHARED, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import table_helpers as CR  # noqa: E402

PIPES = ("p1_static", "hardcoded", "template", "modular")
NAME = CR.NAME
CORE_LABEL = {"P": "P-core", "E": "E-core", "L": "LP E-core"}
HOT_MIN_K = 10
MIN_CLEAN_ROUNDS = 2
read_csv, num, fmt, table = CR.read_csv, CR.num, CR.fmt, CR.table


# --- statistics without dependencies ---
def quant(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    pos = q * (len(xs) - 1)
    lo, hi = int(math.floor(pos)), int(math.ceil(pos))
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def spread(xs, spec=".0f"):
    """'median [min–max]'."""
    xs = [x for x in xs if x is not None]
    if not xs:
        return "-"
    return (f"{format(st.median(xs), spec)} "
            f"[{format(min(xs), spec)}–{format(max(xs), spec)}]")


def five(xs, spec=".0f"):
    xs = [x for x in xs if x is not None]
    if not xs:
        return ["-"] * 6
    return [str(len(xs))] + [format(quant(xs, q), spec)
                             for q in (0, .1, .5, .9, 1)]


def _rank(xs):
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    r = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        for k in range(i, j + 1):
            r[order[k]] = (i + j) / 2.0
        i = j + 1
    return r


def pearson(xs, ys):
    n = len(xs)
    if n < 3:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if not sx or not sy:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy)


def spearman(xs, ys):
    return pearson(_rank(xs), _rank(ys)) if len(xs) >= 3 else None


def ols(X, y):
    """Least squares with intercept."""
    n, k = len(X), (len(X[0]) if X else 0) + 1
    if n <= k:
        return None
    A = [[1.0] + [float(v) for v in row] for row in X]
    M = [[sum(A[r][i] * A[r][j] for r in range(n)) for j in range(k)]
         + [sum(A[r][i] * y[r] for r in range(n))] for i in range(k)]
    for c in range(k):
        p = max(range(c, k), key=lambda r: abs(M[r][c]))
        if abs(M[p][c]) < 1e-12:
            return None
        M[c], M[p] = M[p], M[c]
        for r in range(k):
            if r != c:
                f = M[r][c] / M[c][c]
                for j in range(c, k + 1):
                    M[r][j] -= f * M[c][j]
    beta = [M[i][k] / M[i][i] for i in range(k)]
    pred = [sum(b * a for b, a in zip(beta, row)) for row in A]
    my = sum(y) / n
    ss_tot = sum((v - my) ** 2 for v in y)
    ss_res = sum((v - p) ** 2 for v, p in zip(y, pred))
    return beta, (1 - ss_res / ss_tot) if ss_tot else 1.0


def predict(beta, row):
    return beta[0] + sum(b * float(v) for b, v in zip(beta[1:], row))


def loo_error(X, y):
    """Median and 90th-percentile relative error (%) on models left out of
    the fit, one at a time."""
    errs = []
    for i in range(len(X)):
        f = ols(X[:i] + X[i + 1:], y[:i] + y[i + 1:])
        if f is None or not y[i]:
            continue
        errs.append(abs(predict(f[0], X[i]) - y[i]) / abs(y[i]) * 100)
    return (st.median(errs), quant(errs, .9)) if errs else (None, None)


def count(pred_list):
    """'k/n' of a list of booleans (None = not decidable, left out)."""
    v = [p for p in pred_list if p is not None]
    return f"{sum(v)}/{len(v)}" if v else "-"


# --- reading ---
def unusable(d):
    """Why the measurement in folder `d` is left out of the conclusions, or
    None."""
    try:
        with open(os.path.join(d, "throughput_report.md"),
                  encoding="utf-8") as f:
            if "RUN BOCCIATO" in f.read():
                return "rejected"
    except OSError:
        pass
    try:
        with open(os.path.join(d, "env.csv"), encoding="utf-8") as f:
            if any(ln.strip() == "run_disturbed,True" for ln in f):
                return "disturbed"
    except OSError:
        pass
    return None


COMPARE_DRAIN_S = 0.05
EVENT_MARGIN_S = 1.0


def _throttle_events(d, day):
    """The [start, end] intervals (epoch seconds) in which the machine log saw
    throttling, or None if the disturbance was not only throttling."""
    import datetime as dt
    env = {}
    for r in csv.reader(open(os.path.join(d, "env.csv"), encoding="utf-8")):
        if len(r) >= 2:
            env[r[0]] = r[1]
    if num(env.get("run_powerclamp")) or num(env.get("run_smi")):
        return None
    m = re.search(r"(\d+)-\1 MHz", env.get("frequenza_banco", ""))
    mhz = num(env.get("run_dut_mhz"))
    if not m or not mhz or abs(mhz - int(m.group(1))) > 0.05 * int(m.group(1)):
        return None
    log = read_csv(os.path.join(d, "host_monitor.csv"))
    if len(log) < 2:
        return None
    if any(r.get("alimentazione_rete") not in ("1", "True", "") or
           num(r.get("powerclamp")) or num(r.get("raffreddamento_cpu"))
           for r in log):
        return None
    h, mi, se = (int(x) for x in log[0]["tempo"].split(":"))
    t0 = dt.datetime.combine(day, dt.time(h, mi, se)).timestamp() \
        - num(log[0]["t_s"])
    out = []
    for a, b in zip(log, log[1:]):
        if any((num(b.get(k)) or 0) > (num(a.get(k)) or 0)
               for k in ("throttle_core", "throttle_pacchetto")):
            out.append((t0 + num(a["t_s"]) - EVENT_MARGIN_S,
                        t0 + num(b["t_s"]) + 1.0 + EVENT_MARGIN_S))
    return out


def salvage_compare(d):
    """(compare.csv rows recomputed from the clean rounds of compare_raw.csv
    only, those rounds, (rounds removed, rounds))."""
    import datetime as dt
    raw = read_csv(os.path.join(d, "compare_raw.csv"))
    rows = read_csv(os.path.join(d, "compare.csv"))
    if not raw or not rows or not raw[0].get("t_wall"):
        return None
    day = dt.date.fromtimestamp(num(raw[0]["t_wall"]))
    ev = _throttle_events(d, day)
    if not ev:
        return None

    def hit(r):
        end = num(r["t_wall"]) - COMPARE_DRAIN_S
        start = end - num(r.get("secs"))
        return any(start <= b and end >= a for a, b in ev)
    clean = [r for r in raw if not hit(r)]
    key = lambda r: (r["method"], r["frame"], r.get("phase"))  # noqa: E731
    out = []
    for row in rows:
        pts = [r for r in clean if key(r) == key(row)]
        if len(pts) < MIN_CLEAN_ROUNDS:
            return None
        new = dict(row, rounds=str(len(pts)))
        for k in row:
            if k in ("method", "frame", "phase", "rounds") or k not in pts[0]:
                continue
            vals = [num(r[k]) for r in pts if num(r.get(k)) is not None]
            if vals and num(row[k]) is not None:
                new[k] = str(max(vals) if k == "loss_worst"
                             else st.median(vals))
        out.append(new)
    return out, clean, (len(raw) - len(clean), len(raw))


class Campaign:
    """Everything the report uses, indexed by model."""

    def __init__(self, base):
        self.base = base
        self.seen = set()
        self.excluded = {}
        self.salvaged = {}
        self.models = {}
        self.core_dir = {}
        man = os.path.join(base, "population.csv")
        if os.path.exists(man):
            for r in read_csv(man):
                self.models[r["id"]] = r
            for k in ("P", "E"):
                d = os.path.join(base, f"pop_{k}core")
                if os.path.isdir(d):
                    self.core_dir[k] = d
        self.sat = {}
        self.size = {}
        self.t2 = {}
        self.xport = {}
        for k, d in self.core_dir.items():
            for mid in self.models:
                sub = os.path.join(d, mid)
                s = CR.saturation(self.read(sub, "compare.csv"))
                if s:
                    self.sat[(k, mid)] = s
                ps = read_csv(os.path.join(sub, "prog_size.csv"))
                if ps and mid not in self.size:
                    self.size[mid] = {r["method"]: num(r["xlated_insns"])
                                      for r in ps}
                t, x = self._t2(os.path.join(sub, "rates"))
                if t:
                    self.t2[(k, mid)] = t
                if x:
                    self.xport[(k, mid)] = x
        lpe = os.path.join(base, "lpe")
        for mid in self.models:
            s = CR.saturation(self.read(os.path.join(lpe, mid), "compare.csv"))
            if s:
                self.sat[("L", mid)] = s

    def read(self, d, name):
        """The CSV `name` of the measurement in `d`, or [] if the measurement
        is left out of the conclusions (unusable)."""
        if not os.path.exists(os.path.join(d, name)):
            return []
        rel = os.path.relpath(d, self.base)
        self.seen.add(rel)
        why = unusable(d)
        if why == "disturbed" and name in ("compare.csv", "compare_raw.csv"):
            got = salvage_compare(d)
            if got:
                rows, clean, self.salvaged[rel] = got
                return rows if name == "compare.csv" else clean
        if why:
            self.excluded[rel] = why
            return []
        return read_csv(os.path.join(d, name))

    def read_bitrate(self, d):
        """The summary rows of a growing-rate curve."""
        if not os.path.exists(os.path.join(d, "bitrate.csv")):
            return []
        rel = os.path.relpath(d, self.base)
        self.seen.add(rel)
        why = unusable(d)
        if why is None:
            return read_csv(os.path.join(d, "bitrate.csv"))
        raw_path = os.path.join(d, "bitrate_raw.csv")
        if why == "disturbed" and os.path.exists(raw_path):
            import bench_load_curve as BB
            import plot_load_curve as PB
            raw = PB.read_summary(raw_path)
            clean = [r for r in raw if str(r.get("host_disturbed")) != "True"]
            pts = {}
            for r in raw:
                pts.setdefault((r["method"], r["frame"],
                                r["rate_requested_pps"]), 0)
            for r in clean:
                pts[(r["method"], r["frame"], r["rate_requested_pps"])] += 1
            if pts and min(pts.values()) >= MIN_CLEAN_ROUNDS:
                self.salvaged[rel] = (len(raw) - len(clean), len(raw))
                return [{k: str(v) if isinstance(v, bool) else v
                         for k, v in s.items()}
                        for s in BB.summarise(clean)]
        self.excluded[rel] = why
        return []

    def _t2(self, rates_dir):
        rr = self.read(rates_dir, "rates_raw.csv")
        out, xport = {}, {}
        for m in ("baseline",) + PIPES:
            pts = [r for r in rr if r.get("method") == m]
            mins = [num(r.get("pipe_min_ns")) for r in pts
                    if num(r.get("pipe_min_ns"))]
            avgs = [num(r.get("pipe_avg_ns")) for r in pts
                    if num(r.get("pipe_avg_ns"))]
            if mins and avgs:
                out[m] = (st.median(mins), st.median(avgs))
            xmin = [num(r.get("xport_min_ns")) for r in pts
                    if num(r.get("xport_min_ns"))]
            if xmin:
                avg = {}
                for r in pts:
                    v, q = num(r.get("xport_avg_ns")), num(r.get("rate_req_pps"))
                    if v and q:
                        avg.setdefault(q, []).append(v)
                xport[m] = (st.median(xmin),
                            {q: st.median(v) for q, v in avg.items()})
        return out, xport

    def val(self, core, mid, method, key):
        r = self.sat.get((core, mid), {}).get(method)
        if not r:
            return None
        if key == "mpps":
            return CR.node_mpps(r)
        return num(r.get({"ns": "ns_cpu", "instr": "instr_pkt",
                          "cycles": "cycles_pkt", "ipc": "ipc",
                          "llc": "llc_miss_pkt"}.get(key, key)))

    def nn(self, core, mid, method, key="ns"):
        """The neural network part."""
        a = self.val(core, mid, method, key)
        b = self.val(core, mid, "baseline", key)
        return a - b if a is not None and b is not None else None

    def nn_t2(self, core, mid, method, which=1):
        t = self.t2.get((core, mid), {})
        if method in t and "baseline" in t:
            return t[method][which] - t["baseline"][which]
        return None

    def ids(self, core="P", method=None, family=None):
        out = []
        for mid, r in self.models.items():
            if family and r.get("family") not in family:
                continue
            if method and self.val(core, mid, method, "ns") is None:
                continue
            out.append(mid)
        return out

    def identity(self, mid):
        r = self.models[mid]
        return (r.get("shape"), r.get("layout"), str(r.get("seed")),
                r.get("init"), str(r.get("sparsity")))


# --- sections ---
SUMS = []


def claim(text, evidence):
    SUMS.append((text, evidence))


def sec_population(c):
    L = ["## The population", ""]
    ms = list(c.models.values())
    fams = {}
    for r in ms:
        fams[r.get("family", "-")] = fams.get(r.get("family", "-"), 0) + 1
    L.append("By family: " + ", ".join(f"{k} {v}" for k, v in fams.items())
             + ".")
    L.append("")

    def rng(key, spec=".0f"):
        v = [num(r.get(key)) for r in ms if num(r.get(key)) is not None]
        return f"{fmt(min(v), spec)}–{fmt(max(v), spec)}" if v else "-"
    L += [table(["quantity", "range"], [
        ["inputs (n_in)", rng("n_in")], ["hidden layers", rng("depth")],
        ["neurons per layer (max)", rng("width_max")],
        ["outputs", rng("n_out")], ["weights", rng("weights")],
        ["MACs from the shape", rng("mac_shape")],
        ["executed MACs", rng("mac_exec")],
        ["one-hot features", rng("onehot_feat")],
        ["dense columns", rng("dense_cols")],
        ["zero weights (fraction)", rng("zero_frac", ".2f")]]), ""]
    lays = sorted({r.get("layout") for r in ms})
    depths = sorted({int(num(r["depth"])) for r in ms})
    rows = []
    for lay in lays:
        rows.append([lay] + [str(sum(1 for r in ms if r["layout"] == lay
                                     and int(num(r["depth"])) == d))
                             for d in depths])
    L += ["Models per input layout and depth:", "",
          table(["layout"] + [f"{d} layers" for d in depths], rows),
          ""]
    nop2 = [r["id"] for r in ms if r.get("no_template")]
    if nop2:
        L += [f"P2 cannot run {len(nop2)} models out of {len(ms)} "
              f"(MAX_WEIGHT_ENTRIES): {', '.join(nop2)}. The other pipelines "
              f"run them all.", ""]
        claim("P2 has a weight ceiling the other pipelines do not have",
              f"{len(nop2)}/{len(ms)} models outside P2")
    missing = []
    for k in c.core_dir:
        miss = [m for m in c.models if (k, m) not in c.sat]
        if miss:
            missing.append(f"{CORE_LABEL[k]}: {len(miss)} ({', '.join(miss[:12])}"
                           f"{' ...' if len(miss) > 12 else ''})")
    if missing:
        L += ["Models without a full-load measurement (see the logs): "
              + "; ".join(missing) + ".", ""]
    return L


def sec_correct(c):
    rows = read_csv(os.path.join(c.base, "corretto", "corretto.csv"))
    if not rows:
        return []
    out = []
    for p, lab in (("p1", "P1"), ("p2", "P2"), ("p3", "P3")):
        rs = [r for r in rows if r["pipeline"] == p]
        ok = sum(1 for r in rs if r["esito"] == "OK")
        no = [r["id"] for r in rs if r["esito"] == "NO"]
        na = sum(1 for r in rs if r["esito"] == "N/A")
        err = [r["id"] for r in rs if r["esito"] not in ("OK", "NO", "N/A")]
        out.append([lab, str(ok), str(len(no)), str(na), str(len(err)),
                    ", ".join(no + err) or "-"])
        claim(f"{lab} decides exactly like the integer reference",
              f"{ok}/{ok + len(no)} models"
              + (f" ({len(err)} not concluded)" if err else ""))
    return ["## Correctness on every model", "",
            "Integer reference against eBPF (check_kernel_vs_reference, "
            "BPF_PROG_TEST_RUN, 200 inputs per model): it must match "
            "100%. P1.5 is not in this check (check_kernel_vs_reference "
            "tests P1 with the frozen node, P2 and P3).", "",
            table(["pipeline", "OK", "NO", "not applicable", "error",
                   "which"], out), ""]


def sec_reference(c):
    rows = []
    for k in ("P", "E", "L"):
        s = CR.saturation(c.read(os.path.join(c.base, f"rif_{k}core"),
                                  "compare.csv"))
        for m in ("rxonly", "baseline"):
            if m in s:
                r = s[m]
                rows.append([CORE_LABEL[k], m, fmt(CR.node_mpps(r), ".2f"),
                             fmt(num(r.get("ns_cpu"))),
                             fmt(num(r.get("instr_pkt"))),
                             fmt(num(r.get("ipc")), ".2f")])
    if not rows:
        return []
    return ["## The node without a neural network", "",
            "Receiving (rxonly) and receiving + forwarding (baseline) do not "
            "depend on the model: one measurement per core type.", "",
            table(["core", "program", "Mpps", "ns CPU", "ins/pk", "IPC"],
                  rows), ""]


def sec_cost(c):
    L = ["## What the neural network costs, over the whole population", "",
         "ns per packet of the neural network alone: CPU time with the node "
         "saturated minus the baseline of the same run. n = models measured.",
         ""]
    for k in c.core_dir:
        rows = []
        for m in PIPES:
            ids = c.ids(k, m)
            rows.append([NAME[m]] + five([c.nn(k, i, m) for i in ids]))
        L += [f"**{CORE_LABEL[k]}**", "",
              table(["pipeline", "n", "min", "10th", "median", "90th", "max"],
                    rows), ""]
        rows = []
        for m in ("baseline",) + PIPES:
            ids = c.ids(k, m)
            rows.append([NAME[m]] + five([c.val(k, i, m, "mpps")
                                          for i in ids], ".2f"))
        L += [f"Node capacity, million packets per second per core "
              f"({CORE_LABEL[k]}):", "",
              table(["pipeline", "n", "min", "10th", "median", "90th", "max"],
                    rows), ""]
        if k == "P":
            for m in PIPES:
                v = [c.nn(k, i, m) for i in c.ids(k, m)]
                if v:
                    claim(f"neural network {NAME[m]}, ns per packet (P-core)",
                          spread(v))
    return L


def sec_order(c):
    L = ["## Does the order between pipelines hold on every model?", ""]
    pairs = [("hardcoded", "p1_static"), ("template", "p1_static"),
             ("modular", "p1_static"), ("modular", "template"),
             ("template", "hardcoded")]
    for k in c.core_dir:
        rows = []
        for a, b in pairs:
            ids = [i for i in c.models if c.nn(k, i, a) is not None
                   and c.nn(k, i, b) is not None]
            ratio = [c.nn(k, i, a) / c.nn(k, i, b) for i in ids
                     if c.nn(k, i, b) and c.nn(k, i, b) > 0]
            more = [c.nn(k, i, a) > c.nn(k, i, b) for i in ids]
            rows.append([f"{NAME[a]} / {NAME[b]}", spread(ratio, ".2f"),
                         count(more)])
        full = [i for i in c.models
                if all(c.nn(k, i, m) is not None for m in PIPES)]
        mono = [c.nn(k, i, "p1_static") <= c.nn(k, i, "template")
                <= c.nn(k, i, "modular") for i in full]
        L += [f"**{CORE_LABEL[k]}** — ratio between the neural network "
              f"costs, median [min–max] over the models, and on how many the "
              f"first costs more than the second:", "",
              table(["comparison", "ratio", "the first costs more"], rows),
              "", f"P1 ≤ P2 ≤ P3 on {count(mono)} models.", ""]
        if k == "P":
            claim("P1 ≤ P2 ≤ P3 in neural network cost (P-core)",
                  count(mono))
            for a, b in pairs[1:4]:
                ids = [i for i in c.models if c.nn(k, i, a) and c.nn(k, i, b)
                       and c.nn(k, i, b) > 0]
                claim(f"{NAME[a]} costs {NAME[b]} times",
                      spread([c.nn(k, i, a) / c.nn(k, i, b) for i in ids],
                             ".1f"))
    return L


def sec_size(c):
    if not c.size:
        return []
    L = ["## Loaded against executed instructions", "",
         "Loaded = instructions of the pipeline's programs, counted by the "
         "kernel at load time (prog_census). Executed = instructions per "
         "packet from the hardware counters, minus the baseline: the neural "
         "network alone. ρ = rank correlation between the two over the population "
         "(1 = size orders the models like the work).", ""]
    rows = []
    for m in PIPES:
        ids = [i for i in c.models if c.size.get(i, {}).get(m)
               and c.nn("P", i, m, "instr") is not None]
        ld = [c.size[i][m] for i in ids]
        ex = [c.nn("P", i, m, "instr") for i in ids]
        rho = spearman(ld, ex)
        rows.append([NAME[m], str(len(ids)), spread(ld), spread(ex),
                     fmt(rho, ".2f")])
        if rho is not None:
            claim(f"the size of {NAME[m]} predicts its work "
                  f"(rank ρ)", f"{rho:.2f} over {len(ids)} models")
    L += [table(["pipeline", "n", "loaded", "executed (network)", "ρ"], rows),
          ""]
    ids = [i for i in c.models if all(c.size.get(i, {}).get(m)
                                      for m in ("template", "modular"))
           and all(c.nn("P", i, m, "instr") is not None
                   for m in ("template", "modular"))]
    if ids:
        bigger = [c.size[i]["template"] > c.size[i]["modular"] for i in ids]
        works = [c.nn("P", i, "modular", "instr")
                 > c.nn("P", i, "template", "instr") for i in ids]
        both = [b and w for b, w in zip(bigger, works)]
        L += [f"P2 larger than P3: {count(bigger)}; P3 executes more than P2: "
              f"{count(works)}; both together (size orders "
              f"opposite to the work): {count(both)}.", ""]
        claim("P2 is the largest program but P3 executes more",
              count(both))
    return L


def sec_instr_cores(c):
    if "E" not in c.core_dir:
        return []
    rows, allr = [], []
    for m in ("baseline",) + PIPES:
        ids = [i for i in c.models if c.val("P", i, m, "instr")
               and c.val("E", i, m, "instr")]
        r = [abs(c.val("E", i, m, "instr") / c.val("P", i, m, "instr") - 1)
             * 100 for i in ids]
        allr += r
        rows.append([NAME[m], str(len(ids)), fmt(quant(r, .5), ".2f"),
                     fmt(max(r) if r else None, ".2f")])
    lr = [abs(c.val("L", i, m, "instr") / c.val("P", i, m, "instr") - 1) * 100
          for i in c.models for m in PIPES
          if c.val("L", i, m, "instr") and c.val("P", i, m, "instr")]
    if allr:
        claim("same instructions per packet on P-core and E-core",
              f"maximum difference {max(allr):.1f}% over "
              f"{len(allr)} model-pipeline pairs")
    if lr:
        claim("same instructions on the LP E-core too",
              f"maximum difference {max(lr):.1f}% over {len(lr)} pairs")
    return ["## Instructions per packet do not depend on the core", "",
            "|E/P − 1| of the instructions per packet, in %, on every model:",
            "", table(["pipeline", "n", "median %", "maximum %"], rows), ""] \
        + ([f"LP E-core against P-core: maximum {max(lr):.1f}% over {len(lr)} "
            f"pairs.", ""] if lr else [])


def sec_cores(c):
    if "E" not in c.core_dir:
        return []
    L = ["## What changes on a slower core", ""]
    rows = []
    for m in ("baseline",) + PIPES:
        ids = [i for i in c.models if c.val("P", i, m, "mpps")
               and c.val("E", i, m, "mpps")]
        cap = [c.val("E", i, m, "mpps") / c.val("P", i, m, "mpps")
               for i in ids]
        ipc = [c.val("E", i, m, "ipc") / c.val("P", i, m, "ipc") for i in ids
               if c.val("E", i, m, "ipc") and c.val("P", i, m, "ipc")]
        rows.append([NAME[m], str(len(ids)), spread(cap, ".2f"),
                     spread(ipc, ".2f")])
    L += ["E-core capacity and IPC relative to the P-core (same "
          "frequency, 3.5 GHz), median [min–max] over the models:", "",
          table(["pipeline", "n", "capacity E/P", "IPC E/P"], rows), ""]
    fixed = [c.val("E", i, "baseline", "cycles") / c.val("P", i, "baseline",
                                                         "cycles")
             for i in c.models if c.val("E", i, "baseline", "cycles")
             and c.val("P", i, "baseline", "cycles")]
    rows = []
    share_x, ratio_y = [], []
    for m in PIPES:
        ids = [i for i in c.models if c.nn("P", i, m, "cycles")
               and c.nn("E", i, m, "cycles")
               and c.nn("P", i, m, "cycles") > 0]
        r = [c.nn("E", i, m, "cycles") / c.nn("P", i, m, "cycles")
             for i in ids]
        rows.append([NAME[m], str(len(ids)), spread(r, ".2f")])
        for i in ids:
            tot = c.val("P", i, m, "cycles")
            share_x.append(c.nn("P", i, m, "cycles") / tot)
            ratio_y.append(c.val("E", i, m, "mpps") / c.val("P", i, m, "mpps"))
    L += [f"Cycles per packet E/P: fixed part of the node (baseline) "
          f"{spread(fixed, '.2f')}; neural network:", "",
          table(["pipeline", "n", "network cycles E/P"], rows), ""]
    rho = spearman(share_x, ratio_y)
    if rho is not None:
        L += [f"The more the neural network weighs on the packet, the less the "
              f"core matters: rank ρ between the network's cycle share (P-core) "
              f"and the E/P capacity = {rho:.2f} over {len(share_x)} "
              f"model-pipeline pairs.", ""]
        claim("the E-core loses mostly in the node's fixed part",
              f"fixed cycles E/P {spread(fixed, '.2f')}; ρ(network share, "
              f"capacity E/P) = {rho:.2f}")
    lids = [i for i in c.models if ("L", i) in c.sat]
    if lids:
        rows = []
        for m in ("baseline",) + PIPES:
            ids = [i for i in lids if c.val("L", i, m, "mpps")
                   and c.val("P", i, m, "mpps")]
            rows.append([NAME[m], str(len(ids)),
                         spread([c.val("L", i, m, "mpps")
                                 / c.val("P", i, m, "mpps") for i in ids],
                                ".2f"),
                         spread([c.val("L", i, m, "llc") for i in ids],
                                ".1f")])
        L += [f"LP E-core (2.5 GHz), {len(lids)} models from the lightest to "
              f"the heaviest:", "",
              table(["pipeline", "n", "capacity LP/P", "LLC misses/pk"],
                    rows), ""]
        caps = [c.val("L", i, m, "mpps") / c.val("P", i, m, "mpps")
                for i in lids for m in PIPES
                if c.val("L", i, m, "mpps") and c.val("P", i, m, "mpps")]
        if caps:
            claim("LP E-core capacity relative to the P-core",
                  spread(caps, ".2f"))
    return L


FEATS = {
    "executed MACs + layers": ("mac_exec", "n_layers"),
    "shape MACs + layers": ("mac_shape", "n_layers"),
    "executed non-zero MACs + layers": ("mac_exec_nz", "n_layers"),
}


def _fit_rows(c, k, key, stat=None, families=None):
    rows, laws = [], {}
    for m in PIPES:
        ids = [i for i in c.models if (stat or c.nn)(k, i, m, key) is not None
               and (families is None
                    or c.models[i].get("family") in families)]
        y = [(stat or c.nn)(k, i, m, key) for i in ids]
        for lab, cols in FEATS.items():
            if any(c.models[i].get(col) in (None, "") for i in ids
                   for col in cols):
                continue
            X = [[num(c.models[i][col]) for col in cols] for i in ids]
            f = ols(X, y)
            if f is None:
                continue
            e50, e90 = loo_error(X, y)
            beta, r2 = f
            rows.append([NAME[m], lab, str(len(ids)), f"{beta[0]:.0f}",
                         f"{beta[1]:.2f}", f"{beta[2]:.1f}", f"{r2:.2f}",
                         fmt(e50, ".0f"), fmt(e90, ".0f")])
            laws.setdefault(m, {})[lab] = (beta, r2, e50, len(ids))
    return rows, laws


def sec_law(c):
    L = ["## A cost law, fitted on every model", "",
         "network cost = a + b × MAC + c × layers (least squares over the "
         "population). Error = relative error on a model left out of the "
         "fit (median and 90th percentile, %): how wrong the law is "
         "on a model it has not seen. Executed MACs count a one-hot "
         "as a single column; the non-zero ones remove zero weights.", ""]
    fam = ("base", "replica", "imbuto")
    LAWS = {}
    for k in c.core_dir:
        rows, laws = _fit_rows(c, k, "ns", families=fam)
        LAWS[k] = laws
        if rows:
            L += [f"**ns per packet, {CORE_LABEL[k]}**", "",
                  table(["pipeline", "variables", "n", "a (ns)",
                         "b (ns/MAC)", "c (ns/layer)", "r²", "error 50th",
                         "error 90th"], rows), ""]
        rows, ilaws = _fit_rows(c, k, "instr", families=fam)
        if rows and k == "P":
            L += ["**instructions per packet, P-core** (same form: "
                  "b in instructions per MAC, c per layer)", "",
                  table(["pipeline", "variables", "n", "a", "b", "c", "r²",
                         "error 50th", "error 90th"], rows), ""]
            parts = [f"{NAME[m]} {d[lab][0][2]:.0f} (r² {d[lab][1]:.2f})"
                     for m, d in ilaws.items()
                     for lab in ("executed MACs + layers",) if lab in d]
            if parts:
                claim("instructions executed per extra layer (law, "
                      "P-core)", ", ".join(parts))
    if c.size:
        def loaded(k, i, m, key):
            return c.size.get(i, {}).get(m)
        rows, slaws = _fit_rows(c, None, None, stat=loaded, families=fam)
        if rows:
            L += ["**loaded instructions** (program size, same "
                  "form: b per MAC, c per layer)", "",
                  table(["pipeline", "variables", "n", "a", "b", "c", "r²",
                         "error 50th", "error 90th"], rows), ""]
        parts = []
        for m in PIPES:
            v = [c.size[i][m] for i in c.models if c.size.get(i, {}).get(m)]
            d = slaws.get(m, {}).get("executed MACs + layers")
            if v and min(v) == max(v):
                parts.append(f"{NAME[m]} always {v[0]:.0f}")
            elif d:
                parts.append(f"{NAME[m]} {d[0][2]:+.0f} (r² {d[1]:.2f})")
        if parts:
            claim("loaded instructions per extra layer (law)",
                  ", ".join(parts))
    if c.t2:
        def t2s(k, i, m, key):
            return c.nn_t2(k, i, m)
        rows, _ = _fit_rows(c, "P", None, stat=t2s, families=fam)
        if rows:
            L += ["**ns per packet at light traffic (mean T2−T1 minus "
                  "the baseline), P-core**", "",
                  table(["pipeline", "variables", "n", "a (ns)", "b (ns/MAC)",
                         "c (ns/layer)", "r²", "error 50th", "error 90th"],
                        rows), ""]
    best = LAWS.get("P", {})
    for m, d in best.items():
        lab = "executed MACs + layers"
        if lab in d:
            beta, r2, e50, n = d[lab]
            claim(f"law of {NAME[m]} (P-core)",
                  f"{beta[0]:.0f} ns + {beta[1]:.2f} ns/MAC + "
                  f"{beta[2]:.0f} ns/layer; r² {r2:.2f}, median error "
                  f"{fmt(e50, '.0f')}% on unseen models (n={n})")
    if best:
        better = [m for m, d in best.items()
                  if "executed MACs + layers" in d
                  and "shape MACs + layers" in d
                  and d["executed MACs + layers"][1]
                  > d["shape MACs + layers"][1]]
        claim("counting executed MACs explains the cost better than the shape",
              f"{len(better)}/{len(best)} pipelines")
    return L, LAWS


def sec_replicas(c, laws):
    groups = {}
    for i, r in c.models.items():
        if r.get("group"):
            groups.setdefault(r["group"], []).append(i)
    L = []
    if groups:
        rows = []
        cvs = {m: [] for m in PIPES}
        for g, ids in sorted(groups.items()):
            r0 = c.models[ids[0]]
            line = [g, f"{r0['layout']} {r0['shape']}", str(len(ids))]
            for m in PIPES:
                v = [c.nn("P", i, m) for i in ids
                     if c.nn("P", i, m) is not None]
                if len(v) >= 2 and st.mean(v) > 0:
                    cv = st.pstdev(v) / st.mean(v) * 100
                    cvs[m].append(cv)
                    line.append(f"{st.mean(v):.0f} ± {cv:.0f}%")
                else:
                    line.append("-")
            rows.append(line)
        L += ["## How much the weight seed matters", "",
              "Same shape, different seeds (one with normal weights): ns of "
              "neural network, mean ± coefficient of variation, P-core.", "",
              table(["group", "model", "seeds"]
                    + [NAME[m] for m in PIPES], rows), ""]
        worst = {m: max(v) for m, v in cvs.items() if v}
        if worst:
            claim("with the same shape, the weights change the cost by",
                  ", ".join(f"{NAME[m]} ≤{v:.0f}%" for m, v in worst.items()))
    same = {}
    for i in c.models:
        same.setdefault(c.identity(i), []).append(i)
    reps = [v for v in same.values() if len(v) > 1]
    if reps:
        rows = []
        for v in reps:
            line = [", ".join(v)]
            for m in PIPES:
                xs = [c.nn("P", i, m) for i in v if c.nn("P", i, m)]
                line.append(f"{min(xs):.0f}–{max(xs):.0f}" if xs else "-")
            rows.append(line)
        L += ["## The same model measured several times", "",
              "Same shape, same weights, different folders: the spread "
              "of the measurement, not of the model (ns of neural network, P-core).",
              "", table(["folders"] + [NAME[m] for m in PIPES], rows), ""]
    return L


def sec_sparsity(c, laws):
    ids = [i for i, r in c.models.items()
           if num(r.get("zero_frac")) is not None
           and r.get("family") == "sparsita"]
    law = laws.get("P", {})
    if not ids or not law:
        return []
    rows = []
    ratios = {m: [] for m in PIPES}
    for i in sorted(ids, key=lambda i: num(c.models[i]["zero_frac"])):
        r = c.models[i]
        line = [i, f"{num(r['zero_frac']) * 100:.0f}%"]
        for m in PIPES:
            meas = c.nn("P", i, m)
            d = law.get(m, {}).get("executed MACs + layers")
            if meas is None or d is None:
                line.append("-")
                continue
            pred = predict(d[0], [num(r["mac_exec"]), num(r["n_layers"])])
            ratios[m].append((num(r["zero_frac"]), meas / pred if pred else
                              None))
            line.append(f"{meas:.0f} ({meas / pred:.2f})" if pred else
                        f"{meas:.0f}")
        rows.append(line)
    out = ["## Zero weights", "",
           "Measured ns of neural network and, in brackets, the ratio to the "
           "law fitted on the dense models (1 = sparsity changes "
           "nothing, < 1 = the model gets lighter):", "",
           table(["model", "zero weights"] + [NAME[m] for m in PIPES], rows),
           ""]
    hi = {m: [r for z, r in v if z >= 0.5 and r] for m, v in ratios.items()}
    if any(hi.values()):
        claim("with ≥50% zero weights, measured / predicted by the dense law",
              ", ".join(f"{NAME[m]} {spread(v, '.2f')}"
                        for m, v in hi.items() if v))
    return out


def sec_shape(c):
    """Wide or deep: the imbuto family."""
    groups = {}
    for i, r in c.models.items():
        if r.get("family") == "imbuto":
            groups.setdefault(r["layout"], []).append(i)
    if not any(groups.values()):
        return []
    L = ["## Wide or deep, with the same weights", "",
         "Five shapes per layout, with the same weights within each (~600 "
         "with ipa65, ~210-270 with dense17; at 4-5 layers the executed MACs "
         "grow by 16-43 %), from 1 to 5 layers: ns of neural network "
         "with 1 layer → with 5, and the slope per layer (least squares), "
         "P-core.", ""]
    rows, slopes = [], {m: [] for m in PIPES}
    for lay, ids in groups.items():
        ids = sorted(ids, key=lambda i: num(c.models[i]["depth"]))
        for m in PIPES:
            pts = [(num(c.models[i]["depth"]), c.nn("P", i, m)) for i in ids
                   if c.nn("P", i, m) is not None]
            if len(pts) < 3:
                continue
            f = CR._fit([p[0] for p in pts], [p[1] for p in pts])
            slopes[m].append(f[0])
            rows.append([lay, NAME[m], f"{pts[0][1]:.0f} → {pts[-1][1]:.0f}",
                         f"{(pts[-1][1] / pts[0][1] - 1) * 100:+.0f}%",
                         f"{f[0]:.0f}"])
    L += [table(["layout", "pipeline", "1 → 5 layers", "change",
                 "ns per layer"], rows), ""]
    if any(slopes.values()):
        claim("with the same weights, every extra layer costs (ns, P-core)",
              ", ".join(f"{NAME[m]} {spread(v)}" for m, v in slopes.items()
                        if v))
    return L


def sec_light(c):
    if not c.t2:
        return []
    rows = []
    for k in c.core_dir:
        for m in PIPES:
            ids = [i for i in c.models if c.nn_t2(k, i, m) is not None
                   and c.nn(k, i, m)]
            avg = [c.nn_t2(k, i, m) / c.nn(k, i, m) for i in ids]
            mn = [c.nn_t2(k, i, m, 0) / c.nn_t2(k, i, m) for i in ids
                  if c.nn_t2(k, i, m)]
            rows.append([CORE_LABEL[k], NAME[m], str(len(ids)),
                         spread(avg, ".2f"), spread(mn, ".2f")])
    L = ["## Light traffic against a saturated node", "",
         "At light traffic (T2−T1, below capacity) against a saturated "
         "node (CPU time), always the neural network alone. mean/saturated "
         "≈ 1 means the cost of a packet does not depend on the load; "
         "minimum/mean says how much the packet that finds warm caches and "
         "predictors costs compared with the typical one.", "",
         table(["core", "pipeline", "n", "light mean / saturated",
                "minimum / mean"], rows), ""]
    for k in c.core_dir:
        parts = []
        for m in PIPES:
            v = [c.nn_t2(k, i, m) / c.nn(k, i, m) for i in c.models
                 if c.nn_t2(k, i, m) is not None and c.nn(k, i, m)]
            if v:
                parts.append(f"{NAME[m]} {spread(v, '.2f')}")
        if parts:
            claim(f"cost at light traffic / cost with a saturated node "
                  f"({CORE_LABEL[k]})", ", ".join(parts))
    return L + sec_transport(c)


def sec_transport(c):
    """T3-T2: redirect, virtual cable and reception at the next node, from the
    same three-clock measurement. The minimum is the transport without
    waiting; the mean adds the queue and grows with the rate."""
    rows, mins, gap = [], {}, []
    for k in c.core_dir:
        for m in ("baseline",) + PIPES:
            xs = [c.xport[(k, i)][m] for i in c.models
                  if m in c.xport.get((k, i), {})]
            if not xs:
                continue
            mins.setdefault(k, []).extend(x[0] for x in xs)
            rates = sorted({q for x in xs for q in x[1]})
            avg = ", ".join(
                f"{q / 1e6:g} Mpps {spread([x[1][q] for x in xs if q in x[1]])}"
                for q in rates)
            rows.append([CORE_LABEL[k], NAME[m], str(len(xs)),
                         spread([x[0] for x in xs]), avg])
        for i in c.models:
            x = [c.xport.get((k, i), {}).get(m) for m in PIPES]
            x = [v[0] for v in x if v]
            if len(x) >= 2:
                gap.append((max(x) / min(x) - 1) * 100)
    if not rows:
        return []
    claim("the transport (minimum T3−T2, no waiting) is a common cost, ns",
          ", ".join(f"{CORE_LABEL[k]} {spread(v)}" for k, v in mins.items()))
    if gap:
        claim("the transport does not depend on the pipeline",
              f"difference between the most and least expensive {spread(gap)}% "
              f"over {len(gap)} model-cores")
    return ["## The transport to the next node", "",
            "T3−T2 (redirect, virtual cable, reception) from the three-clock "
            "measurement, ns. The minimum is the transport without waiting. The mean "
            "also contains the queue: here the egress runs on the node core, and "
            "the mean grows with the rate.", "",
            table(["core", "program", "n", "minimum", "mean per rate"],
                  rows), ""]


def sec_load_curves(c):
    rows, agree, ingress = [], [], []
    for k in ("P", "E"):
        root = os.path.join(c.base, f"carico_{k}core")
        if not os.path.isdir(root):
            continue
        for mid in sorted(os.listdir(root)):
            br = c.read_bitrate(os.path.join(root, mid))
            if not br:
                continue
            for m in PIPES:
                kn, mx, best = CR.knee(br, m)
                cap = c.val(k, mid, m, "mpps")
                if mx is None:
                    continue
                if cap:
                    agree.append(mx / cap)
                pts = [r for r in br if r.get("method") == m]
                lost = [max(0, num(r.get("loss_before_xdp")) or 0)
                        for r in pts]
                inpipe = [max(0, num(r.get("loss_in_pipeline")) or 0)
                          for r in pts]
                tot = sum(lost) + sum(inpipe)
                if tot > 0:
                    ingress.append(sum(lost) / tot)
                rows.append([CORE_LABEL[k], mid, NAME[m], fmt(kn, ".1f"),
                             fmt(mx, ".2f"), fmt(cap, ".2f"),
                             best.get("bottleneck", "-") or "-"])
    if not rows:
        return []
    if agree:
        claim("the maximum forwarded under growing rate matches the "
              "full-load capacity (within the noise between sessions)",
              f"ratio {spread(agree, '.2f')} over {len(agree)} curves")
    if ingress:
        claim("above capacity packets are lost before the program, in the queue",
              f"share lost before XDP {spread(ingress, '.3f')}")
    return ["## Under growing traffic", "",
            "Knee = highest requested rate without loss; maximum "
            "forwarded against the capacity measured at full load on the "
            "same model.", "",
            table(["core", "model", "pipeline", "knee Mpps",
                   "max forwarded", "capacity", "bottleneck"], rows), ""]


def sec_two_cores(c):
    rows, scal = [], []
    for k in ("P", "E"):
        root = os.path.join(c.base, f"core2_{k}core")
        if not os.path.isdir(root):
            continue
        for mid in sorted(os.listdir(root)):
            two = CR.saturation(c.read(os.path.join(root, mid), "compare.csv"))
            for m in ("baseline",) + PIPES:
                one = c.val(k, mid, m, "mpps")
                if m in two and one:
                    s = CR.node_mpps(two[m]) / one / 2 * 100
                    scal.append(s)
                    rows.append([CORE_LABEL[k], mid, NAME[m], f"{one:.2f}",
                                 f"{CR.node_mpps(two[m]):.2f}", f"{s:.0f}"])
    if not rows:
        return []
    claim("two cores carry twice one core (within the noise between sessions)",
          f"{spread(scal)}% of double over {len(scal)} pairs")
    return ["## Two node cores", "",
            table(["core", "model", "pipeline", "1 core", "2 cores",
                   "% of double"], rows), ""]


def sec_classes(c):
    root = os.path.join(c.base, "classi")
    if not os.path.isdir(root):
        return []
    rows, fwd_spread, drop_extra = [], [], []
    for mid in sorted(os.listdir(root)):
        pc = [r for r in c.read(os.path.join(root, mid), "per_class.csv")
              if r.get("phase") == "saturazione"]
        for m in PIPES:
            fw = [num(r["ns_cpu"]) for r in pc if r["method"] == m
                  and r.get("scenario_action") == "FORWARD"
                  and num(r.get("ns_cpu"))]
            dr = [num(r["ns_cpu"]) for r in pc if r["method"] == m
                  and r.get("scenario_action") == "DROP"
                  and num(r.get("ns_cpu"))]
            if not fw:
                continue
            sp = (max(fw) / min(fw) - 1) * 100
            fwd_spread.append(sp)
            ex = (st.median(dr) - st.median(fw)) if dr else None
            if ex is not None:
                drop_extra.append(ex)
            rows.append([mid, NAME[m], str(len(fw)), f"{sp:.0f}%",
                         fmt(ex)])
    if not rows:
        return []
    claim("the forwarding classes cost the same",
          f"difference between the most and least expensive {spread(fwd_spread)}%")
    if drop_extra:
        claim("dropping costs more (a bench effect: the packet memory is "
              "freed on the node)", f"{spread(drop_extra)} ns")
    return ["## Different classes", "",
            "One session per decided class: difference between the most and "
            "least expensive forwarding class, and how much more "
            "dropping costs (ns, median over the classes).", "",
            table(["model", "pipeline", "FORWARD classes", "FORWARD spread",
                   "DROP − FORWARD ns"], rows), ""]


def sec_mix(c):
    root = os.path.join(c.base, "mix")
    if not os.path.isdir(root):
        return []
    rows, rel = [], []
    for mid in sorted(os.listdir(root)):
        s = CR.saturation(c.read(os.path.join(root, mid), "compare.csv"))
        for m in PIPES:
            fixed = c.val("P", mid, m, "ns")
            if m in s and fixed:
                v = num(s[m].get("ns_cpu"))
                rel.append((v / fixed - 1) * 100)
                rows.append([mid, NAME[m], f"{fixed:.0f}", f"{v:.0f}",
                             f"{(v / fixed - 1) * 100:+.0f}%"])
    if not rows:
        return []
    claim("a different TTL per packet against a fixed packet",
          f"{spread(rel)}% on the node time")
    return ["## Identical packets against different packets", "",
            "A different TTL for every packet (2–31): the model decides different "
            "classes, drop included. ns of CPU per packet against the "
            "fixed packet of the same model.", "",
            table(["model", "pipeline", "fixed", "mixed TTL", "Δ"], rows),
            ""]


def sec_frames(c):
    root = os.path.join(c.base, "taglie")
    if not os.path.isdir(root):
        return []
    var = []
    for mid in sorted(os.listdir(root)):
        rows = [r for r in c.read(os.path.join(root, mid), "compare.csv")
                if r.get("phase") == "saturazione"]
        for m in ("baseline",) + PIPES:
            v = [num(r["ns_cpu"]) for r in rows if r["method"] == m
                 and num(r.get("ns_cpu"))]
            if len(v) >= 2:
                var.append((max(v) / min(v) - 1) * 100)
    if not var:
        return []
    claim("the packet size does not change the cost",
          f"difference between 64 and 1514 bytes {spread(var, '.1f')}% "
          f"({len(var)} pairs)")
    return ["## Packet size", "",
            f"Difference between the most and least expensive size, per model "
            f"and pipeline: {spread(var, '.1f')}% over {len(var)} pairs.", ""]


def sec_solo(c):
    """The program alone (bench_program_alone.py, BPF_PROG_TEST_RUN), on
    every model."""
    root = os.path.join(c.base, "solo")
    if not os.path.isdir(root):
        return []
    solo, off = {}, []
    for mid in c.models:
        rows = c.read(os.path.join(root, mid), "solo.csv")
        d = {}
        for r in rows:
            if r.get("esito") != "OK":
                continue
            if (num(r.get("fwd_pct")) or 0) < 99:
                off.append(f"{mid}/{r['method']}")
                continue
            d[r["method"]] = r
        if d:
            solo[mid] = d

    def v(mid, m, key):
        return num(solo.get(mid, {}).get(m, {}).get(key))

    def nn(mid, m, key="lat_ns"):
        """The network alone, by itself."""
        if key == "lat_hot" and any((v(mid, x, "hot_k") or 0) < HOT_MIN_K
                                    for x in (m, "baseline")):
            return None
        a, b = v(mid, m, key), v(mid, "baseline", key)
        return a - b if a is not None and b is not None else None

    comp = {}
    for mid in c.models:
        for r in read_csv(os.path.join(c.base, "compila", mid,
                                       "compila.csv")):
            g, k = num(r.get("generate_ms")), num(r.get("compile_ms"))
            if g is not None and k is not None:
                comp.setdefault(r["method"], []).append(g + k)
    rows, upd, lk, light, sat, hot_sat, hot_light = [], [], [], {}, {}, \
        {}, {}
    for m in ("baseline",) + PIPES:
        lat = [v(i, m, "lat_ns") for i in solo]
        net = [nn(i, m) for i in solo] if m != "baseline" else []
        bld = [v(i, m, "build_ms") for i in solo]
        up = [v(i, m, "update_ms") for i in solo]
        look = [v(i, m, "lookups") for i in solo]
        tail = [v(i, m, "n_tail") for i in solo]
        hot = [nn(i, m, "lat_hot") for i in solo] if m != "baseline" \
            else [v(i, m, "lat_hot") for i in solo]
        rows.append([NAME.get(m, m), str(len([x for x in lat if x])),
                     spread(lat), spread(net), spread(hot),
                     spread(bld, ".1f"), spread(comp.get(m, []), ".0f"),
                     spread(up, ".1f"), spread(look, ".1f"),
                     spread(tail)])
        if m == "baseline":
            continue
        light[m] = [c.nn_t2("P", i, m) / nn(i, m) for i in solo
                    if nn(i, m) and c.nn_t2("P", i, m) is not None]
        sat[m] = [c.nn("P", i, m) / nn(i, m) for i in solo
                  if nn(i, m) and c.nn("P", i, m) is not None]
        hot_sat[m] = [c.nn("P", i, m) / nn(i, m, "lat_hot") for i in solo
                      if nn(i, m, "lat_hot")
                      and c.nn("P", i, m) is not None]
        hot_light[m] = [c.nn_t2("P", i, m, 0) / nn(i, m, "lat_hot")
                        for i in solo if nn(i, m, "lat_hot")
                        and c.nn_t2("P", i, m, 0) is not None]
        upd.append((m, up))
        lk.append((m, look))
    if off:
        claim("program alone off the traffic path (not "
              "forwarded)", f"{len(off)} model-pipeline measurements")
    L = ["## The program alone", "",
         "bench_program_alone.py on every model, P-core: latency alone "
         "(BPF_PROG_TEST_RUN, minimum of 7 measurements), and the network alone "
         "(minus the baseline of the same model); build = loading the pipeline "
         "from scratch; install = a new model on a running node (P1: "
         "loading the compiled object; P2, P3: writing the tables); "
         "table lookups and tail calls per packet. Packet and inputs "
         "are those of the traffic (TTL 32, link state that forwards); "
         "a measurement that did not forward is left out"
         + (f" ({len(off)}: {', '.join(off[:12])}"
            + (" ..." if len(off) > 12 else "") + ")" if off else "")
         + ".", "",
         table(["pipeline", "n", "single call ns", "network ns",
                "network, warm loop ns", "build ms", "generate and compile "
                "P1 ms", "install ms", "lookups", "tail calls"], rows), "",
         f"Warm loop: blocks of consecutive runs as long as the decreasing TTL "
         f"does not change the decided class; used only where the block is "
         f"at least {HOT_MIN_K} runs long.", ""]
    rows2 = []
    for m in PIPES:
        if light.get(m) or sat.get(m):
            rows2.append([NAME[m], spread(hot_sat.get(m, []), ".2f"),
                          spread(hot_light.get(m, []), ".2f"),
                          spread(sat.get(m, []), ".2f"),
                          spread(light.get(m, []), ".2f")])
    if rows2:
        L += ["The network alone under traffic divided by the network alone by itself, "
              "model by model:", "",
              table(["pipeline", "saturated node / warm loop",
                     "light traffic, minimum / warm loop",
                     "saturated node / single call",
                     "light traffic, mean / single call"], rows2), ""]
        if any(hot_sat.values()):
            claim("the network with a saturated node / the network alone in a warm loop "
                  "(P-core)",
                  ", ".join(f"{NAME[m]} {spread(hot_sat[m], '.2f')}"
                            for m in PIPES if hot_sat.get(m)))
            claim("the fastest packet under traffic / the warm loop",
                  ", ".join(f"{NAME[m]} {spread(hot_light[m], '.2f')}"
                            for m in PIPES if hot_light.get(m)))
        else:
            claim("the network with a saturated node / the network alone with single "
                  "calls (P-core)",
                  ", ".join(f"{NAME[m]} {spread(sat[m], '.2f')}"
                            for m in PIPES if sat.get(m)))
    if comp:
        claim("generating and compiling P1 for a new model (off the "
              "node), ms", ", ".join(f"{NAME[m]} {spread(v_, '.0f')}"
                                    for m, v_ in comp.items()))
    claim("installing a model on a running node, ms",
          ", ".join(f"{NAME[m]} {spread(u, '.1f')}" for m, u in upd if
                    any(x is not None for x in u)))
    claim("table lookups per packet",
          ", ".join(f"{NAME[m]} {spread(x, '.0f')}" for m, x in lk if
                    any(y is not None for y in x)))
    pts = [(num(c.models[i]["n_layers"]), v(i, "modular", "lookups"),
            v(i, "modular", "n_tail")) for i in solo]
    pts = [p for p in pts if p[1] is not None]
    if len(pts) > 3:
        f = CR._fit([p[0] for p in pts], [p[1] for p in pts])
        same = sum(1 for p in pts if p[2] == p[0])
        claim("P3: table lookups and tail calls grow with the layers",
              f"+{f[0]:.1f} lookups per layer; tail calls = layers on "
              f"{same}/{len(pts)} models")
    return L


def noise(c):
    """How much the same measurement varies."""
    within, base, same = [], {}, []
    for k, d in c.core_dir.items():
        for i in c.models:
            rows = c.read(os.path.join(d, i), "compare_raw.csv")
            by = {}
            for r in rows:
                v = num(r.get("ns_cpu"))
                if r.get("phase") == "saturazione" and v:
                    by.setdefault(r["method"], []).append(v)
            for v in by.values():
                if len(v) >= 2:
                    within.append((max(v) - min(v)) / st.median(v) * 100)
        v = [c.val(k, i, "baseline", "ns") for i in c.models
             if c.val(k, i, "baseline", "ns")]
        if v:
            m = st.median(v)
            base[k] = [abs(x / m - 1) * 100 for x in v]
    root = os.path.join(c.base, "taglie")
    if os.path.isdir(root):
        for i in sorted(os.listdir(root)):
            for r in c.read(os.path.join(root, i), "compare.csv"):
                if r.get("phase") != "saturazione" or r.get("frame") != "64":
                    continue
                a, b = num(r.get("ns_cpu")), c.val("P", i, r["method"], "ns")
                if a and b:
                    same.append(abs(a / b - 1) * 100)
    return dict(within=within, base=base, same=same)


def sec_noise(c):
    """The measurement noise."""
    n = noise(c)
    if not (n["within"] or n["same"]):
        return []
    L = ["## How much the same measurement varies", "",
         "Variation in % of the value: median, 90th percentile, maximum. A "
         "difference within the variation between sessions is not a difference; "
         "a ratio between two measurements from different sessions can exceed 1 "
         "for this reason alone.", ""]
    rows = []
    if n["within"]:
        rows.append(["the rounds of one measurement ((max − min) / median)",
                     str(len(n["within"])), fmt(quant(n["within"], .5), ".1f"),
                     fmt(quant(n["within"], .9), ".1f"),
                     fmt(max(n["within"]), ".1f")])
    for k, v in n["base"].items():
        rows.append([f"the node without a network in different sessions, {CORE_LABEL[k]}",
                     str(len(v)), fmt(quant(v, .5), ".1f"),
                     fmt(quant(v, .9), ".1f"), fmt(max(v), ".1f")])
    if n["same"]:
        rows.append(["same model and version, two sessions",
                     str(len(n["same"])), fmt(quant(n["same"], .5), ".1f"),
                     fmt(quant(n["same"], .9), ".1f"),
                     fmt(max(n["same"]), ".1f")])
        claim("the same measurement repeated in another session changes by",
              f"{quant(n['same'], .5):.1f} % median, "
              f"{quant(n['same'], .9):.1f} % at the 90th percentile, "
              f"{max(n['same']):.1f} % at most ({len(n['same'])} pairs)")
    L += [table(["what", "n", "median %", "90th %", "max %"], rows), ""]
    return L


def sec_excluded(c):
    """The measurements left out of every figure, and why."""
    if not c.seen:
        return []
    try:
        with open(os.path.join(c.base, "escluse.csv"), "w", newline="",
                  encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["folder", "reason"])
            w.writerows(sorted(c.excluded.items()))
    except OSError:
        pass
    claim("measurements left out of the conclusions (disturbed or rejected)",
          f"{len(c.excluded)}/{len(c.seen)}")
    if c.salvaged:
        out = sum(a for a, _ in c.salvaged.values())
        tot = sum(b for _, b in c.salvaged.values())
        claim("disturbed measurements kept without the affected rounds",
              f"{len(c.salvaged)} measurements, {out}/{tot} rounds or windows removed")
    if not c.excluded and not c.salvaged:
        return []
    by = {}
    for rel, why in sorted(c.excluded.items()):
        by.setdefault(why, []).append(rel)
    L = ["## Measurements left out of the conclusions", "",
         "They enter no range and no law. disturbed = "
         "the machine did not stay in the declared conditions (run_disturbed "
         "in env.csv); rejected = the bench's validity check rejected it "
         "(throughput_report.md). They are redone with POP_RIFAI_DISTURBATE=1 "
         "run_population_campaign.sh.", ""]
    for why, rels in by.items():
        L += [f"**{why}** ({len(rels)}): " + ", ".join(rels), ""]
    if c.salvaged:
        L += [f"**measurements kept without the disturbed rounds** (curves: every point, "
              f"full load: every pipeline, with at least {MIN_CLEAN_ROUNDS} "
              f"clean rounds; full load only if the disturbance is throttling, "
              f"removing the rounds within {EVENT_MARGIN_S:g} s of an event): "
              + ", ".join(f"{rel} ({a}/{b})"
                          for rel, (a, b) in sorted(c.salvaged.items())), ""]
    return L


def sec_sums():
    if not SUMS:
        return []
    return ["## The claims", "",
            "Every row is a claim and its evidence over the population: "
            "on how many models it holds, or the range it covers.", "",
            table(["claim", "over the population"],
                  [[a, b] for a, b in SUMS]), ""]


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        sys.exit(__doc__.split("\n\n")[0])
    c = Campaign(argv[0])
    if not c.models:
        sys.exit(f"{argv[0]}: population.csv missing")
    body = []
    body += sec_population(c)
    body += sec_correct(c)
    body += sec_reference(c)
    body += sec_cost(c)
    body += sec_order(c)
    law_md, laws = sec_law(c)
    body += sec_size(c)
    body += sec_instr_cores(c)
    body += sec_cores(c)
    body += law_md
    body += sec_replicas(c, laws)
    body += sec_sparsity(c, laws)
    body += sec_shape(c)
    body += sec_light(c)
    body += sec_load_curves(c)
    body += sec_two_cores(c)
    body += sec_classes(c)
    body += sec_mix(c)
    body += sec_frames(c)
    body += sec_solo(c)
    body += sec_noise(c)
    body += sec_excluded(c)
    title = os.path.basename(os.path.normpath(argv[0]))
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    out = [f"# Population summary: {title}", ""] + sec_sums() + body
    print("\n".join(out))


if __name__ == "__main__":
    main()
