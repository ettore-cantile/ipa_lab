#!/usr/bin/env python3
"""population_report.py -- le conclusioni su una POPOLAZIONE di modelli.

    python3 ipa/test/population_report.py results/popolazione_<data> > sintesi.md
    python3 ipa/test/population_report.py results/campagna_2026-10-10     # assi

campaign_report.py fa le tabelle di un modello alla volta. Qui nessun numero
e' di un modello: ogni riga e' un intervallo sulla popolazione (minimo, 10°
percentile, mediana, 90°, massimo), una legge stimata su tutti i modelli
(minimi quadrati, con l'errore che fa su modelli che non ha visto), o
un'affermazione con il numero di modelli su cui regge ("P3 esegue piu'
istruzioni di P2: 91/91").

Legge, se ci sono (remeasure_popolazione.sh):
    population.csv                         il manifesto (model_population.py)
    corretto/corretto.csv                  equivalenza riferimento / eBPF
    rif_<P|E|L>core/compare.csv            rxonly e baseline senza modello
    pop_<P|E>core/<id>/compare.csv         massima spinta, ogni modello
    pop_<P|E>core/<id>/prog_size.csv       programmi caricati
    pop_<P|E>core/<id>/rates/rates_raw.csv T2-T1 a traffico leggero
    lpe/<id>/compare.csv                   LP E-core, sottoinsieme
    carico_<P|E>core/<id>/bitrate.csv      curve al crescere del rate
    core2_<P|E>core/<id>/compare.csv       due core
    classi/<id>/per_class.csv              una sessione per classe
    mix/<id>/compare.csv                   TTL misti
    taglie/<id>/compare.csv                64 / 512 / 1514 byte

Senza population.csv, ma con le cartelle assi_<P|E>core/ di una campagna di
ottobre, tratta i punti degli assi come una popolazione (i modelli vengono da
ipa/synth/traffic, rigenerati con traffic_models.py se mancano). Sono modelli
costruiti attorno al checkpoint, quindi meno generali; la sintesi lo dice.

Niente root, niente BCC: si rifa' a mano su una campagna gia' raccolta.
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

import campaign_report as CR  # noqa: E402

PIPES = ("p1_static", "hardcoded", "template", "modular")
NAME = CR.NAME
CORE_LABEL = {"P": "P-core", "E": "E-core", "L": "LP E-core"}
# blocco minimo del ciclo caldo di bench_solo per usarne la misura
HOT_MIN_K = 10
# giri puliti che ogni punto di una curva disturbata deve conservare (su 3)
MIN_CLEAN_ROUNDS = 2
read_csv, num, fmt, table = CR.read_csv, CR.num, CR.fmt, CR.table


# --------------------------------------------------------------------------
# statistica senza dipendenze
# --------------------------------------------------------------------------
def quant(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    pos = q * (len(xs) - 1)
    lo, hi = int(math.floor(pos)), int(math.ceil(pos))
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def spread(xs, spec=".0f"):
    """'mediana [min–max]'."""
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
    """Minimi quadrati con intercetta. X: lista di righe (senza la colonna
    dell'intercetta). (coefficienti [b0, b1, ...], r2) o None."""
    n, k = len(X), (len(X[0]) if X else 0) + 1
    if n <= k:
        return None
    A = [[1.0] + [float(v) for v in row] for row in X]
    # equazioni normali, eliminazione di Gauss con pivot parziale
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
    """Errore relativo mediano e al 90° percentile (%) su modelli lasciati
    fuori dalla stima, uno alla volta: quanto la legge sbaglia su un modello
    che non ha visto."""
    errs = []
    for i in range(len(X)):
        f = ols(X[:i] + X[i + 1:], y[:i] + y[i + 1:])
        if f is None or not y[i]:
            continue
        errs.append(abs(predict(f[0], X[i]) - y[i]) / abs(y[i]) * 100)
    return (st.median(errs), quant(errs, .9)) if errs else (None, None)


def count(pred_list):
    """'k/n' di una lista di booleani (None = non decidibile, fuori)."""
    v = [p for p in pred_list if p is not None]
    return f"{sum(v)}/{len(v)}" if v else "-"


# --------------------------------------------------------------------------
# lettura
# --------------------------------------------------------------------------
def unusable(d):
    """Perche' la misura nella cartella `d` non entra nelle conclusioni, o
    None. Due motivi, scritti dal banco stesso: il controllo di validita' di
    bench_throughput l'ha bocciata (throughput_report.md), o la macchina non e'
    rimasta nelle condizioni dichiarate (run_disturbed in env.csv: throttling,
    powerclamp, batteria, frequenza del nodo fuori target)."""
    try:
        with open(os.path.join(d, "throughput_report.md"),
                  encoding="utf-8") as f:
            if "RUN BOCCIATO" in f.read():
                return "bocciata"
    except OSError:
        pass
    try:
        with open(os.path.join(d, "env.csv"), encoding="utf-8") as f:
            if any(ln.strip() == "run_disturbed,True" for ln in f):
                return "disturbata"
    except OSError:
        pass
    return None


# Un giro di bench_throughput --mode compare: la finestra di misura
# (`secs`) finisce DRAIN_S prima di t_wall. host_monitor.csv registra la
# macchina una volta al secondo, con l'ora al secondo intero: un evento cade
# fra due righe, e l'ora della prima riga e' nota a meno di un secondo.
# Margine attorno a ogni evento, per parte.
COMPARE_DRAIN_S = 0.05
EVENT_MARGIN_S = 1.0


def _throttle_events(d, day):
    """Gli intervalli [inizio, fine] (secondi epoch) in cui il registro della
    macchina ha visto un throttling, o None se il disturbo non e' solo
    throttling (powerclamp, raffreddamento passivo, batteria, frequenza del
    nodo fuori target: lo dice env.csv, e allora il run resta fuori)."""
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
    """(righe di compare.csv ricalcolate dai soli giri puliti di
    compare_raw.csv, quei giri, (giri tolti, giri)): un run dura ~30 s, un
    evento di throttling (~1 al minuto su questo portatile) ne tocca uno o
    due giri, non il run. Ogni (pipeline, taglia, fase) deve conservare
    almeno MIN_CLEAN_ROUNDS giri; le mediane sono quelle del banco
    (run_compare), sugli stessi campi. None se non si puo'."""
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
    """Tutto cio' che il report usa, indicizzato per modello."""

    def __init__(self, base):
        self.base = base
        self.legacy = False
        self.seen = set()          # cartelle di misura lette
        self.excluded = {}         # cartella relativa -> motivo
        self.salvaged = {}         # misura -> (giri/finestre tolti, totale)
        self.models = {}           # id -> riga del manifesto
        self.core_dir = {}         # "P"/"E" -> cartella della popolazione
        man = os.path.join(base, "population.csv")
        if os.path.exists(man):
            for r in read_csv(man):
                self.models[r["id"]] = r
            for k in ("P", "E"):
                d = os.path.join(base, f"pop_{k}core")
                if os.path.isdir(d):
                    self.core_dir[k] = d
        else:
            self._legacy()
        self.sat = {}              # (core, id) -> {metodo: riga saturazione}
        self.size = {}             # id -> {metodo: istruzioni caricate}
        self.t2 = {}               # (core, id) -> {metodo: (min, media)}
        self.xport = {}            # (core, id) -> {metodo: T3-T2 medio}
        for k, d in self.core_dir.items():
            for mid in self.models:
                sub = os.path.join(d, self.models[mid].get("_sub", mid))
                s = CR.saturation(self.read(sub, "compare.csv"))
                if s:
                    self.sat[(k, mid)] = s
                # la dimensione caricata non dipende da come e' andata la
                # macchina: si tiene anche da un run disturbato
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
        """Il CSV `name` della misura in `d`, o [] se la misura non entra
        nelle conclusioni (unusable): resta contata in self.excluded. Una
        misura a massima spinta disturbata SOLO da throttling si ricalcola
        dai giri che l'evento non ha toccato (salvage_compare)."""
        if not os.path.exists(os.path.join(d, name)):
            return []
        rel = os.path.relpath(d, self.base)
        self.seen.add(rel)
        why = unusable(d)
        if why == "disturbata" and name in ("compare.csv", "compare_raw.csv"):
            got = salvage_compare(d)
            if got:
                rows, clean, self.salvaged[rel] = got
                return rows if name == "compare.csv" else clean
        if why:
            self.excluded[rel] = why
            return []
        return read_csv(os.path.join(d, name))

    def read_bitrate(self, d):
        """Le righe di sintesi di una curva al crescere del rate. Una curva
        dura ~160 s e un evento della macchina (throttling di pacchetto, ~1
        ogni 60-80 s su questo portatile) ne tocca una finestra di un giro,
        non la curva: da un run disturbato la sintesi si ricalcola dalle sole
        finestre pulite di bitrate_raw.csv, con la stessa summarise del
        banco. La curva resta se ogni punto conserva almeno
        MIN_CLEAN_ROUNDS giri; altrimenti e' fuori come le altre."""
        if not os.path.exists(os.path.join(d, "bitrate.csv")):
            return []
        rel = os.path.relpath(d, self.base)
        self.seen.add(rel)
        why = unusable(d)
        if why is None:
            return read_csv(os.path.join(d, "bitrate.csv"))
        raw_path = os.path.join(d, "bitrate_raw.csv")
        if why == "disturbata" and os.path.exists(raw_path):
            import bench_bitrate as BB
            import plot_bitrate as PB
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
                # come le righe lette da bitrate.csv: i booleani in testo
                return [{k: str(v) if isinstance(v, bool) else v
                         for k, v in s.items()}
                        for s in BB.summarise(clean)]
        self.excluded[rel] = why
        return []

    def _legacy(self):
        """Gli assi di una campagna di ottobre come popolazione."""
        import model_population as MP
        from synth.spec import ModelSpec
        tm_root = os.path.join(_SHARED, "synth", "traffic")
        for k in ("P", "E"):
            d = os.path.join(self.base, f"assi_{k}core")
            if os.path.isdir(d):
                self.core_dir[k] = d
        if not self.core_dir:
            return
        self.legacy = True
        subs = set()
        for d in self.core_dir.values():
            subs |= {s for s in os.listdir(d)
                     if s != "checkpoint" and os.path.isdir(os.path.join(d, s))}
        if subs and not all(os.path.exists(os.path.join(tm_root, s,
                                                        "model.json"))
                            for s in subs):
            import contextlib
            import io
            import traffic_models as TM
            with contextlib.redirect_stdout(io.StringIO()):
                TM.generate()
        for s in sorted(subs):
            mdir = os.path.join(tm_root, s)
            try:
                with open(os.path.join(mdir, "model.json")) as f:
                    mj = json.load(f)
                with open(os.path.join(mdir, "weights.json")) as f:
                    wi = json.load(f)
            except OSError:
                continue
            spec = ModelSpec.from_json(mj)
            r = dict(id=s, _sub=s, family=s.rsplit("_", 1)[0],
                     layout="+".join(f"{f.name}{f.size if f.size > 1 else ''}"
                                     for f in spec.features.features),
                     seed=mj.get("seed"), init=mj.get("weight_init"),
                     sparsity=mj.get("sparsity", 0.0), group="")
            r.update(MP.describe(spec, wi))
            r["no_template"] = ""
            self.models[s] = r

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
            # T3-T2: il minimo e' il trasporto senza attesa; la media
            # contiene anche la coda (l'uscita gira sul core del nodo) e
            # cresce col rate, quindi si tiene rate per rate
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

    # -- grandezze per modello ---------------------------------------------
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
        """La parte della rete neurale: la pipeline meno la baseline dello
        stesso run (stesso caricamento del fabric, stessa sessione)."""
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


# --------------------------------------------------------------------------
# sezioni
# --------------------------------------------------------------------------
SUMS = []      # (affermazione, conteggio o intervallo) per "Le somme"


def claim(text, evidence):
    SUMS.append((text, evidence))


def sec_population(c):
    L = ["## La popolazione", ""]
    ms = list(c.models.values())
    if c.legacy:
        L += ["**Attenzione: popolazione degli assi.** Questi modelli sono gli "
              "assi parametrici della campagna, costruiti variando UN "
              "parametro alla volta attorno al 65-4-4-7 e (quasi) tutti con "
              "lo stesso seme: una prima indicazione, non la generalita' "
              "che dara' remeasure_popolazione.sh.", ""]
        uniq = {c.identity(m) for m in c.models}
        L += [f"{len(ms)} punti, {len(uniq)} modelli distinti (lo stesso "
              f"65-4-4-7 compare in piu' assi).", ""]
    fams = {}
    for r in ms:
        fams[r.get("family", "-")] = fams.get(r.get("family", "-"), 0) + 1
    L.append("Per famiglia: " + ", ".join(f"{k} {v}" for k, v in fams.items())
             + ".")
    L.append("")

    def rng(key, spec=".0f"):
        v = [num(r.get(key)) for r in ms if num(r.get(key)) is not None]
        return f"{fmt(min(v), spec)}–{fmt(max(v), spec)}" if v else "-"
    L += [table(["grandezza", "intervallo"], [
        ["ingressi (n_in)", rng("n_in")], ["strati nascosti", rng("depth")],
        ["neuroni per strato (max)", rng("width_max")],
        ["uscite", rng("n_out")], ["pesi", rng("weights")],
        ["MAC dalla forma", rng("mac_shape")],
        ["MAC eseguite", rng("mac_exec")],
        ["feature one-hot", rng("onehot_feat")],
        ["colonne dense", rng("dense_cols")],
        ["pesi a zero (frazione)", rng("zero_frac", ".2f")]]), ""]
    lays = sorted({r.get("layout") for r in ms})
    if not c.legacy:
        depths = sorted({int(num(r["depth"])) for r in ms})
        rows = []
        for lay in lays:
            rows.append([lay] + [str(sum(1 for r in ms if r["layout"] == lay
                                         and int(num(r["depth"])) == d))
                                 for d in depths])
        L += ["Modelli per composizione dell'ingresso e profondita':", "",
              table(["composizione"] + [f"{d} strati" for d in depths], rows),
              ""]
    nop2 = [r["id"] for r in ms if r.get("no_template")]
    if nop2:
        L += [f"P2 non sa eseguire {len(nop2)} modelli su {len(ms)} "
              f"(MAX_WEIGHT_ENTRIES): {', '.join(nop2)}. Le altre pipeline "
              f"li eseguono tutti.", ""]
        claim("P2 ha un tetto sui pesi che le altre pipeline non hanno",
              f"{len(nop2)}/{len(ms)} modelli fuori da P2")
    missing = []
    for k in c.core_dir:
        miss = [m for m in c.models if (k, m) not in c.sat]
        if miss:
            missing.append(f"{CORE_LABEL[k]}: {len(miss)} ({', '.join(miss[:12])}"
                           f"{' ...' if len(miss) > 12 else ''})")
    if missing:
        L += ["Modelli senza misura a massima spinta (vedi i log): "
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
        claim(f"{lab} decide esattamente come il riferimento intero",
              f"{ok}/{ok + len(no)} modelli"
              + (f" ({len(err)} non conclusi)" if err else ""))
    return ["## Correttezza su ogni modello", "",
            "Riferimento intero contro eBPF (verify_synth_kernel, "
            "BPF_PROG_TEST_RUN, 200 ingressi per modello): deve coincidere al "
            "100%. P1.5 non e' in questo controllo (verify_synth_kernel "
            "prova P1 con il nodo congelato, P2 e P3).", "",
            table(["pipeline", "OK", "NO", "non applicabile", "errore",
                   "quali"], out), ""]


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
    return ["## Il nodo senza rete neurale", "",
            "Ricevere (rxonly) e ricevere + inoltrare (baseline) non "
            "dipendono dal modello: una misura per tipo di core.", "",
            table(["core", "programma", "Mpps", "ns CPU", "istr/pk", "IPC"],
                  rows), ""]


def sec_cost(c):
    L = ["## Quanto costa la rete neurale, su tutta la popolazione", "",
         "ns per pacchetto della sola rete neurale: tempo di CPU a nodo "
         "saturo meno la baseline dello stesso run. n = modelli misurati.",
         ""]
    for k in c.core_dir:
        rows = []
        for m in PIPES:
            ids = c.ids(k, m)
            rows.append([NAME[m]] + five([c.nn(k, i, m) for i in ids]))
        L += [f"**{CORE_LABEL[k]}**", "",
              table(["pipeline", "n", "min", "10°", "mediana", "90°", "max"],
                    rows), ""]
        rows = []
        for m in ("baseline",) + PIPES:
            ids = c.ids(k, m)
            rows.append([NAME[m]] + five([c.val(k, i, m, "mpps")
                                          for i in ids], ".2f"))
        L += [f"Capacita' del nodo, milioni di pacchetti al secondo per core "
              f"({CORE_LABEL[k]}):", "",
              table(["pipeline", "n", "min", "10°", "mediana", "90°", "max"],
                    rows), ""]
        if k == "P":
            for m in PIPES:
                v = [c.nn(k, i, m) for i in c.ids(k, m)]
                if v:
                    claim(f"rete neurale {NAME[m]}, ns per pacchetto (P-core)",
                          spread(v))
    return L


def sec_order(c):
    L = ["## L'ordine fra le pipeline regge su ogni modello?", ""]
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
        L += [f"**{CORE_LABEL[k]}** — rapporto fra i costi della rete "
              f"neurale, mediana [min–max] sui modelli, e su quanti la "
              f"prima costa piu' della seconda:", "",
              table(["confronto", "rapporto", "la prima costa di piu'"], rows),
              "", f"P1 ≤ P2 ≤ P3 su {count(mono)} modelli.", ""]
        if k == "P":
            claim("P1 ≤ P2 ≤ P3 nel costo della rete neurale (P-core)",
                  count(mono))
            for a, b in pairs[1:4]:
                ids = [i for i in c.models if c.nn(k, i, a) and c.nn(k, i, b)
                       and c.nn(k, i, b) > 0]
                claim(f"{NAME[a]} costa {NAME[b]} per",
                      spread([c.nn(k, i, a) / c.nn(k, i, b) for i in ids],
                             ".1f"))
    return L


def sec_size(c):
    if not c.size:
        if c.legacy:
            return ["## Istruzioni caricate contro eseguite", "",
                    "Questa campagna non registrava i programmi caricati "
                    "(prog_size.csv nasce con remeasure_popolazione.sh).", ""]
        return []
    L = ["## Istruzioni caricate contro eseguite", "",
         "Caricate = istruzioni dei programmi della pipeline, contate dal "
         "kernel al caricamento (prog_census). Eseguite = istruzioni per "
         "pacchetto dai contatori hardware, meno la baseline: la sola rete "
         "neurale. ρ = correlazione di rango fra le due sulla popolazione "
         "(1 = la dimensione ordina i modelli come il lavoro).", ""]
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
            claim(f"la dimensione di {NAME[m]} predice il suo lavoro "
                  f"(ρ di rango)", f"{rho:.2f} su {len(ids)} modelli")
    L += [table(["pipeline", "n", "caricate", "eseguite (rete)", "ρ"], rows),
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
        L += [f"P2 piu' grande di P3: {count(bigger)}; P3 esegue piu' di P2: "
              f"{count(works)}; tutte e due insieme (la dimensione ordina "
              f"al contrario del lavoro): {count(both)}.", ""]
        claim("P2 e' il programma piu' grande ma P3 esegue di piu'",
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
        claim("stesse istruzioni per pacchetto su P-core ed E-core",
              f"differenza massima {max(allr):.1f}% su "
              f"{len(allr)} coppie modello-pipeline")
    if lr:
        claim("stesse istruzioni anche sul LP E-core",
              f"differenza massima {max(lr):.1f}% su {len(lr)} coppie")
    return ["## Le istruzioni per pacchetto non dipendono dal core", "",
            "|E/P − 1| delle istruzioni per pacchetto, in %, su ogni modello:",
            "", table(["pipeline", "n", "mediana %", "massimo %"], rows), ""] \
        + ([f"LP E-core contro P-core: massimo {max(lr):.1f}% su {len(lr)} "
            f"coppie.", ""] if lr else [])


def sec_cores(c):
    if "E" not in c.core_dir:
        return []
    L = ["## Che cosa cambia su un core piu' lento", ""]
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
    L += ["Capacita' e IPC dell'E-core in rapporto al P-core (stessa "
          "frequenza, 3,5 GHz), mediana [min–max] sui modelli:", "",
          table(["pipeline", "n", "capacita' E/P", "IPC E/P"], rows), ""]
    # parte fissa contro rete neurale, in cicli
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
    L += [f"Cicli per pacchetto E/P: parte fissa del nodo (baseline) "
          f"{spread(fixed, '.2f')}; rete neurale:", "",
          table(["pipeline", "n", "cicli della rete E/P"], rows), ""]
    rho = spearman(share_x, ratio_y)
    if rho is not None:
        L += [f"Piu' la rete neurale pesa sul pacchetto, meno conta il core: "
              f"ρ di rango fra la quota di cicli della rete (P-core) e la "
              f"capacita' E/P = {rho:.2f} su {len(share_x)} coppie "
              f"modello-pipeline.", ""]
        claim("l'E-core perde soprattutto nella parte fissa del nodo",
              f"cicli fissi E/P {spread(fixed, '.2f')}; ρ(quota rete, "
              f"capacita' E/P) = {rho:.2f}")
    # LP E-core
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
        L += [f"LP E-core (2,5 GHz), {len(lids)} modelli dal piu' leggero al "
              f"piu' pesante:", "",
              table(["pipeline", "n", "capacita' LP/P", "mancate LLC/pk"],
                    rows), ""]
        caps = [c.val("L", i, m, "mpps") / c.val("P", i, m, "mpps")
                for i in lids for m in PIPES
                if c.val("L", i, m, "mpps") and c.val("P", i, m, "mpps")]
        if caps:
            claim("capacita' del LP E-core rispetto al P-core",
                  spread(caps, ".2f"))
    return L


FEATS = {
    "MAC eseguite + strati": ("mac_exec", "n_layers"),
    "MAC dalla forma + strati": ("mac_shape", "n_layers"),
    "MAC eseguite non nulle + strati": ("mac_exec_nz", "n_layers"),
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
    L = ["## Una legge di costo, stimata su tutti i modelli", "",
         "costo della rete = a + b × MAC + c × strati (minimi quadrati sulla "
         "popolazione). Errore = errore relativo su un modello lasciato fuori "
         "dalla stima (mediana e 90° percentile, %): quanto la legge sbaglia "
         "su un modello che non ha visto. Le MAC eseguite contano una one-hot "
         "come una colonna sola; le non nulle tolgono i pesi a zero.", ""]
    # la legge si stima sui modelli densi: i pesi a zero hanno la loro
    # sezione, che la confronta con questa
    fam = ("width", "depth", "isoparam", "nodes", "iv_dense", "iv_onehot")         if c.legacy else ("base", "replica", "imbuto")
    LAWS = {}
    for k in c.core_dir:
        rows, laws = _fit_rows(c, k, "ns", families=fam)
        LAWS[k] = laws
        if rows:
            L += [f"**ns per pacchetto, {CORE_LABEL[k]}**", "",
                  table(["pipeline", "variabili", "n", "a (ns)",
                         "b (ns/MAC)", "c (ns/strato)", "r²", "errore 50°",
                         "errore 90°"], rows), ""]
        rows, ilaws = _fit_rows(c, k, "instr", families=fam)
        if rows and k == "P":
            L += ["**istruzioni per pacchetto, P-core** (stessa forma: "
                  "b in istruzioni per MAC, c per strato)", "",
                  table(["pipeline", "variabili", "n", "a", "b", "c", "r²",
                         "errore 50°", "errore 90°"], rows), ""]
            parts = [f"{NAME[m]} {d[lab][0][2]:.0f} (r² {d[lab][1]:.2f})"
                     for m, d in ilaws.items()
                     for lab in ("MAC eseguite + strati",) if lab in d]
            if parts:
                claim("istruzioni eseguite per strato in piu' (legge, "
                      "P-core)", ", ".join(parts))
    if c.size:
        def loaded(k, i, m, key):
            return c.size.get(i, {}).get(m)
        rows, slaws = _fit_rows(c, None, None, stat=loaded, families=fam)
        if rows:
            L += ["**istruzioni caricate** (dimensione dei programmi, stessa "
                  "forma: b per MAC, c per strato)", "",
                  table(["pipeline", "variabili", "n", "a", "b", "c", "r²",
                         "errore 50°", "errore 90°"], rows), ""]
        parts = []
        for m in PIPES:
            v = [c.size[i][m] for i in c.models if c.size.get(i, {}).get(m)]
            d = slaws.get(m, {}).get("MAC eseguite + strati")
            if v and min(v) == max(v):
                parts.append(f"{NAME[m]} sempre {v[0]:.0f}")
            elif d:
                parts.append(f"{NAME[m]} {d[0][2]:+.0f} (r² {d[1]:.2f})")
        if parts:
            claim("istruzioni caricate per strato in piu' (legge)",
                  ", ".join(parts))
    if c.t2:
        def t2s(k, i, m, key):
            return c.nn_t2(k, i, m)
        rows, _ = _fit_rows(c, "P", None, stat=t2s, families=fam)
        if rows:
            L += ["**ns per pacchetto a traffico leggero (media T2−T1 meno "
                  "la baseline), P-core**", "",
                  table(["pipeline", "variabili", "n", "a (ns)", "b (ns/MAC)",
                         "c (ns/strato)", "r²", "errore 50°", "errore 90°"],
                        rows), ""]
    best = LAWS.get("P", {})
    for m, d in best.items():
        lab = "MAC eseguite + strati"
        if lab in d:
            beta, r2, e50, n = d[lab]
            claim(f"legge di {NAME[m]} (P-core)",
                  f"{beta[0]:.0f} ns + {beta[1]:.2f} ns/MAC + "
                  f"{beta[2]:.0f} ns/strato; r² {r2:.2f}, errore mediano "
                  f"{fmt(e50, '.0f')}% su modelli non visti (n={n})")
    if best:
        better = [m for m, d in best.items()
                  if "MAC eseguite + strati" in d
                  and "MAC dalla forma + strati" in d
                  and d["MAC eseguite + strati"][1]
                  > d["MAC dalla forma + strati"][1]]
        claim("contare le MAC eseguite spiega il costo meglio della forma",
              f"{len(better)}/{len(best)} pipeline")
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
        L += ["## Quanto conta il seme dei pesi", "",
              "Stessa forma, semi diversi (uno con pesi normali): ns di rete "
              "neurale, media ± coefficiente di variazione, P-core.", "",
              table(["gruppo", "modello", "semi"]
                    + [NAME[m] for m in PIPES], rows), ""]
        worst = {m: max(v) for m, v in cvs.items() if v}
        if worst:
            claim("a parita' di forma, i pesi cambiano il costo di",
                  ", ".join(f"{NAME[m]} ≤{v:.0f}%" for m, v in worst.items()))
    # ripetibilita': lo stesso modello misurato in piu' punti
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
        L += ["## Lo stesso modello misurato piu' volte", "",
              "Stessa forma, stessi pesi, cartelle diverse: la dispersione "
              "della misura, non del modello (ns di rete neurale, P-core).",
              "", table(["cartelle"] + [NAME[m] for m in PIPES], rows), ""]
    return L


def sec_sparsity(c, laws):
    ids = [i for i, r in c.models.items()
           if num(r.get("zero_frac")) is not None
           and (r.get("family") == "sparsita"
                or (c.legacy and i.startswith("sparsity_")))]
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
            d = law.get(m, {}).get("MAC eseguite + strati")
            if meas is None or d is None:
                line.append("-")
                continue
            pred = predict(d[0], [num(r["mac_exec"]), num(r["n_layers"])])
            ratios[m].append((num(r["zero_frac"]), meas / pred if pred else
                              None))
            line.append(f"{meas:.0f} ({meas / pred:.2f})" if pred else
                        f"{meas:.0f}")
        rows.append(line)
    out = ["## Pesi a zero", "",
           "ns di rete neurale misurati e, fra parentesi, il rapporto con la "
           "legge stimata sui modelli densi (1 = la sparsita' non cambia "
           "niente, < 1 = il modello dimagrisce):", "",
           table(["modello", "pesi a zero"] + [NAME[m] for m in PIPES], rows),
           ""]
    hi = {m: [r for z, r in v if z >= 0.5 and r] for m, v in ratios.items()}
    if any(hi.values()):
        claim("con ≥50% di pesi a zero, misurato / previsto dalla legge densa",
              ", ".join(f"{NAME[m]} {spread(v, '.2f')}"
                        for m, v in hi.items() if v))
    return out


def sec_shape(c):
    """Larga o profonda: famiglia imbuto (o asse isoparam)."""
    if c.legacy:
        groups = {"ipa65": [i for i in c.models if i.startswith("isoparam_")]}
    else:
        groups = {}
        for i, r in c.models.items():
            if r.get("family") == "imbuto":
                groups.setdefault(r["layout"], []).append(i)
    if not any(groups.values()):
        return []
    L = ["## Larga o profonda, a parita' di pesi", "",
         "Cinque forme per composizione, a pari pesi dentro ognuna (~600 "
         "con ipa65, ~210-270 con dense17; a 4-5 strati le MAC eseguite "
         "crescono del 16-43 %), da 1 a 5 strati: ns di rete neurale "
         "con 1 strato → con 5, e la pendenza per strato (minimi quadrati), "
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
    L += [table(["composizione", "pipeline", "1 → 5 strati", "variazione",
                 "ns per strato"], rows), ""]
    if any(slopes.values()):
        claim("a parita' di pesi, ogni strato in piu' costa (ns, P-core)",
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
    L = ["## Traffico leggero contro nodo saturo", "",
         "A traffico leggero (T2−T1, sotto la capacita') contro a nodo "
         "saturo (tempo di CPU), sempre la sola rete neurale. media/saturo "
         "≈ 1 vuol dire che il costo di un pacchetto non dipende dal carico; "
         "minimo/media dice quanto costa il pacchetto che trova cache e "
         "predittori caldi rispetto a quello tipico.", "",
         table(["core", "pipeline", "n", "media leggero / saturo",
                "minimo / media"], rows), ""]
    # Per pipeline, mai mescolate: P2 e P3 stanno attorno a 1, P1 e P1.5 no
    # (sotto il P-core, sopra sull'E-core), e una sola cifra le nasconderebbe.
    for k in c.core_dir:
        parts = []
        for m in PIPES:
            v = [c.nn_t2(k, i, m) / c.nn(k, i, m) for i in c.models
                 if c.nn_t2(k, i, m) is not None and c.nn(k, i, m)]
            if v:
                parts.append(f"{NAME[m]} {spread(v, '.2f')}")
        if parts:
            claim(f"costo a traffico leggero / costo a nodo saturo "
                  f"({CORE_LABEL[k]})", ", ".join(parts))
    return L + sec_transport(c)


def sec_transport(c):
    """T3-T2: redirect, cavo virtuale e ricezione al nodo successivo, dalla
    stessa misura a tre orologi. Il minimo e' il trasporto senza attesa; la
    media aggiunge la coda, perche' in questa misura l'uscita gira sul core
    del nodo, e cresce col rate. Che non dipenda dalla pipeline lo si
    verifica su ogni modello: differenza fra la piu' cara e la meno cara."""
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
    claim("il trasporto (T3−T2 minimo, senza attesa) e' un costo comune, ns",
          ", ".join(f"{CORE_LABEL[k]} {spread(v)}" for k, v in mins.items()))
    if gap:
        claim("il trasporto non dipende dalla pipeline",
              f"differenza fra la piu' cara e la meno cara {spread(gap)}% "
              f"su {len(gap)} modelli-core")
    return ["## Il trasporto verso il nodo successivo", "",
            "T3−T2 (redirect, cavo virtuale, ricezione) dalla misura a tre "
            "orologi, ns. Il minimo e' il trasporto senza attesa. La media "
            "contiene anche la coda: qui l'uscita gira sul core del nodo, e "
            "la media cresce col rate.", "",
            table(["core", "programma", "n", "minimo", "media per rate"],
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
                # due contatori letti in istanti diversi: una differenza
                # appena negativa e' zero, non una perdita negativa (dava
                # quote sopra 1)
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
        claim("il massimo inoltrato al crescere del rate coincide con la "
              "capacita' a massima spinta (entro il rumore fra sessioni)",
              f"rapporto {spread(agree, '.2f')} su {len(agree)} curve")
    if ingress:
        claim("oltre la capacita' si perde prima del programma, alla coda",
              f"quota persa prima di XDP {spread(ingress, '.3f')}")
    return ["## Al crescere del traffico", "",
            "Ginocchio = rate chiesto piu' alto senza perdite; massimo "
            "inoltrato contro la capacita' misurata a massima spinta sullo "
            "stesso modello.", "",
            table(["core", "modello", "pipeline", "ginocchio Mpps",
                   "max inoltrati", "capacita'", "collo"], rows), ""]


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
    # un core e due core vengono da sessioni diverse: un valore sopra 100
    # e' rumore di misura (sec_noise), non un guadagno
    claim("due core reggono il doppio di uno (entro il rumore fra sessioni)",
          f"{spread(scal)}% del doppio su {len(scal)} coppie")
    return ["## Due core del nodo", "",
            table(["core", "modello", "pipeline", "1 core", "2 core",
                   "% del doppio"], rows), ""]


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
    claim("le classi che inoltrano costano uguale",
          f"differenza fra la piu' cara e la meno cara {spread(fwd_spread)}%")
    if drop_extra:
        claim("scartare costa in piu' (effetto del banco: la memoria del "
              "pacchetto si libera sul nodo)", f"{spread(drop_extra)} ns")
    return ["## Classi diverse", "",
            "Una sessione per classe decisa: differenza fra la classe che "
            "inoltra piu' cara e la meno cara, e quanto costa in piu' "
            "scartare (ns, mediana delle classi).", "",
            table(["modello", "pipeline", "classi FORWARD", "spread FORWARD",
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
    claim("TTL diversi pacchetto per pacchetto contro pacchetto fisso",
          f"{spread(rel)}% sul tempo del nodo")
    return ["## Pacchetti tutti uguali contro pacchetti diversi", "",
            "TTL diversi a ogni pacchetto (2–31): il modello decide classi "
            "diverse, compreso lo scarto. ns di CPU per pacchetto contro il "
            "pacchetto fisso dello stesso modello.", "",
            table(["modello", "pipeline", "fisso", "TTL misti", "Δ"], rows),
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
    claim("la taglia del pacchetto non cambia il costo",
          f"differenza fra 64 e 1514 byte {spread(var, '.1f')}% "
          f"({len(var)} coppie)")
    return ["## Taglia del pacchetto", "",
            f"Differenza fra la taglia piu' cara e la meno cara, per modello "
            f"e pipeline: {spread(var, '.1f')}% su {len(var)} coppie.", ""]


def sec_solo(c):
    """Il programma da solo (bench_solo.py, BPF_PROG_TEST_RUN), su ogni
    modello: la sua latenza contro il traffico, il tempo per installare un
    modello, le letture di tabella e i salti per pacchetto."""
    root = os.path.join(c.base, "solo")
    if not os.path.isdir(root):
        return []
    # Una misura vale solo se il programma ha preso la strada del traffico:
    # inoltrato in (quasi) ogni esecuzione. Un solo.csv senza fwd_pct viene
    # da bench_solo con il pacchetto di bench_scaling (TTL 255), dove un
    # modello su quattro scartava: non si usa.
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
        """La sola rete da sola: la pipeline meno la baseline dello stesso
        modello. Con key="lat_hot" il ciclo caldo, solo dove il blocco
        e' lungo almeno HOT_MIN_K esecuzioni per entrambe."""
        if key == "lat_hot" and any((v(mid, x, "hot_k") or 0) < HOT_MIN_K
                                    for x in (m, "baseline")):
            return None
        a, b = v(mid, m, key), v(mid, "baseline", key)
        return a - b if a is not None and b is not None else None

    # generare il C di P1 e compilarlo (bench_solo.py --compila, senza
    # kernel): un modello nuovo per P1 costa questo, fuori dal nodo
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
        # sotto traffico (media T2-T1 a traffico leggero, minimo, e tempo
        # di CPU a nodo saturo, tutti meno la baseline) / da solo
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
        claim("programma da solo fuori dalla strada del traffico (non "
              "inoltrato)", f"{len(off)} misure modello-pipeline")
    L = ["## Il programma da solo", "",
         "bench_solo.py su ogni modello, P-core: latenza da solo "
         "(BPF_PROG_TEST_RUN, minimo su 7 misure), e la sola rete (meno la "
         "baseline dello stesso modello); build = caricare la pipeline da "
         "zero; installare = un modello nuovo su un nodo in servizio (P1: "
         "caricare l'oggetto compilato; P2, P3: scrivere le tabelle); "
         "letture di tabella e salti per pacchetto. Pacchetto e ingressi "
         "sono quelli del traffico (TTL 32, stato dei link che inoltra); "
         "una misura che non ha inoltrato resta fuori"
         + (f" ({len(off)}: {', '.join(off[:12])}"
            + (" ..." if len(off) > 12 else "") + ")" if off else "")
         + ".", "",
         table(["pipeline", "n", "chiamata singola ns", "rete ns",
                "rete, ciclo caldo ns", "build ms", "generare e compilare "
                "P1 ms", "installare ms", "letture", "salti"], rows), "",
         f"Ciclo caldo: blocchi di esecuzioni di fila finche' il TTL che "
         f"scende non cambia la classe decisa; si usa solo dove il blocco e' "
         f"lungo almeno {HOT_MIN_K} esecuzioni.", ""]
    rows2 = []
    for m in PIPES:
        if light.get(m) or sat.get(m):
            rows2.append([NAME[m], spread(hot_sat.get(m, []), ".2f"),
                          spread(hot_light.get(m, []), ".2f"),
                          spread(sat.get(m, []), ".2f"),
                          spread(light.get(m, []), ".2f")])
    if rows2:
        L += ["La sola rete sotto traffico divisa per la sola rete da sola, "
              "modello per modello:", "",
              table(["pipeline", "nodo saturo / ciclo caldo",
                     "traffico leggero, minimo / ciclo caldo",
                     "nodo saturo / chiamata singola",
                     "traffico leggero, media / chiamata singola"], rows2), ""]
        if any(hot_sat.values()):
            claim("la rete a nodo saturo / la rete da sola in un ciclo caldo "
                  "(P-core)",
                  ", ".join(f"{NAME[m]} {spread(hot_sat[m], '.2f')}"
                            for m in PIPES if hot_sat.get(m)))
            claim("il pacchetto piu' veloce sotto traffico / il ciclo caldo",
                  ", ".join(f"{NAME[m]} {spread(hot_light[m], '.2f')}"
                            for m in PIPES if hot_light.get(m)))
        else:
            # misure di bench_solo senza ciclo caldo: il confronto e' con la
            # chiamata singola, che non e' il programma in cache
            claim("la rete a nodo saturo / la rete da sola a chiamate "
                  "singole (P-core)",
                  ", ".join(f"{NAME[m]} {spread(sat[m], '.2f')}"
                            for m in PIPES if sat.get(m)))
    if comp:
        claim("generare e compilare P1 per un modello nuovo (fuori dal "
              "nodo), ms", ", ".join(f"{NAME[m]} {spread(v_, '.0f')}"
                                    for m, v_ in comp.items()))
    claim("installare un modello su un nodo in servizio, ms",
          ", ".join(f"{NAME[m]} {spread(u, '.1f')}" for m, u in upd if
                    any(x is not None for x in u)))
    claim("letture di tabella per pacchetto",
          ", ".join(f"{NAME[m]} {spread(x, '.0f')}" for m, x in lk if
                    any(y is not None for y in x)))
    # P3: letture e salti contro gli strati
    pts = [(num(c.models[i]["n_layers"]), v(i, "modular", "lookups"),
            v(i, "modular", "n_tail")) for i in solo]
    pts = [p for p in pts if p[1] is not None]
    if len(pts) > 3:
        f = CR._fit([p[0] for p in pts], [p[1] for p in pts])
        same = sum(1 for p in pts if p[2] == p[0])
        claim("P3: letture di tabella e salti crescono con gli strati",
              f"+{f[0]:.1f} letture per strato; salti = strati su "
              f"{same}/{len(pts)} modelli")
    return L


def noise(c):
    """Quanto varia la stessa misura: dentro una misura (i giri), fra sessioni
    con lo stesso programma (il nodo senza rete, in ogni sessione `pop`), e
    fra sessioni con lo stesso modello e la stessa versione (le taglie a 64
    byte contro `pop`). In % del valore; liste, per spread() e quant()."""
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
    """Il rumore di misura: la soglia sotto cui una differenza non e' una
    differenza. Due misure di sessioni diverse (un core contro due, il
    massimo di una curva contro la capacita') possono dare un rapporto
    sopra 1 anche dove fisicamente non puo' esserlo."""
    n = noise(c)
    if not (n["within"] or n["same"]):
        return []
    L = ["## Quanto varia la stessa misura", "",
         "Variazione in % del valore: mediana, 90° percentile, massimo. Una "
         "differenza dentro la variazione fra sessioni non e' una differenza; "
         "un rapporto fra due misure di sessioni diverse puo' superare 1 per "
         "questo solo motivo.", ""]
    rows = []
    if n["within"]:
        rows.append(["i giri di una misura ((max − min) / mediana)",
                     str(len(n["within"])), fmt(quant(n["within"], .5), ".1f"),
                     fmt(quant(n["within"], .9), ".1f"),
                     fmt(max(n["within"]), ".1f")])
    for k, v in n["base"].items():
        rows.append([f"il nodo senza rete in sessioni diverse, {CORE_LABEL[k]}",
                     str(len(v)), fmt(quant(v, .5), ".1f"),
                     fmt(quant(v, .9), ".1f"), fmt(max(v), ".1f")])
    if n["same"]:
        rows.append(["stesso modello e versione, due sessioni",
                     str(len(n["same"])), fmt(quant(n["same"], .5), ".1f"),
                     fmt(quant(n["same"], .9), ".1f"),
                     fmt(max(n["same"]), ".1f")])
        claim("la stessa misura rifatta in un'altra sessione cambia di",
              f"{quant(n['same'], .5):.1f} % in mediana, "
              f"{quant(n['same'], .9):.1f} % al 90° percentile, "
              f"{max(n['same']):.1f} % al massimo ({len(n['same'])} coppie)")
    L += [table(["che cosa", "n", "mediana %", "90° %", "max %"], rows), ""]
    return L


def sec_excluded(c):
    """Le misure lasciate fuori da ogni cifra, e perche'. Dopo tutte le altre
    sezioni: i sottoinsiemi si leggono sezione per sezione. L'elenco va anche
    in escluse.csv accanto ai risultati: POP_RIFAI_DISTURBATE=1
    remeasure_popolazione.sh rifa' esattamente quelle."""
    if not c.seen:
        return []
    try:
        with open(os.path.join(c.base, "escluse.csv"), "w", newline="",
                  encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["cartella", "motivo"])
            w.writerows(sorted(c.excluded.items()))
    except OSError:
        pass
    claim("misure fuori dalle conclusioni (disturbate o bocciate)",
          f"{len(c.excluded)}/{len(c.seen)}")
    if c.salvaged:
        out = sum(a for a, _ in c.salvaged.values())
        tot = sum(b for _, b in c.salvaged.values())
        claim("misure disturbate tenute senza i giri colpiti",
              f"{len(c.salvaged)} misure, {out}/{tot} giri o finestre tolti")
    if not c.excluded and not c.salvaged:
        return []
    by = {}
    for rel, why in sorted(c.excluded.items()):
        by.setdefault(why, []).append(rel)
    L = ["## Misure fuori dalle conclusioni", "",
         "Non entrano in nessun intervallo ne' in nessuna legge. disturbata = "
         "la macchina non e' rimasta nelle condizioni dichiarate (run_disturbed "
         "in env.csv); bocciata = il controllo di validita' del banco l'ha "
         "respinta (throughput_report.md). Si rifanno con POP_RIFAI_DISTURBATE=1 "
         "remeasure_popolazione.sh.", ""]
    for why, rels in by.items():
        L += [f"**{why}** ({len(rels)}): " + ", ".join(rels), ""]
    if c.salvaged:
        L += [f"**misure tenute senza i giri disturbati** (curve: ogni punto, "
              f"massima spinta: ogni pipeline, con almeno {MIN_CLEAN_ROUNDS} "
              f"giri puliti; massima spinta solo se il disturbo e' throttling, "
              f"tolti i giri entro {EVENT_MARGIN_S:g} s da un evento): "
              + ", ".join(f"{rel} ({a}/{b})"
                          for rel, (a, b) in sorted(c.salvaged.items())), ""]
    return L


def sec_sums():
    if not SUMS:
        return []
    return ["## Le somme", "",
            "Ogni riga e' un'affermazione e la sua prova sulla popolazione: "
            "su quanti modelli regge, o l'intervallo che copre.", "",
            table(["affermazione", "sulla popolazione"],
                  [[a, b] for a, b in SUMS]), ""]


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        sys.exit(__doc__.split("\n\n")[0])
    c = Campaign(argv[0])
    if not c.models:
        sys.exit(f"{argv[0]}: ne' population.csv ne' assi_<P|E>core")
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
    out = [f"# Sintesi sulla popolazione: {title}", ""] + sec_sums() + body
    print("\n".join(out))


if __name__ == "__main__":
    main()
