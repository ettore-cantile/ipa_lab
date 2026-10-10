#!/usr/bin/env python3
"""campaign_report.py -- le tabelle della campagna (remeasure_campagna.sh),
in markdown, dai CSV che i banchi hanno scritto.

    python3 ipa/test/campaign_report.py results/campagna_2026-10-06 > sintesi.md

Legge, se ci sono:
    <sez>/compare/compare.csv      capacita' a un core   (sez = pcore, ecore, lpe)
    <sez>/cores2/compare.csv       capacita' a due core
    <sez>/bitrate/bitrate.csv      curve al crescere del rate
    <sez>/rates/rates_raw.csv      tre marcature
    pcore/per_class/per_class.csv  costo per classe
    pcore/frames/compare.csv       costo per taglia
    assi_<P|E>core/<asse>_<punto>/compare.csv
    assi_<P|E>core/<asse>_<punto>/rates/rates_raw.csv   T2-T1 sugli assi
    assi_<P|E>core/checkpoint/rates/rates_raw.csv       T2-T1 del checkpoint

Niente root, niente BCC: si puo' rifare a mano su una campagna gia' raccolta.
Una cella senza dato resta "-".
"""
import csv
import os
import re
import statistics
import sys

PIPES = ("rxonly", "baseline", "p1_static", "hardcoded", "template", "modular")
NAME = {"rxonly": "rxonly", "baseline": "baseline", "p1_static": "P1",
        "hardcoded": "P1.5", "template": "P2", "modular": "P3"}
CORES = (("pcore", "P-core"), ("ecore", "E-core"), ("lpe", "LP E-core"))
LOSS_OK = 0.1           # % di perdita sotto cui un punto della curva e' pulito


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_env(path):
    return {r["campo"]: r["valore"] for r in read_csv(path)
            if "campo" in r and "valore" in r}


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def fmt(v, spec=".0f"):
    return "-" if v is None else format(v, spec)


def table(head, rows):
    out = ["| " + " | ".join(head) + " |",
           "|" + "|".join("---:" if i else "---" for i in range(len(head)))
           + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def saturation(rows, frame="64"):
    """{metodo: riga} della fase di saturazione, una taglia."""
    out = {}
    for r in rows:
        if r.get("phase", "saturazione") != "saturazione":
            continue
        if frame and r.get("frame") not in (None, "", frame):
            continue
        out[r["method"]] = r
    return out


def node_mpps(r):
    for k in ("proc_pps", "hit_pps", "rx_pps"):
        v = num(r.get(k))
        if v:
            return v / 1e6
    return None


def dut_freq(env):
    """La frequenza misurata del DUT, da env.csv (MHz), o None."""
    txt = env.get("host_frequenza_misurata", "")
    dut = env.get("cpu_dut", "").split(",")[0].strip()
    m = re.search(rf"cpu{dut} (\d+) MHz", txt) if dut else None
    return int(m.group(1)) if m else None


def disturbed(env):
    v = env.get("host_finestre_disturbate") or env.get("host_disturbato")
    return v


# --------------------------------------------------------------------------
def sec_capacity(base):
    L = ["## Capacita' a un core: lo stesso nodo su core diversi", ""]
    data, freq = {}, {}
    for sec, label in CORES:
        d = os.path.join(base, sec, "compare")
        rows = saturation(read_csv(os.path.join(d, "compare.csv")))
        if rows:
            data[sec] = rows
            freq[sec] = dut_freq(read_env(os.path.join(d, "env.csv")))
    if not data:
        return []
    L.append("Nodo: " + "; ".join(
        f"{dict(CORES)[s]} a {fmt(freq[s])} MHz misurati" for s in data)
        + ". Generatore e uscita su P-core in tutte le righe.")
    L.append("")
    head = ["pipeline"]
    for s in data:
        lab = dict(CORES)[s]
        head += [f"{lab} Mpps", f"{lab} ns CPU", f"{lab} cicli/pk",
                 f"{lab} istr/pk", f"{lab} IPC"]
    rows = []
    for m in PIPES:
        if not any(m in data[s] for s in data):
            continue
        row = [NAME[m]]
        for s in data:
            r = data[s].get(m, {})
            row += [fmt(node_mpps(r), ".2f") if r else "-",
                    fmt(num(r.get("ns_cpu"))), fmt(num(r.get("cycles_pkt"))),
                    fmt(num(r.get("instr_pkt"))),
                    fmt(num(r.get("ipc")), ".2f")]
        rows.append(row)
    L.append(table(head, rows))
    L.append("")

    # rapporti contro il P-core
    if "pcore" in data and len(data) > 1:
        L.append("Rapporto con il P-core (capacita', cicli per pacchetto, "
                 "istruzioni per pacchetto, IPC):")
        L.append("")
        head = ["pipeline"]
        others = [s for s in data if s != "pcore"]
        for s in others:
            lab = dict(CORES)[s]
            head += [f"{lab}/P Mpps", f"{lab}/P cicli", f"{lab}/P istr",
                     f"{lab}/P IPC"]
        rows = []
        for m in PIPES:
            p = data["pcore"].get(m)
            if not p:
                continue
            row = [NAME[m]]
            for s in others:
                r = data[s].get(m) or {}

                def ratio(get):
                    a, b = get(r), get(p)
                    return fmt(a / b, ".2f") if a and b else "-"
                row += [ratio(node_mpps),
                        ratio(lambda x: num(x.get("cycles_pkt"))),
                        ratio(lambda x: num(x.get("instr_pkt"))),
                        ratio(lambda x: num(x.get("ipc")))]
            rows.append(row)
        L.append(table(head, rows))
        L.append("")

    # dettaglio dei contatori
    det = []
    for s in data:
        for m in PIPES:
            r = data[s].get(m)
            if not r or num(r.get("ipc")) is None:
                continue
            det.append([dict(CORES)[s], NAME[m],
                        fmt(num(r.get("llc_miss_pkt")), ".3f"),
                        fmt(num(r.get("br_miss_pkt")), ".3f"),
                        fmt(num(r.get("dut_ghz_busy")), ".2f"),
                        fmt(num(r.get("cpu_dut_pct")), ".0f"),
                        fmt(num(r.get("egress_cycles_pkt"))),
                        fmt(num(r.get("respinti_pct")), ".1f")])
    if det:
        L.append("Contatori per pacchetto (LLC = mancate dell'ultimo livello, "
                 "GHz = cicli/(durata x core), uscita = cicli del core "
                 "d'uscita per pacchetto):")
        L.append("")
        L.append(table(["core", "pipeline", "LLC/pk", "br-miss/pk", "GHz",
                        "nodo %", "uscita cicli/pk", "respinti %"], det))
        L.append("")
    return L


def sec_cores2(base):
    L = []
    rows = []
    for sec, label in CORES:
        one = saturation(read_csv(os.path.join(base, sec, "compare",
                                               "compare.csv")))
        two = saturation(read_csv(os.path.join(base, sec, "cores2",
                                               "compare.csv")))
        for m in PIPES:
            if m not in two:
                continue
            a, b = node_mpps(one.get(m, {})), node_mpps(two[m])
            rows.append([label, NAME[m], fmt(a, ".2f"), fmt(b, ".2f"),
                         fmt(b / a / 2 * 100 if a and b else None, ".0f"),
                         fmt(num(two[m].get("ns_cpu"))),
                         fmt(num(two[m].get("ipc")), ".2f"),
                         fmt(num(two[m].get("respinti_pct")), ".1f")])
    if rows:
        L += ["## Due core del nodo", "",
              table(["core", "pipeline", "1 core Mpps", "2 core Mpps",
                     "% del doppio", "ns CPU per core", "IPC",
                     "respinti %"], rows), ""]
    return L


def knee(rows, method):
    """(ultimo rate chiesto senza perdita, massimo inoltrato) di una curva."""
    pts = [r for r in rows if r.get("method") == method]
    if not pts:
        return None, None, None
    clean = [num(r["rate_requested_pps"]) for r in pts
             if (num(r.get("loss_total_pct")) or 0) <= LOSS_OK
             and r.get("gen_limited") != "True"]
    key = "forwarded_pps" if method != "rxonly" else "rx_pps"
    best = max(pts, key=lambda r: num(r.get(key)) or 0)
    return (max(clean) / 1e6 if clean else None,
            (num(best.get(key)) or 0) / 1e6, best)


def sec_bitrate(base):
    L = []
    rows = []
    for sec, label in CORES:
        br = read_csv(os.path.join(base, sec, "bitrate", "bitrate.csv"))
        if not br:
            continue
        for m in PIPES:
            k, mx, best = knee(br, m)
            if mx is None:
                continue
            lat = [r for r in br if r.get("method") == m
                   and num(r.get("e2e_latency_p50_us")) is not None]
            lat_lo = min(lat, key=lambda r: num(r["rate_requested_pps"])) \
                if lat else None
            rows.append([label, NAME[m], fmt(k, ".1f"), fmt(mx, ".2f"),
                         fmt(num(lat_lo.get("e2e_latency_p50_us")) if lat_lo
                             else None, ".0f"),
                         fmt(num(best.get("e2e_latency_p50_us")), ".0f"),
                         fmt(num(best.get("ipc")), ".2f"),
                         best.get("bottleneck", "-") or "-"])
    if rows:
        L += ["## Saturazione al crescere del rate (bench_bitrate)", "",
              f"Ginocchio = rate chiesto piu' alto con perdita totale <= "
              f"{LOSS_OK}% (finestre limitate dal generatore escluse). "
              f"Latenze end-to-end mediane, in µs.", "",
              table(["core", "pipeline", "ginocchio Mpps", "max inoltrati Mpps",
                     "p50 a basso carico", "p50 al massimo", "IPC al massimo",
                     "collo"], rows), ""]
    return L


def sec_rates(base):
    L = []
    rows = []
    for sec, label in CORES:
        rr = read_csv(os.path.join(base, sec, "rates", "rates_raw.csv"))
        if not rr:
            continue
        for m in PIPES[1:]:
            pts = [r for r in rr if r.get("method") == m]
            if not pts:
                continue
            pipe = [num(r.get("pipe_min_ns")) for r in pts
                    if num(r.get("rate_req_pps") or 0) >= 4e5
                    and num(r.get("pipe_min_ns"))]
            xp = [num(r.get("xport_min_ns")) for r in pts
                  if num(r.get("rate_req_pps") or 0) >= 4e5
                  and num(r.get("xport_min_ns"))]
            lo = min(num(r.get("rate_req_pps")) or 0 for r in pts)
            e2e = [num(r.get("e2e_min_ns")) for r in pts
                   if num(r.get("rate_req_pps")) == lo
                   and num(r.get("e2e_min_ns"))]
            rows.append([label, NAME[m],
                         fmt(statistics.median(pipe) if pipe else None),
                         fmt(statistics.median(xp) if xp else None),
                         fmt(statistics.median(e2e) if e2e else None)])
    if rows:
        L += ["## Tre marcature (build strumentata)", "",
              "T2−T1 = la sola pipeline, T3−T2 = redirect + veth + ricezione "
              "(mediana dei minimi da 0,5 Mpps in su); T3−T1 al rate piu' "
              "basso = latenza minima arrivo → ripartenza. ns.", "",
              table(["core", "pipeline", "T2−T1", "T3−T2", "T3−T1 minimo"],
                    rows), ""]
    return L


def sec_per_class(base):
    rows = read_csv(os.path.join(base, "pcore", "per_class", "per_class.csv"))
    rows = [r for r in rows if r.get("phase") == "saturazione"]
    if not rows:
        return []
    classes = sorted({r["scenario_class"] for r in rows}, key=int)
    acts = {r["scenario_class"]: r.get("scenario_action", "") for r in rows}
    head = ["pipeline"] + [f"classe {c} ({acts[c][:3]})" for c in classes]
    out = []
    for m in PIPES[1:]:
        line = [NAME[m]]
        for c in classes:
            r = next((x for x in rows if x["method"] == m
                      and x["scenario_class"] == c), None)
            v = num(r.get("ns_cpu")) if r else None
            ipc = num(r.get("ipc")) if r else None
            line.append(fmt(v) + (f" ({ipc:.2f})" if ipc else ""))
        out.append(line)
    return ["## Per classe, P-core (ns di CPU, IPC fra parentesi)", "",
            table(head, out), ""]


def sec_frames(base):
    rows = read_csv(os.path.join(base, "pcore", "frames", "compare.csv"))
    rows = [r for r in rows if r.get("phase") == "saturazione"]
    if not rows:
        return []
    frames = sorted({r["frame"] for r in rows}, key=int)
    out = []
    for m in PIPES:
        line = [NAME[m]]
        for f in frames:
            r = next((x for x in rows if x["method"] == m
                      and x["frame"] == f), None)
            line.append(fmt(num(r.get("ns_cpu"))) if r else "-")
        if len(line) > 1 and any(v != "-" for v in line[1:]):
            out.append(line)
    return ["## Per taglia del frame, P-core (ns di CPU)", "",
            table(["pipeline"] + [f"{f} B" for f in frames], out), ""]


AXIS_TITLE = {"width": "Larghezza: 65-v-v-7", "depth": "Profondita': 65-4×d-7",
              "isoparam": "A parita' di pesi (~592): da 1 a 5 strati",
              "sparsity": "Sparsita': % di pesi a zero, 65-4-4-7",
              "nodes": "Nodi della rete: (13+n)-4-4-7",
              "iv_dense": "Ingressi densi: n-8-8-7, ogni colonna moltiplicata",
              "iv_onehot": "Ingressi one-hot: n-8-8-7, la larghezza in una one-hot"}
AXES_ORDER = tuple(AXIS_TITLE)
# Gli esperimenti della retta "costo per moltiplicazione" (slide del costo per
# MAC): ingressi densi, ingressi one-hot, larghezza, profondita'.
MAC_AXES = ("iv_dense", "iv_onehot", "width", "depth")
TRAFFIC_MODELS = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "synth", "traffic")


def point_of(sub, axis):
    """Il punto di una cartella `<asse>_<punto>`, o None se non e' di
    quell'asse (iv_dense_5 -> 5; depth_2 non e' di `depth_camp`)."""
    if not sub.startswith(axis + "_"):
        return None
    rest = sub[len(axis) + 1:]
    return int(rest) if rest.isdigit() else None


def sec_axes(base):
    L = []
    dirs = sorted(d for d in os.listdir(base)
                  if d.startswith("assi_") and os.path.isdir(
                      os.path.join(base, d))) if os.path.isdir(base) else []
    if not dirs:
        return []
    L += ["## Assi parametrici sotto traffico (xdp_gen)", "",
          "Per ogni punto: ns di CPU per pacchetto, poi istruzioni per "
          "pacchetto e IPC. La baseline (senza inferenza) e' nella colonna "
          "di riferimento.", ""]
    for axis in AXES_ORDER:
        for d in dirs:
            core = d.split("_", 1)[1]
            pts = []
            for sub in os.listdir(os.path.join(base, d)):
                p = point_of(sub, axis)
                if p is not None:
                    pts.append((p, sub))
            if not pts:
                continue
            pts.sort()
            head = ["punto", "baseline"] + [
                NAME[m] for m in PIPES[2:]]
            rows_ns, rows_hw = [], []
            for p, sub in pts:
                sat = saturation(read_csv(os.path.join(base, d, sub,
                                                       "compare.csv")))
                rows_ns.append([str(p)] + [fmt(num(sat.get(m, {})
                                                   .get("ns_cpu")))
                                           for m in PIPES[1:]])
                rows_hw.append([str(p)] + [
                    (fmt(num(sat[m].get("instr_pkt"))) + " / "
                     + fmt(num(sat[m].get("ipc")), ".2f"))
                    if m in sat and num(sat[m].get("ipc")) else "-"
                    for m in PIPES[1:]])
            L += [f"### {AXIS_TITLE[axis]} — nodo su {core}", "",
                  "ns di CPU per pacchetto:", "", table(head, rows_ns), "",
                  "istruzioni per pacchetto / IPC:", "",
                  table(head, rows_hw), ""]
            rows_t2 = [[str(p)] + axis_t2(os.path.join(base, d, sub, "rates"))
                       for p, sub in pts]
            if any(v != "-" for r in rows_t2 for v in r[1:]):
                L += ["T2−T1, la sola pipeline (build strumentata), minimo / "
                      "media in ns, mediana fra giri e rate:", "",
                      table(head, rows_t2), ""]
    return L


def axis_t2(rates_dir):
    """Per pipeline 'minimo / media' di T2−T1 da un rates_raw.csv degli assi:
    mediana fra giri e rate (T2−T1 e' piatto sul rate)."""
    rr = read_csv(os.path.join(rates_dir, "rates_raw.csv"))
    out = []
    for m in PIPES[1:]:
        pts = [r for r in rr if r.get("method") == m]
        mins = [num(r.get("pipe_min_ns")) for r in pts
                if num(r.get("pipe_min_ns"))]
        avgs = [num(r.get("pipe_avg_ns")) for r in pts
                if num(r.get("pipe_avg_ns"))]
        out.append(f"{fmt(statistics.median(mins))} / "
                   f"{fmt(statistics.median(avgs) if avgs else None)}"
                   if mins else "-")
    return out


def t2_net(rates_dir, stat="pipe_avg_ns"):
    """{pipeline: ns di rete neurale} da un rates_raw.csv: T2-T1 (mediana fra
    giri e rate) meno quello della baseline. Vuoto se manca."""
    rr = read_csv(os.path.join(rates_dir, "rates_raw.csv"))
    med = {}
    for m in PIPES[1:]:
        v = [num(r.get(stat)) for r in rr if r.get("method") == m
             and num(r.get(stat))]
        if v:
            med[m] = statistics.median(v)
    b = med.pop("baseline", None)
    return {m: v - b for m, v in med.items()} if b is not None else {}


def sec_checkpoint_t2(base):
    rows = []
    for d, label in (("assi_Pcore", "P-core"), ("assi_Ecore", "E-core"),
                     ("assi_Lcore", "LP E-core")):
        rd = os.path.join(base, d, "checkpoint", "rates")
        lo, avg = t2_net(rd, "pipe_min_ns"), t2_net(rd, "pipe_avg_ns")
        if avg:
            rows.append([label] + [f"{fmt(lo.get(m))} / {fmt(avg.get(m))}"
                                   for m in PIPES[2:]])
    if not rows:
        return []
    return ["## La sola rete neurale del checkpoint (T2−T1, xdp_gen)", "",
            "ns di rete neurale per pacchetto, minimo / media, baseline "
            "sottratta (stessi rate degli assi):", "",
            table(["core"] + [NAME[m] for m in PIPES[2:]], rows), ""]


def executed_macs(model_dir):
    """(MAC eseguite, MAC dalla forma) di un modello degli assi. Una one-hot
    attiva una colonna sola: h1 addizioni, qualunque sia la sua larghezza
    (bench_scaling.mac_count_eff); le colonne dense contano per intero."""
    import json
    with open(os.path.join(model_dir, "model.json")) as f:
        mj = json.load(f)
    hidden = [int(h) for h in mj["arch"]["hidden"]]
    n_out = int(mj["arch"]["n_out"])
    h1 = hidden[0] if hidden else n_out
    first_eff = first_nom = 0
    for f in mj["descriptor"]:
        size = int(f["size"])
        first_nom += size * h1
        first_eff += h1 if f.get("kind") == "onehot" else size * h1
    rest = hidden + [n_out]
    tail = sum(rest[i - 1] * rest[i] for i in range(1, len(rest)))
    return first_eff + tail, first_nom + tail


def _fit(xs, ys):
    """(pendenza, intercetta, r2) dei minimi quadrati, o None."""
    n = len(xs)
    if n < 3 or len(set(xs)) < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    m = sxy / sxx
    q = my - m * mx
    ss_res = sum((y - (m * x + q)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - my) ** 2 for y in ys)
    return m, q, (1 - ss_res / ss_tot) if ss_tot else 1.0


def sec_mac_fit(base):
    """La retta 'costo per MAC eseguita' rifatta sotto traffico: ns di rete
    neurale (media T2-T1, baseline sottratta) contro MAC eseguite, sui
    quattro esperimenti di MAC_AXES."""
    L = []
    for d, label in (("assi_Pcore", "P-core"), ("assi_Ecore", "E-core")):
        root = os.path.join(base, d)
        if not os.path.isdir(root):
            continue
        pts = {m: [] for m in PIPES[2:]}
        for sub in sorted(os.listdir(root)):
            if not any(point_of(sub, a) is not None for a in MAC_AXES):
                continue
            mdir = os.path.join(TRAFFIC_MODELS, sub)
            net = t2_net(os.path.join(root, sub, "rates"))
            if not net or not os.path.exists(os.path.join(mdir, "model.json")):
                continue
            eff, nom = executed_macs(mdir)
            for m, v in net.items():
                if m in pts:
                    pts[m].append((eff, nom, v))
        rows = []
        for m, p in pts.items():
            fe = _fit([x[0] for x in p], [x[2] for x in p])
            fn = _fit([x[1] for x in p], [x[2] for x in p])
            if fe:
                rows.append([NAME[m], str(len(p)), f"{fe[0]:.2f}",
                             f"{fe[2]:.2f}", f"{fn[2]:.2f}" if fn else "-"])
        if rows:
            L += [f"## Costo per MAC eseguita sotto traffico — nodo su {label}",
                  "", "Media T2−T1 meno la baseline contro le MAC eseguite "
                  "per pacchetto (una one-hot conta h1), su ingressi densi, "
                  "ingressi one-hot, larghezza e profondita'. r² con le MAC "
                  "contate dalla forma per confronto.", "",
                  table(["pipeline", "punti", "ns per MAC", "r² (eseguite)",
                         "r² (dalla forma)"], rows), ""]
    return L


def sec_env(base):
    L = ["## Condizioni", ""]
    rows = []
    for root, dirs, files in os.walk(base, followlinks=True):
        if "env.csv" not in files:
            continue
        env = read_env(os.path.join(root, "env.csv"))
        rows.append([os.path.relpath(root, base), env.get("data", "-"),
                     env.get("ruolo_dut", env.get("cpu_dut", "-")),
                     str(dut_freq(env) or "-"),
                     env.get("alimentazione", "-").split(",")[0],
                     (env.get("contatori_hw", "-")[:40]
                      .replace("|", "/"))])
    rows.sort()
    if not rows:
        return []
    L.append(table(["misura", "data", "DUT", "MHz misurati", "alimentazione",
                    "contatori hw"], rows))
    L.append("")
    return L


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        sys.exit(__doc__)
    base = argv[0]
    L = [f"# Campagna: {os.path.basename(os.path.abspath(base))}", ""]
    for part in (sec_capacity, sec_cores2, sec_bitrate, sec_rates,
                 sec_checkpoint_t2, sec_mac_fit,
                 sec_per_class, sec_frames, sec_axes, sec_env):
        L += part(base)
    print("\n".join(L))


if __name__ == "__main__":
    main()
