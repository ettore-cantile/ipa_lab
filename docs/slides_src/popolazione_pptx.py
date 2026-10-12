#!/usr/bin/env python3
"""
popolazione_pptx.py -- riscrive "Inferenza di una rete neurale nel kernel
Linux con eBPF XDP.pptx" con le cifre di una campagna di popolazione.

Si usa da popolazione.py (--pptx). Lo stile resta quello del file: di ogni
grafico si sostituiscono i dati (chart.replace_data), di ogni casella il
testo, copiando la formattazione del primo pezzo; "**...**" nel testo vuol
dire grassetto. La slide 22 e' un'immagine e si ridisegna con matplotlib.

La slide "Cambiare modello costa millisecondi" e la tabella della slide 17
(letture di tabella, salti) vengono dalla sezione `solo` della campagna
(bench_solo.py) e dalla compilazione di P1 (bench_solo.py --compila).
"""
import copy
import math
import os
import statistics as st

from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor

import popolazione as POP

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.dirname(HERE)
DECK = os.path.join(DOCS, "Inferenza di una rete neurale nel kernel Linux "
                          "con eBPF XDP.pptx")
# Il modello da cui si parte ogni volta: il deck con le slide del checkpoint,
# di cui si tengono stile e disposizione. Partire da DECK non andrebbe: al
# secondo giro la slide del cambio di modello sarebbe gia' uscita.
BASE = os.path.join(HERE, "inferenza_base.pptx")
PIPES = POP.PIPES
ALL = POP.ALL
CATS = ["baseline", "P1 statica", "P1.5", "P2", "P3"]
NAMES = ["P1 statica", "P1.5", "P2", "P3"]
COLOR = {"p1_static": "#C8551E", "hardcoded": "#F09A3E",
         "template": "#2E9C8F", "modular": "#1F5F8B"}


# --------------------------------------------------------------------------
# numeri all'italiana
# --------------------------------------------------------------------------
def it(x, d=0):
    """1234.5 -> '1 234,5' (spazio per le migliaia, virgola decimale)."""
    if x is None:
        return "–"
    s = f"{x:,.{d}f}"
    return s.replace(",", " ").replace(".", ",")


def pct(x, d=0):
    return it(x * 100, d)


def r(s, d=0, scale=1.0):
    """'mediana [min–max]' di un summ()."""
    if not s:
        return "–"
    return (f"{it(s['med'] * scale, d)} [{it(s['min'] * scale, d)}–"
            f"{it(s['max'] * scale, d)}]")


def span(s, d=0, scale=1.0):
    """'min–max' di un summ()."""
    if not s:
        return "–"
    return f"{it(s['min'] * scale, d)}–{it(s['max'] * scale, d)}"


def md(s, d=0, scale=1.0):
    return it(s["med"] * scale, d) if s else "–"


# --------------------------------------------------------------------------
# pptx: testo e grafici
# --------------------------------------------------------------------------
def shape(slide, name):
    for sh in slide.shapes:
        if sh.name == name:
            return sh
    raise KeyError(f"slide senza {name}")


def set_text(slide, name, text):
    """Il testo di una casella, con **grassetto**. Una riga = un paragrafo;
    la formattazione viene dal primo pezzo del primo paragrafo."""
    tf = shape(slide, name).text_frame
    p0 = tf.paragraphs[0]._p
    runs = p0.findall("{http://schemas.openxmlformats.org/drawingml/2006/main}r")
    template = copy.deepcopy(runs[0]) if runs else None
    # via i paragrafi oltre il primo, e i pezzi del primo
    for p in list(tf.paragraphs)[1:]:
        p._p.getparent().remove(p._p)
    for rr in runs:
        p0.remove(rr)
    for k, line in enumerate(text.split("\n")):
        if k == 0:
            pe = p0
        else:
            pe = copy.deepcopy(p0)
            for rr in pe.findall("{http://schemas.openxmlformats.org/"
                                 "drawingml/2006/main}r"):
                pe.remove(rr)
            p0.getparent().append(pe)
        end = pe.find("{http://schemas.openxmlformats.org/drawingml/2006/"
                      "main}endParaRPr")
        bold, marked = False, "**" in line
        for seg in line.split("**"):
            if seg:
                rr = copy.deepcopy(template)
                rr.find("{http://schemas.openxmlformats.org/drawingml/2006/"
                        "main}t").text = seg
                rpr = rr.find("{http://schemas.openxmlformats.org/drawingml/"
                              "2006/main}rPr")
                # senza ** resta il grassetto del modello (titoli, schede)
                if rpr is not None and marked:
                    rpr.set("b", "1" if bold else "0")
                if end is not None:
                    end.addprevious(rr)
                else:
                    pe.append(rr)
            bold = not bold


def set_chart(slide, name, cats, series, colors=None):
    """Sostituisce categorie e serie; il colore di una serie resta quello
    della serie con lo stesso indice, o quello dato in `colors`."""
    ch = shape(slide, name).chart
    cd = CategoryChartData()
    cd.categories = cats
    for sname, vals in series:
        cd.add_series(sname, [None if v is None else round(v, 3)
                              for v in vals])
    ch.replace_data(cd)
    for k, c in (colors or {}).items():
        se = ch.plots[0].series[k]
        rgb = RGBColor.from_string(c.lstrip("#"))
        se.format.fill.solid()
        se.format.fill.fore_color.rgb = rgb
        se.format.line.color.rgb = rgb


def axis_title(slide, name, cat=None, val=None):
    ch = shape(slide, name).chart
    for ax, txt in ((ch.category_axis, cat), (ch.value_axis, val)):
        if txt is None:
            continue
        p = ax.axis_title.text_frame.paragraphs[0]
        if p.runs:            # dentro il pezzo esistente: resta lo stile
            p.runs[0].text = txt
            for rr in p.runs[1:]:
                rr.text = ""
        else:
            ax.axis_title.text_frame.text = txt


def set_table(slide, name, rows):
    t = shape(slide, name).table
    for i, row in enumerate(rows):
        for j, v in enumerate(row):
            cell = t.cell(i, j)
            p = cell.text_frame.paragraphs[0]
            if p.runs:
                p.runs[0].text = v
                for rr in p.runs[1:]:
                    rr.text = ""
            else:
                p.text = v


def drop_slide(prs, index):
    sld = prs.slides._sldIdLst[index]
    prs.part.drop_rel(sld.rId)
    prs.slides._sldIdLst.remove(sld)


# --------------------------------------------------------------------------
# le cifre che servono solo alle slide
# --------------------------------------------------------------------------
def groups(pop, ids, group, stat):
    """{pipeline o baseline: [mediana per valore del gruppo]} e i valori."""
    vals = sorted({int(POP.num(pop.m(i, group))) for i in ids})
    out = {}
    for m in ALL:
        g = {v: [] for v in vals}
        for i in ids:
            x = stat(i, m)
            if x is not None:
                g[int(POP.num(pop.m(i, group)))].append(x)
        out[m] = [st.median(g[v]) if g[v] else None for v in vals]
    return vals, out


def sparse_twin(pop, k="P"):
    """Tempo del nodo del modello sparso / gemello denso, per sparsita'."""
    res = {}
    for i in pop.ids_of(("sparsita",)):
        twin = [j for j in pop.ids_of(("base", "replica"))
                if pop.m(j, "shape") == pop.m(i, "shape")
                and pop.m(j, "layout") == pop.m(i, "layout")]
        sp = round(POP.num(pop.m(i, "sparsity")), 1)
        for m in PIPES:
            a = pop.val(k, i, m, "ns")
            b = POP.med([pop.val(k, j, m, "ns") for j in twin])
            if a and b:
                res.setdefault((m, sp), []).append(a / b)
    return {m: [1.0] + [POP.med(res.get((m, sp), [])) for sp in (0.5, 0.9)]
            for m in PIPES}


def n_progs(pop):
    out = {}
    for i in pop.ids:
        for k in ("P",):
            rows = POP.PR.read_csv(os.path.join(pop.base, f"pop_{k}core", i,
                                                "prog_size.csv"))
            for row in rows:
                out.setdefault(row["method"], set()).add(row["n_progs"])
    return {m: "/".join(sorted(v)) for m, v in out.items()}


# --------------------------------------------------------------------------
# la figura della slide 22
# --------------------------------------------------------------------------
def law_figure(pop, facts, path):
    """Costo della rete meno c x strati contro le MAC eseguite, un punto per
    modello denso: la parte che la legge attribuisce alle MAC, che deve
    stare su una retta di pendenza b."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ink, ink2, grid = "#222B36", "#5B6676", "#E3E7EC"
    marker = {"p1_static": "o", "hardcoded": "s", "template": "D",
              "modular": "^"}
    name = {"p1_static": "P1 statica", "hardcoded": "P1.5", "template": "P2",
            "modular": "P3"}
    fig, ax = plt.subplots(figsize=(6.4, 4.0), dpi=200)
    ax.set_facecolor("white")
    ids = pop.ids_of(POP.DENSE)
    xmax = max(POP.num(pop.m(i, "mac_exec")) for i in ids)
    for m in PIPES:
        law = facts["laws"][("P", "ns", m)]
        xs, ys = [], []
        for i in ids:
            y = pop.nn("P", i, m)
            if y is None:
                continue
            xs.append(POP.num(pop.m(i, "mac_exec")))
            ys.append(y - law["c"] * POP.num(pop.m(i, "n_layers")))
        ax.scatter(xs, ys, s=16, marker=marker[m], color=COLOR[m],
                   alpha=0.75, linewidths=0.6, edgecolors="white",
                   label=f"{name[m]}: {it(law['b'], 2)} ns/MAC, "
                         f"r² {it(law['r2'], 2)}", zorder=3)
        ax.plot([0, xmax * 1.03], [law["a"], law["a"] + law["b"] * xmax * 1.03],
                color=COLOR[m], linewidth=2, zorder=2)
        # P1 e P1.5 finiscono quasi nello stesso punto: etichette scostate
        dy = {"hardcoded": 9, "p1_static": -9}.get(m, 0)
        ax.annotate(name[m], (xmax * 1.035,
                              law["a"] + law["b"] * xmax * 1.03 + dy),
                    color=ink, fontsize=8, va="center")
    ax.set_xlim(0, xmax * 1.16)
    ax.set_ylim(bottom=0)
    ax.set_xlabel("moltiplicazioni (MAC) eseguite per pacchetto", color=ink2,
                  fontsize=8)
    ax.set_ylabel("ns di rete neurale − c × strati", color=ink2, fontsize=8)
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


def replace_picture(slide, name, png):
    old = shape(slide, name)
    left, top, w, h = old.left, old.top, old.width, old.height
    old._element.getparent().remove(old._element)
    pic = slide.shapes.add_picture(png, left, top, width=w)
    if pic.height > h:     # resta nella scatola, con le proporzioni
        scale = h / pic.height
        pic.height = h
        pic.width = int(w * scale)


# --------------------------------------------------------------------------
# le slide
# --------------------------------------------------------------------------
def build(pop, f, out=DECK):
    prs = Presentation(BASE)
    S = list(prs.slides)
    L = f["laws"]
    nn, ns, mpps = f["nn"], f["ns"], f["mpps"]
    ref = f["ref"]
    n = f["n_models"]
    base_ids = pop.ids_of(("base",))
    n85 = nn["P"]["template"]["n"]
    p1 = lambda d: d["p1_static"]   # noqa: E731

    # 1 -- copertina
    set_text(S[0], "TextBox 4",
             f"Quattro versioni della stessa rete neurale, misurate sul "
             f"traffico vero su {n} modelli diversi: quanto costa un "
             f"pacchetto, quante istruzioni esegue, e che cosa cambia da un "
             f"P-core a un E-core.")

    # 2 -- le quattro versioni
    set_text(S[1], "TextBox 6",
             f"Tutte e quattro calcolano lo stesso modello e prendono la stessa "
             f"decisione: verificato su {n} modelli ({n85} per P2, che ha un "
             f"tetto sui pesi). Cambia solo **quanto sanno già** quando "
             f"vengono compilate.")
    set_text(S[1], "TextBox 8",
             "* Solo P1 statica può congelare anche **quali interfacce il "
             "nodo ha davvero**: le colonne dei collegamenti che non esistono non "
             "vengono generate (se un link è su o giù resta letto a runtime). "
             "Serve il nodo congelato, perché le porte dipendono da quale nodo "
             "si è. Le misure di queste slide usano tutte le porte.")

    # 3 -- quanto costa un pacchetto
    rx, bl = ref["rxonly_P"]["ns"], ref["baseline_P"]["ns"]
    nnP = [None] + [nn["P"][m]["med"] for m in PIPES]
    set_chart(S[2], "Chart 6",
              ["solo ricezione", "baseline"] + NAMES,
              [("ricevere il frame", [rx] * 6),
               ("parse, TTL, redirect, accodamento", [0] + [bl - rx] * 5),
               ("rete neurale", [0, 0] + nnP[1:])])
    set_text(S[2], "TextBox 10", f"{it(ns['P']['baseline']['med'])} ns")
    set_text(S[2], "TextBox 11",
             f"{it(mpps['P']['baseline']['med'], 1)} M pacchetti/s, "
             f"{n} modelli")
    lo = min(ns["P"]["p1_static"]["min"], ns["P"]["hardcoded"]["min"])
    hi = max(ns["P"]["p1_static"]["max"], ns["P"]["hardcoded"]["max"])
    set_text(S[2], "TextBox 15", f"{it(lo)}–{it(hi)} ns")
    set_text(S[2], "TextBox 16",
             f"{span(mpps['P']['p1_static'], 1)} M pacchetti/s")
    set_text(S[2], "TextBox 20", f"{span(ns['P']['template'])} ns")
    set_text(S[2], "TextBox 21",
             f"{span(mpps['P']['template'], 1)} M pacchetti/s")
    set_text(S[2], "TextBox 25", f"{span(ns['P']['modular'])} ns")
    set_text(S[2], "TextBox 26",
             f"{span(mpps['P']['modular'], 1)} M pacchetti/s")
    set_text(S[2], "TextBox 5",
             f"64 byte, P-core a 3,5 GHz  ·  barre: mediana su {n} modelli "
             f"(P2: {n85})  ·  schede: dal modello più leggero al più "
             f"pesante")
    set_text(S[2], "TextBox 30",
             f"Ricevere e inoltrare costano **~{it(bl)} ns**, con qualunque "
             f"modello. La rete neurale aggiunge **{span(p1(nn['P']))} ns** "
             f"con i pesi compilati (mediana {md(p1(nn['P']))}), "
             f"**{span(nn['P']['template'])} ns** se la forma è letta da "
             f"tabella (P2), **{span(nn['P']['modular'])} ns** se anche la "
             f"profondità (P3): un core regge da **"
             f"{it(mpps['P']['p1_static']['max'], 1)}** a **"
             f"{it(mpps['P']['modular']['min'], 1)} milioni** di pacchetti al "
             f"secondo, secondo modello e pipeline.")

    # 4 -- caricate contro eseguite
    ld = f["loaded"]
    set_chart(S[3], "Chart 6", CATS,
              [("caricate", [ld[m]["med"] for m in ALL]),
               ("eseguite", [f["instr"]["P"][m]["med"] for m in ALL])])
    lpe_instr = {k: pop.per_pipe(k, "instr",
                                 ids=[i for i in pop.ids
                                      if ("L", i) in pop.c.sat])
                 for k in "PEL"}
    set_chart(S[3], "Chart 7", CATS,
              [(lab, [lpe_instr[k][m]["med"] for m in ALL])
               for k, lab in (("P", "P-core"), ("E", "E-core"),
                              ("L", "LP E-core"))])
    b2 = f["p2_bigger_p3_works"]
    iep = max(abs(f["instr_E_P"][m]["max"] - 1) for m in ALL) * 100
    ilp = max(abs(f["lpe"]["instr_L_P"][m]["max"] - 1) for m in PIPES) * 100
    set_text(S[3], "TextBox 8",
             f"**Caricate contro eseguite** (mediane). P2 carica più "
             f"istruzioni di P3 ma ne esegue meno: su {b2[0]} modelli su "
             f"{b2[1]}.")
    set_text(S[3], "TextBox 9",
             f"**Stesse istruzioni su ogni core.** Entro lo "
             f"{it(iep, 1)} % fra P-core ed E-core su {n} modelli, entro lo "
             f"{it(ilp, 1)} % sul LP E-core ({f['lpe']['n']} modelli).")
    set_text(S[3], "TextBox 5",
             "Caricate: contate dal kernel al caricamento  ·  eseguite: "
             "contatori hardware, per pacchetto, nodo saturo  ·  a destra i "
             f"{f['lpe']['n']} modelli misurati sui tre core")

    # 5 -- P, E, LP
    lpe = f["lpe"]
    set_chart(S[4], "Chart 6", CATS,
              [(lab, [lpe["mpps"][k][m]["med"] for m in ALL])
               for k, lab in (("P", "P-core"), ("E", "E-core"),
                              ("L", "LP E-core"))])
    set_chart(S[4], "Chart 7", CATS,
              [(lab, [lpe["ns"][k][m]["med"] for m in ALL])
               for k, lab in (("P", "P-core"), ("E", "E-core"),
                              ("L", "LP E-core"))])
    ce = f["cap_E_P"]
    lo = min(ce[m]["min"] for m in ALL)
    hi = max(ce[m]["max"] for m in ALL)
    set_text(S[4], "TextBox 3",
             f"Su un E-core il nodo regge dal {pct(lo)} al {pct(hi)} % del "
             f"P-core")
    set_text(S[4], "TextBox 8",
             f"**Milioni di pacchetti al secondo.** Capacità E/P su {n} "
             f"modelli: baseline {span(ce['baseline'], 2)}, P3 "
             f"{span(ce['modular'], 2)}.")
    cyc = f["cycles_E_P"]
    nnc = f["nn_cycles_E_P"]
    set_text(S[4], "TextBox 9",
             f"**ns di CPU per pacchetto.** Sull'E-core la baseline costa il "
             f"{pct(cyc['baseline']['med'] - 1)} % in più, la sola rete "
             f"neurale di P3 il {pct(nnc['modular']['med'] - 1)} % "
             f"(mediane).")
    cl = lpe["cap_L_P"]
    set_text(S[4], "TextBox 13",
             f"A parità di frequenza l'E-core è più lento soprattutto nel "
             f"**lavoro di rete del kernel**: più la pipeline è pesante, meno "
             f"pesa la differenza (capacità E/P {md(ce['baseline'], 2)} per la "
             f"baseline, {md(ce['p1_static'], 2)} per P1, "
             f"{md(ce['template'], 2)}–{md(ce['modular'], 2)} per P2 e P3). "
             f"Il LP E-core (fuori dalla L3, 2,5 GHz) regge dal "
             f"{pct(min(cl[m]['min'] for m in PIPES))} al "
             f"{pct(max(cl[m]['max'] for m in PIPES))} % del P-core sulle "
             f"pipeline.")
    set_text(S[4], "TextBox 5",
             "P-core e E-core a 3,5 GHz, LP E-core a 2,5 GHz; generatore e "
             "uscita su P-core  ·  grafici: mediana dei "
             f"{lpe['n']} modelli del sottoinsieme LP, dal più leggero al più "
             "pesante")

    # 6 -- IPC
    set_chart(S[5], "Chart 6", CATS,
              [(lab, [lpe["ipc"][k][m]["med"] for m in ALL])
               for k, lab in (("P", "P-core"), ("E", "E-core"),
                              ("L", "LP E-core"))])
    set_table(S[5], "Table 7" if any(sh.name == "Table 7" for sh in S[5].shapes)
              else [sh.name for sh in S[5].shapes if sh.has_table][0],
              [["Versione", "Istruzioni", "Cicli P", "Cicli E"]]
              + [[nm, it(f["instr"]["P"][m]["med"]),
                  it(f["cycles"]["P"][m]["med"]),
                  it(f["cycles"]["E"][m]["med"])]
                 for nm, m in zip(NAMES, PIPES)])
    ipc = f["ipc"]
    llc = lpe["llc"]["L"]
    set_text(S[5], "TextBox 11",
             f"Le istruzioni per pacchetto sono le stesse su ogni core: il "
             f"codice non cambia. Cambia l'IPC: {md(ipc['P']['baseline'], 1)} "
             f"→ {md(ipc['E']['baseline'], 1)} per la baseline (lavoro di "
             f"rete, salti, memoria), {md(ipc['P']['modular'], 1)} → "
             f"{md(ipc['E']['modular'], 1)} per P3 (aritmetica lineare). Il "
             f"LP E-core ha {it(min(llc[m]['med'] for m in ALL))}–"
             f"{it(max(llc[m]['med'] for m in ALL))} mancate di cache per "
             f"pacchetto.")
    set_text(S[5], "TextBox 5",
             "Contatori hardware sul core del nodo, nodo saturo  ·  mediane: "
             f"tabella su {n} modelli, grafico sui {lpe['n']} misurati sui "
             "tre core")

    # 7 -- dove l'E-core perde tempo
    fixP, fixE = f["cycles"]["P"]["baseline"]["med"], \
        f["cycles"]["E"]["baseline"]["med"]
    cats7, fixed, net = [], [], []
    for m, nm in zip(ALL, ["baseline", "P1", "P1.5", "P2", "P3"]):
        for k, fx in (("P", fixP), ("E", fixE)):
            cats7.append(f"{nm} · {k}")
            fixed.append(fx)
            net.append(0 if m == "baseline"
                       else f["nn_cycles"][k][m]["med"])
    set_chart(S[6], "Chart 6", cats7,
              [("parte fissa del nodo", fixed), ("rete neurale", net)])

    def delta(x):
        v = (x - 1) * 100
        return f"{'+' if v >= 0 else '−'}{it(abs(v))}%"
    set_text(S[6], "TextBox 10", delta(cyc["baseline"]["med"]))
    set_text(S[6], "TextBox 11",
             f"{it(fixP)} → {it(fixE)} cicli, P → E "
             f"({span(cyc['baseline'], 2)}×)")
    for (val, sub), m in zip((("TextBox 15", "TextBox 16"),
                              ("TextBox 20", "TextBox 21"),
                              ("TextBox 25", "TextBox 26")),
                             ("p1_static", "template", "modular")):
        set_text(S[6], val, delta(nnc[m]["med"]))
        set_text(S[6], sub,
                 f"{it(f['nn_cycles']['P'][m]['med'])} → "
                 f"{it(f['nn_cycles']['E'][m]['med'])} cicli "
                 f"({span(nnc[m], 2)}×)")
    set_text(S[6], "TextBox 30",
             f"Ricevere, inoltrare e restituire la pagina è lavoro del kernel "
             f"con salti e memoria: l'E-core lo esegue a IPC "
             f"{md(ipc['E']['baseline'], 1)} invece di "
             f"{md(ipc['P']['baseline'], 1)}, su ogni modello. L'aritmetica "
             f"della rete è una fila di moltiplicazioni, e l'E-core la esegue "
             f"quasi altrettanto bene.")
    set_text(S[6], "TextBox 5",
             "Cicli per pacchetto dai contatori hardware, 3,5 GHz  ·  parte "
             "fissa = baseline, rete = pipeline meno baseline  ·  mediane su "
             f"{n} modelli")

    # 8 -- LP E-core
    set_chart(S[7], "Chart 6", CATS,
              [(lab, [lpe["llc"][k][m]["med"] for m in ALL])
               for k, lab in (("P", "P-core"), ("E", "E-core"),
                              ("L", "LP E-core"))])
    set_chart(S[7], "Chart 7", CATS,
              [(lab, [lpe["cycles"][k][m]["med"] for m in ALL])
               for k, lab in (("P", "P-core"), ("E", "E-core"),
                              ("L", "LP E-core"))])
    lc = lpe["cycles"]
    set_text(S[7], "TextBox 8",
             f"**Mancate di cache.** Zero sul P-core e sull'E-core; "
             f"{it(min(llc[m]['med'] for m in ALL))}–"
             f"{it(max(llc[m]['med'] for m in ALL))} per pacchetto sul LP "
             f"E-core, fuori dalla L3.")
    set_text(S[7], "TextBox 9",
             f"**Cicli per pacchetto** (mediane). P3: "
             f"{it(lc['P']['modular']['med'])} → "
             f"{it(lc['E']['modular']['med'])} → "
             f"{it(lc['L']['modular']['med'])}; in tempo "
             f"{it(lpe['ns']['P']['modular']['med'])} → "
             f"{it(lpe['ns']['E']['modular']['med'])} → "
             f"{it(lpe['ns']['L']['modular']['med'])} ns.")
    lipc = lpe["ipc"]["L"]
    set_text(S[7], "TextBox 13",
             f"Il LP E-core sta su un'altra parte del chip: i pacchetti scritti "
             f"dal generatore gli arrivano dalla memoria. Fra memoria, IPC più "
             f"basso ({it(min(lipc[m]['med'] for m in ALL), 1)}–"
             f"{it(max(lipc[m]['med'] for m in ALL), 1)}) e 2,5 GHz regge dal "
             f"{pct(min(cl[m]['min'] for m in PIPES))} al "
             f"{pct(max(cl[m]['max'] for m in PIPES))} % del P-core sulle "
             f"pipeline.")
    set_text(S[7], "TextBox 5",
             "Contatori hardware del core del nodo, per pacchetto, nodo saturo"
             f"  ·  LP E-core a 2,5 GHz, fuori dalla L3  ·  mediane dei "
             f"{lpe['n']} modelli misurati sui tre core")

    # 9 -- traffico crescente, curve normalizzate alla capacita'
    ld9 = f["load"]
    cats9 = [f"{it(g, 2)}×" for g in ld9["grid"]]
    for chart, k in (("Chart 6", "P"), ("Chart 7", "E")):
        set_chart(S[8], chart, cats9,
                  [(nm, ld9["curves"][k][m]) for nm, m in zip(NAMES, PIPES)])
        axis_title(S[8], chart, cat="traffico chiesto / capacità",
                   val="inoltrati / capacità")
    kc = ld9["knee_over_cap"]
    n_curves = kc["P"]["n"] // 4
    set_text(S[8], "TextBox 8",
             f"**P-core.** Fino alla capacità passa tutto, poi la curva è "
             f"piatta: massimo {r(kc['P'], 2)} della capacità, "
             f"{kc['P']['n']} curve.")
    set_text(S[8], "TextBox 9",
             f"**E-core.** Stesso andamento: {r(kc['E'], 2)}, "
             f"{kc['E']['n']} curve. Divise per la capacità, le curve di "
             f"modelli diversi si sovrappongono.")
    set_text(S[8], "TextBox 13",
             "I pacchetti si perdono **all'ingresso**, non dopo il programma: "
             "il collo di bottiglia è il programma eBPF, su ogni tipo di core. "
             "Fa eccezione P1 sui modelli più leggeri: oltre i 9 milioni di "
             "pacchetti al secondo comincia a perdere anche l'uscita.")
    set_text(S[8], "TextBox 5",
             f"bench_bitrate, xdp_gen, 3 giri per punto, 64 byte, "
             f"{n_curves} modelli dal più leggero al più pesante  ·  asse x e "
             f"asse y divisi per la capacità del modello  ·  mediana delle "
             f"curve")

    # 10 -- due core
    tw = f["two"]
    for chart, k in (("Chart 6", "P"), ("Chart 7", "E")):
        set_chart(S[9], chart, CATS,
                  [("1 core", [tw[k]["one"][m] for m in ALL]),
                   ("2 core", [tw[k]["two"][m] for m in ALL])])
    set_text(S[9], "TextBox 8",
             f"**P-core.** {r(tw['P']['pct_all'])} % del doppio su "
             f"{tw['P']['pct_all']['n']} coppie modello-pipeline.")
    set_text(S[9], "TextBox 9",
             f"**E-core.** {r(tw['E']['pct_all'])} % del doppio, con un "
             f"E-core per modulo: i due moduli non si disturbano.")
    set_text(S[9], "TextBox 5",
             "Un thread di xdp_gen, una coda e un core d'uscita per core del "
             "nodo  ·  P: CPU 6 e 8  ·  E: CPU 12 e 16  ·  mediane di "
             f"{tw['P']['n']} modelli")

    # 11 -- tre orologi
    ck = f["clocks"]
    cats11, progv, xpv = [], [], []
    for m, nm in zip(ALL, ["baseline", "P1", "P1.5", "P2", "P3"]):
        for k in ("P", "E"):
            cats11.append(f"{nm} · {k}")
            progv.append(ck["prog"][(k, m)]["med"])
            xpv.append(ck["xport"][(k, m)]["med"])
    set_chart(S[10], "Chart 6", cats11,
              [("il programma (T2−T1)", progv),
               ("il trasporto (T3−T2)", xpv)])
    pP = ck["prog"]
    set_text(S[10], "TextBox 10",
             f"Da {md(pP[('P', 'baseline')])} ns (baseline) a "
             f"{md(pP[('P', 'modular')])} ns (P3) sul P-core, mediane; P3 va "
             f"da {span(pP[('P', 'modular')])} ns secondo il modello.")
    xp = [ck["xport"][("P", m)] for m in ALL]
    xe = [ck["xport"][("E", m)] for m in ALL]
    set_text(S[10], "TextBox 14",
             f"Redirect, veth e ricezione: "
             f"{it(min(s['min'] for s in xp))}–{it(max(s['max'] for s in xp))} "
             f"ns sul P-core, {it(min(s['min'] for s in xe))}–"
             f"{it(max(s['max'] for s in xe))} sull'E-core, su ogni modello e "
             f"pipeline.")
    lat = lambda k, m: (pP[(k, m)]["med"] + ck["xport"][(k, m)]["med"])  # noqa
    set_text(S[10], "TextBox 18",
             f"Il trasporto è un costo comune che non dipende né dalla "
             f"pipeline né dal modello; il programma pesa di più sull'E-core "
             f"quanto più è lungo. La latenza minima arrivo → ripartenza va "
             f"da {it(lat('P', 'baseline'))} a {it(lat('P', 'modular'))} ns "
             f"sul P-core, da {it(lat('E', 'baseline'))} a "
             f"{it(lat('E', 'modular'))} sull'E-core (mediane).")
    set_text(S[10], "TextBox 5",
             "T1 all'ingresso del programma, T2 prima di bpf_redirect, T3 "
             "all'arrivo dall'altra parte  ·  minimi, a 0,25 e 0,5 Mpps  ·  "
             f"barre: mediana su {n} modelli")

    # 12 -- taglia e classi
    fr = f["frames"]
    set_chart(S[11], "Chart 6", CATS,
              [(f"{sz} byte", [fr["ns"][sz][m] for m in ALL])
               for sz in fr["sizes"]])
    cs = f["classes"]
    set_chart(S[11], "Chart 7", CATS,
              [("classi che inoltrano", [cs["fwd"].get(m) for m in ALL]),
               ("scarta", [cs["drop"].get(m) for m in ALL])],
              colors={0: "#6C819C", 1: "#C0443C"})
    set_text(S[11], "TextBox 8",
             f"**Taglia del pacchetto: nessun effetto** "
             f"({r(fr['var'], 1)} % fra 64 e 1 514 byte, "
             f"{fr['var']['n']} coppie). Il nodo legge solo l'intestazione.")
    set_text(S[11], "TextBox 9",
             f"**Porta d'uscita: nessun effetto** ({r(cs['spread'])} % fra "
             f"le classi che inoltrano). Scartare costa {r(cs['extra'])} ns "
             f"in più.")
    mx = f["mix"]["rel"]
    set_text(S[11], "TextBox 13",
             f"Basta un numero per pipeline e modello a descrivere il costo "
             f"del nodo: non dipende da taglia del pacchetto, porta d'uscita "
             f"o TTL (TTL diversi a ogni pacchetto: {r(mx)} %); solo la "
             f"decisione di scartare costa ~{md(cs['extra'])} ns in più.")
    set_text(S[11], "TextBox 5",
             "Una sessione per classe decisa, verificata su ogni pipeline  ·  "
             f"P-core a 3,5 GHz  ·  mediane: {fr['n']} modelli per le taglie, "
             f"{cs['n']} per le classi, dal più leggero al più pesante")

    # 13 -- profondita' e pesi a zero, tempo del nodo
    dv, dg = groups(pop, base_ids, "depth",
                    lambda i, m: pop.val("P", i, m, "ns"))
    set_chart(S[12], "Chart 6", [str(v) for v in dv],
              [(nm, dg[m]) for nm, m in zip(NAMES, PIPES)])
    tw13 = sparse_twin(pop)
    set_chart(S[12], "Chart 7", ["0 %", "50 %", "90 %"],
              [(nm, tw13[m]) for nm, m in zip(NAMES, PIPES)])
    axis_title(S[12], "Chart 7", val="tempo del nodo / modello denso")
    set_text(S[12], "TextBox 3", "Profondità e pesi a zero, sul nodo vero")
    set_text(S[12], "TextBox 8",
             f"**Profondità** (mediane per numero di strati, "
             f"{len(base_ids)} modelli). Per strato in più, a MAC ferme: P3 "
             f"~{it(L[('P', 'ns', 'modular')]['c'])} ns, P2 "
             f"~{it(L[('P', 'ns', 'template')]['c'])}, P1 e P1.5 "
             f"~{it(L[('P', 'ns', 'p1_static')]['c'])}.")
    set_text(S[12], "TextBox 9",
             f"**Pesi a zero** (tempo del nodo diviso quello del modello "
             f"denso con la stessa forma). Al 90 % P1 "
             f"{it(tw13['p1_static'][2], 2)}×, P1.5 "
             f"{it(tw13['hardcoded'][2], 2)}×; P2 e P3 ferme.")
    set_text(S[12], "TextBox 13",
             f"Sul nodo vero, su tutta la popolazione: la profondità costa "
             f"soprattutto a P3 e P2, i pesi a zero aiutano solo P1 e P1.5. "
             f"Il costo fisso del nodo (~{it(bl)} ns) resta lo stesso con "
             f"qualunque modello.")
    set_text(S[12], "TextBox 5",
             "Tempo di CPU per pacchetto, xdp_gen, P-core  ·  profondità: "
             f"famiglia base ({len(base_ids)} modelli)  ·  pesi a zero: 4 "
             "forme contro il gemello denso")

    # 14 -- istruzioni per strato
    dvi, dgi = groups(pop, base_ids, "depth",
                      lambda i, m: pop.val("P", i, m, "instr"))
    set_chart(S[13], "Chart 6", [str(v) for v in dvi],
              [(nm, dgi[m]) for nm, m in zip(NAMES, PIPES)])
    _, dgE = groups(pop, base_ids, "depth",
                    lambda i, m: pop.val("E", i, m, "ns"))
    set_chart(S[13], "Chart 7", [str(v) for v in dv],
              [("P3 · P-core", dg["modular"]), ("P3 · E-core", dgE["modular"]),
               ("P2 · P-core", dg["template"]),
               ("P2 · E-core", dgE["template"])])
    li = L[("P", "instr", "modular")]
    set_text(S[13], "TextBox 3",
             f"Ogni strato di P3 costa ~{it(round(li['c'], -1))} istruzioni")
    set_text(S[13], "TextBox 8",
             f"**Istruzioni.** Legge su {li['n']} modelli: P3 "
             f"+{it(li['c'])} per strato (r² {it(li['r2'], 2)}), identiche su "
             f"P-core ed E-core; P2 +{it(L[('P', 'instr', 'template')]['c'])}"
             f" per strato.")
    set_text(S[13], "TextBox 9",
             f"**Tempo.** P3 ~{it(L[('P', 'ns', 'modular')]['c'])} ns per "
             f"strato sul P-core, ~{it(L[('E', 'ns', 'modular')]['c'])} "
             f"sull'E-core (legge). Tratteggio = E-core.")
    set_text(S[13], "TextBox 13",
             "In P3 ogni strato è un salto più le letture che ricostruiscono "
             "il contesto: lo stesso conto di istruzioni a ogni strato, su "
             "ogni modello. La profondità si paga a ogni pacchetto, e "
             "sull'E-core un po' di più.")
    set_text(S[13], "TextBox 5",
             f"Mediane per numero di strati sui {len(base_ids)} modelli della "
             "famiglia base  ·  leggi su tutti i modelli densi  ·  contatori "
             "hardware del core del nodo, per pacchetto")

    # 15 -- larghezza e pari pesi, tempo del nodo
    wv, wg = groups(pop, base_ids, "width_max",
                    lambda i, m: pop.val("P", i, m, "ns"))
    _, wgE = groups(pop, base_ids, "width_max",
                    lambda i, m: pop.val("E", i, m, "ns"))
    set_chart(S[14], "Chart 6", [str(v) for v in wv],
              [(nm, wg[m]) for nm, m in zip(NAMES, PIPES)]
              + [("P3 · E-core", wgE["modular"])])
    iso = f["isoparam"]["total"]
    dd = [str(d) for d in sorted(int(x) for x in iso["P"]["modular"])]
    set_chart(S[14], "Chart 7", dd,
              [(nm, [iso["P"][m][int(d)] if int(d) in iso["P"][m]
                     else iso["P"][m].get(d) for d in dd])
               for nm, m in zip(NAMES, PIPES)]
              + [("P3 · E-core", [iso["E"]["modular"].get(int(d),
                                  iso["E"]["modular"].get(d)) for d in dd])])
    set_text(S[14], "TextBox 8",
             f"**Larghezza.** Da 2 a 8 neuroni sale su tutte: P1 "
             f"{it(wg['p1_static'][0])} → {it(wg['p1_static'][-1])}, P3 "
             f"{it(wg['modular'][0])} → {it(wg['modular'][-1])} ns (mediane).")
    rise = f["isoparam"]["rise"]
    set_text(S[14], "TextBox 9",
             f"**A pari pesi.** Da 1 a 5 strati P2 "
             f"+{md(rise['template'])} %, P3 +{md(rise['modular'])} %; le P1 "
             f"+{md(rise['hardcoded'])}–{md(rise['p1_static'])} %.")
    eratio = [wgE["modular"][j] / wg["modular"][j] for j in range(len(wv))]
    set_text(S[14], "TextBox 13",
             f"Le stesse scelte valgono sul nodo vero, con il costo fisso del "
             f"nodo in più. Sull'E-core P3 sta più in alto del "
             f"{pct(min(eratio) - 1)}–{pct(max(eratio) - 1)} %, con la stessa "
             f"forma: la forma migliore non cambia con il core.")
    set_text(S[14], "TextBox 5",
             "Tempo di CPU per pacchetto, nodo su P-core  ·  tratteggio: P3 "
             f"sull'E-core  ·  larghezza: famiglia base ({len(base_ids)} "
             f"modelli); pari pesi: famiglia imbuto ({f['isoparam']['n']} "
             "modelli, 2 composizioni)")

    # 16 -- traffico leggero contro nodo saturo
    lt = f["depth_light"]
    _, dnn = groups(pop, base_ids, "depth", lambda i, m: pop.nn("P", i, m))
    _, dmin = groups(pop, base_ids, "depth",
                     lambda i, m: pop.c.nn_t2("P", i, m, 0))
    _, davg = groups(pop, base_ids, "depth",
                     lambda i, m: pop.c.nn_t2("P", i, m, 1))
    for chart, m in (("Chart 6", "modular"), ("Chart 7", "template")):
        set_chart(S[15], chart, [str(v) for v in dv],
                  [("nodo saturo (tempo di CPU)", dnn[m]),
                   ("traffico leggero, minimo", dmin[m]),
                   ("traffico leggero, media", davg[m])])
        axis_title(S[15], chart, cat="strati nascosti")
    li_ = ck["light"]
    mav = ck["minavg"]
    set_text(S[15], "TextBox 3",
             "Leggero o saturo, la rete di P2 e P3 costa uguale")
    set_text(S[15], "TextBox 8",
             f"**P3.** Media a traffico leggero / nodo saturo "
             f"{r(li_[('P', 'modular')], 2)} su {li_[('P', 'modular')]['n']} "
             f"modelli; il minimo sta al {pct(mav[('P', 'modular')]['med'])} "
             f"% della media.")
    set_text(S[15], "TextBox 9",
             f"**P2.** {r(li_[('P', 'template')], 2)}. P1 e P1.5 no: "
             f"{md(li_[('P', 'p1_static')], 2)} e "
             f"{md(li_[('P', 'hardcoded')], 2)} (mediane), con una rete da "
             f"poche decine di ns.")
    set_text(S[15], "TextBox 13",
             f"Tempo di CPU a nodo saturo e T2−T1 a traffico leggero danno "
             f"lo stesso costo della rete per P2 e P3, su ogni modello. Il "
             f"pacchetto più veloce costa "
             f"~{pct(1 - mav[('P', 'modular')]['med'])} % meno della media: "
             f"cache e predittori non sempre caldi.")
    set_text(S[15], "TextBox 5",
             "T2−T1 (build strumentata), xdp_gen a 0,25 e 0,5 Mpps, baseline "
             "sottratta  ·  mediane per strati, famiglia base "
             f"({len(base_ids)} modelli)  ·  P-core")
    set_text(S[15], "TextBox 2",
             "GLI ASSI SOTTO TRAFFICO · LA SOLA RETE NEURALE · P-CORE")

    # 17 -- la configurabilita' si paga per pacchetto
    set_chart(S[16], "Chart 6", CATS,
              [("ns", [ns["P"][m]["med"] for m in ALL])])
    npg = n_progs(pop)  # noqa: F841 (resta per chi volesse la colonna)
    so = f["solo"]
    set_table(S[16], [sh.name for sh in S[16].shapes if sh.has_table][0],
              [["Versione", "Istruzioni", "Letture tabella", "Salti"]]
              + [[nm, it(ld[m]["med"]),
                  (it(so["lookups"][m]["med"])
                   if so["lookups"][m]["min"] == so["lookups"][m]["max"]
                   or m != "modular"
                   else f"{it(so['lookups'][m]['min'])}–"
                        f"{it(so['lookups'][m]['max'])}"),
                  ("1/strato" if m == "modular"
                   else it(so["n_tail"][m]["med"]))]
                 for nm, m in zip(NAMES, PIPES)])
    set_text(S[16], "TextBox 3",
             f"La configurabilità si paga per pacchetto: "
             f"+{md(p1(nn['P']))} → +{md(nn['P']['modular'])} ns")
    set_text(S[16], "TextBox 11",
             f"La configurabilità si paga nelle **letture di tabella** "
             f"({md(so['lookups']['p1_static'])} → "
             f"{md(so['lookups']['modular'])} per pacchetto) e nei **salti** "
             f"(P3: uno per strato), non nell'aritmetica. Sopra la baseline, "
             f"rendere "
             f"configurabile la forma (P2) costa **{r(f['p2_over_p1'], 1)}×** "
             f"P1; anche la profondità (P3) **{r(f['p3_over_p1'], 1)}×**. Fra "
             f"P1 e P1.5: {r(f['p15_over_p1'], 1)}×.")
    set_text(S[16], "TextBox 5",
             f"Mediane su {n} modelli (P2: {n85})  ·  tempo di CPU, xdp_gen, "
             "P-core  ·  letture e salti per pacchetto: build strumentata")

    # 19 -- la rete puo' crescere (diventa la 18)
    nd = f["nodes"]
    set_chart(S[18], "Chart 6", [str(x) for x in nd["sizes"]],
              [(nm, [nd["residual"][m].get(x, nd["residual"][m].get(str(x)))
                     for x in nd["sizes"]]) for nm, m in zip(NAMES, PIPES)])
    axis_title(S[18], "Chart 6", cat="nodi della rete",
               val="ns: misurato − legge")
    va = shape(S[18], "Chart 6").chart.value_axis
    va.minimum_scale, va.maximum_scale = -40, 40
    from pptx.enum.chart import XL_TICK_LABEL_POSITION
    shape(S[18], "Chart 6").chart.category_axis.tick_label_position = \
        XL_TICK_LABEL_POSITION.LOW
    _, wnn = groups(pop, base_ids, "width_max", lambda i, m: pop.nn("P", i, m))
    set_chart(S[18], "Chart 7", [str(v) for v in wv],
              [(nm, wnn[m]) for nm, m in zip(NAMES, PIPES)])
    slope = nd["ns_per_node"]
    set_text(S[18], "TextBox 8",
             f"**Nodi della rete** ({nd['n']} modelli, reti da "
             f"{nd['sizes'][0]} a {nd['sizes'][-1]} nodi). Lo scarto dalla "
             f"legge non cresce: al più "
             f"{it(max(abs(v) for v in slope.values()), 2)} ns per nodo.")
    set_text(S[18], "TextBox 9",
             f"**Larghezza del modello.** Da 2 a 8 neuroni sale su tutte e "
             f"quattro: P1 {it(wnn['p1_static'][0])} → "
             f"{it(wnn['p1_static'][-1])} ns, P3 {it(wnn['modular'][0])} → "
             f"{it(wnn['modular'][-1])} ns (mediane).")
    set_text(S[18], "TextBox 5",
             "Tempo di CPU meno la baseline, xdp_gen, P-core  ·  a sinistra: "
             "misurato meno la legge, mediana per taglia della rete  ·  a "
             "destra: famiglia base")

    # 20 -- profondita' (diventa la 19)
    _, dsz = groups(pop, base_ids, "depth",
                    lambda i, m: pop.c.size.get(i, {}).get(m))
    set_chart(S[19], "Chart 6", [str(v) for v in dv],
              [(nm, dsz[m]) for nm, m in zip(NAMES, PIPES)])
    set_chart(S[19], "Chart 7", [str(v) for v in dv],
              [(nm, dnn[m]) for nm, m in zip(NAMES, PIPES)])
    sz = L
    set_text(S[19], "TextBox 8",
             f"**Dimensione.** P2 ricompila e srotola: "
             f"+{it(sz[('size', 'template')]['c'])} istruzioni per strato "
             f"(r² {it(sz[('size', 'template')]['r2'], 2)}). P3 non si muove: "
             f"{it(ld['modular']['med'])} su ogni modello.")
    set_text(S[19], "TextBox 9",
             f"**Tempo.** P3 paga ~{it(L[('P', 'ns', 'modular')]['c'])} ns "
             f"per strato, P2 ~{it(L[('P', 'ns', 'template')]['c'])}, P1 e "
             f"P1.5 ~{it(L[('P', 'ns', 'p1_static')]['c'])} (legge, a MAC "
             f"ferme).")
    set_text(S[19], "TextBox 13",
             f"Un modello profondo si paga sempre: con P2 in un programma più "
             f"grande da ricompilare (~{it(round(sz[('size', 'template')]['c'], -1))}"
             f" istruzioni per strato), con P3 in "
             f"~{it(L[('P', 'ns', 'modular')]['c'])} ns per pacchetto a ogni "
             f"strato. P3 è la più flessibile, ed è quella che la profondità "
             f"rallenta di più.")
    set_text(S[19], "TextBox 5",
             f"Mediane per numero di strati, famiglia base ({len(base_ids)} "
             "modelli)  ·  dimensione: istruzioni del programma caricato  ·  "
             "tempo: CPU meno baseline, xdp_gen, P-core a 3,5 GHz")

    # 21 -- a pari pesi (diventa la 20)
    isn = f["isoparam"]["nn"]["P"]
    set_chart(S[20], "Chart 6", dd,
              [(nm, [isn[m].get(int(d), isn[m].get(d)) for d in dd])
               for nm, m in zip(NAMES, PIPES)])
    slp = f["isoparam"]["slope"]
    set_text(S[20], "TextBox 10",
             f"Da 1 a 5 strati, a pesi fermi: P2 +{r(rise['template'])} %, "
             f"P3 +{r(rise['modular'])} %; ~{md(slp['modular'])} ns per "
             f"strato per P3.")
    p1v = [v for m in ("p1_static", "hardcoded") for v in isn[m].values()]
    set_text(S[20], "TextBox 14",
             f"**{it(min(p1v))}–{it(max(p1v))} ns** (mediane): srotolano "
             f"tutto in una funzione sola, e la forma conta poco "
             f"(~{md(slp['p1_static'])} ns per strato).")
    set_text(S[20], "TextBox 18",
             f"Con le versioni specializzate la forma della rete si sceglie "
             f"per l'accuratezza. Con le generiche, a parità di pesi, conviene "
             f"una rete larga e poco profonda: da 1 a 5 strati il costo sale "
             f"del {md(rise['template'])} % (P2) e del "
             f"{md(rise['modular'])} % (P3).")
    set_text(S[20], "TextBox 5",
             "Cinque forme con circa 592 pesi, da 1 a 5 strati, 2 "
             f"composizioni dell'ingresso ({f['isoparam']['n']} modelli)  ·  "
             "mediane  ·  CPU meno baseline, P-core")

    # 22 -- la legge (diventa la 21)
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        png = os.path.join(tmp, "legge_costo.png")
        law_figure(pop, f, png)
        replace_picture(S[21], [sh.name for sh in S[21].shapes
                                if sh.shape_type == 13][0], png)
    # la stessa figura, vettoriale, per il september_notebook
    law_figure(pop, f, os.path.join(DOCS, "figures", "popolazione_legge.pdf"))
    # dove va il tempo: quota mediana di ogni termine della legge
    sh21 = f["law_shares"]
    set_table(S[21], [sh.name for sh in S[21].shapes if sh.has_table][0],
              [["Versione", "fisso · MAC · strati"]]
              + [[nm, " · ".join(f"{pct(x['med'])} %" for x in sh21[m])]
                 for nm, m in zip(NAMES, PIPES)])
    errs = [L[("P", "ns", m)]["err50"] for m in PIPES]
    r2s = [L[("P", "ns", m)]["r2"] for m in PIPES]
    r2sh = [L[("P", "ns", m)]["r2_shape"] for m in PIPES]
    set_text(S[21], "TextBox 3",
             "Il costo di un modello si prevede: a + b × MAC + c × strati")
    struct = [1 - sh21[m][1]["med"] for m in ("template", "modular")]
    set_text(S[21], "TextBox 8",
             f"**Dove va il tempo** (quota mediana di ogni termine). P1 e "
             f"P1.5: circa metà nelle moltiplicazioni. P2 e P3: "
             f"{pct(min(struct)) if pct(min(struct)) == pct(max(struct)) else pct(min(struct)) + '–' + pct(max(struct))}"
             f" % nella parte fissa e "
             f"negli strati, cioè tail call e letture di tabella. La legge "
             f"regge su tutte (r² {it(min(r2s), 2)}–{it(max(r2s), 2)}, "
             f"errore {it(min(errs))}–{it(max(errs))} % su modelli non "
             f"visti).")
    lp1, lp3 = L[("P", "ns", "p1_static")], L[("P", "ns", "modular")]
    set_text(S[21], "TextBox 12",
             f"Il costo di un modello si **stima prima di misurarlo**: "
             f"~{it(lp1['a'])} ns + **{it(lp1['b'], 2)} ns** per MAC con i "
             f"pesi compilati (P1), ~{it(lp3['a'])} ns + "
             f"**{it(lp3['b'], 2)} ns** per MAC + ~{it(lp3['c'])} ns per "
             f"strato con P3. Per P2 e P3 pesa la **struttura** (tail call, "
             f"letture di tabella), non l'aritmetica.")
    set_text(S[21], "TextBox 5",
             f"Legge su {lp1['n']} modelli densi (P2: "
             f"{L[('P', 'ns', 'template')]['n']}), errore su modelli lasciati "
             "fuori  ·  grafico: misurato meno c × strati  ·  tabella: "
             "quote mediane dei tre termini  ·  P-core")

    # 23 -- pesi a zero (diventa la 22)
    sp = f["sparsity"]["ratio"]          # {pipeline: {0.0|0.5|0.9: summ}}
    vals23 = {m: [sp[m][k]["med"] if sp[m].get(k) else None
                  for k in (0.0, 0.5, 0.9)] for m in PIPES}
    set_chart(S[22], "Chart 6", ["0 %", "50 %", "90 %"],
              [(nm, vals23[m]) for nm, m in zip(NAMES, PIPES)])
    axis_title(S[22], "Chart 6", val="misurato / previsto dalla legge densa")
    szr = f["sparsity"]["size"]
    set_text(S[22], "TextBox 10",
             f"Al 90 % di zeri il programma scende a "
             f"{span(szr['hardcoded@0.9'], 2)}× quello del modello denso, e "
             f"il costo della rete a {r(sp['hardcoded'][0.9], 2)}× del "
             f"previsto. Il compilatore vede lo zero e cancella la "
             f"moltiplicazione.")
    set_text(S[22], "TextBox 14",
             f"Dimensione identica al modello denso, costo "
             f"{r(sp['template'][0.9], 2)}× (P2) e "
             f"{r(sp['modular'][0.9], 2)}× (P3) del previsto: zero, letto da "
             f"una tabella, è un numero come un altro.")
    set_text(S[22], "TextBox 18",
             f"Potare il modello (pesi a zero) rende più veloci **solo le "
             f"versioni specializzate**: al 90 % di zeri P1 costa "
             f"**{md(sp['p1_static'][0.9], 2)}×** e P1.5 "
             f"**{md(sp['hardcoded'][0.9], 2)}×** del modello denso "
             f"previsto. Con P2 e P3 non dà niente.")
    set_text(S[22], "TextBox 5",
             "4 forme al 50 e al 90 % di pesi a zero, ciascuna contro la legge "
             "stimata sui modelli densi  ·  tempo di CPU meno la baseline, "
             "xdp_gen, nodo saturo, P-core a 3,5 GHz")

    # 18 -- cambiare modello (bench_solo.py: il nodo, e clang fuori dal nodo)
    S18 = S[17]
    up, bm, cp = so["update_ms"], so["build_ms"], so["compile_p1"]
    v18 = [bm["template"]["med"], cp["p1_static"]["med"],
           up["p1_static"]["med"],
           st.median([up["template"]["med"], up["modular"]["med"]])]
    # i valori nei nomi delle categorie: su scala logaritmica le etichette
    # delle barre sotto il millisecondo finiscono sull'asse (LibreOffice)
    set_chart(S18, "Chart 6",
              [f"P2: compila\n(una volta)\n{it(v18[0])} ms",
               f"P1: genera\ne compila\n{it(v18[1])} ms",
               f"P1: carica\nsul nodo\n{it(v18[2], 1)} ms",
               f"P2 / P3:\nla tabella\n{it(v18[3], 1)} ms"],
              [("ms", v18)])
    # scala logaritmica: sotto il millisecondo le barre devono vedersi
    va18 = shape(S18, "Chart 6").chart.value_axis
    va18.minimum_scale = 0.01
    va18.tick_labels.number_format = "General"
    va18.tick_labels.number_format_is_linked = False
    shape(S18, "Chart 6").chart.plots[0].has_data_labels = False
    set_text(S18, "TextBox 10",
             f"Il nodo carica un file pronto: {span(up['p1_static'], 1)} ms "
             f"(mediana {md(up['p1_static'], 1)}). Generarlo e compilarlo con "
             f"clang, fuori dal nodo, costa {span(cp['p1_static'])} ms "
             f"secondo il modello (mediana {md(cp['p1_static'])}).")
    lo_t = min(up["template"]["min"], up["modular"]["min"])
    hi_t = max(up["template"]["max"], up["modular"]["max"])
    set_text(S18, "TextBox 14",
             f"Un modello nuovo si installa scrivendo le sue tabelle: "
             f"{it(lo_t, 2)}–{it(hi_t, 2)} ms, nessun compilatore. Il "
             f"programma generico si compila una volta sola all'avvio (P2 "
             f"{it(bm['template']['min'] / 1000, 1)}–"
             f"{it(bm['template']['max'] / 1000, 1)} s, P3 "
             f"{it(bm['modular']['med'] / 1000, 1)} s).")
    set_text(S18, "TextBox 18",
             f"Il tempo per cambiare modello non è un criterio di scelta: "
             f"sul nodo meno di {it(math.ceil(max(up[m]['max'] for m in PIPES)))}"
             f" ms per tutte, su ogni modello. Si sceglie sul costo per "
             f"pacchetto ({span(p1(nn['P']))} ns di rete con i pesi compilati, "
             f"{it(nn['P']['template']['min'])}–"
             f"{it(nn['P']['modular']['max'])} con quelli da tabella) e su "
             f"dove serve un compilatore.")
    set_text(S18, "TextBox 5",
             "Tempo per installare un modello nuovo su un nodo già in servizio "
             f"(scala logaritmica)  ·  mediane su {so['n']} modelli, "
             "bench_solo.py  ·  clang senza cache, fuori dal nodo")

    # i numeri in fondo
    for k, sl in enumerate(prs.slides, 1):
        for sh in sl.shapes:
            if sh.name == "TextBox 4" and sh.has_text_frame \
                    and sh.text_frame.text.strip().isdigit():
                set_text(sl, "TextBox 4", str(k))
    prs.save(out)
    print(f"scritto {out} ({len(prs.slides)} slide)")
