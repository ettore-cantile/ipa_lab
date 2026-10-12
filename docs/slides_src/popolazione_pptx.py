#!/usr/bin/env python3
"""
popolazione_pptx.py -- riscrive "Inferenza di una rete neurale nel kernel
Linux con eBPF XDP.pptx" con le cifre di una campagna di popolazione.

Si usa da popolazione.py (--pptx). Lo stile resta quello del file: di ogni
grafico si sostituiscono i dati (chart.replace_data), di ogni casella il
testo, copiando la formattazione del primo pezzo; "**...**" nel testo vuol
dire grassetto. La slide della legge di costo e' un'immagine e si ridisegna
con matplotlib. I testi sono scritti per chi non conosce il repository: niente
nomi di script nelle slide, ogni termine detto in italiano semplice, e una
slide in piu' («Come leggere i numeri», copiata dalla struttura della slide 2).

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
# "senza rete" = la baseline: il nodo che riceve e inoltra senza rete neurale
CATS = ["senza rete", "P1 statica", "P1.5", "P2", "P3"]
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
# per chi non conosce il repo
# --------------------------------------------------------------------------
# L'etichetta in alto di ogni slide (indice nel deck di base): un percorso in
# cinque parti, al posto delle etichette della storia del progetto.
SEZIONI = {
    2: "1 · IL NODO · QUANTO COSTA UN PACCHETTO",
    3: "1 · IL NODO · LE ISTRUZIONI",
    4: "2 · TRE TIPI DI CORE",
    5: "2 · TRE TIPI DI CORE · ISTRUZIONI PER CICLO",
    6: "2 · TRE TIPI DI CORE · DOVE L'E-CORE PERDE TEMPO",
    7: "2 · TRE TIPI DI CORE · IL CORE A BASSO CONSUMO",
    8: "3 · SOTTO CARICO · TRAFFICO CRESCENTE",
    9: "3 · SOTTO CARICO · DUE CORE",
    10: "3 · SOTTO CARICO · PROGRAMMA E TRASPORTO",
    11: "3 · SOTTO CARICO · CHE COSA NON CONTA",
    12: "4 · LA FORMA DEL MODELLO · IL NODO INTERO",
    13: "4 · LA FORMA DEL MODELLO · LE ISTRUZIONI",
    14: "4 · LA FORMA DEL MODELLO · LARGHEZZA E PARI PESI",
    15: "4 · LA FORMA DEL MODELLO · DUE MODI DI MISURARE",
    16: "5 · LA SOLA RETE NEURALE · IL PREZZO DELLA CONFIGURABILITÀ",
    17: "5 · LA SOLA RETE NEURALE · CAMBIARE MODELLO",
    18: "5 · LA SOLA RETE NEURALE · TAGLIA DELLA RETE E DEL MODELLO",
    19: "5 · LA SOLA RETE NEURALE · PROFONDITÀ",
    20: "5 · LA SOLA RETE NEURALE · A PARITÀ DI PESI",
    21: "5 · LA SOLA RETE NEURALE · PREVEDERE IL COSTO",
    22: "5 · LA SOLA RETE NEURALE · PESI A ZERO",
}

# I titoli degli assi del deck di base, detti senza gergo.
VOCABOLARIO = {
    "ns per pacchetto": "tempo per pacchetto (ns)",
    "ns di CPU per pacchetto": "tempo per pacchetto (ns)",
    "M pacchetti/s": "milioni di pacchetti al secondo",
    "M pacchetti/s, P-core": "milioni di pacchetti/s, P-core",
    "M pacchetti/s, E-core": "milioni di pacchetti/s, E-core",
    "cicli per pacchetto": "cicli di clock per pacchetto",
    "mancate dell'ultimo livello di cache per pacchetto":
        "letture andate in memoria, per pacchetto",
    "ns": "tempo (ns)",
    "ns di rete neurale per pacchetto": "tempo della sola rete (ns)",
    "istruzioni (scala logaritmica)": "istruzioni del programma (scala log.)",
    "istruzioni per ciclo": "istruzioni per ciclo di clock",
}


def vocabolario_assi(prs):
    for sl in prs.slides:
        for sh in sl.shapes:
            if not sh.has_chart:
                continue
            for ax in (sh.chart.category_axis, sh.chart.value_axis):
                try:
                    if not ax.has_title:
                        continue
                except Exception:
                    continue
                t = ax.axis_title.text_frame.text
                if t in VOCABOLARIO:
                    p = ax.axis_title.text_frame.paragraphs[0]
                    p.runs[0].text = VOCABOLARIO[t]
                    for rr in p.runs[1:]:
                        rr.text = ""


def clona_slide(prs, src, posizione):
    """Una copia di `src` (solo forme senza relazioni: testo e tabelle) in
    `posizione` (0 = prima)."""
    new = prs.slides.add_slide(src.slide_layout)
    for sh in list(new.shapes):
        sh._element.getparent().remove(sh._element)
    for sh in src.shapes:
        new.shapes._spTree.insert_element_before(copy.deepcopy(sh._element),
                                                 "p:extLst")
    bg = src._element.cSld.bg
    if bg is not None:
        new._element.cSld.insert(0, copy.deepcopy(bg))
    lst = prs.slides._sldIdLst
    el = lst[-1]
    lst.remove(el)
    lst.insert(posizione, el)
    return new


def come_leggere(prs, src, f):
    """La slide «Come leggere i numeri», con la struttura della slide 2:
    la tabella delle versioni diventa una tabella a due colonne."""
    from pptx.oxml.ns import qn
    sl = clona_slide(prs, src, 2)
    n = f["n_models"]
    rg = f["ranges"]
    set_text(sl, "TextBox 2", "COME LEGGERE I NUMERI")
    set_text(sl, "TextBox 3", f"Ogni cifra vale per {n} modelli, non per uno")
    set_text(sl, "TextBox 6",
             f"Ogni misura è ripetuta su **{n} reti neurali diverse**: da "
             f"{it(rg['n_in'][0])} a {it(rg['n_in'][1])} ingressi, da "
             f"{it(rg['depth'][0])} a {it(rg['depth'][1])} strati, da "
             f"{it(rg['width_max'][0])} a {it(rg['width_max'][1])} neuroni per "
             f"strato. Una conclusione vale solo se regge su tutte.")
    tab = shape(sl, "Table 7")
    tbl = tab.table._tbl
    W = sum(int(g.get("w")) for g in tbl.tblGrid.findall(qn("a:gridCol")))
    for g in tbl.tblGrid.findall(qn("a:gridCol"))[2:]:
        tbl.tblGrid.remove(g)
    for tr in tbl.tr_lst:
        for tc in tr.tc_lst[2:]:
            tr.remove(tc)
    cols = tbl.tblGrid.findall(qn("a:gridCol"))
    cols[0].set("w", str(int(W * 0.30)))
    cols[1].set("w", str(W - int(W * 0.30)))
    righe = [["Si legge", "Vuol dire"],
             ["52 [19–155] ns", "la mediana dei modelli e, fra parentesi, il "
                                "più leggero e il più pesante"],
             ["85/85", "vale su 85 modelli su 85"],
             ["4,3 volte", "un rapporto calcolato modello per modello, poi la "
                           "mediana"],
             ["senza rete", "il nodo che riceve e inoltra senza rete neurale: "
                            "il costo fisso"]]
    set_table(sl, "Table 7", righe)
    t = tab.table
    for i in range(1, len(righe)):
        for j in range(2):
            c = t.cell(i, j)
            c.fill.solid()
            c.fill.fore_color.rgb = RGBColor.from_string(
                "FFFFFF" if i % 2 else "F4F6F9")
            for p in c.text_frame.paragraphs:
                for rr in p.runs:
                    rr.font.color.rgb = RGBColor.from_string("222B36")
                    rr.font.bold = (j == 0)
    set_text(sl, "TextBox 8",
             "Il **nodo** è il computer che riceve il pacchetto, esegue la "
             "rete neurale per scegliere da quale porta farlo uscire, e lo "
             "inoltra. Il processore ha tre tipi di core: **P-core** veloci, "
             "**E-core** efficienti, **LP E-core** a basso consumo. Un "
             "nanosecondo (ns) è un miliardesimo di secondo.")
    set_text(sl, "TextBox 10",
             "Il **costo** di un pacchetto è il tempo di processore che "
             "serve per elaborarlo; 1 diviso quel tempo è la **capacità**, "
             "quanti pacchetti al secondo il nodo regge.")
    set_text(sl, "TextBox 5",
             "Campagna dell'11–12 ottobre 2026, portatile di laboratorio "
             "(Intel Core Ultra 7 155H), core a frequenza fissa")
    return sl


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
                   label=f"{name[m]}: {it(law['b'], 2)} ns per "
                         f"moltiplicazione", zorder=3)
        ax.plot([0, xmax * 1.03], [law["a"], law["a"] + law["b"] * xmax * 1.03],
                color=COLOR[m], linewidth=2, zorder=2)
        # P1 e P1.5 finiscono quasi nello stesso punto: etichette scostate
        dy = {"hardcoded": 9, "p1_static": -9}.get(m, 0)
        ax.annotate(name[m], (xmax * 1.035,
                              law["a"] + law["b"] * xmax * 1.03 + dy),
                    color=ink, fontsize=8, va="center")
    ax.set_xlim(0, xmax * 1.16)
    ax.set_ylim(bottom=0)
    ax.set_xlabel("moltiplicazioni eseguite per pacchetto", color=ink2,
                  fontsize=8)
    ax.set_ylabel("ns di rete neurale, tolta la parte per strato", color=ink2,
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
             f"Quattro modi di scrivere la stessa rete neurale dentro il "
             f"kernel Linux, misurati con traffico vero su {n} reti diverse: "
             f"quanto costa ogni pacchetto, perché, e che cosa cambia su un "
             f"core più lento.")

    # 2 -- le quattro versioni
    set_text(S[1], "TextBox 6",
             f"Tutte e quattro prendono la stessa decisione su ogni pacchetto "
             f"(verificato su {n} modelli). Cambia solo **quanto sanno già** "
             f"quando vengono compilate.")
    set_text(S[1], "TextBox 8",
             "* Solo P1 statica può togliere dal programma anche i "
             "**collegamenti che il suo nodo non ha**, perché conosce già il "
             "nodo su cui girerà. Le misure di queste slide non lo fanno: "
             "tutte le versioni vedono tutte le porte.")

    # 3 -- quanto costa un pacchetto
    rx, bl = ref["rxonly_P"]["ns"], ref["baseline_P"]["ns"]
    nnP = [None] + [nn["P"][m]["med"] for m in PIPES]
    set_chart(S[2], "Chart 6",
              ["solo ricezione", "senza rete"] + NAMES,
              [("ricevere il pacchetto", [rx] * 6),
               ("leggere l'intestazione e inoltrare", [0] + [bl - rx] * 5),
               ("rete neurale", [0, 0] + nnP[1:])])
    set_text(S[2], "TextBox 10", f"{it(ns['P']['baseline']['med'])} ns")
    set_text(S[2], "TextBox 11",
             f"{it(mpps['P']['baseline']['med'], 1)} milioni di pacchetti/s")
    lo = min(ns["P"]["p1_static"]["min"], ns["P"]["hardcoded"]["min"])
    hi = max(ns["P"]["p1_static"]["max"], ns["P"]["hardcoded"]["max"])
    set_text(S[2], "TextBox 15", f"{it(lo)}–{it(hi)} ns")
    set_text(S[2], "TextBox 16",
             f"{span(mpps['P']['p1_static'], 1)} milioni di pacchetti/s")
    set_text(S[2], "TextBox 20", f"{span(ns['P']['template'])} ns")
    set_text(S[2], "TextBox 21",
             f"{span(mpps['P']['template'], 1)} milioni di pacchetti/s")
    set_text(S[2], "TextBox 25", f"{span(ns['P']['modular'])} ns")
    set_text(S[2], "TextBox 26",
             f"{span(mpps['P']['modular'], 1)} milioni di pacchetti/s")
    set_text(S[2], "TextBox 5",
             f"Nodo su un core veloce (P-core) a 3,5 GHz, pacchetti da 64 "
             f"byte  ·  barre: mediana dei {n} modelli  ·  schede: dal "
             f"modello più leggero al più pesante")
    set_text(S[2], "TextBox 30",
             f"Ricevere e inoltrare un pacchetto costa **~{it(bl)} ns**, con "
             f"qualunque modello. La rete neurale aggiunge "
             f"**{span(p1(nn['P']))} ns** con i pesi scritti nel programma "
             f"(P1), **{span(nn['P']['template'])} ns** se la forma si legge "
             f"da tabella (P2), **{span(nn['P']['modular'])} ns** se anche il "
             f"numero di strati (P3). Un core regge da "
             f"{it(mpps['P']['p1_static']['max'], 1)} a "
             f"{it(mpps['P']['modular']['min'], 1)} milioni di pacchetti al "
             f"secondo.")

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
             f"**Caricate contro eseguite.** P2 è il più grande ma esegue "
             f"meno istruzioni di P3 ({b2[0]} modelli su {b2[1]}).")
    set_text(S[3], "TextBox 9",
             f"**Stesse istruzioni su ogni core:** al più {it(iep, 1)} % di "
             f"differenza ({it(ilp, 1)} % sul LP E-core).")
    set_text(S[3], "TextBox 5",
             "Caricate: la dimensione del programma, contata dal kernel  ·  "
             "eseguite: contate dal processore per ogni pacchetto  ·  a "
             f"destra i {f['lpe']['n']} modelli misurati su tutti e tre i core")

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
             f"**Milioni di pacchetti al secondo.** Rispetto al P-core, "
             f"l'E-core regge {span(ce['baseline'], 2)} volte senza rete e "
             f"{span(ce['modular'], 2)} volte con P3.")
    cyc = f["cycles_E_P"]
    nnc = f["nn_cycles_E_P"]
    set_text(S[4], "TextBox 9",
             f"**Tempo per pacchetto.** Sull'E-core il lavoro fisso del nodo "
             f"costa il {pct(cyc['baseline']['med'] - 1)} % in più, la rete "
             f"neurale di P3 solo il {pct(nnc['modular']['med'] - 1)} %.")
    cl = lpe["cap_L_P"]
    set_text(S[4], "TextBox 13",
             f"A parità di frequenza l'E-core rallenta soprattutto il **lavoro "
             f"fisso del nodo** (ricevere e inoltrare): più la rete pesa sul "
             f"totale, meno conta il core. Il core a basso consumo (LP E-core, "
             f"2,5 GHz) regge dal {pct(min(cl[m]['min'] for m in PIPES))} al "
             f"{pct(max(cl[m]['max'] for m in PIPES))} % del P-core.")
    set_text(S[4], "TextBox 5",
             "Core veloce (P-core) ed efficiente (E-core) a 3,5 GHz, a basso "
             "consumo (LP E-core) a 2,5 GHz  ·  grafici: mediana dei "
             f"{lpe['n']} modelli misurati su tutti e tre i core")

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
             f"Il codice è lo stesso su ogni core; cambia quante istruzioni il "
             f"core esegue a ogni ciclo di clock (IPC): "
             f"{md(ipc['P']['baseline'], 1)} → {md(ipc['E']['baseline'], 1)} "
             f"senza rete, dove il kernel salta e aspetta la memoria; "
             f"{md(ipc['P']['modular'], 1)} → {md(ipc['E']['modular'], 1)} "
             f"con P3, una fila di moltiplicazioni.")
    set_text(S[5], "TextBox 5",
             "Contatori del processore sul core del nodo  ·  tabella: mediane "
             f"su {n} modelli  ·  grafico: i {lpe['n']} modelli misurati sui "
             "tre core")

    # 7 -- dove l'E-core perde tempo
    fixP, fixE = f["cycles"]["P"]["baseline"]["med"], \
        f["cycles"]["E"]["baseline"]["med"]
    cats7, fixed, net = [], [], []
    for m, nm in zip(ALL, ["senza rete", "P1", "P1.5", "P2", "P3"]):
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
             f"Ricevere, inoltrare e liberare la memoria è lavoro del kernel, "
             f"pieno di salti e attese: l'E-core ne esegue "
             f"{md(ipc['E']['baseline'], 1)} istruzioni per ciclo invece di "
             f"{md(ipc['P']['baseline'], 1)}. La rete è una fila di "
             f"moltiplicazioni, che l'E-core esegue quasi come il P-core.")
    set_text(S[6], "TextBox 5",
             "Cicli di clock per pacchetto, contati dal processore  ·  parte "
             "fissa = il nodo senza rete, rete = il resto  ·  mediane su "
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
             f"**Letture andate in memoria** (il dato non è in cache): zero "
             f"su P-core ed E-core, {it(min(llc[m]['med'] for m in ALL))}–"
             f"{it(max(llc[m]['med'] for m in ALL))} per pacchetto sul "
             f"LP E-core.")
    set_text(S[7], "TextBox 9",
             f"**Cicli per pacchetto.** Per P3: "
             f"{it(lc['P']['modular']['med'])} sul P-core, "
             f"{it(lc['E']['modular']['med'])} sull'E-core, "
             f"{it(lc['L']['modular']['med'])} sul LP E-core; in tempo "
             f"{it(lpe['ns']['P']['modular']['med'])}, "
             f"{it(lpe['ns']['E']['modular']['med'])} e "
             f"{it(lpe['ns']['L']['modular']['med'])} ns.")
    lipc = lpe["ipc"]["L"]
    set_text(S[7], "TextBox 13",
             f"Il LP E-core sta in un'altra parte del chip, fuori dalla cache "
             f"che gli altri core condividono: i pacchetti gli arrivano dalla "
             f"memoria. Fra attese, un core più semplice e 2,5 GHz regge dal "
             f"{pct(min(cl[m]['min'] for m in PIPES))} al "
             f"{pct(max(cl[m]['max'] for m in PIPES))} % del P-core.")
    set_text(S[7], "TextBox 5",
             "Contatori del processore, per pacchetto, a nodo pieno  ·  "
             f"LP E-core a 2,5 GHz  ·  mediane dei {lpe['n']} modelli misurati "
             "sui tre core")

    # 9 -- traffico crescente, curve normalizzate alla capacita'
    ld9 = f["load"]
    cats9 = [f"{it(g, 2)}×" for g in ld9["grid"]]
    for chart, k in (("Chart 6", "P"), ("Chart 7", "E")):
        set_chart(S[8], chart, cats9,
                  [(nm, ld9["curves"][k][m]) for nm, m in zip(NAMES, PIPES)])
        axis_title(S[8], chart, cat="traffico offerto ÷ capacità",
                   val="inoltrati ÷ capacità")
    kc = ld9["knee_over_cap"]
    n_curves = kc["P"]["n"] // 4
    set_text(S[8], "TextBox 8",
             f"**P-core.** Fino alla capacità passa tutto, poi la curva resta "
             f"piatta: il massimo inoltrato è {md(kc['P'], 2)} volte la "
             f"capacità misurata a parte.")
    set_text(S[8], "TextBox 9",
             f"**E-core.** Stesso andamento ({md(kc['E'], 2)}). Divise per la "
             f"capacità del loro modello, le curve di modelli diversi "
             f"coincidono.")
    set_text(S[8], "TextBox 13",
             "Oltre la capacità i pacchetti si perdono **in coda, prima del "
             "programma**: il collo di bottiglia è il programma, su ogni tipo "
             "di core. Fa eccezione P1 sui modelli più leggeri: sopra i 9 "
             "milioni di pacchetti al secondo perde anche l'uscita.")
    set_text(S[8], "TextBox 5",
             f"Traffico crescente da 0,5 a 12 milioni di pacchetti al "
             f"secondo, {n_curves} modelli dal più leggero al più pesante  ·  "
             f"entrambi gli assi divisi per la capacità del modello")

    # 10 -- due core
    tw = f["two"]
    for chart, k in (("Chart 6", "P"), ("Chart 7", "E")):
        set_chart(S[9], chart, CATS,
                  [("1 core", [tw[k]["one"][m] for m in ALL]),
                   ("2 core", [tw[k]["two"][m] for m in ALL])])
    set_text(S[9], "TextBox 8",
             f"**P-core.** Con due core il nodo regge il "
             f"{md(tw['P']['pct_all'])} % del doppio (fra il "
             f"{span(tw['P']['pct_all'])} %).")
    set_text(S[9], "TextBox 9",
             f"**E-core.** Il {md(tw['E']['pct_all'])} % del doppio, con i due "
             f"core in gruppi diversi del chip.")
    set_text(S[9], "TextBox 5",
             "Una coda, un generatore e un core d'uscita per ogni core del "
             f"nodo  ·  mediane di {tw['P']['n']} modelli dal più leggero al "
             "più pesante")

    # 11 -- tre orologi
    ck = f["clocks"]
    cats11, progv, xpv = [], [], []
    for m, nm in zip(ALL, ["senza rete", "P1", "P1.5", "P2", "P3"]):
        for k in ("P", "E"):
            cats11.append(f"{nm} · {k}")
            progv.append(ck["prog"][(k, m)]["med"])
            xpv.append(ck["xport"][(k, m)]["med"])
    set_chart(S[10], "Chart 6", cats11,
              [("il programma", progv),
               ("il trasporto", xpv)])
    pP = ck["prog"]
    set_text(S[10], "TextBox 10",
             f"Da {md(pP[('P', 'baseline')])} ns senza rete a "
             f"{md(pP[('P', 'modular')])} ns con P3 (mediane, P-core). Per "
             f"P3 da {span(pP[('P', 'modular')])} ns secondo il modello.")
    xp = [ck["xport"][("P", m)] for m in ALL]
    xe = [ck["xport"][("E", m)] for m in ALL]
    set_text(S[10], "TextBox 14",
             f"Consegnare il pacchetto al nodo successivo: "
             f"{it(min(s['min'] for s in xp))}–{it(max(s['max'] for s in xp))} "
             f"ns sul P-core, {it(min(s['min'] for s in xe))}–"
             f"{it(max(s['max'] for s in xe))} sull'E-core, con ogni modello e "
             f"versione.")
    lat = lambda k, m: (pP[(k, m)]["med"] + ck["xport"][(k, m)]["med"])  # noqa
    set_text(S[10], "TextBox 18",
             f"Il trasporto è un costo comune, che non dipende né dalla "
             f"versione né dal modello. Dall'arrivo del pacchetto alla sua "
             f"ripartenza servono almeno {it(lat('P', 'baseline'))}–"
             f"{it(lat('P', 'modular'))} ns sul P-core e "
             f"{it(lat('E', 'baseline'))}–{it(lat('E', 'modular'))} "
             f"sull'E-core (dal nodo senza rete a P3).")
    set_text(S[10], "TextBox 5",
             "Tre orologi letti dal programma: all'ingresso, prima di "
             "inoltrare, all'arrivo al nodo successivo  ·  minimi, a traffico "
             f"leggero  ·  barre: mediana dei {n} modelli")

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
             f"**Taglia del pacchetto: nessun effetto** ({md(fr['var'], 1)} % "
             f"fra 64 e 1 514 byte, in mediana). Il nodo legge solo "
             f"l'intestazione.")
    set_text(S[11], "TextBox 9",
             f"**Porta d'uscita: nessun effetto.** Scartare il pacchetto costa "
             f"~{md(cs['extra'])} ns in più: la sua memoria si libera sul core "
             f"del nodo.")
    mx = f["mix"]["rel"]
    set_text(S[11], "TextBox 13",
             f"Basta un numero per versione e modello a descrivere il costo "
             f"del nodo: non contano la taglia del pacchetto, la porta "
             f"d'uscita né il TTL. Solo la decisione di scartare costa "
             f"~{md(cs['extra'])} ns in più, per come è fatto il banco.")
    set_text(S[11], "TextBox 5",
             "Una prova per ogni decisione che il modello sa prendere  ·  "
             f"P-core a 3,5 GHz  ·  mediane di {fr['n']} modelli (taglie) e "
             f"{cs['n']} (decisioni)")

    # 13 -- profondita' e pesi a zero, tempo del nodo
    dv, dg = groups(pop, base_ids, "depth",
                    lambda i, m: pop.val("P", i, m, "ns"))
    set_chart(S[12], "Chart 6", [str(v) for v in dv],
              [(nm, dg[m]) for nm, m in zip(NAMES, PIPES)])
    tw13 = sparse_twin(pop)
    set_chart(S[12], "Chart 7", ["0 %", "50 %", "90 %"],
              [(nm, tw13[m]) for nm, m in zip(NAMES, PIPES)])
    axis_title(S[12], "Chart 7", val="tempo ÷ stesso modello senza zeri")
    set_text(S[12], "TextBox 3",
             "Profondità e pesi a zero, sul nodo vero")
    set_text(S[12], "TextBox 8",
             f"**Profondità.** Ogni strato nascosto in più costa "
             f"~{it(L[('P', 'ns', 'modular')]['c'])} ns a P3, "
             f"~{it(L[('P', 'ns', 'template')]['c'])} a P2, quasi niente a P1 "
             f"e P1.5.")
    set_text(S[12], "TextBox 9",
             f"**Pesi a zero.** Al 90 % di zeri il nodo con P1 scende a "
             f"{it(tw13['p1_static'][2], 2)} e con P1.5 a "
             f"{it(tw13['hardcoded'][2], 2)} volte il tempo dello stesso "
             f"modello senza zeri; P2 e P3 non cambiano.")
    set_text(S[12], "TextBox 13",
             f"Su tutta la popolazione la profondità costa soprattutto a P3 e "
             f"P2, i pesi a zero aiutano solo P1 e P1.5. Il lavoro fisso del "
             f"nodo (~{it(bl)} ns) è lo stesso con qualunque modello.")
    set_text(S[12], "TextBox 5",
             "Tempo per pacchetto, P-core  ·  profondità: mediane dei "
             f"{len(base_ids)} modelli del disegno principale  ·  pesi a zero: "
             "4 forme, contro lo stesso modello senza zeri")

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
             f"**Istruzioni eseguite.** Ogni strato in più ne aggiunge "
             f"{it(li['c'])} a P3 e {it(L[('P', 'instr', 'template')]['c'])} "
             f"a P2, uguali su P-core ed E-core.")
    set_text(S[13], "TextBox 9",
             f"**Tempo.** Ogni strato costa a P3 "
             f"~{it(L[('P', 'ns', 'modular')]['c'])} ns sul P-core e "
             f"~{it(L[('E', 'ns', 'modular')]['c'])} sull'E-core (tratteggio): "
             f"stesse istruzioni, eseguite più lentamente.")
    set_text(S[13], "TextBox 13",
             "P3 esegue uno strato alla volta: a ogni strato salta a un altro "
             "programma e rilegge dalle tabelle dove si trova. È sempre lo "
             "stesso lavoro, per questo ogni strato costa uguale, su ogni "
             "modello.")
    set_text(S[13], "TextBox 5",
             f"Mediane per numero di strati sui {len(base_ids)} modelli del "
             f"disegno principale  ·  costo per strato stimato su "
             f"{li['n']} modelli senza zeri  ·  contatori del processore")

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
             f"**Larghezza.** Da 2 a 8 neuroni per strato il tempo sale su "
             f"tutte: P1 da {it(wg['p1_static'][0])} a "
             f"{it(wg['p1_static'][-1])} ns, P3 da {it(wg['modular'][0])} a "
             f"{it(wg['modular'][-1])} ns.")
    rise = f["isoparam"]["rise"]
    set_text(S[14], "TextBox 9",
             f"**A pari pesi.** Gli stessi ~592 pesi su 5 strati invece di 1: "
             f"P2 +{md(rise['template'])} %, P3 +{md(rise['modular'])} %, "
             f"P1 e P1.5 solo +{md(rise['hardcoded'])}–"
             f"{md(rise['p1_static'])} %.")
    eratio = [wgE["modular"][j] / wg["modular"][j] for j in range(len(wv))]
    set_text(S[14], "TextBox 13",
             f"Sull'E-core P3 ha la stessa forma, più in alto del "
             f"{pct(min(eratio) - 1)}–{pct(max(eratio) - 1)} %: la forma "
             f"migliore del modello non dipende dal core su cui girerà.")
    set_text(S[14], "TextBox 5",
             "Tempo per pacchetto, P-core; tratteggio: P3 sull'E-core  ·  "
             f"larghezza: {len(base_ids)} modelli del disegno principale  ·  "
             f"pari pesi: {f['isoparam']['n']} modelli")

    # 16 -- traffico leggero contro nodo saturo
    lt = f["depth_light"]
    _, dnn = groups(pop, base_ids, "depth", lambda i, m: pop.nn("P", i, m))
    _, dmin = groups(pop, base_ids, "depth",
                     lambda i, m: pop.c.nn_t2("P", i, m, 0))
    _, davg = groups(pop, base_ids, "depth",
                     lambda i, m: pop.c.nn_t2("P", i, m, 1))
    for chart, m in (("Chart 6", "modular"), ("Chart 7", "template")):
        set_chart(S[15], chart, [str(v) for v in dv],
                  [("nodo pieno", dnn[m]),
                   ("poco traffico, il pacchetto più veloce", dmin[m]),
                   ("poco traffico, media", davg[m])])
        axis_title(S[15], chart, cat="strati nascosti")
    li_ = ck["light"]
    mav = ck["minavg"]
    set_text(S[15], "TextBox 3",
             "Poco traffico o nodo pieno: la rete di P2 e P3 costa uguale")
    set_text(S[15], "TextBox 8",
             f"**P3.** Con poco traffico la rete costa "
             f"{md(li_[('P', 'modular')], 2)} volte quanto a nodo pieno; il "
             f"pacchetto più veloce il {pct(1 - mav[('P', 'modular')]['med'])} "
             f"% meno della media.")
    set_text(S[15], "TextBox 9",
             f"**P2:** {md(li_[('P', 'template')], 2)} volte. Per P1 e P1.5 no "
             f"({md(li_[('P', 'p1_static')], 2)} e "
             f"{md(li_[('P', 'hardcoded')], 2)}): la loro rete costa poche "
             f"decine di ns, e le due misure non la distinguono bene.")
    set_text(S[15], "TextBox 13",
             "Due modi indipendenti di misurare la rete, a nodo pieno e con "
             "poco traffico, danno lo stesso costo per P2 e P3 su ogni "
             "modello. Il pacchetto più veloce è quello che trova la cache "
             "già pronta.")
    set_text(S[15], "TextBox 5",
             "Tempo letto dal programma stesso, con 0,25 e 0,5 milioni di "
             "pacchetti al secondo, meno il nodo senza rete  ·  mediane per "
             f"strati, {len(base_ids)} modelli  ·  P-core")

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
                  (span(so["n_tail"][m]) if m == "modular"
                   else it(so["n_tail"][m]["med"]))]
                 for nm, m in zip(NAMES, PIPES)])
    set_text(S[16], "TextBox 3",
             f"La configurabilità si paga per pacchetto: da "
             f"+{md(p1(nn['P']))} a +{md(nn['P']['modular'])} ns")
    set_text(S[16], "TextBox 11",
             f"Il prezzo della configurabilità sta nelle **letture di "
             f"tabella** (da {md(so['lookups']['p1_static'])} a "
             f"{md(so['lookups']['modular'])} per pacchetto) e nei **salti "
             f"fra programmi** (P3 ne fa uno per strato), non nelle "
             f"moltiplicazioni. In mediana P2 costa "
             f"**{md(f['p2_over_p1'], 1)} volte** P1, P3 "
             f"**{md(f['p3_over_p1'], 1)} volte**; P1.5 quasi come P1.")
    set_text(S[16], "TextBox 5",
             f"Mediane su {n} modelli (P2: {n85})  ·  tempo per pacchetto, "
             "P-core  ·  letture e salti contati da una versione del "
             "programma che li conta")

    # 19 -- la rete puo' crescere (diventa la 18)
    nd = f["nodes"]
    set_chart(S[18], "Chart 6", [str(x) for x in nd["sizes"]],
              [(nm, [nd["residual"][m].get(x, nd["residual"][m].get(str(x)))
                     for x in nd["sizes"]]) for nm, m in zip(NAMES, PIPES)])
    axis_title(S[18], "Chart 6", cat="nodi della rete",
               val="scarto dalla legge (ns)")
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
             f"**Nodi della rete.** Reti da {nd['sizes'][0]} a "
             f"{nd['sizes'][-1]} nodi ({nd['n']} modelli): il costo resta "
             f"quello previsto dalla legge, al più "
             f"{it(max(abs(v) for v in slope.values()), 2)} ns per nodo in "
             f"più.")
    set_text(S[18], "TextBox 9",
             f"**Larghezza del modello.** Da 2 a 8 neuroni sale su tutte: P1 "
             f"da {it(wnn['p1_static'][0])} a {it(wnn['p1_static'][-1])} ns, "
             f"P3 da {it(wnn['modular'][0])} a {it(wnn['modular'][-1])} ns.")
    set_text(S[18], "TextBox 5",
             "Tempo della sola rete, P-core  ·  a sinistra: costo misurato "
             "meno quello previsto dalla legge, per taglia della rete  ·  a "
             f"destra: {len(base_ids)} modelli del disegno principale")

    # 20 -- profondita' (diventa la 19)
    _, dsz = groups(pop, base_ids, "depth",
                    lambda i, m: pop.c.size.get(i, {}).get(m))
    set_chart(S[19], "Chart 6", [str(v) for v in dv],
              [(nm, dsz[m]) for nm, m in zip(NAMES, PIPES)])
    set_chart(S[19], "Chart 7", [str(v) for v in dv],
              [(nm, dnn[m]) for nm, m in zip(NAMES, PIPES)])
    sz = L
    set_text(S[19], "TextBox 8",
             f"**Dimensione.** P2 si ricompila per ogni profondità: "
             f"~{it(round(sz[('size', 'template')]['c'], -1))} istruzioni in "
             f"più per strato. P3 resta di {it(ld['modular']['med'])} "
             f"istruzioni con ogni modello.")
    set_text(S[19], "TextBox 9",
             f"**Tempo.** Ogni strato costa a P3 "
             f"~{it(L[('P', 'ns', 'modular')]['c'])} ns, a P2 "
             f"~{it(L[('P', 'ns', 'template')]['c'])}, a P1 e P1.5 "
             f"~{it(L[('P', 'ns', 'p1_static')]['c'])}.")
    set_text(S[19], "TextBox 13",
             f"Un modello profondo si paga sempre: P2 con un programma più "
             f"grande da compilare, P3 con ~{it(L[('P', 'ns', 'modular')]['c'])}"
             f" ns in più a ogni pacchetto per ogni strato. P3 è la versione "
             f"più flessibile, ed è quella che la profondità rallenta di più.")
    set_text(S[19], "TextBox 5",
             f"Mediane per numero di strati, {len(base_ids)} modelli del "
             "disegno principale  ·  dimensione: istruzioni del programma "
             "caricato  ·  tempo: sola rete, P-core")

    # 21 -- a pari pesi (diventa la 20)
    isn = f["isoparam"]["nn"]["P"]
    set_chart(S[20], "Chart 6", dd,
              [(nm, [isn[m].get(int(d), isn[m].get(d)) for d in dd])
               for nm, m in zip(NAMES, PIPES)])
    slp = f["isoparam"]["slope"]
    set_text(S[20], "TextBox 10",
             f"Gli stessi ~592 pesi su 5 strati invece di 1: P2 costa il "
             f"{md(rise['template'])} % in più, P3 il {md(rise['modular'])} % "
             f"(~{md(slp['modular'])} ns per strato).")
    p1v = [v for m in ("p1_static", "hardcoded") for v in isn[m].values()]
    set_text(S[20], "TextBox 14",
             f"**{it(min(p1v))}–{it(max(p1v))} ns**: P1 e P1.5 scrivono la rete "
             f"per esteso in una funzione sola, e la forma conta poco "
             f"(~{md(slp['p1_static'])} ns per strato).")
    set_text(S[20], "TextBox 18",
             f"Con le versioni che hanno i pesi nel programma la forma della "
             f"rete si sceglie per l'accuratezza. Con quelle che li leggono da "
             f"tabella, a parità di pesi conviene una rete larga e poco "
             f"profonda: da 1 a 5 strati il costo sale del "
             f"{md(rise['template'])} % (P2) e del {md(rise['modular'])} % "
             f"(P3).")
    set_text(S[20], "TextBox 5",
             "Cinque forme con circa 592 pesi, da 1 a 5 strati, su 2 tipi di "
             f"ingresso ({f['isoparam']['n']} modelli)  ·  mediane  ·  sola "
             "rete, P-core")

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
              [["Versione", "fisso · moltipl. · strati"]]
              + [[nm, " · ".join(f"{pct(x['med'])} %" for x in sh21[m])]
                 for nm, m in zip(NAMES, PIPES)])
    errs = [L[("P", "ns", m)]["err50"] for m in PIPES]
    r2s = [L[("P", "ns", m)]["r2"] for m in PIPES]
    r2sh = [L[("P", "ns", m)]["r2_shape"] for m in PIPES]
    set_text(S[21], "TextBox 3",
             "Il costo di un modello si può prevedere prima di misurarlo")
    struct = [1 - sh21[m][1]["med"] for m in ("template", "modular")]
    set_text(S[21], "TextBox 8",
             f"**Dove va il tempo.** Con P1 e P1.5 circa metà è "
             f"moltiplicazioni. Con P2 e P3 circa l'"
             f"{pct(min(struct))} % è struttura: il lavoro fisso e quello per "
             f"strato, cioè salti fra programmi e letture di tabella. Su "
             f"modelli mai visti la legge sbaglia del {it(min(errs))}–"
             f"{it(max(errs))} %.")
    lp1, lp3 = L[("P", "ns", "p1_static")], L[("P", "ns", "modular")]
    set_text(S[21], "TextBox 12",
             f"**Costo della rete ≈ fisso + moltiplicazioni × costo di una + "
             f"strati × costo di uno.** P1: ~{it(lp1['a'])} ns + "
             f"{it(lp1['b'], 2)} ns per moltiplicazione. P3: ~{it(lp3['a'])} "
             f"ns + {it(lp3['b'], 2)} ns per moltiplicazione + "
             f"~{it(lp3['c'])} ns per strato.")
    set_text(S[21], "TextBox 5",
             f"Stimata su {lp1['n']} modelli senza pesi a zero, errore su "
             "modelli lasciati fuori  ·  grafico: costo meno la parte per "
             "strato  ·  tabella: quanto pesa ogni parte")

    # 23 -- pesi a zero (diventa la 22)
    sp = f["sparsity"]["ratio"]          # {pipeline: {0.0|0.5|0.9: summ}}
    vals23 = {m: [sp[m][k]["med"] if sp[m].get(k) else None
                  for k in (0.0, 0.5, 0.9)] for m in PIPES}
    set_chart(S[22], "Chart 6", ["0 %", "50 %", "90 %"],
              [(nm, vals23[m]) for nm, m in zip(NAMES, PIPES)])
    axis_title(S[22], "Chart 6", val="misurato ÷ previsto senza zeri")
    szr = f["sparsity"]["size"]
    set_text(S[22], "TextBox 10",
             f"Al 90 % di zeri il programma scende a circa un terzo "
             f"({span(szr['hardcoded@0.9'], 2)} volte) e la rete costa "
             f"{md(sp['hardcoded'][0.9], 2)} volte quanto previsto per lo "
             f"stesso modello senza zeri: il compilatore toglie le "
             f"moltiplicazioni per zero.")
    set_text(S[22], "TextBox 14",
             f"Programma identico e costo come previsto "
             f"({md(sp['template'][0.9], 2)} volte per P2, "
             f"{md(sp['modular'][0.9], 2)} per P3): uno zero letto da una "
             f"tabella è un numero come un altro.")
    set_text(S[22], "TextBox 18",
             f"Mettere pesi a zero rende più veloci **solo le versioni con i "
             f"pesi nel programma**: al 90 % di zeri P1 costa "
             f"**{md(sp['p1_static'][0.9], 2)}** e P1.5 "
             f"**{md(sp['hardcoded'][0.9], 2)}** volte il previsto. Con P2 e "
             f"P3 non dà niente.")
    set_text(S[22], "TextBox 5",
             "4 forme con il 50 e il 90 % di pesi a zero, confrontate con la "
             "legge stimata sui modelli senza zeri  ·  sola rete, P-core a "
             "3,5 GHz")

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
             f"Il nodo carica un programma già compilato in "
             f"{span(up['p1_static'], 1)} ms. Compilarlo per un modello "
             f"nuovo, su un'altra macchina, costa {span(cp['p1_static'])} ms.")
    lo_t = min(up["template"]["min"], up["modular"]["min"])
    hi_t = max(up["template"]["max"], up["modular"]["max"])
    set_text(S18, "TextBox 14",
             f"Un modello nuovo si installa scrivendo le sue tabelle: "
             f"{it(lo_t, 2)}–{it(hi_t, 2)} ms, nessun compilatore sul nodo. "
             f"Il programma generico si compila una volta sola, "
             f"all'accensione ({it(min(bm['template']['min'], bm['modular']['min']) / 1000, 1)}–"
             f"{it(max(bm['template']['max'], bm['modular']['max']) / 1000, 1)} s).")
    set_text(S18, "TextBox 18",
             f"Cambiare modello non è un criterio di scelta: sul nodo costa "
             f"meno di {it(math.ceil(max(up[m]['max'] for m in PIPES)))} ms a "
             f"tutte. Si sceglie sul costo per pacchetto e su dove serve un "
             f"compilatore: P1 ne vuole uno per ogni modello nuovo, P2 e P3 "
             f"no.")
    set_text(S18, "TextBox 5",
             "Tempo per installare un modello nuovo su un nodo già in "
             f"servizio, scala logaritmica  ·  mediane su {so['n']} modelli  ·  "
             "compilazione da zero, fuori dal nodo")

    # per chi non conosce il repo: le etichette del percorso, i due «QUINDI»
    # che venivano dal deck di base, i titoli degli assi, e la slide che
    # spiega come leggere le cifre
    for k, lab in SEZIONI.items():
        set_text(S[k], "TextBox 2", lab)
    set_text(S[3], "TextBox 13",
             "La dimensione dice quanto è **grande** il programma, non quanto "
             "**lavora**: conta quante istruzioni il processore esegue davvero "
             "per ogni pacchetto. E sono le stesse su ogni tipo di core: "
             "cambia solo quante ne esegue a ogni ciclo di clock.")
    set_text(S[9], "TextBox 13",
             "Ogni core ha i suoi contatori e la sua coda d'uscita: il secondo "
             "core non rallenta il primo. Una scheda di rete che divide i "
             "pacchetti su **N code** regge circa **N volte** la capacità di "
             "un core.")
    set_text(S18, "TextBox 9", "P1: si compila prima, fuori dal nodo")
    set_text(S[2], "TextBox 9", "senza rete")
    set_text(S[11], "TextBox 3",
             "Il costo dipende solo da versione e modello")
    set_text(S[17], "TextBox 3",
             "Cambiare modello costa millisecondi a tutte le versioni")
    set_text(S[22], "TextBox 3", "Pesi a zero: accelerano solo P1 e P1.5")
    vocabolario_assi(prs)
    come_leggere(prs, S[1], f)

    # i numeri in fondo
    for k, sl in enumerate(prs.slides, 1):
        for sh in sl.shapes:
            if sh.name == "TextBox 4" and sh.has_text_frame \
                    and sh.text_frame.text.strip().isdigit():
                set_text(sl, "TextBox 4", str(k))
    prs.save(out)
    print(f"scritto {out} ({len(prs.slides)} slide)")
