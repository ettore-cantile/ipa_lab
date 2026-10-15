#!/usr/bin/env python3
"""
build.py -- rigenera i PDF "<presentazione> - spiegazione.pdf": ogni slide,
una alla volta, con la sua spiegazione sotto.

Le immagini delle slide vengono dal .pptx (LibreOffice -> PDF -> PNG), il testo
da spiegazione_<nome>.txt (formato descritto in testa al file). L'HTML si stampa
in PDF con Chrome senza interfaccia.

    python3 docs/slides_src/build.py                 # tutte
    python3 docs/slides_src/build.py inferenza       # solo una

Una sezione "== 0 | titolo" e' una pagina introduttiva, senza immagine.

Serve: libreoffice (soffice), pdftoppm (poppler), google-chrome o chromium.
$SOFFICE sostituisce il comando di LibreOffice.
"""
import base64
import glob
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.dirname(HERE)
# nome -> (presentazione, titolo, glossario in più)
DECKS = {
    "inferenza": ("Inferenza di una rete neurale nel kernel Linux con eBPF XDP",
                  "Inferenza di una rete neurale nel kernel Linux"),
}

GLOSSARY = [
    ("Nodo", "Il computer che riceve il pacchetto, esegue la rete neurale per scegliere da quale porta farlo uscire, e lo inoltra."),
    ("XDP, eBPF", "XDP è il primo punto del kernel Linux in cui un programma può vedere un pacchetto appena arrivato; eBPF è il linguaggio di quei programmi, che il kernel controlla prima di eseguirli."),
    ("Versione (P1, P1.5, P2, P3)", "Uno dei quattro modi di scrivere il programma che esegue la rete neurale: da tutto scritto nel programma (P1) a tutto letto da tabelle (P3)."),
    ("Senza rete (baseline)", "Il nodo che riceve e inoltra senza eseguire nessuna rete neurale: il costo fisso che ogni versione paga. «Solo ricezione» riceve e basta."),
    ("Tabella", "Una zona di memoria del kernel che il programma consulta mentre gira e che si può riscrivere senza ricompilarlo (in eBPF si chiama mappa)."),
    ("Salto fra programmi", "Il passaggio da un programma eBPF a un altro (tail call). P3 ne fa uno per ogni strato della rete."),
    ("Compilare", "Tradurre il programma in codice eseguibile. P1 si compila per ogni modello nuovo, fuori dal nodo; P2 e P3 una volta sola."),
    ("Popolazione", "Le 91 reti neurali generate su cui gira ogni misura: diverse per ingressi, strati, neuroni, pesi e pesi a zero."),
    ("Mediana, fra i modelli", "La mediana sui modelli: metà costa meno, metà di più. «Fra i modelli da A a B»: il modello più leggero e il più pesante, che sono reti diverse, non un errore di misura."),
    ("Rumore di misura", "Quanto cambia la stessa misura rifatta in un'altra sessione: fino al 5 % (90° percentile). Una differenza più piccola non è una differenza, e un rapporto fra due misure di sessioni diverse può uscire poco sopra 100 %."),
    ("Legge di costo", "Costo della rete ≈ parte fissa + moltiplicazioni × costo di una + strati × costo di uno, stimata su tutti i modelli e provata su modelli lasciati fuori."),
    ("Moltiplicazioni eseguite", "Le moltiplicazioni che il programma fa davvero per un pacchetto (in inglese MAC). Un ingresso con molte colonne di cui una sola vale 1 ne conta una."),
    ("Capacità", "Quanti pacchetti al secondo il nodo riesce a elaborare al massimo."),
    ("Costo per pacchetto", "Il tempo di processore per elaborare un pacchetto: 1 diviso la capacità. 2 milioni di pacchetti al secondo = 500 ns per pacchetto."),
    ("ns, µs, ms", "Nanosecondi (miliardesimi di secondo), microsecondi (1 µs = 1 000 ns), millisecondi (1 ms = 1 000 µs)."),
    ("Nodo pieno", "Il generatore manda più pacchetti di quanti il nodo ne regga: la coda resta piena e il core lavora il 100 % del tempo."),
    ("Coda", "I posti davanti al nodo dove i pacchetti aspettano. Se è piena, chi arriva è respinto."),
    ("Collo di bottiglia", "Il pezzo più lento della catena: decide quanto traffico passa."),
    ("P-core, E-core, LP E-core", "I tre tipi di core del processore: veloci, efficienti (a gruppi di quattro che condividono una cache) e a basso consumo (in un'altra parte del chip, al massimo 2,5 GHz)."),
    ("Ciclo di clock, IPC", "Il ciclo è il battito dell'orologio del core (3,5 miliardi al secondo a 3,5 GHz). IPC = istruzioni eseguite per ciclo: dice quanto lavoro il core fa a ogni battito."),
    ("Istruzioni per pacchetto", "Quante istruzioni il processore esegue per ogni pacchetto, contate dal processore stesso. Dipendono dal codice, non dal core."),
    ("Cache", "Una piccola memoria veloce vicino al core. Un dato che non c'è va letto dalla memoria principale, molto più lenta."),
    ("Tre orologi", "Una versione del programma legge l'orologio all'ingresso, prima di inoltrare e all'arrivo al nodo successivo: separa il tempo del programma da quello del trasporto."),
    ("Programma da solo", "Il kernel esegue il programma su un pacchetto preparato, senza traffico: serve a contare letture di tabella e salti, e a misurare il cambio di modello."),
]

CSS = """
@page { size: A4; margin: 18mm 17mm; }
body { font-family: Carlito, Calibri, Lato, sans-serif; color: #222B36; font-size: 10.5pt; line-height: 1.5; }
h1 { color: #1F3A5F; font-size: 24pt; margin: 0 0 4pt; }
.sub { color: #6B7C93; font-size: 12pt; margin-bottom: 14pt; }
h2 { color: #1F3A5F; font-size: 15pt; margin: 18pt 0 8pt; }
.slide { page-break-before: always; }
.label { color: #E07A2D; font-size: 9pt; font-weight: bold; letter-spacing: 1.5pt; margin-bottom: 2pt; }
.title { color: #1F3A5F; font-size: 16pt; font-weight: bold; margin-bottom: 8pt; }
img { width: 100%; border: 1px solid #D5DCE5; margin: 4pt 0 10pt; }
p { margin: 0 0 7pt; }
ul, ol { margin: 0 0 7pt; padding-left: 18pt; }
li { margin-bottom: 3pt; }
.box { padding: 7pt 10pt; margin: 6pt 0 9pt; border-radius: 2pt; break-inside: avoid; }
.ex { background: #EEF1F5; }
.warn { background: #FFF4DE; border-left: 3pt solid #F2B134; }
.ok { background: #E6F4EE; border-left: 3pt solid #2E9C6E; }
code { font-family: "JetBrains Mono", "Fira Code", monospace; font-size: 9pt; background: #F3F5F8; padding: 0 2pt; }
table { border-collapse: collapse; width: 100%; font-size: 10pt; }
td { border-bottom: 1px solid #E2E7EE; padding: 5pt 6pt; vertical-align: top; }
td:first-child { font-weight: bold; color: #1F3A5F; width: 34%; }
"""


def inline(t):
    t = html.escape(t, quote=False)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"`(.+?)`", r"<code>\1</code>", t)
    return t


def parse(path):
    """[(numero, titolo, [blocchi])], blocco = (tipo, [righe])."""
    slides, cur = [], None
    for raw in open(path, encoding="utf-8"):
        line = raw.rstrip("\n")
        if line.startswith("#"):
            continue
        m = re.match(r"== (\d+) \| (.*)", line)
        if m:
            cur = (int(m.group(1)), m.group(2), [])
            slides.append(cur)
            continue
        if cur is None:
            continue
        blocks = cur[2]
        if not line.strip():
            blocks.append(("sep", []))
            continue
        for pre, kind in (("- ", "ul"), ("1. ", "ol"), (">> ", "ex"),
                          ("!! ", "warn"), ("ok ", "ok")):
            if line.startswith(pre):
                body = line[len(pre):]
                if blocks and blocks[-1][0] == kind and kind in ("ul", "ol"):
                    blocks[-1][1].append(body)
                else:
                    blocks.append((kind, [body]))
                break
        else:
            blocks.append(("p", [line]))
    return slides


def render_blocks(blocks):
    out = []
    for kind, lines in blocks:
        if kind == "sep":
            continue
        if kind == "p":
            out.append(f"<p>{inline(lines[0])}</p>")
        elif kind in ("ul", "ol"):
            items = "".join(f"<li>{inline(x)}</li>" for x in lines)
            out.append(f"<{kind}>{items}</{kind}>")
        else:
            out.append(f'<div class="box {kind}">{inline(lines[0])}</div>')
    return "\n".join(out)


def slide_images(tmp, pptx):
    soffice = os.environ.get("SOFFICE") or shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        sys.exit("serve LibreOffice (soffice)")
    profile = "file://" + os.path.join(tmp, "lo_profile")
    subprocess.run([soffice, f"-env:UserInstallation={profile}", "--headless",
                    "--convert-to", "pdf", "--outdir", tmp, pptx],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pdf = os.path.join(tmp, os.path.splitext(os.path.basename(pptx))[0] + ".pdf")
    subprocess.run(["pdftoppm", "-png", "-scale-to-x", "1920", "-scale-to-y", "-1",
                    pdf, os.path.join(tmp, "s")], check=True)
    imgs = sorted(glob.glob(os.path.join(tmp, "s-*.png")),
                  key=lambda p: int(re.search(r"-(\d+)\.png$", p).group(1)))
    return {i + 1: p for i, p in enumerate(imgs)}


def build(name, chrome):
    base, title = DECKS[name]
    pptx = os.path.join(DOCS, base + ".pptx")
    out = os.path.join(DOCS, base + " - spiegazione.pdf")
    slides = parse(os.path.join(HERE, f"spiegazione_{name}.txt"))
    with tempfile.TemporaryDirectory() as tmp:
        imgs = slide_images(tmp, pptx)
        parts = [f"<style>{CSS}</style>",
                 f"<h1>{html.escape(title)}</h1>",
                 '<div class="sub">Le slide una alla volta, ognuna con la sua spiegazione</div>',
                 "<p>Ogni pagina ha l'immagine di una slide e sotto la spiegazione. I riquadri "
                 "grigi sono <b>esempi con i numeri</b>; i riquadri gialli segnalano i <b>punti "
                 "da correggere o da dire con cautela</b>; i riquadri verdi le <b>verifiche</b> "
                 "fatte ricontrollando i dati.</p>",
                 "<h2>Le parole e le unità che tornano sempre</h2><table>"]
        parts += [f"<tr><td>{inline(a)}</td><td>{inline(b)}</td></tr>" for a, b in GLOSSARY]
        parts.append("</table>")
        for n, title, blocks in slides:
            if n == 0:
                parts.append(f'<div class="slide"><h2>{inline(title)}</h2>'
                             + render_blocks(blocks) + "</div>")
                continue
            img = imgs.get(n)
            data = base64.b64encode(open(img, "rb").read()).decode() if img else ""
            parts.append(f'<div class="slide"><div class="label">SLIDE {n}</div>'
                         f'<div class="title">{inline(title)}</div>'
                         + (f'<img src="data:image/png;base64,{data}">' if data else "")
                         + render_blocks(blocks) + "</div>")
        page = os.path.join(tmp, "spiegazione.html")
        with open(page, "w", encoding="utf-8") as f:
            f.write('<!doctype html><html lang="it"><head><meta charset="utf-8">'
                    f"<title>{html.escape(title)}</title></head><body>"
                    + "\n".join(parts) + "</body></html>")
        subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={out}", "file://" + page],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"scritto {out}")


def main():
    chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    if not chrome:
        sys.exit("serve google-chrome o chromium")
    names = sys.argv[1:] or list(DECKS)
    for n in names:
        if n not in DECKS:
            sys.exit(f"presentazione sconosciuta: {n} ({', '.join(DECKS)})")
        build(n, chrome)


if __name__ == "__main__":
    main()
