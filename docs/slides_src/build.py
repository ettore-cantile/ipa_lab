#!/usr/bin/env python3
"""
build.py -- rigenera "Test reale su dual boot - spiegazione.pdf".

Le immagini delle slide vengono dal .pptx (LibreOffice -> PDF -> PNG), il testo
da spiegazione.txt (formato descritto in testa al file). L'HTML si stampa in
PDF con Chrome senza interfaccia, come il PDF originale.

    python3 docs/slides_src/build.py

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
PPTX = os.path.join(DOCS, "Test reale su dual boot.pptx")
OUT = os.path.join(DOCS, "Test reale su dual boot - spiegazione.pdf")
TEXT = os.path.join(HERE, "spiegazione.txt")

GLOSSARY = [
    ("Nodo", "Il computer che riceve il pacchetto, esegue la rete neurale e lo inoltra. Nel banco è il core 6."),
    ("XDP", "Il primo punto del kernel Linux in cui un programma può vedere un pacchetto appena arrivato."),
    ("Pipeline", "Una delle versioni del programma che esegue la rete neurale (P1, P1.5, P2, P3)."),
    ("baseline / rxonly", "I due programmi di riferimento: la baseline inoltra senza rete neurale, rxonly riceve e basta."),
    ("Coda", "I 256 posti davanti al nodo dove i pacchetti aspettano. Se è piena, chi arriva è respinto."),
    ("Coda d'uscita", "La coda del cavo virtuale verso il nodo successivo. Con più core sul nodo ce n'è una per core, svuotata da un core suo (slide 14)."),
    ("Capacità", "Quanti pacchetti al secondo il nodo riesce a elaborare al massimo."),
    ("Collo di bottiglia", "Il pezzo più lento della catena: decide quanto traffico passa."),
    ("M/s", "Milioni di pacchetti al secondo."),
    ("ns, µs, ms", "Nanosecondi (miliardesimi di secondo), microsecondi (1 µs = 1 000 ns), millisecondi (1 ms = 1 000 µs)."),
    ("Gbit/s", "Miliardi di bit al secondo. Con pacchetti da 64 byte, 1 Gbit/s ≈ 1,95 milioni di pacchetti al secondo."),
    ("Costo per pacchetto", "1 diviso la capacità. 2 milioni di pacchetti al secondo = 500 ns per pacchetto."),
    ("Tempo di CPU per pacchetto", "Quanto tempo il core del nodo lavora davvero per ogni pacchetto: occupazione del core × 1 diviso la capacità. Coincide con il costo per pacchetto quando il nodo lavora il 100% del tempo."),
    ("Scrittore", "Chi mette pacchetti in una coda. Con una scheda di rete vera è la scheda stessa: uno per coda."),
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


def slide_images(tmp):
    soffice = os.environ.get("SOFFICE") or shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        sys.exit("serve LibreOffice (soffice)")
    profile = "file://" + os.path.join(tmp, "lo_profile")
    subprocess.run([soffice, f"-env:UserInstallation={profile}", "--headless",
                    "--convert-to", "pdf", "--outdir", tmp, PPTX],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pdf = os.path.join(tmp, os.path.splitext(os.path.basename(PPTX))[0] + ".pdf")
    subprocess.run(["pdftoppm", "-png", "-scale-to-x", "1920", "-scale-to-y", "-1",
                    pdf, os.path.join(tmp, "s")], check=True)
    imgs = sorted(glob.glob(os.path.join(tmp, "s-*.png")),
                  key=lambda p: int(re.search(r"-(\d+)\.png$", p).group(1)))
    return {i + 1: p for i, p in enumerate(imgs)}


def main():
    chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    if not chrome:
        sys.exit("serve google-chrome o chromium")
    slides = parse(TEXT)
    with tempfile.TemporaryDirectory() as tmp:
        imgs = slide_images(tmp)
        parts = [f"<style>{CSS}</style>",
                 "<h1>Il test reale su dual boot</h1>",
                 '<div class="sub">Le slide una alla volta, ognuna con la sua spiegazione</div>',
                 "<p>Ogni pagina ha l'immagine di una slide e sotto la spiegazione. I riquadri "
                 "grigi sono <b>esempi con i numeri</b>; i riquadri gialli segnalano i <b>punti "
                 "da correggere o da dire con cautela</b>; i riquadri verdi le <b>verifiche</b> "
                 "fatte ricontrollando i dati.</p>",
                 "<h2>Le parole e le unità che tornano sempre</h2><table>"]
        parts += [f"<tr><td>{inline(a)}</td><td>{inline(b)}</td></tr>" for a, b in GLOSSARY]
        parts.append("</table>")
        for n, title, blocks in slides:
            img = imgs.get(n)
            data = base64.b64encode(open(img, "rb").read()).decode() if img else ""
            parts.append(f'<div class="slide"><div class="label">SLIDE {n}</div>'
                         f'<div class="title">{inline(title)}</div>'
                         + (f'<img src="data:image/png;base64,{data}">' if data else "")
                         + render_blocks(blocks) + "</div>")
        page = os.path.join(tmp, "spiegazione.html")
        with open(page, "w", encoding="utf-8") as f:
            f.write('<!doctype html><html lang="it"><head><meta charset="utf-8">'
                    "<title>Il test reale su dual boot</title></head><body>"
                    + "\n".join(parts) + "</body></html>")
        subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={OUT}", "file://" + page],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"scritto {OUT}")


if __name__ == "__main__":
    main()
