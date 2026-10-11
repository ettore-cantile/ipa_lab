#!/usr/bin/env python3
"""model_population.py -- la popolazione di modelli su cui si misura tutto.

Perche' esiste
--------------
Fino alla campagna del 10 ottobre ogni misura del nodo (capacita',
istruzioni, core, curve, due core, classi, taglie) girava sul checkpoint
65-4-4-7, e gli assi (traffic_models.py) variavano UN parametro alla volta
attorno allo stesso modello, con lo stesso seme. Ogni conclusione era quindi
una conclusione su un modello, o su un intorno di un modello.

Qui il modello non e' piu' un dato fisso: e' una variabile campionata. Ogni
test della campagna (remeasure_popolazione.sh) gira su una popolazione che
copre lo spazio che le pipeline sanno eseguire, e le conclusioni
(population_report.py) sono intervalli e leggi su tutta la popolazione, con il
numero di modelli su cui reggono.

Il disegno
----------
Quattro famiglie, tutte nella cartella ipa/synth/population/:

  base      il fattoriale: 7 composizioni dell'ingresso x 15 architetture
            (profondita' 1, 2, 3, 4, 6 x larghezza 2, 4, 8). Con --tier base
            (default) se ne misura META', scelta a scacchiera (composizione +
            architettura pari): ogni composizione vede ogni profondita' e ogni
            larghezza, e i fattori restano scorrelati. --tier full le prende
            tutte e 105. n_out ruota su 3, 5, 7 lungo il fattoriale, cosi' anche
            le uscite variano senza moltiplicare i punti.
  replica   6 configurazioni (dalla piu' leggera alla piu' pesante) con 3 semi
            in piu' ciascuna, uno dei quali con pesi normali invece che
            uniformi: dice quanto del costo dipende dai PESI estratti e non
            dalla forma. Senza, una differenza fra due modelli non si
            distingue dal caso.
  sparsita  4 configurazioni con il 50 e il 90% dei pesi a zero.
  imbuto    le cinque forme a ~592 pesi (da 1 a 5 strati) su due composizioni
            diverse: larga contro profonda a parita' di pesi.

Le composizioni dell'ingresso coprono i tipi di feature che il datapath sa
leggere (binari, scalari, one-hot, vettori di coda), in proporzioni diverse:

  ipa17     link 3, porta 3 (one-hot), ttl, nodo 10 (one-hot)       n_in 17
  ipa65     link 6, porta 6, ttl, nodo 52      (il descrittore del checkpoint)
  ipa117    link 8, porta 8, ttl, nodo 100                          n_in 117
  dense5    link 2, code 2, ttl              (tutto moltiplicato)   n_in 5
  dense17   link 8, code 8, ttl              (tutto moltiplicato)   n_in 17
  onehot105 nodo 100, ttl, code 4            (quasi tutto one-hot)  n_in 105
  mixed33   link 4, code 4, ttl, nodo 24     (i quattro tipi)       n_in 33

Il checkpoint NON e' nella popolazione: ipa65 ne ha il descrittore, ma pesi e
semi sono sintetici come per tutti gli altri.

I limiti delle pipeline (pipeline_limits.why_not) non filtrano la popolazione:
un modello che P2 non sa eseguire (troppi pesi per MAX_WEIGHT_ENTRIES) resta,
con il motivo scritto nel manifesto, perche' "quali modelli una pipeline non
sa eseguire" e' un risultato quanto il costo. Si scartano solo i modelli che
NESSUNA pipeline con inferenza sa eseguire.

Sottoinsiemi
------------
I test lunghi (curve al crescere del rate, LP E-core, due core, per classe,
TTL misti, taglie del frame) non girano su tutti i modelli ma su un
sottoinsieme della famiglia base, scelto a quantili di un costo stimato
(MAC eseguite + 150 per strato): sempre il piu' leggero e il piu' pesante, e
in mezzo punti equidistanti. Ogni sottoinsieme va quindi dal caso meno
stressante al piu' stressante.

Il seme
-------
Ogni modello ha il suo seme (SEED + indice), non uno comune: due modelli non
condividono i pesi per costruzione. Come in traffic_models, il pacchetto di
prova (TTL 32, nodo 7, porta 1) deve essere INOLTRATO in almeno uno stato dei
link; dove non lo e', si prova il seme successivo e il seme usato si scrive.

Uso
---
    python3 ipa/test/model_population.py                    # genera, stampa
    python3 ipa/test/model_population.py --tier full
    python3 ipa/test/model_population.py --list             # cartelle, tutte
    python3 ipa/test/model_population.py --list --subset carico
    python3 ipa/test/model_population.py --manifest out.csv # copia il manifesto

Il manifesto (population.csv, nella cartella della popolazione) ha una riga
per modello: forma, composizione, MAC per la forma ed eseguite, pesi a zero,
classi raggiunte, i limiti per pipeline e l'appartenenza ai sottoinsiemi.
population_report.py lo legge accanto ai CSV dei banchi.
"""
import argparse
import contextlib
import csv
import io
import json
import os
import shutil
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_SHARED = os.path.dirname(_TEST_DIR)
for _p in (_SHARED, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from synth.spec import FeatureSet, FeatureSpec, ModelSpec  # noqa: E402

ROOT = os.path.join(_SHARED, "synth", "population")
MANIFEST = "population.csv"
TOPOLOGY_FILE = "topology_config.json"
SEED = 20261011
INITIAL_TTL = 30
MAX_SEED_TRIES = 50
MIN_CLASSES = 2
SEED_RULE = f"inoltra il pacchetto di prova; almeno {MIN_CLASSES} classi"
SEED_STAMP = "population_seed.json"
TIERS = ("quick", "base", "full")


# --------------------------------------------------------------------------
# le composizioni dell'ingresso
# --------------------------------------------------------------------------
def _ttl():
    return FeatureSpec("ttl", "real", lo=1, hi=INITIAL_TTL, scale=INITIAL_TTL,
                       code=0x03)


def _link(k):
    return FeatureSpec("link_state", "binary", size=k, min_ones=1, code=0x01)


def _queues(k):
    # "binary" solo per come si campionano gli ingressi di prova: il datapath
    # legge queue_state per quello che vale.
    return FeatureSpec("queue_occupancy", "binary", size=k, code=0x05)


def _iface(k):
    return FeatureSpec("ingress_iface", "onehot", size=k, code=0x02)


def _node(k):
    return FeatureSpec("node", "onehot", size=k, code=0x04)


# nome -> (feature, rete). La rete dichiara le dimensioni che le feature
# leggono; n_interfaces e n_queues servono anche dove nessuna feature le usa
# (il fabric e le mappe esistono comunque).
LAYOUTS = {
    "ipa17": (lambda: FeatureSet([_link(3), _iface(3), _ttl(), _node(10)]),
              dict(n_interfaces=3, n_nodes=10, n_queues=4)),
    "ipa65": (lambda: FeatureSet([_link(6), _iface(6), _ttl(), _node(52)]),
              dict(n_interfaces=6, n_nodes=52, n_queues=4)),
    "ipa117": (lambda: FeatureSet([_link(8), _iface(8), _ttl(), _node(100)]),
               dict(n_interfaces=8, n_nodes=100, n_queues=4)),
    "dense5": (lambda: FeatureSet([_link(2), _queues(2), _ttl()]),
               dict(n_interfaces=2, n_nodes=52, n_queues=2)),
    "dense17": (lambda: FeatureSet([_link(8), _queues(8), _ttl()]),
                dict(n_interfaces=8, n_nodes=52, n_queues=8)),
    "onehot105": (lambda: FeatureSet([_node(100), _ttl(), _queues(4)]),
                  dict(n_interfaces=6, n_nodes=100, n_queues=4)),
    "mixed33": (lambda: FeatureSet([_link(4), _queues(4), _ttl(), _node(24)]),
                dict(n_interfaces=4, n_nodes=24, n_queues=4)),
}
LAYOUT_ORDER = list(LAYOUTS)

DEPTHS = (1, 2, 3, 4, 6)
WIDTHS = (2, 4, 8)
N_OUTS = (3, 5, 7)
SHAPES = [(d, w) for d in DEPTHS for w in WIDTHS]

# Le forme a ~592 pesi di bench_scaling.ISOPARAM_DIMS: imbuto, h1 >= h, gli
# strati dopo il secondo uguali (il vincolo di P2).
ISOPARAM_DIMS = {1: (8,), 2: (8, 4), 3: (8, 3, 3), 4: (7, 5, 5, 5),
                 5: (7, 4, 4, 4, 4)}
ISOPARAM_LAYOUTS = ("ipa65", "dense17")

# (composizione, profondita', larghezza): dal leggero al pesante, ogni
# composizione al piu' una volta.
REPLICA_CONFIGS = [("dense5", 1, 2), ("ipa17", 2, 4), ("mixed33", 3, 4),
                   ("ipa65", 2, 8), ("onehot105", 4, 8), ("dense17", 6, 8)]
REPLICA_SEEDS = 3
SPARSE_CONFIGS = [("ipa65", 2, 4), ("dense17", 2, 8), ("mixed33", 4, 4),
                  ("ipa117", 1, 8)]
SPARSITIES = (0.5, 0.9)

# Quanti modelli per sottoinsieme, per tier.
SUBSETS = {
    #           quick base full
    "carico":  (4,   6,   8),     # curve al crescere del rate (bench_bitrate)
    "lpe":     (6,   14,  20),    # nodo sul LP E-core
    "core2":   (4,   8,   10),    # due core del nodo
    "classi":  (4,   8,   10),    # una sessione per classe decisa
    "mix":     (6,   12,  16),    # TTL diversi pacchetto per pacchetto
    "taglie":  (3,   6,   8),     # 64 / 512 / 1514 byte
}
PROXY_PER_LAYER = 150


# --------------------------------------------------------------------------
# il disegno
# --------------------------------------------------------------------------
def _n_out(li, si):
    return N_OUTS[(li + si) % len(N_OUTS)]


def design(tier="base"):
    """[dict] dei modelli da generare, in ordine stabile. Ogni voce: id,
    famiglia, composizione, hidden, n_out, init, sparsita', gruppo di replica,
    seme di partenza."""
    if tier not in TIERS:
        raise ValueError(f"tier {tier!r}: validi {TIERS}")
    out = []

    def add(family, layout, hidden, n_out, init="uniform", sparsity=0.0,
            group="", seed_off=0):
        idx = len(out)
        out.append(dict(id=f"m{idx:03d}", family=family, layout=layout,
                        hidden=list(hidden), n_out=n_out, init=init,
                        sparsity=sparsity, group=group,
                        seed0=SEED + 1000 * idx + seed_off))

    for li, lay in enumerate(LAYOUT_ORDER):
        for si, (d, w) in enumerate(SHAPES):
            keep = {"full": True,
                    "base": (li + si) % 2 == 0,
                    "quick": (li + si) % 4 == 0}[tier]
            if keep:
                add("base", lay, [w] * d, _n_out(li, si))

    n_rep = {"quick": 2, "base": len(REPLICA_CONFIGS),
             "full": len(REPLICA_CONFIGS)}[tier]
    for gi, (lay, d, w) in enumerate(REPLICA_CONFIGS[:n_rep] if tier != "quick"
                                     else REPLICA_CONFIGS[::3][:n_rep]):
        li, si = LAYOUT_ORDER.index(lay), SHAPES.index((d, w))
        group = f"r{gi}"
        # il seme 0 del gruppo e' il modello "base" con la stessa forma, se il
        # fattoriale lo contiene; altrimenti lo si aggiunge qui.
        base_twin = any(e["family"] == "base" and e["layout"] == lay
                        and e["hidden"] == [w] * d for e in out)
        if base_twin:
            for e in out:
                if e["family"] == "base" and e["layout"] == lay \
                        and e["hidden"] == [w] * d:
                    e["group"] = group
        else:
            add("replica", lay, [w] * d, _n_out(li, si), group=group)
        n_seeds = REPLICA_SEEDS if tier != "quick" else 2
        for k in range(n_seeds):
            add("replica", lay, [w] * d, _n_out(li, si),
                init="normal" if k == n_seeds - 1 else "uniform",
                group=group, seed_off=k + 1)

    sparse = SPARSE_CONFIGS if tier != "quick" else SPARSE_CONFIGS[:1]
    for lay, d, w in sparse:
        li, si = LAYOUT_ORDER.index(lay), SHAPES.index((d, w))
        for p in SPARSITIES:
            add("sparsita", lay, [w] * d, _n_out(li, si), init="sparse",
                sparsity=p)

    if tier != "quick":
        for lay in ISOPARAM_LAYOUTS:
            for k, dims in ISOPARAM_DIMS.items():
                add("imbuto", lay, dims, 7)
    return out


def _topology(entry):
    _, net = LAYOUTS[entry["layout"]]
    return {"topology": f"pop_{entry['id']}", "initial_ttl": INITIAL_TTL,
            **net}


def _spec(entry, seed):
    feats, _ = LAYOUTS[entry["layout"]]
    kw = {}
    if entry["init"] == "sparse":
        kw = dict(weight_init="sparse", sparsity=entry["sparsity"])
    else:
        kw = dict(weight_init=entry["init"])
    return ModelSpec(f"pop_{entry['id']}", feats(), n_out=entry["n_out"],
                     hidden=list(entry["hidden"]), seed=seed,
                     drop_class=entry["n_out"] - 1, **kw)


def folder_of(entry, root=ROOT):
    shape = "-".join(str(h) for h in entry["hidden"])
    return os.path.join(root, f"{entry['id']}_{entry['layout']}_h{shape}"
                              f"_o{entry['n_out']}")


# --------------------------------------------------------------------------
# le grandezze del modello che il report usa come variabili
# --------------------------------------------------------------------------
def describe(spec, weights_int=None):
    """Forma, MAC e pesi a zero del modello. MAC eseguite: una feature one-hot
    attiva UNA colonna del primo strato, quindi costa h1 e non size*h1; ogni
    colonna densa (binaria, scalare, coda) costa h1. weights_int, se c'e',
    serve a contare i pesi che la quantizzazione ha reso zero lungo il
    percorso eseguito (quelli che P1 e P1.5 non moltiplicano)."""
    dims = spec.layer_dims
    h1 = dims[0][1]
    feats = spec.features.features
    n_dense = sum(f.size for f in feats if f.kind != "onehot")
    n_onehot_feat = sum(1 for f in feats if f.kind == "onehot")
    n_onehot_cols = sum(f.size for f in feats if f.kind == "onehot")
    rest = sum(a * b for a, b in dims[1:])
    mac_shape = sum(a * b for a, b in dims)
    mac_exec = h1 * (n_dense + n_onehot_feat) + rest
    d = dict(
        n_in=spec.features.n_in, n_out=spec.n_out,
        hidden="-".join(str(h) for h in spec.hidden),
        depth=len(spec.hidden), width_max=max(spec.hidden),
        width_first=spec.hidden[0], n_layers=len(dims),
        shape=spec.shape_str, weights=spec.weight_count(),
        n_feat=len(feats), dense_cols=n_dense, onehot_feat=n_onehot_feat,
        onehot_cols=n_onehot_cols,
        mac_shape=mac_shape, mac_exec=mac_exec,
    )
    if weights_int is not None:
        # nonzero lungo il percorso eseguito: colonne dense intere, per una
        # one-hot la media sulle sue colonne (quale sia attiva dipende dal
        # nodo e dalla porta), strati successivi interi.
        n_in0 = dims[0][0]
        w0 = weights_int[:n_in0 * h1]
        col_nz = [sum(1 for j in range(h1) if w0[j * n_in0 + i] != 0)
                  for i in range(n_in0)]
        nz_first, col = 0.0, 0
        for f in feats:
            cols = col_nz[col: col + f.size]
            nz_first += (sum(cols) / f.size) if f.kind == "onehot" \
                else sum(cols)
            col += f.size
        off = n_in0 * h1 + h1
        nz_rest = 0
        for a, b in dims[1:]:
            nz_rest += sum(1 for x in weights_int[off: off + a * b] if x != 0)
            off += a * b + b
        d["mac_exec_nz"] = round(nz_first + nz_rest, 1)
        n_w = sum(a * b for a, b in dims)
        zeros, off = 0, 0
        for a, b in dims:
            zeros += sum(1 for x in weights_int[off: off + a * b] if x == 0)
            off += a * b + b
        d["zero_frac"] = round(zeros / n_w, 3)
    return d


def proxy_cost(row):
    return float(row["mac_exec"]) + PROXY_PER_LAYER * float(row["n_layers"])


def limits(spec):
    import pipeline_limits as PL
    return {p: PL.why_not(p, spec.hidden, spec.features.n_in, spec.n_out) or ""
            for p in ("p1_static", "hardcoded", "template", "modular")}


# --------------------------------------------------------------------------
# generazione
# --------------------------------------------------------------------------
def _forwards(d):
    """Lo stesso controllo di traffic_models.forwards (e del banco): il
    pacchetto dei generatori viene inoltrato in almeno uno stato dei link."""
    import traffic_models as TM
    return TM.forwards(d)


def _quiet():
    return contextlib.redirect_stdout(io.StringIO())


def _generate_one(entry, root, force):
    from synth.generate import generate_scenario
    d = folder_of(entry, root)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, TOPOLOGY_FILE), "w") as f:
        json.dump(_topology(entry), f, indent=2)
    # La cartella si riusa solo se e' stata generata con la stessa voce del
    # disegno e lo stesso criterio sul seme (SEED_RULE): population_seed.json
    # li registra. Senza, si rigenera.
    stamp_path = os.path.join(d, SEED_STAMP)
    want = dict(rule=SEED_RULE, seed0=entry["seed0"], init=entry["init"],
                sparsity=entry["sparsity"], hidden=entry["hidden"],
                n_out=entry["n_out"], layout=entry["layout"])
    seed, info = None, None
    if not force and os.path.exists(stamp_path) and \
            os.path.exists(os.path.join(d, "model.json")):
        with open(stamp_path) as f:
            stamp = json.load(f)
        if {k: stamp.get(k) for k in want} == want:
            seed = stamp["seed"]
    if seed is None:
        # Due condizioni sul seme: il pacchetto di prova viene inoltrato (se
        # no il banco non si applica), e il modello decide almeno MIN_CLASSES
        # classi diverse sugli ingressi di prova. Pesi casuali stretti e
        # profondi spesso collassano su una classe sola, cosa che un modello
        # addestrato non fa; se nessun seme la soddisfa si tiene il primo
        # che inoltra, e classes_reached nel manifesto lo dice.
        first_ok = None
        for seed in range(entry["seed0"], entry["seed0"] + MAX_SEED_TRIES):
            with _quiet():
                info = generate_scenario(_spec(entry, seed), d, n_inputs=300)
            if not _forwards(d):
                continue
            if first_ok is None:
                first_ok = seed
            if len(set(info["classes_int8"])) >= MIN_CLASSES:
                break
        else:
            if first_ok is None:
                raise RuntimeError(f"{entry['id']}: nessun seme fra "
                                   f"{entry['seed0']} e {seed} inoltra il "
                                   f"pacchetto dei generatori")
            seed = first_ok
            with _quiet():
                generate_scenario(_spec(entry, seed), d, n_inputs=300)
        with open(stamp_path, "w") as f:
            json.dump(dict(want, seed=seed), f)
    with open(os.path.join(d, "weights.json")) as f:
        wi = json.load(f)
    with open(os.path.join(d, "expected.json")) as f:
        exp = json.load(f)
    spec = _spec(entry, seed)
    row = dict(id=entry["id"], family=entry["family"], layout=entry["layout"],
               group=entry["group"], init=entry["init"],
               sparsity=entry["sparsity"], seed=seed,
               seed_retries=seed - entry["seed0"],
               folder=os.path.relpath(d, os.path.dirname(_SHARED)).replace(
                   os.sep, "/"))
    row.update(describe(spec, wi))
    row["classes_reached"] = len({e["cls"] for e in exp["int8"]})
    row["quant_agreement"] = round(exp.get("quant_agreement", 0), 3)
    for p, why in limits(spec).items():
        row[f"no_{p}"] = why
    return row


def _pick_subsets(rows, tier):
    """Sottoinsiemi della famiglia base, ai quantili del costo stimato.

    Solo modelli che tutte le pipeline sanno eseguire: un sottoinsieme serve
    a confrontarle, e una cella vuota per P2 sul modello piu' pesante
    toglierebbe proprio il caso piu' stressante. Ai quantili si prende il
    modello piu' vicino nel costo, preferendo una composizione dell'ingresso
    non ancora scelta: senza, i primi quantili cadono tutti su ipa17 e
    dense5, che hanno i costi stimati piu' bassi."""
    ti = TIERS.index(tier)
    base = sorted((r for r in rows if r["family"] == "base"
                   and not any(r[f"no_{p}"] for p in
                               ("p1_static", "hardcoded", "template",
                                "modular"))),
                  key=lambda r: (proxy_cost(r), r["id"]))
    n = len(base)
    for name, sizes in SUBSETS.items():
        k = min(sizes[ti], n)
        chosen, layouts = [], set()
        targets = [round(i * (n - 1) / (k - 1)) for i in range(k)] \
            if k > 1 else ([n - 1] if k else [])
        window = max(1, n // (2 * max(k, 1)))
        for j, t in enumerate(targets):
            # gli estremi restano esattamente il piu' leggero e il piu' pesante
            if j in (0, len(targets) - 1):
                cands = [t]
            else:
                cands = sorted(range(max(0, t - window),
                                     min(n, t + window + 1)),
                               key=lambda i: (base[i]["layout"] in layouts,
                                              abs(i - t)))
            for i in cands:
                if base[i]["id"] not in chosen:
                    chosen.append(base[i]["id"])
                    layouts.add(base[i]["layout"])
                    break
        for r in rows:
            r[f"sub_{name}"] = int(r["id"] in chosen)


def generate(tier="base", root=ROOT, force=False, verbose=True):
    entries = design(tier)
    rows = []
    # Le cartelle di un tier precedente che questo non usa si tolgono: il
    # banco le scoprirebbe con --list e ne misurerebbe i resti.
    want = {os.path.basename(folder_of(e, root)) for e in entries}
    if os.path.isdir(root):
        for name in os.listdir(root):
            p = os.path.join(root, name)
            if os.path.isdir(p) and name not in want and name.startswith("m"):
                shutil.rmtree(p)
    for e in entries:
        r = _generate_one(e, root, force)
        rows.append(r)
        if verbose:
            nope = [p for p in ("template", "modular") if r[f"no_{p}"]]
            print(f"{r['id']} {r['family']:8s} {r['layout']:9s} "
                  f"{r['shape']:22s} {r['weights']:5d} pesi  MAC "
                  f"{r['mac_exec']:4d}/{r['mac_shape']:4d}  classi "
                  f"{r['classes_reached']}  seme {r['seed']}"
                  + (f" (+{r['seed_retries']})" if r["seed_retries"] else "")
                  + (f"  [non per {', '.join(nope)}]" if nope else ""))
    _pick_subsets(rows, tier)
    for r in rows:
        r["tier"] = tier
    write_manifest(rows, os.path.join(root, MANIFEST))
    return rows


def write_manifest(rows, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    keys = []
    for r in rows:
        for k in r:
            if k not in keys:
                keys.append(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def read_manifest(path=os.path.join(ROOT, MANIFEST)):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tier", choices=TIERS, default="base")
    ap.add_argument("--force", action="store_true",
                    help="rigenera anche le cartelle gia' presenti")
    ap.add_argument("--list", action="store_true",
                    help="stampa le cartelle (dal manifesto), una per riga")
    ap.add_argument("--subset", choices=list(SUBSETS), default=None,
                    help="con --list: solo i modelli di un sottoinsieme")
    ap.add_argument("--family", default=None,
                    help="con --list: solo una famiglia (base, replica, "
                         "sparsita, imbuto)")
    ap.add_argument("--manifest", metavar="CSV", default=None,
                    help="copia il manifesto qui (accanto ai risultati)")
    a = ap.parse_args(argv)
    if a.list:
        rows = read_manifest()
        if not rows:
            sys.exit("nessun manifesto: genera prima la popolazione")
        root = os.path.dirname(_SHARED)
        for r in rows:
            if a.subset and r.get(f"sub_{a.subset}") != "1":
                continue
            if a.family and r["family"] != a.family:
                continue
            print(os.path.join(root, r["folder"]))
        return
    if a.manifest:
        src = os.path.join(ROOT, MANIFEST)
        if not os.path.exists(src):
            sys.exit("nessun manifesto: genera prima la popolazione")
        os.makedirs(os.path.dirname(os.path.abspath(a.manifest)),
                    exist_ok=True)
        shutil.copyfile(src, a.manifest)
        return
    rows = generate(a.tier, force=a.force)
    fam = {}
    for r in rows:
        fam[r["family"]] = fam.get(r["family"], 0) + 1
    print(f"\n{len(rows)} modelli ({', '.join(f'{k} {v}' for k, v in fam.items())}); "
          f"manifesto in {os.path.relpath(os.path.join(ROOT, MANIFEST))}")
    for name in SUBSETS:
        ids = [r["id"] for r in rows if r[f"sub_{name}"]]
        print(f"  sottoinsieme {name:7s} {len(ids):3d}: {' '.join(ids)}")


if __name__ == "__main__":
    main()
