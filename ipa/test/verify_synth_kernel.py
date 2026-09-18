#!/usr/bin/env python3
"""
verify_synth_kernel.py -- il confronto a TRE VIE, su modelli SINTETICI.

    float (Python)  vs  int8 (Python)  vs  int8 (eBPF, nel kernel)

--------------------------------------------------------------------------
PERCHE' ESISTE
--------------------------------------------------------------------------
Il progetto sapeva gia' fare due confronti, ma su due oggetti diversi:

  * sul modello DEPOSITATO, `test_suite` confronta float e int8 in Python e
    `verify_prog_run` confronta il programma XDP con un riferimento intero
    indipendente. Tre vie, un modello solo.
  * sui modelli SINTETICI, `test_synth --kernel` verificava che i pesi
    compilassero e che i control plane fossero importabili. Compilazione, non
    equivalenza numerica.

Restava quindi scoperta proprio l'affermazione che i modelli sintetici servono
a sostenere: *le pipeline sono corrette indipendentemente dal modello*. Questo
script chiude quel buco: prende uno scenario sintetico, lo fa girare nel
kernel, e misura quante decisioni coincidono.

--------------------------------------------------------------------------
LE TRE VIE, E PERCHE' SERVONO TUTTE
--------------------------------------------------------------------------
Due confronti soli non distinguono due cause diverse di disaccordo:

    float  vs  int8(Python)   ->  errore di QUANTIZZAZIONE
                                  (il modello a interi decide diversamente
                                  dal modello a virgola mobile)

    int8(Python) vs int8(eBPF) ->  errore di IMPLEMENTAZIONE
                                  (il datapath calcola diversamente dal
                                  riferimento, a parita' di aritmetica)

    float  vs  int8(eBPF)      ->  il totale, che e' quello che vede l'utente

La seconda riga e' quella che interessa al progetto e deve valere **100%**:
un solo disaccordo li' e' un bug del datapath, non un effetto della
quantizzazione. La prima riga invece puo' benissimo non essere 100%, ed e' una
proprieta' del modello e della scala scelta.

--------------------------------------------------------------------------
QUALI INGRESSI, E PERCHE' NON QUELLI DI inputs.json
--------------------------------------------------------------------------
`inputs.json` contiene 1 000 vettori campionati liberamente. Il datapath pero'
non accetta un vettore arbitrario: costruisce il suo ingresso dai valori che
ha sotto mano -- le mappe dense (link_state, queue_state), il TTL del
pacchetto, la porta d'ingresso risolta, l'indice del nodo. Un one-hot `node`
diverso a ogni campione vorrebbe dire ricompilare il programma a ogni
campione.

Quindi qui si campiona nello spazio che il datapath sa DAVVERO esprimere, e si
costruisce il vettore Python esattamente come lo costruisce lui. E' la stessa
scelta gia' fatta da `ref_infer_sparse`, di cui questo script riusa il
costruttore: confrontare due implementazioni su ingressi che una delle due non
potrebbe mai ricevere non dimostrerebbe niente sulle due.

--------------------------------------------------------------------------
USO
--------------------------------------------------------------------------
    sudo python3 ipa/test/verify_synth_kernel.py \
        --scenario ipa/synth/scenarios/ipa_like --n 200

    # tutti gli scenari depositati, pipeline P1
    sudo python3 ipa/test/verify_synth_kernel.py --all

Serve Linux, root e BCC.
"""
import os
import sys
import json
import random
import argparse
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")

# I nomi che gli scenari sintetici usano, tradotti nei tipi del catalogo di
# model_meta. Tutti coincidono tranne uno: lo scenario `mixed` chiama
# `queue_occ` quella che il catalogo chiama `queue_occupancy`. Tradurre qui,
# una volta, evita di sparpagliare il caso speciale nel resto del file.
NOMI = {"queue_occ": "queue_occupancy"}


def ok(m):
    print(f"  {GREEN}[PASS]{NC} {m}")


def fail(m):
    print(f"  {RED}[FAIL]{NC} {m}")


def info(m):
    print(f"  {YELLOW}[INFO]{NC} {m}")


def note(m):
    print(f"  {GREY}{m}{NC}")


# ==========================================================================
# Lo scenario sintetico, tradotto in ciò che il generatore eBPF si aspetta
# ==========================================================================
def carica_scenario(d):
    """model.json + i due file di pesi. Ritorna tutto ciò che serve dopo."""
    with open(os.path.join(d, "model.json")) as f:
        model = json.load(f)
    with open(os.path.join(d, "weights.json")) as f:
        wi = json.load(f)
    with open(os.path.join(d, "weights_float.json")) as f:
        wf = json.load(f)
    wi = wi["weights"] if isinstance(wi, dict) else wi
    wf = wf["weights"] if isinstance(wf, dict) else wf
    return model, wi, wf


def descrittore(model):
    """Il descrittore dello scenario nel formato di `derive_shape`.

    `build_combined_hardcoded_source` vuole [{"type", "size"}]; lo scenario
    scrive [{"name", "size", "kind", ...}]. La traduzione e' solo di nomi --
    gli offset li ricalcola il generatore, e che coincidano con i suoi lo
    verifica gia' `test_synth` (prova [6] e [6] descriptor convention)."""
    out = []
    for f in model["descriptor"]:
        t = NOMI.get(f["name"], f["name"])
        out.append({"type": t, "size": int(f["size"])})
    return out


def topologia(feats):
    """n_interfaces / n_nodes / n_queues dedotti dalle TAGLIE del descrittore.

    Non si inventano: sono esattamente le larghezze che lo scenario ha gia'
    scelto, e il generatore deve vedere le stesse o costruirebbe mappe di
    dimensione diversa da quella dei pesi."""
    per_tipo = {f["type"]: f["size"] for f in feats}
    return {
        "n_interfaces": per_tipo.get("link_state",
                                     per_tipo.get("ingress_iface", 1)),
        "n_nodes": per_tipo.get("node", 1),
        "n_queues": per_tipo.get("queue_occupancy", 1),
    }


def dims_strati(model):
    """[(n_prev, n_cur), ...] dalla forma dichiarata nello scenario."""
    a = model["arch"]
    sizes = [int(a["n_in"])] + [int(h) for h in a["hidden"]] + [int(a["n_out"])]
    return [(sizes[i], sizes[i + 1]) for i in range(len(sizes) - 1)]


# ==========================================================================
# Il campionamento: solo ciò che il datapath sa esprimere
# ==========================================================================
def campioni(feats, n, seed, ttl_min=2, ttl_max=30):
    """`n` ingressi, ognuno come (valori delle mappe dense, porta, ttl).

    Le mappe dense portano interi piccoli e non solo 0/1: il datapath le legge
    come valori, non come bit, e campionare solo 0/1 lascerebbe non provata
    meta' dell'aritmetica. La porta include 0, che vuol dire "nessuna porta
    risolta" ed e' il caso in cui l'one-hot resta tutto a zero."""
    rng = random.Random(seed)
    per_tipo = {f["type"]: f["size"] for f in feats}
    n_if = per_tipo.get("ingress_iface", 0)
    fuori = []
    for _ in range(n):
        mappe = {}
        if "link_state" in per_tipo:
            mappe["link_state"] = [rng.randint(0, 1)
                                   for _ in range(per_tipo["link_state"])]
        if "queue_occupancy" in per_tipo:
            mappe["queue_state"] = [rng.randint(0, 15)
                                    for _ in range(per_tipo["queue_occupancy"])]
        fuori.append({
            "mappe": mappe,
            "porta": rng.randint(0, n_if) if n_if else 0,
            "ttl": rng.randint(ttl_min, ttl_max),
        })
    return fuori


def vettore_intero(feats, caso, node_index, scale_ttl):
    """Il vettore d'ingresso come lo costruisce il datapath.

    Rispecchia `ref_infer_sparse` di verify_prog_run, che a sua volta
    rispecchia i generatori C per tipo di feature. Tenuto qui separato perche'
    serve anche alla via float, che non passa da quella funzione."""
    import model_meta as mm
    x = [0] * sum(f["size"] for f in feats)
    o = 0
    for f in feats:
        t, size = f["type"], f["size"]
        kind = mm.FEATURE_CATALOG[t]["kind"]
        if kind == "scalar":
            x[o] = caso["ttl"] & 0xFF
        elif kind == "dense_vector_map":
            vals = caso["mappe"].get(mm.FEATURE_CATALOG[t]["map"], [0] * size)
            for i in range(size):
                x[o + i] = vals[i]
        elif kind == "onehot" and t == "ingress_iface":
            if 1 <= caso["porta"] <= size:
                x[o + caso["porta"] - 1] = 1
        elif kind == "onehot" and t == "node":
            if node_index is not None and 0 <= node_index < size:
                x[o + node_index] = 1
        o += size
    return x


def scale_colonne(model):
    """Il divisore per colonna, dal descrittore dello scenario.

    Solo le feature `real` ne hanno uno diverso da 1. E' la lista che il
    riferimento intero applica al PRODOTTO, ed e' anche cio' che trasforma il
    vettore intero nella sua vista float: le due vie devono partire dallo
    stesso ingresso, o il confronto misurerebbe la conversione invece del
    modello.

    Si legge dal descrittore e non da `inputs.json` perche' qui gli ingressi
    se li campiona questo script -- ma il risultato deve coincidere con i
    `col_scales` depositati, e `--dry-run` lo verifica."""
    out = []
    for f in model["descriptor"]:
        out.extend([int(f.get("scale", 1) or 1)] * int(f["size"]))
    return out


# ==========================================================================
# Le tre vie
# ==========================================================================
def via_float(wf, layer_dims, x_int, scales):
    from synth import reference as ref
    x_f = [v / s if s else float(v) for v, s in zip(x_int, scales)]
    return ref.argmax(ref.forward_float(wf, layer_dims, x_f))


def via_int8_python(wi, layer_dims, x_int, scales, scale):
    """Il riferimento intero puro Python, dal pacchetto `synth`.

    E' la STESSA funzione che ha prodotto `expected.json`, quindi questa via e'
    la verita' di riferimento del modello sintetico, non una seconda opinione.
    La seconda opinione la da' `via_int8_verify` qui sotto."""
    from synth import reference as ref
    return ref.argmax(ref.forward_int8(wi, layer_dims, x_int, scales,
                                       scale=scale))


def via_int8_verify(wi, feats, model, caso, node_index, scale):
    """Il riferimento intero dell'altro lato del progetto, per controprova.

    `ref_infer_sparse` e' scritto per verificare il datapath e ricostruisce il
    vettore d'ingresso per conto suo. Se concorda con `synth.reference` su ogni
    campione, allora le due meta' del progetto sono d'accordo su che cosa
    calcola il modello -- ed e' un controllo gratuito che un confronto a tre
    vie soltanto non farebbe. Vive qui e non nella via principale perche'
    importa `bcc`."""
    from verify_prog_run import ref_infer_sparse
    cls, _ = ref_infer_sparse(
        wi, feats, [int(h) for h in model["arch"]["hidden"]],
        int(model["arch"]["n_out"]), caso["ttl"], 0,
        caso["mappe"], ingress_port=caso["porta"], scale=scale,
        node_index=node_index)
    return cls


def via_ebpf(setup, caso, model, scale):
    """Un pacchetto attraverso il programma XDP vero, e la classe che ha scelto.

    `repeat=1` non e' prudenza: il programma decrementa il TTL e
    BPF_PROG_TEST_RUN non ripristina il buffer fra una ripetizione e l'altra,
    quindi ripetere farebbe scendere il TTL e finirebbe per provare il
    percorso di scadenza invece della decisione sotto esame."""
    from verify_prog_run import (build_frame_sparse, prog_test_run,
                                 _reset_stats, _read_u64)
    from common import write_vector_map

    for nome, vals in caso["mappe"].items():
        write_vector_map(setup["b"], nome, vals)

    n_out = int(model["arch"]["n_out"])
    frame = build_frame_sparse(0, caso["ttl"], scale,
                               int(model["arch"]["n_in"]), n_out)
    _reset_stats(setup, n_classes=n_out)
    prog_test_run(setup["disp"].fd, frame, repeat=1, ingress_ifindex=0)

    # La classe scelta si legge da cls_stats, che le pipeline scrivono su OGNI
    # esito -- inoltro, DROP e UNUSED. Prima veniva scritta solo sul percorso
    # d'inoltro riuscito, e "quale classe ha scelto il modello?" non aveva
    # risposta quando la risposta era DROP.
    for c in range(n_out):
        if _read_u64(setup["cls_stats"], c) > 0:
            return c
    return -1


# ==========================================================================
def costruisci_p1(model, wi, feats, node_index):
    """P1 compilata sui pesi sintetici, con il descrittore dello scenario."""
    from bcc import BPF
    from ebpf_program import build_combined_hardcoded_source
    from verify_prog_run import _install_mac_table
    import model_meta as mm

    n_out = int(model["arch"]["n_out"])
    scale = int(model["quant"]["scale_factor"])
    topo = topologia(feats)
    src = build_combined_hardcoded_source(
        [(0, wi, scale, None)],
        n_interfaces=topo["n_interfaces"], n_nodes=topo["n_nodes"],
        hidden_dims=tuple(int(h) for h in model["arch"]["hidden"]),
        features=feats, n_out=n_out,
        static_node=node_index)
    b = BPF(text=src)
    model_fn = b.load_func("model_0", BPF.XDP)
    disp = b.load_func("ipa_switch_hardcoded", BPF.XDP)
    b["model_progs"][ct.c_int(0)] = ct.c_int(model_fn.fd)

    semantics = mm.descriptor_semantics_or_reference(n_out, "verify:synth")
    _install_mac_table(b, "mac_table", semantics=semantics)
    return {"b": b, "disp": disp, "fn": model_fn, "scale": scale,
            "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"]}


def confronta(d, n, seed, node_index, dry=False):
    nome = os.path.basename(os.path.abspath(d))
    model, wi, wf = carica_scenario(d)
    feats = descrittore(model)
    scale = int(model["quant"]["scale_factor"])
    layer_dims = dims_strati(model)
    scales = scale_colonne(model)

    print(f"\n{YELLOW}=== {nome}: {model['arch']['shape']}, "
          f"{len(wi)} pesi, scala {scale} ==={NC}")
    note(f"descrittore: {[(f['type'], f['size']) for f in feats]}")

    # I col_scales calcolati dal descrittore devono coincidere con quelli
    # depositati accanto agli ingressi. Se divergono, ogni confronto piu' sotto
    # starebbe misurando due conversioni diverse invece di due modelli.
    att = os.path.join(d, "inputs.json")
    if os.path.exists(att):
        with open(att) as f:
            depositati = json.load(f).get("col_scales")
        if depositati is not None and list(depositati) != list(scales):
            fail(f"col_scales ricalcolati diversi da quelli depositati "
                 f"({scales[:8]}... contro {list(depositati)[:8]}...)")
            return False
        ok("col_scales ricalcolati dal descrittore == quelli depositati")

    setup = None
    if not dry:
        setup = costruisci_p1(model, wi, feats, node_index)
        ok(f"P1 compilata e caricata sui pesi sintetici "
           f"(nodo congelato: {node_index})")

    casi = campioni(feats, n, seed)
    acc_qf = acc_impl = acc_tot = acc_ref = 0
    esempi = []
    for c in casi:
        x = vettore_intero(feats, c, node_index, scale)
        c_float = via_float(wf, layer_dims, x, scales)
        c_int8 = via_int8_python(wi, layer_dims, x, scales, scale)
        if dry:
            continue
        c_ref = via_int8_verify(wi, feats, model, c, node_index, scale)
        c_bpf = via_ebpf(setup, c, model, scale)
        acc_qf += (c_float == c_int8)
        acc_ref += (c_int8 == c_ref)
        acc_impl += (c_int8 == c_bpf)
        acc_tot += (c_float == c_bpf)
        if c_int8 != c_bpf and len(esempi) < 5:
            esempi.append((c, c_int8, c_bpf))

    if dry:
        # Senza kernel resta il confronto fra le due vie Python, che e' quello
        # che questo script puo' verificare ovunque.
        acc_qf = sum(
            via_float(wf, layer_dims,
                      vettore_intero(feats, c, node_index, scale), scales)
            == via_int8_python(wi, layer_dims,
                               vettore_intero(feats, c, node_index, scale),
                               scales, scale)
            for c in casi)
        n = len(casi)
        print()
        print(f"  float vs int8 (Python): accordo {100.0*acc_qf/n:.2f}%, "
              f"disaccordo {100.0*(n-acc_qf)/n:.2f}%  su {n} ingressi")
        note("questa percentuale NON e' `quant_agreement` di expected.json: "
             "li' gli ingressi sono campionati liberamente, qui solo fra "
             "quelli che il datapath sa esprimere. Due distribuzioni diverse, "
             "due numeri diversi, nessuna contraddizione.")
        note("modalita' --dry-run: il kernel non e' stato interrogato")
        return True

    n = len(casi)
    print()
    print(f"  {'confronto':34s} {'accordo':>9s} {'disaccordo':>11s}")
    print("  " + "-" * 56)
    for etichetta, acc in (
            ("float  vs  int8 (Python)", acc_qf),
            ("int8 (Python)  vs  int8 (riferim.)", acc_ref),
            ("int8 (Python)  vs  int8 (eBPF)", acc_impl),
            ("float  vs  int8 (eBPF)", acc_tot)):
        print(f"  {etichetta:34s} {100.0*acc/n:8.2f}% "
              f"{100.0*(n-acc)/n:10.2f}%")
    print()

    # La riga che decide. Le altre due descrivono il modello; questa descrive
    # il codice, e per il codice l'unico valore accettabile e' 100%.
    if acc_impl == n:
        ok(f"implementazione: {n}/{n} decisioni identiche fra riferimento "
           f"intero ed eBPF")
    else:
        fail(f"implementazione: {n - acc_impl}/{n} decisioni DIVERSE fra "
             f"riferimento intero ed eBPF -- e' un difetto del datapath, "
             f"non della quantizzazione")
        for c, a, b in esempi:
            note(f"  ttl={c['ttl']} porta={c['porta']} mappe={c['mappe']} "
                 f"-> python={a} ebpf={b}")
    if acc_ref != n:
        fail(f"le due implementazioni intere di Python non concordano su "
             f"{n - acc_ref}/{n}: prima di leggere le altre righe va risolto "
             f"questo, perche' non e' chiaro quale sia il riferimento")
    if acc_qf < n:
        note(f"il {100.0*(n-acc_qf)/n:.1f}% di disaccordo float/int8 e' "
             f"quantizzazione: proprieta' del modello e della scala, non un "
             f"difetto")
    return acc_impl == n and acc_ref == n


# ==========================================================================
def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("USO")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario", help="cartella di uno scenario sintetico")
    p.add_argument("--all", action="store_true",
                   help="tutti gli scenari in ipa/synth/scenarios/")
    p.add_argument("--n", type=int, default=200,
                   help="quanti ingressi per scenario (default 200)")
    p.add_argument("--seed", type=int, default=20260918)
    p.add_argument("--node", type=int, default=7,
                   help="indice del nodo congelato nel programma")
    p.add_argument("--dry-run", action="store_true",
                   help="solo le due vie Python (float contro int8): non serve "
                        "ne' Linux ne' root, e verifica la costruzione degli "
                        "ingressi prima di portare il test su una macchina vera")
    a = p.parse_args()

    if not a.dry_run:
        if sys.platform != "linux":
            sys.exit(f"serve Linux, non {sys.platform} "
                     f"(oppure --dry-run per le sole vie Python)")
        if os.geteuid() != 0:
            sys.exit("serve root: sudo python3 ipa/test/verify_synth_kernel.py ...")

    if a.all:
        base = os.path.join(SHARED_DIR, "synth", "scenarios")
        dirs = sorted(os.path.join(base, d) for d in os.listdir(base)
                      if os.path.isdir(os.path.join(base, d)))
    elif a.scenario:
        dirs = [a.scenario]
    else:
        p.error("serve --scenario DIR oppure --all")

    print(f"{YELLOW}{'=' * 74}{NC}")
    print(" Confronto a tre vie su modelli SINTETICI: float / int8 Python / eBPF")
    print(f"{YELLOW}{'=' * 74}{NC}")

    esiti = {}
    for d in dirs:
        try:
            esiti[os.path.basename(d)] = confronta(d, a.n, a.seed, a.node,
                                                  dry=a.dry_run)
        except Exception as e:
            fail(f"{os.path.basename(d)}: {type(e).__name__}: {e}")
            esiti[os.path.basename(d)] = False

    print(f"\n{YELLOW}{'=' * 74}{NC}")
    buoni = sum(1 for v in esiti.values() if v)
    if a.dry_run:
        print(f" {buoni}/{len(esiti)} scenari percorsi in --dry-run: "
              f"costruzione degli ingressi e vie Python verificate.")
        print(f" {RED}Il kernel NON e' stato interrogato{NC}: "
              f"l'equivalenza con eBPF resta da dimostrare, rilancia senza "
              f"--dry-run su Linux.")
    else:
        print(f" {buoni}/{len(esiti)} scenari con equivalenza numerica esatta "
              f"fra riferimento intero ed eBPF")
    for nome, v in esiti.items():
        print(f"   {'OK ' if v else 'NO '} {nome}")
    print(f"{YELLOW}{'=' * 74}{NC}")
    return 0 if buoni == len(esiti) else 1


if __name__ == "__main__":
    sys.exit(main())
