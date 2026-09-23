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

    # P2 (template) o P3 (modulare): gli scenari che la pipeline non accetta
    # sono contati a parte come NON APPLICABILI, con il motivo
    sudo python3 ipa/test/verify_synth_kernel.py --all --pipeline p2
    sudo python3 ipa/test/verify_synth_kernel.py --all --pipeline p3

Serve Linux, root e BCC.

--------------------------------------------------------------------------
LA SCALA DEL TTL, E COME SI DIMOSTRA CHE P2/P3 LA LEGGONO
--------------------------------------------------------------------------
P1 compila la scala come letterale. P2 e P3 la leggono a runtime dal campo
`scale` di `struct feat_ent`, e con 0 ricadono sul #define 30. Un 100% su un
modello con ttl/16 NON basta a dire che il campo viene letto, per due ragioni
misurabili, e lo script le misura entrambe:

  1. la scala deve CAMBIARE le decisioni. Per ogni scenario si conta K, i
     casi in cui il riferimento a scala dichiarata e quello a 30 scelgono
     classi diverse. Con K = 0 (`ones`, `large`) un 100% e' compatibile anche
     con un datapath che usa sempre 30, e lo script lo dice.
  2. controllo negativo, P2/P3 nel kernel: si riscrive `feat_ent.scale` a 30
     e si ripetono gli stessi pacchetti. L'eBPF deve seguire il riferimento a
     30 su tutti e staccarsi da quello dichiarato esattamente sui K previsti.
     Cambia solo quel byte: se le decisioni si spostano, e' quel byte che il
     kernel sta leggendo.
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

# L'ifindex sotto cui il programma vede arrivare il pacchetto.
#
# NON si puo' scegliere. `prog_test_run` accetta un parametro
# `ingress_ifindex` ma la sua docstring dice che e' "accepted for API
# compatibility but unused": BPF_PROG_TEST_RUN gira senza `ctx_in`, perche' la
# semantica dei campi di xdp_md per ctx_in non e' portabile fra kernel, e il
# programma vede quindi l'ifindex del dispositivo di prova del kernel --
# `TEST_RUN_DEFAULT_INGRESS_IFINDEX`, che su questo kernel vale 1.
#
# Costato un giro a vuoto: scrivevo la mappa `ingress_port` alla chiave 100 e
# passavo `ingress_ifindex=100`, mentre il programma cercava la chiave 1. La
# riga non aveva alcun effetto, e infatti i tre scenari che dovevano risalire
# al 100% sono rimasti alla cifra precedente, identica al centesimo.


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

    `p1_aot.p1_source` vuole [{"type", "size"}]; lo scenario
    scrive [{"name", "size", "kind", ...}]. La traduzione e' solo di nomi --
    gli offset li ricalcola il generatore, e che coincidano con i suoi lo
    verifica gia' `test_synth` (prova [6] e [6] descriptor convention)."""
    out = []
    for f in model["descriptor"]:
        t = NOMI.get(f["name"], f["name"])
        # La scala DICHIARATA dallo scenario viaggia con la feature: da qui
        # la prendono sia il generatore C sia il riferimento intero, che prima
        # la ripescavano entrambi dal catalogo ignorando il modello.
        out.append({"type": t, "size": int(f["size"]),
                    "scale": int(f.get("scale", 1) or 1)})
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


def logit_int8_python(wi, layer_dims, x_int, scales, scale):
    from synth import reference as ref
    return ref.forward_int8(wi, layer_dims, x_int, scales, scale=scale)


def via_int8_python(wi, layer_dims, x_int, scales, scale):
    """Il riferimento intero puro Python, dal pacchetto `synth`.

    E' la STESSA funzione, con la stessa `scale`, che ha prodotto
    `expected.json`, quindi questa via e' la verita' di riferimento del modello
    sintetico, non una seconda opinione. Con la stessa `scale` solo dal
    2026-09-23: prima generate.py la chiamava senza, e `expected.json` teneva
    i logit di uno schema con il bias non riscalato che nessuna pipeline
    esegue (`load_scenario` ora rifiuta quei file). La seconda opinione la da'
    `via_int8_verify` qui sotto."""
    from synth import reference as ref
    return ref.argmax(logit_int8_python(wi, layer_dims, x_int, scales, scale))


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


# La chiave sotto cui la via kernel scrive `ingress_port`:
# TEST_RUN_DEFAULT_INGRESS_IFINDEX di verify_prog_run, che qui non si puo'
# importare perche' importa bcc. Per il sorgente valutato il numero in se' non
# conta; conta che la chiave letta sia quella scritta, come nel kernel.
_KIF_SORGENTE = 1


def via_sorgente_c(prog, caso, feats):
    """Il C che P1 compila, valutato dal TESTO con p1_c_eval: logit e classe.

    Gli stessi ingressi della via kernel -- mappe dense, TTL, porta scritta in
    `ingress_port` anche quando vale 0 -- senza clang, verificatore e JIT. E'
    la riga che --dry-run puo' dire sull'implementazione: prima, senza kernel,
    si confrontavano solo le due vie Python, e un generatore che emetteva un
    moltiplicatore diverso dal riferimento passava inosservato."""
    maps = dict(caso["mappe"])
    if any(f["type"] == "ingress_iface" for f in feats):
        maps["ingress_port"] = {_KIF_SORGENTE: int(caso["porta"])}
    return prog.run(caso["ttl"], maps, ingress_ifindex=_KIF_SORGENTE)


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

    # LA PORTA D'INGRESSO VA DETTA AL KERNEL, non solo al riferimento.
    #
    # Prima qui c'era `ingress_ifindex=0` fisso mentre il lato Python usava
    # `caso["porta"]`, che varia: le due meta' costruivano due vettori
    # d'ingresso diversi e il confronto misurava quella differenza invece del
    # datapath. Si vedeva benissimo nei dati -- `mixed`, l'unico scenario
    # SENZA la feature `ingress_iface`, era anche l'unico al 100%.
    if "ingress_port" in setup:
        from verify_prog_run import TEST_RUN_DEFAULT_INGRESS_IFINDEX as _KIF
        setup["ingress_port"][ct.c_uint32(_KIF)] = \
            ct.c_uint32(int(caso["porta"]))

    n_out = int(model["arch"]["n_out"])
    frame = build_frame_sparse(0, caso["ttl"], scale,
                               int(model["arch"]["n_in"]), n_out)
    _reset_stats(setup, n_classes=n_out)
    # `ingress_ifindex` non viene passato: il parametro esiste ma e' ignorato,
    # e passarlo darebbe l'impressione di controllare qualcosa che non si
    # controlla. Quello che si controlla e' la MAPPA, scritta qui sopra.
    prog_test_run(setup["disp"].fd, frame, repeat=1)

    # La classe scelta si legge da cls_stats, che le pipeline scrivono su OGNI
    # esito -- inoltro, DROP e UNUSED. Prima veniva scritta solo sul percorso
    # d'inoltro riuscito, e "quale classe ha scelto il modello?" non aveva
    # risposta quando la risposta era DROP.
    for c in range(n_out):
        if _read_u64(setup["cls_stats"], c) > 0:
            return c
    return -1


class NonApplicabile(Exception):
    """Lo scenario non entra nei limiti della pipeline scelta. Non e' un
    fallimento del datapath: e' un modello che quella pipeline rifiuta, e il
    riepilogo lo conta a parte invece di mescolarlo agli esiti."""


def fuori_limiti(pipeline, model):
    """Perche' `pipeline` non puo' eseguire questo modello, oppure None.

    Solo i limiti leggibili senza caricare niente, con i numeri presi dai
    moduli e non riscritti qui. Il resto lo rifiutano i loader, e anche quel
    rifiuto diventa NonApplicabile."""
    hidden = [int(h) for h in model["arch"]["hidden"]]
    n_in, n_out = int(model["arch"]["n_in"]), int(model["arch"]["n_out"])
    if pipeline == "p2":
        import ebpf_template_arch as A
        # Fino al 2026-09-23 qui c'era "n_out diverso da quello del modello
        # configurato (7)": il piano di controllo di P2 lo rifiutava. Il
        # datapath no -- legge n_out da arch_registry -- e il vincolo e' stato
        # tolto; resta il tetto MAX_N_OUT, controllato da semantics.validate().
        if not hidden:
            return "P2 ha bisogno di almeno uno strato nascosto"
        if any(h != hidden[1] for h in hidden[2:]):
            return (f"strati nascosti {hidden}: in P2 quelli oltre il secondo "
                    f"sono n_h2 -> n_h2")
        n_h1 = hidden[0]
        n_h2 = hidden[1] if len(hidden) > 1 else hidden[0]
        if n_h1 > A.T2_MAX_H1 or n_h2 > A.T2_MAX_H2:
            return (f"strati nascosti {hidden} oltre T2_MAX_H1/T2_MAX_H2 "
                    f"({A.T2_MAX_H1}/{A.T2_MAX_H2})")
        nw = A.arch_weight_count(n_h1, n_h2, n_in, n_out, n_hidden=len(hidden))
        if nw > A.MAX_WEIGHT_ENTRIES:
            return f"{nw} pesi oltre MAX_WEIGHT_ENTRIES={A.MAX_WEIGHT_ENTRIES}"
    elif pipeline == "p3":
        import ebpf_modular as M
        dims = dims_strati(model)
        if dims[0][1] > M.ML1_MAX_H1 or any(max(a, b) > M.MLH_MAX_H
                                            for a, b in dims[1:]):
            return (f"strati {dims} oltre ML1_MAX_H1/MLH_MAX_H "
                    f"({M.ML1_MAX_H1}/{M.MLH_MAX_H})")
        nw = sum(a * b + b for a, b in dims)
        if nw > M.MAX_LAYER_WEIGHT_ENTRIES:
            return (f"{nw} pesi oltre MAX_LAYER_WEIGHT_ENTRIES="
                    f"{M.MAX_LAYER_WEIGHT_ENTRIES}")
    return None


def costruisci_p2(model, wi, feats, node_index):
    """P2 sui pesi sintetici: dispatcher + foglia compilata per la profondita'
    dello scenario, pesi e descrittore nelle mappe. Lo stesso montaggio di
    verify_prog_run.setup_template, con la forma dello scenario al posto di
    quella del checkpoint. Il nodo viene dalla mappa `node_id_t2`: P2 non lo
    congela mai."""
    from bcc import BPF
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                    build_arch_leaf, load_arch_weights,
                                    load_model_desc)
    from verify_prog_run import _install_mac_table
    import model_meta as mm

    hidden = [int(h) for h in model["arch"]["hidden"]]
    n_in, n_out = int(model["arch"]["n_in"]), int(model["arch"]["n_out"])
    scale = int(model["quant"]["scale_factor"])
    n_h1 = hidden[0]
    n_h2 = hidden[1] if len(hidden) > 1 else hidden[0]
    semantics = mm.descriptor_semantics_or_reference(n_out, "verify:synth")
    b = BPF(text="#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
            + "\n" + build_arch_leaf(len(hidden)))
    disp = b.load_func("ipa_switch_template", BPF.XDP)
    leaf = b.load_func("arch_generic_2layer", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
    try:
        load_arch_weights(b, wi, model_id=0, scale=scale, n_h1=n_h1, n_h2=n_h2,
                          features=feats, n_in=n_in, semantics=semantics,
                          n_hidden=len(hidden))
    except ValueError as e:
        raise NonApplicabile(f"load_arch_weights: {e}")
    _install_mac_table(b, "mac_table_t2", semantics=semantics)
    b["node_id_t2"][ct.c_uint32(0)] = ct.c_uint32(node_index)
    return {"b": b, "disp": disp, "fn": leaf, "scale": scale,
            "cls_stats": b["cls_stats_t2"], "pkt_stats": b["pkt_stats_t2"],
            "ingress_port": b["ingress_port_t2"],
            "ricarica_desc": lambda f: load_model_desc(b, f, n_in, model_id=0)}


def costruisci_p3(model, wi, feats, node_index):
    """P3 sui pesi sintetici: dispatcher, layer_first, layer_hidden e la
    catena di tail call completa, come verify_prog_run.setup_modular ma con
    gli strati dello scenario. Il nodo viene dalla mappa `node_id_t3`."""
    from bcc import BPF
    from ebpf_modular import (EBPF_MODULAR_FULL, LAYER_CHAIN_SIZE,
                              load_modular_weights, load_model_desc)
    from verify_prog_run import _install_mac_table
    import model_meta as mm

    n_in, n_out = int(model["arch"]["n_in"]), int(model["arch"]["n_out"])
    scale = int(model["quant"]["scale_factor"])
    semantics = mm.descriptor_semantics_or_reference(n_out, "verify:synth")
    b = BPF(text=EBPF_MODULAR_FULL)
    disp = b.load_func("modular_dispatcher", BPF.XDP)
    first = b.load_func("layer_first", BPF.XDP)
    hidden_fn = b.load_func("layer_hidden", BPF.XDP)
    b["layer_chain"][ct.c_int(0)] = ct.c_int(first.fd)
    for i in range(1, LAYER_CHAIN_SIZE):
        b["layer_chain"][ct.c_int(i)] = ct.c_int(hidden_fn.fd)
    try:
        load_modular_weights(b, wi, model_id=0, scale=scale,
                             layer_dims=dims_strati(model), features=feats,
                             semantics=semantics)
    except ValueError as e:
        raise NonApplicabile(f"load_modular_weights: {e}")
    _install_mac_table(b, "mac_table_t3", semantics=semantics)
    b["node_id_t3"][ct.c_uint32(0)] = ct.c_uint32(node_index)
    return {"b": b, "disp": disp, "fn": first, "fn_hidden": hidden_fn,
            "scale": scale,
            "cls_stats": b["cls_stats_t3"], "pkt_stats": b["pkt_stats_t3"],
            "ingress_port": b["ingress_port_t3"],
            "ricarica_desc": lambda f: load_model_desc(b, f, n_in, model_id=0)}


def scale_colonne_default(model):
    """I divisori per colonna che il datapath userebbe se ignorasse la scala
    dichiarata: quelli del catalogo (ttl 30, tutto il resto 1). E' il
    riferimento del controllo negativo."""
    import model_meta as mm
    out = []
    for f in model["descriptor"]:
        t = NOMI.get(f["name"], f["name"])
        out.extend([int(mm.feature_scale(t))] * int(f["size"]))
    return out


# ==========================================================================
def sorgente_p1(model, wi, feats, node_index):
    """Il sorgente di P1 sui pesi sintetici, con il descrittore dello scenario.

    Una funzione sola per le due vie che lo usano: il kernel lo compila,
    --dry-run lo valuta dal testo. Devono guardare lo STESSO sorgente, o il
    confronto senza kernel proverebbe un altro programma.

    E' l'OGGETTO AOT (p1_aot, lo stesso generatore del deploy); fino al
    2026-09-23 era il sorgente BCC, che su un nodo non va mai."""
    import p1_aot
    import model_meta as mm
    n_out = int(model["arch"]["n_out"])
    scale = int(model["quant"]["scale_factor"])
    return p1_aot.p1_source(
        [(0, wi, scale)],
        hidden_dims=tuple(int(h) for h in model["arch"]["hidden"]),
        features=feats, n_out=n_out,
        semantics=mm.descriptor_semantics_or_reference(n_out, "verify:synth"),
        static_node=node_index)


def costruisci_p1(model, wi, feats, node_index):
    """P1 (l'oggetto AOT) sui pesi sintetici, con il descrittore dello
    scenario, caricato e pinnato da loader_aot."""
    import p1_aot
    from verify_prog_run import _install_mac_table
    import model_meta as mm

    n_out = int(model["arch"]["n_out"])
    scale = int(model["quant"]["scale_factor"])
    src = sorgente_p1(model, wi, feats, node_index)
    o_path, _ = p1_aot.compile_object(src)
    obj = p1_aot.AotObject(o_path, p1_aot._PROG_RE.findall(src))
    b = obj.b
    b._owner = obj

    semantics = mm.descriptor_semantics_or_reference(n_out, "verify:synth")
    _install_mac_table(b, "mac_table", semantics=semantics)
    setup = {"b": b, "disp": obj.progs["xdp_dispatch"],
             "fn": obj.progs["xdp_model"], "scale": scale,
             "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"]}
    # La mappa esiste solo se il descrittore usa `ingress_iface`: gli scenari
    # che non la dichiarano non la fanno nemmeno generare.
    try:
        setup["ingress_port"] = b["ingress_port"]
    except Exception:
        pass
    return setup


def confronta(d, n, seed, node_index, dry=False, pipeline="p1"):
    """Un scenario, una pipeline. Ritorna {"esito": True/False/None,
    "scala_provata": bool}; None vuol dire NON APPLICABILE, e scala_provata
    che lo scenario ha una scala diversa dal default che cambia almeno una
    decisione, e che (nel kernel, P2/P3) il controllo negativo l'ha vista."""
    nome = os.path.basename(os.path.abspath(d))
    model, wi, wf = carica_scenario(d)
    feats = descrittore(model)
    # Il nodo congelato deve stare dentro la larghezza del one-hot di QUESTO
    # scenario: `ones` ne ha 4, e il 7 di default faceva rifiutare la
    # generazione. Il generatore ha ragione a rifiutare -- una colonna tutta a
    # zero sembrerebbe un programma funzionante per un nodo che non esiste --
    # quindi si sceglie un indice valido invece di insistere.
    larghezza_nodo = next((f["size"] for f in feats if f["type"] == "node"), 0)
    if larghezza_nodo and node_index >= larghezza_nodo:
        node_index = larghezza_nodo - 1
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

    # LA SCALA PER-FEATURE, DA QUANDO IL DATAPATH LA SEGUE.
    #
    # Fino al 2026-09-18 i tre datapath fissavano la scala a compile time
    # (`feature_scale(tipo)` in P1, `T2_TTL_SCALE`/`ML_TTL_SCALE` in P2/P3) e
    # ignoravano quella dichiarata dal modello: `small` (16), `large` (64) e
    # `ones` (8) venivano eseguiti con 30. Adesso la scala viaggia nel
    # descrittore e il campo `scale` di `struct feat_ent` la porta fino al
    # kernel. Resta utile DIRE quali modelli si discostano dal default, perche'
    # sono esattamente quelli che il vecchio codice sbagliava.
    import model_meta as _mm
    fuori_default = []
    for f in model["descriptor"]:
        t = NOMI.get(f["name"], f["name"])
        dichiarata = int(f.get("scale", 1) or 1)
        catalogo = int(_mm.feature_scale(t))
        if dichiarata != catalogo:
            fuori_default.append((t, dichiarata, catalogo))
    if fuori_default:
        for t, dich, cat in fuori_default:
            info(f"la feature `{t}` usa scala {dich}, diversa dal default del "
                 f"catalogo ({cat}): il datapath deve seguire il modello")

    casi = campioni(feats, n, seed)
    scales_def = scale_colonne_default(model)
    # K: quante decisioni la scala dichiarata sposta rispetto al default. E'
    # la misura di quanto questo scenario METTE ALLA PROVA la scala: con K = 0
    # un datapath che la ignorasse passerebbe lo stesso.
    k_scala = 0
    if fuori_default:
        k_scala = sum(
            via_int8_python(wi, layer_dims, x, scales, scale)
            != via_int8_python(wi, layer_dims, x, scales_def, scale)
            for x in (vettore_intero(feats, c, node_index, scale) for c in casi))
        if k_scala:
            ok(f"la scala dichiarata sposta {k_scala}/{len(casi)} decisioni "
               f"rispetto al default: questo scenario la mette alla prova")
        else:
            info(f"la scala dichiarata sposta 0/{len(casi)} decisioni: con "
                 f"questi pesi un 100% NON prova che il datapath la applichi")

    if pipeline != "p1":
        motivo = fuori_limiti(pipeline, model)
        if motivo:
            info(f"{pipeline.upper()} NON APPLICABILE: {motivo}")
            return {"esito": None, "scala_provata": False}

    setup = prog = None
    if not dry:
        costruisci = {"p1": costruisci_p1, "p2": costruisci_p2,
                      "p3": costruisci_p3}[pipeline]
        try:
            setup = costruisci(model, wi, feats, node_index)
        except NonApplicabile as e:
            info(f"{pipeline.upper()} NON APPLICABILE: {e}")
            return {"esito": None, "scala_provata": False}
        dove = "congelato" if pipeline == "p1" else "dalla mappa node_id"
        ok(f"{pipeline.upper()} compilata e caricata sui pesi sintetici "
           f"(nodo {node_index}, {dove})")
    else:
        from p1_c_eval import P1Program
        prog = P1Program(sorgente_p1(model, wi, feats, node_index),
                         func="xdp_model")
        ok(f"P1 generata sui pesi sintetici e letta da p1_c_eval "
           f"(nodo congelato: {node_index})")
        if pipeline != "p1":
            note(f"{pipeline.upper()} non si valuta senza kernel: in --dry-run "
                 f"restano le vie Python e il C di P1")
    acc_qf = acc_impl = acc_tot = acc_ref = acc_cat = acc_src = 0
    esempi = []
    for c in casi:
        x = vettore_intero(feats, c, node_index, scale)
        c_float = via_float(wf, layer_dims, x, scales)
        c_int8 = via_int8_python(wi, layer_dims, x, scales, scale)
        if dry:
            acc_qf += (c_float == c_int8)
            atteso = logit_int8_python(wi, layer_dims, x, scales, scale)
            dal_c = via_sorgente_c(prog, c, feats)
            acc_src += (dal_c["logits"] == atteso and dal_c["cls"] == c_int8)
            if dal_c["logits"] != atteso and len(esempi) < 5:
                esempi.append((c, atteso, dal_c["logits"]))
            continue
        c_ref = via_int8_verify(wi, feats, model, c, node_index, scale)
        c_bpf = via_ebpf(setup, c, model, scale)
        acc_qf += (c_float == c_int8)
        acc_ref += (c_int8 == c_ref)
        # LA RIGA CHE ASSOLVE O CONDANNA IL DATAPATH.
        #
        # `ref_infer_sparse` applica la scala del CATALOGO, la stessa che i tre
        # generatori compilano. Se l'eBPF concorda con lui al 100% mentre
        # entrambi divergono da `synth.reference` (che usa la scala DICHIARATA
        # dal modello), allora il datapath non sbaglia un conto: esegue
        # correttamente una configurazione sbagliata. Sono due difetti diversi
        # e chiedono due rimedi diversi.
        acc_cat += (c_ref == c_bpf)
        acc_impl += (c_int8 == c_bpf)
        acc_tot += (c_float == c_bpf)
        if c_int8 != c_bpf and len(esempi) < 5:
            esempi.append((c, c_int8, c_bpf))

    if dry:
        # Senza kernel restano le due vie Python e il C di P1 valutato dal
        # sorgente: quello che questo script puo' verificare ovunque.
        n = len(casi)
        print()
        print(f"  float vs int8 (Python): accordo {100.0*acc_qf/n:.2f}%, "
              f"disaccordo {100.0*(n-acc_qf)/n:.2f}%  su {n} ingressi")
        if acc_src == n:
            ok(f"int8 (Python) vs C di P1 (sorgente valutato): {n}/{n} "
               f"ingressi con logit identici")
        else:
            fail(f"int8 (Python) vs C di P1 (sorgente valutato): logit "
                 f"diversi su {n - acc_src}/{n}. Il riferimento e il "
                 f"generatore non calcolano la stessa formula.")
            for c, a, b in esempi:
                note(f"  ttl={c['ttl']} porta={c['porta']} mappe={c['mappe']} "
                     f"-> python={a} C={b}")
        note("modalita' --dry-run: il kernel non e' stato interrogato; il C "
             "e' valutato dal testo, senza clang, verificatore e JIT")
        return {"esito": acc_src == n, "scala_provata": k_scala > 0}

    n = len(casi)
    print()
    print(f"  {'confronto':34s} {'accordo':>9s} {'disaccordo':>11s}")
    print("  " + "-" * 56)
    for etichetta, acc in (
            ("float  vs  int8 (Python)", acc_qf),
            ("int8 (Python)  vs  int8 (riferim.)", acc_ref),
            ("int8 (riferim.)  vs  int8 (eBPF)", acc_cat),
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
        # Non si dice "difetto del datapath" e basta. Misurato il
        # 2026-09-18: un disaccordo del 29% su cinque scenari veniva tutto da
        # un difetto di QUESTO script, che non comunicava al kernel la porta
        # d'ingresso, e il messaggio accusava il datapath di un errore di
        # calcolo che non aveva fatto. Si elencano le cause possibili in
        # ordine di probabilita', e la prima e' il banco.
        fail(f"implementazione: {n - acc_impl}/{n} decisioni DIVERSE fra "
             f"riferimento intero ed eBPF. NON e' quantizzazione. Le cause, "
             f"in ordine: (1) il banco non passa al kernel un ingresso che il "
             f"riferimento usa; (2) una scala dichiarata dal modello che il "
             f"datapath non applica, vedi sopra; (3) un difetto del datapath.")
        for c, a, b in esempi:
            note(f"  ttl={c['ttl']} porta={c['porta']} mappe={c['mappe']} "
                 f"-> python={a} ebpf={b}")
    if acc_ref != n and acc_cat == n:
        # Il caso interessante, e quello che la scheda in claims.md deve
        # riportare: aritmetica esatta, configurazione sbagliata.
        ok(f"il datapath e' ESATTO rispetto alla scala che gli e' stata "
           f"compilata: {n}/{n} decisioni identiche a `ref_infer_sparse`. Il "
           f"disaccordo con `synth.reference` ({n - acc_ref}/{n}) e' tutto "
           f"nella scala dichiarata dal modello e mai applicata.")
    elif acc_ref != n:
        fail(f"le due implementazioni intere di Python non concordano su "
             f"{n - acc_ref}/{n}, E l'eBPF non concorda con nessuna delle due: "
             f"qui non basta la scala a spiegare, va indagato")
    if acc_qf < n:
        note(f"il {100.0*(n-acc_qf)/n:.1f}% di disaccordo float/int8 e' "
             f"quantizzazione: proprieta' del modello e della scala, non un "
             f"difetto")

    # IL CONTROLLO NEGATIVO (P2/P3). Si riscrive SOLO il byte `scale` di
    # feat_ent al default e si ripetono gli stessi pacchetti. Se il kernel
    # legge quel byte, le decisioni si spostano esattamente sui K casi in cui
    # le due scale non concordano; se non lo leggesse, non si sposterebbe
    # niente. P1 la scala la compila come letterale, e non ha un byte da
    # riscrivere: per P1 la prova e' la riga "implementazione" qui sopra.
    controllo = True
    scala_provata = False
    if pipeline != "p1" and fuori_default:
        if not k_scala:
            info("controllo negativo non eseguito: K = 0, non distinguerebbe "
                 "niente")
        else:
            import model_meta as _mm2
            feats_def = [dict(f, scale=int(_mm2.feature_scale(f["type"])))
                         for f in feats]
            setup["ricarica_desc"](feats_def)
            segue_def = stacca = 0
            for c in casi:
                x = vettore_intero(feats, c, node_index, scale)
                c_bpf = via_ebpf(setup, c, model, scale)
                segue_def += (c_bpf == via_int8_python(wi, layer_dims, x,
                                                       scales_def, scale))
                stacca += (c_bpf != via_int8_python(wi, layer_dims, x,
                                                    scales, scale))
            setup["ricarica_desc"](feats)
            if segue_def == n and stacca == k_scala:
                scala_provata = True
                ok(f"controllo negativo: con feat_ent.scale riscritto al "
                   f"default l'eBPF segue il riferimento al default su "
                   f"{n}/{n} e si stacca da quello dichiarato esattamente sui "
                   f"{k_scala} casi previsti -- il kernel legge quel byte")
            else:
                controllo = False
                fail(f"controllo negativo: con feat_ent.scale al default "
                     f"l'eBPF segue quel riferimento su {segue_def}/{n} e si "
                     f"stacca dal dichiarato su {stacca} casi (attesi "
                     f"{n}/{n} e {k_scala}). Il datapath non divide per il "
                     f"byte che il piano di controllo scrive.")
    elif pipeline == "p1" and fuori_default and k_scala and acc_impl == n:
        scala_provata = True
    esito = acc_impl == n and acc_ref == n and controllo
    # "Provata" solo se tutto il resto regge: un datapath che usa sempre il
    # default passa il controllo negativo e fallisce la riga implementazione,
    # e non ha dimostrato di seguire nessuna scala.
    return {"esito": esito, "scala_provata": scala_provata and esito}


# ==========================================================================
# Gli scenari: presenti o rigenerati, mai pretesi
# ==========================================================================
def scenari(base_richiesta=None, n_inputs=64):
    """Le cartelle degli scenari, generandole se non ci sono.

    `ipa/synth/scenarios/` e' in .gitignore di proposito: sono artefatti
    rigenerabili, e `make_scenario.py --preset all` li riscrive
    byte-identici a parita' di seme. Una copia fresca del repository quindi
    NON li ha, e pretenderli faceva morire questo script con un
    FileNotFoundError su una macchina perfettamente sana.

    Generarli qui costa qualche secondo, non sporca il repository (si scrive
    in una cartella temporanea) e toglie di mezzo la domanda "li hai
    rigenerati?" -- che e' una domanda a cui un test non dovrebbe costringere.
    """
    # `n_inputs` basso di proposito: gli ingressi depositati in inputs.json
    # QUI non si usano -- questo script campiona i propri, fra quelli che il
    # datapath sa esprimere. Dell'artefatto serve solo `col_scales`, che non
    # dipende da quanti vettori ci sono dentro. Generarne mille costerebbe una
    # forward di torch per ciascuno, per poi buttarli.
    import tempfile
    from synth.generate import preset, generate_scenario, PRESETS

    if base_richiesta and os.path.isdir(base_richiesta):
        dirs = sorted(os.path.join(base_richiesta, d)
                      for d in os.listdir(base_richiesta)
                      if os.path.isdir(os.path.join(base_richiesta, d)))
        if dirs:
            note(f"scenari gia' presenti in {base_richiesta}")
            # Una cartella generata prima che un preset esistesse non lo ha:
            # prenderla com'e' vorrebbe dire saltarlo senza dirlo.
            presenti = {os.path.basename(x) for x in dirs}
            mancanti = [p for p in PRESETS if p not in presenti]
            if mancanti:
                base = tempfile.mkdtemp(prefix="ipa_synth_scen_")
                info(f"preset assenti da quella cartella: {mancanti}; li "
                     f"genero in {base}")
                for nome in mancanti:
                    d = os.path.join(base, nome)
                    generate_scenario(preset(nome), d, n_inputs=n_inputs)
                    dirs.append(d)
            return dirs

    base = tempfile.mkdtemp(prefix="ipa_synth_scen_")
    info(f"scenari non presenti: li rigenero in {base} "
         f"({len(PRESETS)} preset, seme fisso)")
    dirs = []
    for nome in PRESETS:
        d = os.path.join(base, nome)
        generate_scenario(preset(nome), d, n_inputs=n_inputs)
        dirs.append(d)
    return dirs


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
                   help="indice del nodo (P1: congelato nel programma; "
                        "P2/P3: scritto nella mappa node_id)")
    p.add_argument("--pipeline", choices=("p1", "p2", "p3"), default="p1",
                   help="quale pipeline mettere a confronto (default p1)")
    p.add_argument("--dry-run", action="store_true",
                   help="le due vie Python (float contro int8) e il C di P1 "
                        "valutato dal sorgente (p1_c_eval): non serve ne' "
                        "Linux ne' root, e verifica ingressi e formula prima "
                        "di portare il test su una macchina vera")
    a = p.parse_args()

    if not a.dry_run:
        if sys.platform != "linux":
            sys.exit(f"serve Linux, non {sys.platform} "
                     f"(oppure --dry-run per le sole vie Python)")
        if os.geteuid() != 0:
            sys.exit("serve root: sudo python3 ipa/test/verify_synth_kernel.py ...")

    if a.all:
        dirs = scenari(os.path.join(SHARED_DIR, "synth", "scenarios"))
    elif a.scenario:
        if not os.path.isdir(a.scenario):
            sys.exit(f"{a.scenario} non esiste. Gli scenari sono artefatti "
                     f"rigenerabili e non stanno in git: usa --all, che li "
                     f"genera da solo, oppure "
                     f"`python3 ipa/synth/make_scenario.py --preset all`.")
        dirs = [a.scenario]
    else:
        p.error("serve --scenario DIR oppure --all")

    print(f"{YELLOW}{'=' * 74}{NC}")
    print(f" Confronto a tre vie su modelli SINTETICI: float / int8 Python / "
          f"eBPF -- pipeline {a.pipeline.upper()}")
    print(f"{YELLOW}{'=' * 74}{NC}")

    esiti, provata = {}, []
    for d in dirs:
        try:
            r = confronta(d, a.n, a.seed, a.node, dry=a.dry_run,
                          pipeline=a.pipeline)
            esiti[os.path.basename(d)] = r["esito"]
            if r["scala_provata"]:
                provata.append(os.path.basename(d))
        except Exception as e:
            fail(f"{os.path.basename(d)}: {type(e).__name__}: {e}")
            esiti[os.path.basename(d)] = False

    print(f"\n{YELLOW}{'=' * 74}{NC}")
    buoni = sum(1 for v in esiti.values() if v)
    na = sum(1 for v in esiti.values() if v is None)
    if na:
        print(f" {na} scenari NON APPLICABILI a {a.pipeline.upper()} (il "
              f"motivo e' nel dettaglio sopra): non contano come esiti")
    if a.dry_run:
        print(f" {buoni}/{len(esiti) - na} scenari in --dry-run con logit identici "
              f"fra riferimento Python e C di P1 valutato dal sorgente.")
        print(f" {RED}Il kernel NON e' stato interrogato{NC}: "
              f"l'equivalenza con eBPF resta da dimostrare, rilancia senza "
              f"--dry-run su Linux.")
        note(" L'accordo float/int8 stampato sopra NON e' `quant_agreement` "
             "di expected.json e non va confrontato con lui: li' gli ingressi "
             "sono campionati liberamente, qui solo fra quelli che il datapath "
             "sa esprimere. Ma fino al 2026-09-23 la distanza fra i due numeri "
             "(0,789 contro 97,7% su ipa_like) veniva quasi tutta da un'altra "
             "causa: expected.json era calcolato con il bias NON riscalato, "
             "uno schema che nessuna pipeline esegue. Rigenerato, ipa_like "
             "vale 0,986.")
    else:
        print(f" {buoni}/{len(esiti) - na} scenari con equivalenza numerica "
              f"esatta fra riferimento intero ed eBPF")
    if provata:
        print(f" scala diversa dal default messa alla prova"
              f"{' e vista dal kernel' if not a.dry_run and a.pipeline != 'p1' else ''}"
              f": {', '.join(provata)}")
    else:
        print(f" {RED}nessuno scenario ha messo alla prova una scala diversa "
              f"dal default{NC}: questo run non dice niente su di essa")
    for nome, v in esiti.items():
        stato = "N/A" if v is None else ("OK " if v else "NO ")
        print(f"   {stato} {nome}")
    print(f"{YELLOW}{'=' * 74}{NC}")
    return 0 if all(v is not False for v in esiti.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
