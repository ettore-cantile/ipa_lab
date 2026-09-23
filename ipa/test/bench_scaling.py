#!/usr/bin/env python3
"""
bench_scaling.py -- parametric scaling analysis across ALL THREE pipelines.

The question: how does the cost of the datapath change as the network, or the
model, gets bigger? And -- the part that matters for the design-space argument
-- do the three pipelines have DIFFERENT slopes?

They do, and the slopes are the whole point of having three of them:

                        P1 hardcoded     P2 template      P3 modular
  more NODES            grows            flat             flat
  more LAYERS           grows            needs a rebuild  flat
  more NEURONS/layer    grows            grows            grows
  sparser WEIGHTS       shrinks          flat             flat
  changing the model    ~1.2 s of clang  a map write      a map write

Each cell of that table is a claim this script measures rather than asserts.

--------------------------------------------------------------------------
THREE AXES, one variable each
--------------------------------------------------------------------------
Exactly one thing moves per axis; everything else is pinned, so a curve can
be attributed to the variable named on the x axis and nothing else.

  nodes  n_nodes in {10, 25, 52, 75, 100}, hidden (4,4), n_out 7
         The node one-hot is `n_nodes` wide, so this is the input width:
         n_in = n_interfaces + n_interfaces + 1 + n_nodes = 13 + n_nodes.
         52 is Germany50, the checked-in topology. Capped at 100 because
         MAX_N_IN / ML_MAX_N_IN is 128 in P2 and P3.

  depth  1..6 hidden layers of 4 neurons, n_nodes 52 (n_in 65)
         Depth is the one dimension P2 does NOT cover at runtime: its widths
         come from a map, its depth is compiled in. build_arch_leaf(n) emits
         the extra blocks, so P2 reaches any depth -- by rebuilding. On this
         axis P2 therefore recompiles at every point and P3 does not, and
         that difference, not a missing point, is the result.

  width  2, 4, 6, 8 neurons per hidden layer, two hidden layers, n_nodes 52
         8 is the compiled ceiling in P2 (T2_MAX_H1/H2) and P3 (ML1_MAX_H1,
         MLH_MAX_H). P1 has no ceiling but is swept over the same values so
         the three curves are comparable.

  descriptor  the four input-vector compositions of bench_depth_vs_width:
         0, 1 or 2 one-hot features, and a small (6) vs large (52) one. Same
         model otherwise. Categorical, so it is drawn as bars.

  sparsity  0, 25, 50, 75, 90 percent of the weights exactly zero, same shape
         throughout. P1 compiles weights in as literals, so clang deletes a
         multiply by zero: its instruction count should FALL. P2 and P3 read
         the same bytes from a map and should not move at all. This is where
         'the weights are in the code' stops being a description and becomes
         a number.

--------------------------------------------------------------------------
WHAT IS MEASURED
--------------------------------------------------------------------------
  insns      xlated instructions, summed over every program the pipeline
             loads -- the same convention test_suite.py --only kernel uses
             (dispatcher + leaves), so numbers are comparable with its table.
  jited      native bytes, same summation.
  lat_ns     per-packet latency, MIN of TRIALS independent BPF_PROG_TEST_RUN
             measurements. Min, not mean or median: the noise here is
             one-sided (an interrupt can only slow a trial down), so the
             smallest sample is the best estimate of the interference-free
             cost. Same reasoning as bench_depth_vs_width.py and hyperfine.
             Ogni misura e' spezzata in chunk da 200 esecuzioni con un frame
             NUOVO per chunk (prog_test_run_bench, la stessa di test_suite):
             senza, il TTL si inchioda a 1 e le ripetizioni successive
             saltano la coda di inoltro. Vedi _sample.
  update_ms  cost of INSTALLING A NEW MODEL on a node already running. This
             is the metric where the three pipelines differ in KIND rather
             than degree, and the two must not be confused:
               P1  the weights are C literals, so a new model means
                   generating C and running clang -- order 1.5 s.
               P2  arch_registry + model_desc + a slice of arch_weights.
               P3  layer_registry + layer_shapes + model_desc + weights.
             For P2 and P3 no compiler runs, so this is map writes only.
  build_ms   cost of compiling and loading the eBPF program ONCE. For P2 and
             P3 this is paid when the node starts and never again, because
             the source never mentions the model's shape. For P1 it is the
             same event as update_ms, by construction -- the program IS the
             model. Plotting build_ms as if it were the cost of changing a
             model would make P2 and P3 look MORE expensive than P1, which
             is backwards: their ~2.5 s compile happens once, P1's ~1.5 s
             happens on every model.
  map_bytes  total map memory, per-CPU maps counted per CPU.
  tail       tail calls executed per packet (P3's grows with depth).
  nw         number of int8 weights the model has, for reference.

--------------------------------------------------------------------------
WHY EVERY CELL RUNS IN ITS OWN SUBPROCESS
--------------------------------------------------------------------------
P1 unrolls the whole network into one C function, and past a certain size
the 512-byte eBPF stack overflows. BCC's LLVM backend reports that with a
PROCESS-FATAL abort, not a Python exception, so one bad cell would kill the
whole sweep. Each cell therefore runs in a fresh subprocess (this file
re-invoked with --_worker) and a crash marks only that cell as CRASHED.
The same isolation covers a verifier refusal, which is a normal outcome
here rather than a bug -- see docs/testing.md on P3's complexity budget.

--------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------
    sudo python3 ipa/test/bench_scaling.py                  # all three axes
    sudo python3 ipa/test/bench_scaling.py --axis nodes
    sudo python3 ipa/test/bench_scaling.py --axis depth --trials 15
    sudo python3 ipa/test/bench_scaling.py --out results/   # CSV per axis

    python3 ipa/test/bench_scaling.py --plot results/       # no root needed

Measuring needs Linux + BCC + root. Plotting reads the CSV and needs only
matplotlib, so the graphs can be regenerated anywhere, including on the
machine the thesis is written on.
"""
import os
import sys
import csv
import json
import time
import random
import argparse
import subprocess
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")

# Pinned across every sweep: only the axis variable moves.
N_INTERFACES = 6
N_OUT = 7
SCALE = 128
# Four points on one ladder: how much is known when the program is compiled.
#
#   p1_static  weights AND this node's index baked in    -> one binary per NODE
#   hardcoded  weights baked, node index from a map      -> one binary per MODEL
#   template   nothing baked but the ceilings            -> one binary
#   modular    depth read at runtime too                 -> one binary
#
# `hardcoded` is the pipeline the rest of this project calls P1; against
# p1_static it is really a P1.5, because its feature LAYOUT is compiled in but
# the node index is not. Naming it here would break every existing CSV, so the
# distinction lives in this comment and in the figures' labels.
PIPELINES = ("p1_static", "hardcoded", "template", "modular")

# Which node this node is, when the index is frozen at compile time. Any value
# inside the topology works; 7 is what the fabric test installs, so the two
# agree by eye. Axes go down to 10 nodes, so 7 is always in range.
STATIC_NODE = 7

# Input-vector compositions. Imported rather than copied: bench_depth_vs_width
# already curates this set to separate onehot COUNT from onehot SIZE, and two
# copies would drift.
from bench_depth_vs_width import FEATURE_SETS      # noqa: E402
DEFAULT_DESCRIPTOR = "default"


_POOL_SIZE = 8192


def make_weights(nw, sparsity, seed=42):
    """The first `nw` weights of a fixed pool with a `sparsity` fraction of
    zeros.

    Why the weights matter at all: P1 writes them into the C source as
    literals, so clang deletes a multiply by zero outright and turns a multiply
    by a power of two into a shift. P1's instruction count therefore depends on
    the VALUES, not only on the shape. P2 and P3 read the same weights from a
    map, where a zero is a byte like any other. The sparsity axis turns that
    difference from an argument into a measurement.

    Why a POOL, rather than a fresh vector per shape: exactly because of the
    above. Drawing an independent vector for each `nw` meant that moving along
    an axis changed two things at once -- the model's shape AND every one of
    its weights -- so part of P1's curve was weight noise wearing the x axis's
    name. Taking a prefix of one pool makes a bigger model an EXTENSION of the
    smaller one: the weights they share are identical, and only the new ones
    are new.

    How much this matters is not hypothetical. On the depth axis, the shape
    (4,4,4,4) with seed 42 is REFUSED by the verifier while seeds 1, 2, 3, 7,
    123 and 999 all load, at 1 075 to 1 175 instructions -- the same program
    size, the same architecture, different values. That is a real property of
    compiling weights in, and it is why this function is written the way it is.

    A prefix holds roughly, not exactly, the requested zero fraction: the pool
    is shuffled, so any prefix is a random sample of it. The exact count per
    cell is not the point; holding the weights still while the axis moves
    is."""
    rng = random.Random(seed)
    n_zero = int(round(_POOL_SIZE * sparsity))
    pool = [0] * n_zero + [rng.choice([v for v in range(-100, 101) if v != 0])
                           for _ in range(_POOL_SIZE - n_zero)]
    rng.shuffle(pool)
    if nw > _POOL_SIZE:
        raise ValueError(
            f"make_weights: {nw} weights asked of a {_POOL_SIZE}-wide pool. "
            f"Raise _POOL_SIZE -- but note that doing so changes every weight "
            f"vector, so re-measure the whole sweep rather than comparing new "
            f"numbers with old ones.")
    return pool[:nw]

# One axis = one variable. `cell(v)` returns everything a worker needs, so a
# new axis is a new entry here and nothing else. `kind` is "num" for an axis
# whose x is a number (plotted as a curve) or "cat" for one whose values are
# names (plotted as bars -- a line between two descriptors would imply a
# gradient that does not exist).
AXES = {
    "nodes": {
        "xlabel": "nodi della rete (larghezza della colonna che identifica il nodo)",
        "kind": "num",
        "values": [10, 25, 52, 75, 100],
        "cell": lambda v: dict(n_nodes=v, dims=(4, 4)),
        "note": "n_in = 13 + n_nodes; il modello resta 4-4, cambia solo l'ingresso",
    },
    "depth": {
        "xlabel": "numero di strati nascosti",
        "kind": "num",
        "values": [1, 2, 3, 4, 5, 6],
        "cell": lambda v: dict(n_nodes=52, dims=tuple([4] * v)),
        "note": "P2 copre la profondita' RICOMPILANDO (build_arch_leaf), P3 no: "
                "la ricompilazione E' il confronto",
    },
    "width": {
        "xlabel": "neuroni per strato nascosto",
        "kind": "num",
        "values": [2, 4, 6, 8],
        "cell": lambda v: dict(n_nodes=52, dims=(v, v)),
        "note": "8 e' il soffitto compilato di P2 (T2_MAX_H1/H2) e P3 (ML1_MAX_H1)",
    },
    "descriptor": {
        "xlabel": "composizione del vettore d'ingresso",
        "kind": "cat",
        "values": list(FEATURE_SETS),
        "cell": lambda v: dict(n_nodes=52, dims=(4, 4), descriptor=v),
        "note": "stesso modello 4-4, IV diverse: 0/1/2 one-hot, piccola (6) o grande (52)",
    },
    # LARGA CONTRO PROFONDA, a parametri comparabili.
    #
    # The width and depth axes above answer "what does it cost to widen / to
    # deepen", and on both of them the parameter count moves with the axis. The
    # question they cannot answer is the one that matters for choosing an
    # architecture: GIVEN a parameter budget, is it better spent on one wide
    # layer or on several narrow ones?
    #
    # These five shapes hold the weight count at 592 +/- 2%: 591, 599, 595,
    # 604, 589. They are a coherent family -- a funnel, h1 >= h, with every
    # layer after the second the same width, which is also what P2's compiled
    # leaf requires -- so the only thing that really changes along the axis is
    # how the same budget is arranged. Every point is inside the compiled
    # ceilings of P2 and P3 (h <= 8), so all four pipelines can run all five.
    #
    # The achieved weight count is printed per cell (the `pesi` column), so
    # "comparable" is something the reader checks rather than takes on trust.
    "isoparam": {
        "xlabel": "strati nascosti, a parita' di pesi (~592)",
        "kind": "num",
        "values": [1, 2, 3, 4, 5],
        "cell": lambda v: dict(n_nodes=52, dims=ISOPARAM_DIMS[v]),
        "note": "stesso budget di pesi speso in modi diversi: una layer largo "
                "contro molti stretti",
    },
    # Quante delle n_interfaces porte esistono DAVVERO sul nodo. Non e' una
    # topologia nuova: e' la cella di sempre (52 nodi, 4-4, descrittore
    # default) con `static_ports` che varia, quindi n_in, la forma e i PESI
    # restano identici punto per punto -- cambia solo quante colonne di
    # link_state P1 specializzata genera.
    #
    # Le altre tre pipeline non specializzano, quindi sull'asse restano
    # piatte: e' il controllo che dice che l'asse di per se' non costa nulla,
    # e che qualunque pendenza nella colonna p1_static viene da static_ports.
    #
    # Su Germany50 i gradi reali vanno da 2 a 5 (88 link, 50 nodi, grado medio
    # 3,52) e nessun nodo arriva a 6: il modello riserva 6 colonne perche' e'
    # il massimo della rete, non il grado di chi lo esegue.
    "degree": {
        "xlabel": "porte realmente presenti sul nodo (su 6 previste)",
        "kind": "num",
        "values": [2, 3, 4, 5, 6],
        # LISTA, non set: la cella viaggia in JSON verso il sottoprocesso che
        # isola ogni misura, e un set non e' serializzabile.
        "cell": lambda v: dict(n_nodes=52, dims=(4, 4),
                               static_ports=list(range(v))),
        "note": "stesso modello, stessi pesi, stesse colonne di peso: cambia "
                "solo quante di esse la P1 specializzata genera",
    },
    "sparsity": {
        "xlabel": "frazione di pesi esattamente zero",
        "kind": "num",
        "values": [0.0, 0.25, 0.5, 0.75, 0.9],
        "cell": lambda v: dict(n_nodes=52, dims=(4, 4), sparsity=v),
        "note": "stessa forma, pesi diversi: P1 li compila come letterali, P2/P3 li leggono da mappa",
    },

    # ======================================================================
    # LA CAMPAGNA: le stesse architetture che il throughput bench deve poi
    # rimisurare sotto traffico. `campaign: True` le tiene fuori da
    # `--axis all` (gli assi storici restano quelli, e i loro CSV pure) e le
    # manda tutte in UN file, results/model_scaling_test_suite.csv.
    #
    # Modello di riferimento 65-4-4-7: e' il primo punto di `width_camp`.
    # ======================================================================

    # A, versione che una pendenza ce l'ha davvero.
    #
    # n_in = n_interfaces + n_queues + 1, con le due tenute uguali. Ogni
    # colonna e' letta da una mappa e moltiplicata per h1 pesi, quindi le MAC
    # nominali e quelle eseguite coincidono. Il soffitto e' 17 e non si supera:
    # IPA_MAX_IFACES e IPA_MAX_QUEUES valgono 8, MAX_FEAT vale 4 e
    # _validate_feature_types rifiuta i duplicati, quindi non si possono
    # impilare piu' letture dense di queste.
    "iv_dense": {
        "xlabel": "colonne d'ingresso, tutte moltiplicate davvero",
        "kind": "num",
        "values": [5, 9, 13, 17],
        "cell": lambda v: dict(n_nodes=52, dims=(8, 8), descriptor="iv_dense",
                               n_interfaces=(v - 1) // 2,
                               n_queues=(v - 1) // 2),
        "campaign": True,
        "note": "n_in = 2k+1 con link_state(k) + queue_occupancy(k) + ttl; "
                "ogni colonna costa h1 moltiplicazioni. Tetto duro a 17",
    },

    # A come richiesta: n_in 16/32/65 a width, depth e n_out fermi.
    #
    # Sopra le 17 colonne dense la larghezza PUO' venire solo da una one-hot, e
    # una one-hot non costa: FEAT_INGRESS_IF indicizza una colonna e fa h1
    # addizioni, qualunque sia `size`. Previsione, verificabile sul CSV: insns
    # e pesi salgono, `macs` sale, `macs_eff` no, e la latenza nemmeno. Lo
    # stesso lo dice gia' result/scaling_nodes.csv, dove n_in va da 23 a 113 e
    # le quattro latenze restano ferme.
    #
    # n_nodes resta 52 e `node` non e' nel descrittore: questo asse muove il
    # VETTORE D'INGRESSO, non la rete. L'asse `nodes` misura l'altra cosa e
    # resta separato.
    "iv_onehot": {
        "xlabel": "colonne d'ingresso, larghezza in una colonna singola",
        "kind": "num",
        "values": [16, 32, 65],
        "cell": lambda v: dict(n_nodes=52, dims=(8, 8), descriptor="iv_onehot",
                               n_interfaces=v - 5, n_queues=4),
        "campaign": True,
        "note": "n_in = k+5 con ingress_iface(k) + ttl + queue_occupancy(4); "
                "la one-hot costa h1 addizioni comunque sia larga",
    },

    # B. 4 e' il riferimento 65-4-4-7. 16 e 32 sfondano T2_MAX_H1/H2 e
    # ML1_MAX_H1, quindi su template e modular escono RIFIUTATO senza essere
    # misurati: i soffitti non si toccano, e una riga misurata la' sarebbe un
    # programma che risponde XDP_PASS.
    "width_camp": {
        "xlabel": "neuroni per strato nascosto (campagna)",
        "kind": "num",
        "values": [4, 8, 16, 32],
        "cell": lambda v: dict(n_nodes=52, dims=(v, v)),
        "campaign": True,
        "note": "65-v-v-7; sopra 8 solo P1 e p1_static, che non hanno soffitti "
                "di larghezza",
    },

    # C. Profondita' a width 8, che e' il massimo che P2 e P3 reggono. L'asse
    # `depth` storico usa width 4 e arriva a 6: questo e' piu' stretto e piu'
    # largo, e proprio per questo puo' finire contro il budget di complessita'
    # del verificatore di P3 sui punti in fondo. Un rifiuto la' e' un dato.
    "depth_camp": {
        "xlabel": "strati nascosti, 8 neuroni ciascuno (campagna)",
        "kind": "num",
        "values": [1, 2, 3, 4],
        "cell": lambda v: dict(n_nodes=52, dims=tuple([8] * v)),
        "campaign": True,
        "note": "65-8...8-7; P2 ricompila a ogni punto, P3 no -- e a width 8 "
                "il verificatore di P3 puo' dire di no",
    },
}

# Gli assi della campagna, nell'ordine in cui vanno letti.
CAMPAIGN_AXES = [k for k, v in AXES.items() if v.get("campaign")]
# Gli storici: quelli che `--axis all` ha sempre percorso.
LEGACY_AXES = [k for k, v in AXES.items() if not v.get("campaign")]
CAMPAIGN_CSV = "model_scaling_test_suite.csv"


def cell_of(axis, v):
    """Fill an axis cell out with the defaults the worker expects."""
    # static_ports=None = "tutte le colonne", cioe' il comportamento storico:
    # ogni asse diverso da `degree` produce lo stesso C di prima e i CSV gia'
    # raccolti restano confrontabili.
    c = dict(n_nodes=52, dims=(4, 4), descriptor=DEFAULT_DESCRIPTOR,
             sparsity=0.0, static_ports=None,
             n_interfaces=N_INTERFACES, n_queues=N_QUEUES)
    c.update(AXES[axis]["cell"](v))
    return c


# n_queues is declared even though the default descriptor does not use a
# queue feature: the `no_onehot` set does, and a descriptor cannot resolve a
# dimension the topology does not state. Leaving it out made all three
# pipelines fail that column with
#   ScenarioError: feature 'queue_occupancy' needs topology dimension 'n_queues'
# which reads like a pipeline problem and is really a missing line here.
# 4 is under both compiled ceilings (IPA_MAX_QUEUES is 8 in P2 and in P3).
N_QUEUES = 4


# Larghezza per profondita' a budget costante. Ricavate cercando, dentro i
# soffitti compilati, la famiglia a imbuto che minimizza lo scarto di pesi.
ISOPARAM_DIMS = {
    1: (8,),             # 591 pesi -- tutto in un layer largo
    2: (8, 4),           # 599
    3: (8, 3, 3),        # 595
    4: (7, 5, 5, 5),     # 604
    5: (7, 4, 4, 4, 4),  # 589 -- lo stesso budget spalmato su cinque
}


# Descrittori in piu', vivi solo qui: gli assi IV della campagna hanno bisogno
# di comporre il vettore d'ingresso in due modi che bench_depth_vs_width non
# cura. FEATURE_SETS resta intatto, cosi' l'asse `descriptor` continua a
# spazzare esattamente i quattro di prima.
#
#   iv_dense   link_state + queue_occupancy + ttl: OGNI colonna e' una lettura
#              densa, quindi costa n_in*h1 moltiplicazioni. Soffitto duro a
#              n_in = 8 + 8 + 1 = 17, vedi IV_DENSE_MAX.
#   iv_onehot  ingress_iface + ttl + queue_occupancy: la larghezza sta nella
#              one-hot, che nel kernel costa h1 ADDIZIONI qualunque sia la sua
#              taglia (l'arm FEAT_INGRESS_IF indicizza una colonna sola). Qui
#              n_in arriva a 128 ma la latenza non deve muoversi -- ed e' il
#              motivo per cui i due assi esistono entrambi.
IV_FEATURE_SETS = {
    "iv_dense":  ["link_state", "queue_occupancy", "ttl"],
    "iv_onehot": ["ingress_iface", "ttl", "queue_occupancy"],
}
DESCRIPTORS = dict(FEATURE_SETS, **IV_FEATURE_SETS)


# I soffitti COMPILATI, ricopiati qui per poterli controllare senza caricare
# nulla. Non sono manopole: cambiarli invalida ogni CSV gia' raccolto, e
# ebpf_modular.py avverte che sono scogliere e non pendenze. Stanno qui perche'
# una cella che li sfonda va segnata RIFIUTATA *senza misurarla*: P3 non
# fallisce il caricamento, risponde XDP_PASS a runtime
#   if (n_out == 0 || n_out > ML1_MAX_H1) return XDP_PASS;
# e una misura su quel programma e' una latenza vera di un programma che non
# calcola niente -- il modo peggiore di rompersi.
P2_MAX_H   = 8      # T2_MAX_H1 / T2_MAX_H2   in ebpf_template_arch.py
P3_MAX_H1  = 8      # ML1_MAX_H1              in ebpf_modular.py
P3_MAX_H   = 8      # MLH_MAX_H               in ebpf_modular.py
MAX_N_IN   = 128    # MAX_N_IN / ML_MAX_N_IN  in entrambe
MAX_FEAT   = 4      # MAX_FEAT / ML_MAX_FEAT  in entrambe
# 8 (link_state) + 8 (queue_occupancy) + 1 (ttl): il piu' largo vettore
# d'ingresso che si possa fare di sole colonne che costano aritmetica.
IV_DENSE_MAX = 17


def topology(n_nodes, n_interfaces=N_INTERFACES, n_queues=N_QUEUES):
    return {"n_interfaces": n_interfaces, "n_nodes": n_nodes,
            "n_queues": n_queues}


def build_shape(n_nodes, hidden_dims, descriptor=DEFAULT_DESCRIPTOR,
                n_interfaces=N_INTERFACES, n_queues=N_QUEUES):
    """Resolve the feature descriptor for this topology. n_out is DECLARED,
    never derived from the interface count -- see class_semantics.py."""
    import model_meta as mm
    meta = {"features": DESCRIPTORS[descriptor], "n_out": N_OUT,
            "hidden_dims": list(hidden_dims)}
    return mm.derive_shape(
        meta, topology_config=topology(n_nodes, n_interfaces, n_queues))


def shape_of(cell):
    """La forma di UNA cella. `.get` e non `[]`: verify_static e verify_ports
    si costruiscono la cella a mano e non conoscono le chiavi nuove."""
    return build_shape(cell["n_nodes"], cell["dims"],
                       cell.get("descriptor", DEFAULT_DESCRIPTOR),
                       cell.get("n_interfaces", N_INTERFACES),
                       cell.get("n_queues", N_QUEUES))


def weight_count(n_in, dims, n_out):
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] + sizes[i] for i in range(1, len(sizes)))


def mac_count(n_in, dims, n_out):
    """MAC NOMINALI: il prodotto riga per colonna di ogni layer, come lo
    conterebbe chiunque guardando la forma. Senza i bias, che sono addizioni."""
    sizes = [n_in] + list(dims) + [n_out]
    return sum(sizes[i - 1] * sizes[i] for i in range(1, len(sizes)))


def mac_count_eff(shape, dims, n_out):
    """MAC REALMENTE ESEGUITE, che sul primo layer non sono le nominali.

    Una feature one-hot occupa `size` colonne della matrice dei pesi, ma nel
    datapath ne attiva UNA: l'arm FEAT_NODE_ID / FEAT_INGRESS_IF fa h1
    addizioni e basta, senza guardare `size`. Contarla come size*h1 MAC e' il
    modo in cui un grafico "MAC contro latenza" finisce per mostrare una retta
    piatta e sembrare rotto.

    Le colonne dense (link_state, queue_occupancy) e lo scalare ttl contano per
    quello che sono. I layer dopo il primo sono densi per costruzione."""
    import model_meta as mm
    h1 = dims[0] if dims else n_out
    primo = 0
    for f in shape["features"]:
        kind = mm.FEATURE_CATALOG[f["type"]]["kind"]
        primo += h1 if kind == "onehot" else int(f["size"]) * h1
    resto = list(dims) + [n_out]
    return primo + sum(resto[i - 1] * resto[i] for i in range(1, len(resto)))


def ceiling_refusal(pipeline, shape, dims):
    """Perche' questa cella non si puo' misurare su questa pipeline, o None.

    Gira nel PADRE, prima di aprire il sottoprocesso, cosi' la cella non viene
    ne' compilata ne' cronometrata. P1 e p1_static non compaiono: srotolano il
    modello nel C e non hanno soffitti di larghezza -- se sfondano lo fanno
    sullo stack da 512 byte, che e' un crash del figlio e va gia' nella colonna
    CRASH."""
    n_in, n_out = shape["n_in"], shape["n_out"]
    if pipeline not in ("template", "modular"):
        return None
    n_feat = len(shape["features"])
    if n_feat > MAX_FEAT:
        return f"{n_feat} feature > MAX_FEAT={MAX_FEAT}"
    if n_in > MAX_N_IN:
        return f"n_in={n_in} > MAX_N_IN={MAX_N_IN}"
    if pipeline == "template":
        oltre = [d for d in dims if d > P2_MAX_H]
        if oltre:
            return f"hidden {oltre} > T2_MAX_H1/H2={P2_MAX_H}"
        if n_out > P2_MAX_H:
            return f"n_out={n_out} > T2_MAX_H2={P2_MAX_H}"
    else:
        if dims and dims[0] > P3_MAX_H1:
            return f"h1={dims[0]} > ML1_MAX_H1={P3_MAX_H1}"
        oltre = [d for d in dims[1:] if d > P3_MAX_H]
        if oltre:
            return f"hidden {oltre} > MLH_MAX_H={P3_MAX_H}"
        if n_out > P3_MAX_H:
            return f"n_out={n_out} > MLH_MAX_H={P3_MAX_H}"
    return None


# ==========================================================================
# WORKERS -- one per pipeline, each running in its own subprocess
# ==========================================================================
def _timed(fn):
    t0 = time.perf_counter()
    out = fn()
    return out, (time.perf_counter() - t0) * 1000.0


def _sample(disp_fd, mk_frame, repeat, trials):
    """MIN of `trials` independent measurements; see the module docstring on
    why min rather than mean. Returns (min, p50, max, retval).

    Prende una FABBRICA di frame, non un frame, e il motivo e' un difetto che
    questa funzione si e' portata dietro a lungo.

    Riusava UN pacchetto per tutte le ripetizioni. Ma BPF_PROG_TEST_RUN non
    ripristina il buffer fra una ripetizione e l'altra, e il datapath
    decrementa il TTL: dopo una quarantina di esecuzioni restava inchiodato a
    1, e da li' in poi ogni ripetizione prendeva il ramo
    `if (ip->ttl <= 1) return XDP_PASS`.

    Quel ramo sta DOPO l'inferenza, quindi il modello girava lo stesso -- ed
    e' il motivo per cui le curve scalavano in modo regolare invece di
    risultare piatte, cioe' per cui il difetto non si vedeva. Ma saltava la
    coda di inoltro: decremento del TTL, checksum, pkt_stats, cls_stats,
    mac_table, bpf_redirect. Le cifre dicevano "parse + inferenza", non
    "tutto il percorso", e non erano confrontabili con quelle di test_suite.

    Il difetto riguardava tutti gli assi, non uno: `_sample` e' una sola.

    `prog_test_run_bench` e' la stessa funzione che usa test_suite: rinfresca
    il frame ogni TEST_RUN_MAX_CHUNK = 200 esecuzioni, e la fabbrica lo
    consegna con BENCH_TTL = 255. 255 - 200 = 55, quindi nessuna ripetizione
    arriva alla scadenza. `repeat` resta un bersaglio: la funzione lo limita a
    TEST_RUN_MAX_CHUNKS chunk, perche' oltre quel punto il minimo delle medie
    non migliora piu' e le syscall in piu' sono solo tempo di parete."""
    from verify_prog_run import prog_test_run_bench
    prog_test_run_bench(disp_fd, mk_frame, 1000, max_chunks=2)   # scalda
    samples, retval = [], None
    for _ in range(trials):
        retval, ns = prog_test_run_bench(disp_fd, mk_frame, repeat)
        samples.append(ns)
    samples.sort()
    return samples[0], samples[len(samples) // 2], samples[-1], retval


# Ripetizioni del conteggio lookup. 200 = TEST_RUN_MAX_CHUNK, e il frame
# parte da TTL 255 apposta: BPF_PROG_TEST_RUN non ripristina il buffer fra una
# ripetizione e l'altra e il datapath decrementa il TTL, quindi con un TTL
# basso le ripetizioni dopo la quarta prendono il ramo di scadenza -- che fa
# UN LOOKUP IN MENO (niente cls_stats su un non-forward). E' lo stesso
# inciampo documentato in _count_lookups_defaults; qui il TTL non arriva mai a
# 1 (255 - 200 = 55).
LOOKUP_REPEAT = 200
LOOKUP_TTL = 255


def _instrumented(raw):
    """La stessa sorgente, con ogni `.lookup()` contato."""
    from common import instrument_map_lookups
    return "#define IPA_COUNT_LOOKUPS 1\n" + instrument_map_lookups(raw)


def _lookups_safe(build, n_in, n_out):
    """Lookup di mappa per pacchetto, o None se non si riesce a misurarli.

    `build` restituisce (oggetto BPF, fd del dispatcher) dalla sorgente
    strumentata. Un fallimento qui non deve perdere la cella: la latenza e le
    istruzioni sono gia' state misurate sulla build PULITA, e questa e' una
    colonna in piu'. La strumentazione gonfia il programma, e su P2 puo'
    benissimo sfondare il limite di taglia -- allora la colonna resta vuota e
    lo si vede, invece di far sparire la riga."""
    from verify_prog_run import build_frame_sparse, prog_test_run
    try:
        bb, disp_fd = build()
        frame = build_frame_sparse(model_id=0, ttl=LOOKUP_TTL, scale=SCALE,
                                   n_in=n_in, n_out=n_out)
        ctr = bb["lookup_ctr"]
        if getattr(ctr, "Leaf", None) is None:
            # P1, oggetto AOT: un ARRAY semplice con somma atomica (p1_aot).
            ctr[ct.c_int(0)] = ct.c_ulonglong(0)
            prog_test_run(disp_fd, frame, repeat=LOOKUP_REPEAT)
            return (int.from_bytes(ctr[ct.c_int(0)], "little")
                    / float(LOOKUP_REPEAT))
        ctr[ct.c_int(0)] = ctr.Leaf()        # per-CPU, azzerato ovunque
        prog_test_run(disp_fd, frame, repeat=LOOKUP_REPEAT)
        return sum(int(v) for v in ctr[ct.c_int(0)]) / float(LOOKUP_REPEAT)
    except Exception as e:
        print(f"[lookups] non misurabile: {type(e).__name__}: {str(e)[:90]}",
              file=sys.stderr)
        return None


def _totals(b, progs):
    """Sum xlated + jited over every loaded program, and map memory over every
    map, exactly as test_suite.py reports them.

    The map names come from test_suite._PIPELINE_MAP_NAMES rather than a copy
    kept here. That list carries a warning about staying in sync with the three
    eBPF sources, and it earned it: it was once incomplete, and because a
    missing map is silently skipped, the only symptom was a footprint smaller
    than the truth. A second copy would reintroduce exactly that failure.

    (A BCC `BPF` object has no .items(): it exposes maps through __getitem__
    and only caches the ones already asked for, so iterating it would have
    returned whatever happened to have been touched. That is what the first
    version of this function did, and every cell of the sweep crashed with
    `AttributeError: 'BPF' object has no attribute 'items'`.)"""
    from verify_prog_run import prog_insn_count, map_bytes, _nr_cpus
    from test_suite import _PIPELINE_MAP_NAMES
    insns = jited = 0
    per_prog = {}
    for name, fd in progs.items():
        x, j = prog_insn_count(fd)
        per_prog[name] = x
        insns += x
        jited += j
    nr = _nr_cpus()
    mb = 0
    counted = []
    for mname in _PIPELINE_MAP_NAMES:
        try:
            one = map_bytes(b[mname].map_fd, nr)
        except Exception:
            continue          # not a map this pipeline declares
        mb += one
        counted.append(mname)
    return insns, jited, mb, per_prog, counted


def _bench_p1(cell, repeat, trials, static_node=None):
    # La stessa cella descrive entrambe le pipeline; solo quella specializzata
    # sfrutta static_ports. Non e' una convenzione da ricordare: il generatore
    # RIFIUTA static_ports senza static_node, quindi e' la forma che la
    # chiamata deve avere perche' `hardcoded` resti quello di sempre.
    ports = cell.get("static_ports") if static_node is not None else None
    import p1_aot
    from verify_prog_run import build_frame_sparse, _seed_link_state

    dims = cell["dims"]
    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"])
    sparsity_real = weights.count(0) / len(weights) if weights else 0.0

    def _load(strumentata=False):
        # P1 is the AOT object (p1_aot), as it is deployed. Installing a model
        # = generating the C, running clang (offline, on a build box) and
        # loading the object on the node. build_ms times all three, uncached;
        # update_ms is the NODE's part alone: the loader's open + load
        # (verifier + JIT). Until 2026-09-23 P1 was measured on BCC, where
        # clang runs on the node and the two were the same event.
        return p1_aot.load_p1([(0, weights, SCALE)], instrument=strumentata,
                              cache=False, features=shape["features"],
                              n_out=n_out, hidden_dims=tuple(dims),
                              static_node=static_node, static_ports=ports)

    setup, build_ms = _timed(_load)
    update_ms = setup["t_redirect_s"] * 1000.0
    b, disp_fn = setup["b"], setup["disp"]
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(b, setup["progs"])
    lookups = None
    if cell.get("lookups"):
        def _ins():
            # link_state va seminata anche qui: senza, la feature densa legge
            # una mappa vuota e il percorso non e' quello misurato sopra.
            s2 = _load(True)
            _seed_link_state(s2["b"], 1)
            return s2["b"], s2["disp"].fd
        lookups = _lookups_safe(_ins, n_in, n_out)
    # Un pacchetto NUOVO per ogni chunk, non uno riusato: vedi _sample.
    from verify_prog_run import BENCH_TTL

    def mk_frame():
        return build_frame_sparse(model_id=0, ttl=BENCH_TTL, scale=SCALE,
                                  n_in=n_in, n_out=n_out)

    lo, med, hi, retval = _sample(disp_fn.fd, mk_frame, repeat, trials)
    # Throughput is 1/latency and nothing more -- a THEORETICAL peak from a
    # loop over one buffer, not a rate anything sustained. It is reported
    # because it is the unit the question is usually asked in.
    mpps = (1000.0 / lo) if lo else 0.0
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=1, nw=nw,
                n_in=n_in, build_ms=build_ms, update_ms=update_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, mpps=mpps, retval=retval, per_prog=per_prog,
                n_maps=len(maps), sparsity_real=sparsity_real,
                lookups=lookups)


def _bench_p2(cell, repeat, trials):
    # Checked BEFORE the imports on purpose: "P2 cannot do this depth" is a
    # property of P2, not of whether BCC happens to be installed. Behind the
    # imports, a machine without BCC would report this cell as a crash rather
    # than as the structural limit it is.
    dims = cell["dims"]
    if len(dims) < 1:
        raise NotImplementedError("P2 ha almeno un hidden layer")
    if len(set(dims[1:])) > 1:
        raise NotImplementedError(
            f"in P2 i layer oltre il secondo sono larghi n_h2; questa forma "
            f"chiede larghezze diverse: {dims[1:]}")
    n_hidden = len(dims)
    # With one hidden layer there is no fc2, and the datapath carries h1 into
    # h2 unchanged -- so n_h2 must be registered equal to n_h1. See
    # build_arch_leaf; load_arch_weights refuses any other value.
    n_h1 = dims[0]
    n_h2 = dims[1] if n_hidden >= 2 else dims[0]

    from bcc import BPF
    from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                    build_arch_leaf,
                                    load_arch_weights)
    from verify_prog_run import build_frame_sparse, _seed_link_state

    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"])
    sparsity_real = weights.count(0) / len(weights) if weights else 0.0

    # The source does not mention the model's WIDTHS anywhere -- that is P2's
    # claim, and why its instruction count is flat on the nodes and width
    # axes. DEPTH is different: it is baked in at compile time, so the leaf
    # is built for this shape's depth. On the depth axis P2 therefore
    # RECOMPILES at every point while P3 does not, and that is exactly the
    # comparison being made.
    src = ("#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
           + "\n" + build_arch_leaf(n_hidden))

    def _load(strumentata=False):
        bb = BPF(text=_instrumented(src) if strumentata else src)
        d = bb.load_func("ipa_switch_template", BPF.XDP)
        leaf = bb.load_func("arch_generic_2layer", BPF.XDP)
        bb["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
        return bb, d, leaf

    (b, disp_fn, leaf_fn), build_ms = _timed(_load)
    # Installing a model in P2 is writing maps -- arch_registry, model_desc
    # and a slice of arch_weights. No compiler runs. This is the number that
    # belongs next to P1's build_ms, not P2's own build_ms, which is a
    # ONE-TIME cost paid when the node starts and never again.
    _, update_ms = _timed(lambda: load_arch_weights(
        b, weights, model_id=0, scale=SCALE,
        n_h1=n_h1, n_h2=n_h2, n_hidden=n_hidden,
        features=shape["features"], n_in=n_in,
        semantics=shape.get("semantics")))
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(
        b, {"ipa_switch_template": disp_fn.fd,
            "arch_generic_2layer": leaf_fn.fd})
    lookups = None
    if cell.get("lookups"):
        def _ins():
            bb, dd, _leaf = _load(True)
            load_arch_weights(bb, weights, model_id=0, scale=SCALE,
                              n_h1=n_h1, n_h2=n_h2, n_hidden=n_hidden,
                              features=shape["features"], n_in=n_in,
                              semantics=shape.get("semantics"))
            _seed_link_state(bb, 1)
            return bb, dd.fd
        lookups = _lookups_safe(_ins, n_in, n_out)
    # Un pacchetto NUOVO per ogni chunk, non uno riusato: vedi _sample.
    from verify_prog_run import BENCH_TTL

    def mk_frame():
        return build_frame_sparse(model_id=0, ttl=BENCH_TTL, scale=SCALE,
                                  n_in=n_in, n_out=n_out)

    lo, med, hi, retval = _sample(disp_fn.fd, mk_frame, repeat, trials)
    # Throughput is 1/latency and nothing more -- a THEORETICAL peak from a
    # loop over one buffer, not a rate anything sustained. It is reported
    # because it is the unit the question is usually asked in.
    mpps = (1000.0 / lo) if lo else 0.0
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=1, nw=nw,
                n_in=n_in, build_ms=build_ms, update_ms=update_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, mpps=mpps, retval=retval, per_prog=per_prog,
                n_maps=len(maps), sparsity_real=sparsity_real,
                lookups=lookups)


def _bench_p3(cell, repeat, trials):
    from bcc import BPF
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    from verify_prog_run import build_frame_sparse, _seed_link_state

    dims = cell["dims"]
    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    weights = make_weights(nw, cell["sparsity"])
    sparsity_real = weights.count(0) / len(weights) if weights else 0.0

    sizes = [n_in] + list(dims) + [n_out]
    layer_dims = [(sizes[i - 1], sizes[i]) for i in range(1, len(sizes))]

    def _load(strumentata=False):
        bb = BPF(text=_instrumented(EBPF_MODULAR_FULL) if strumentata
                 else EBPF_MODULAR_FULL)
        d = bb.load_func("modular_dispatcher", BPF.XDP)
        first = bb.load_func("layer_first", BPF.XDP)
        hidden = bb.load_func("layer_hidden", BPF.XDP)
        bb["layer_chain"][ct.c_int(0)] = ct.c_int(first.fd)
        for i in range(1, 16):                       # LAYER_CHAIN_SIZE
            bb["layer_chain"][ct.c_int(i)] = ct.c_int(hidden.fd)
        return bb, d, first, hidden

    (b, disp_fn, first_fn, hidden_fn), build_ms = _timed(_load)
    # Same as P2: a model install is a set of map writes -- layer_registry,
    # layer_shapes, model_desc and a slice of layer_weights. No compiler.
    _, update_ms = _timed(lambda: load_modular_weights(
        b, weights, model_id=0, scale=SCALE,
        layer_dims=layer_dims,
        features=shape["features"],
        semantics=shape.get("semantics")))
    _seed_link_state(b, 1)

    insns, jited, mb, per_prog, maps = _totals(
        b, {"modular_dispatcher": disp_fn.fd,
            "layer_first": first_fn.fd,
            "layer_hidden": hidden_fn.fd})
    lookups = None
    if cell.get("lookups"):
        def _ins():
            bb, dd, _f, _h = _load(True)
            load_modular_weights(bb, weights, model_id=0, scale=SCALE,
                                 layer_dims=layer_dims,
                                 features=shape["features"],
                                 semantics=shape.get("semantics"))
            _seed_link_state(bb, 1)
            return bb, dd.fd
        lookups = _lookups_safe(_ins, n_in, n_out)
    # Un pacchetto NUOVO per ogni chunk, non uno riusato: vedi _sample.
    from verify_prog_run import BENCH_TTL

    def mk_frame():
        return build_frame_sparse(model_id=0, ttl=BENCH_TTL, scale=SCALE,
                                  n_in=n_in, n_out=n_out)

    lo, med, hi, retval = _sample(disp_fn.fd, mk_frame, repeat, trials)
    # Throughput is 1/latency and nothing more -- a THEORETICAL peak from a
    # loop over one buffer, not a rate anything sustained. It is reported
    # because it is the unit the question is usually asked in.
    mpps = (1000.0 / lo) if lo else 0.0
    # Tail calls actually executed: dispatcher -> layer_first -> layer_hidden
    # x (n_layers - 1). NOT the number of distinct programs, which is always 3.
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=len(layer_dims),
                nw=nw, n_in=n_in, build_ms=build_ms, update_ms=update_ms, lat_ns=lo, lat_p50=med,
                lat_max=hi, mpps=mpps, retval=retval, per_prog=per_prog,
                n_maps=len(maps), sparsity_real=sparsity_real,
                lookups=lookups)


def _bench_p1_static(cell, repeat, trials):
    """P1 with this node's index frozen into the source. The node one-hot
    switch and the node_id map read both disappear; what is left are n_h1
    constants clang can fold. The binary is then valid on ONE node."""
    return _bench_p1(cell, repeat, trials, static_node=STATIC_NODE)


def _bench_baseline(cell, repeat, trials):
    """Il pavimento: parse, decremento del TTL, redirect. Nessuna inferenza.

    Non dipende dalla cella, ed e' esattamente il punto: da' al grafico
    "MAC contro latenza" il suo punto a MAC = 0, cioe' quanto del numero di
    una pipeline e' framework XDP e non modello. Rimisurato a ogni cella
    apposta: la sua dispersione lungo l'asse dice quanto rumore aveva la
    macchina mentre le altre quattro venivano misurate.

    Non passa da setup_baseline() perche' quella chiama load_weights() su un
    .pt, e qui i modelli sono sintetici. Il programma e' lo stesso: la
    baseline non legge pesi."""
    from bcc import BPF
    from verify_prog_run import (EBPF_BASELINE, _install_mac_table,
                                 build_frame_sparse)
    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]

    def _load(strumentata=False):
        bb = BPF(text=_instrumented(EBPF_BASELINE) if strumentata
                 else EBPF_BASELINE)
        d = bb.load_func("xdp_baseline", BPF.XDP)
        _install_mac_table(bb, "mac_table")
        return bb, d

    (b, disp_fn), build_ms = _timed(_load)
    insns, jited, mb, per_prog, maps = _totals(b, {"xdp_baseline": disp_fn.fd})
    lookups = None
    if cell.get("lookups"):
        lookups = _lookups_safe(
            lambda: (lambda t: (t[0], t[1].fd))(_load(True)), n_in, n_out)
    # Un pacchetto NUOVO per ogni chunk, non uno riusato: vedi _sample.
    from verify_prog_run import BENCH_TTL

    def mk_frame():
        return build_frame_sparse(model_id=0, ttl=BENCH_TTL, scale=SCALE,
                                  n_in=n_in, n_out=n_out)

    lo, med, hi, retval = _sample(disp_fn.fd, mk_frame, repeat, trials)
    mpps = (1000.0 / lo) if lo else 0.0
    # update_ms = 0 e non build_ms: qui non c'e' nessun modello da installare,
    # e confondere "compilare una volta" con "cambiare modello" e' l'errore
    # contro cui il docstring del modulo mette in guardia per P1.
    return dict(insns=insns, jited=jited, map_bytes=mb, tail=0, nw=0,
                n_in=n_in, build_ms=build_ms, update_ms=0.0, lat_ns=lo,
                lat_p50=med, lat_max=hi, mpps=mpps, retval=retval,
                per_prog=per_prog, n_maps=len(maps), sparsity_real=0.0,
                lookups=lookups)


_BENCH = {"baseline": _bench_baseline,
          "p1_static": _bench_p1_static, "hardcoded": _bench_p1,
          "template": _bench_p2, "modular": _bench_p3}


def _worker(pipeline, spec_json):
    """Runs in the subprocess. Prints exactly one JSON line; that is the
    parent's only contract with it.

    The cell arrives as JSON rather than as positional arguments: adding an
    axis then means adding a key, not editing an argv layout in three
    places."""
    os.chdir(SHARED_DIR)
    spec = json.loads(spec_json)
    repeat, trials = spec.pop("repeat"), spec.pop("trials")
    spec["dims"] = tuple(spec["dims"])
    try:
        out = _BENCH[pipeline](spec, repeat, trials)
        out["ok"] = True
    except NotImplementedError as e:
        out = {"ok": False, "skipped": True, "detail": str(e)}
    except Exception as e:
        detail = str(e).strip().splitlines()
        msg = f"{type(e).__name__}: {detail[-1][:110] if detail else ''}"
        # A verifier refusal is a RESULT, not a failure of this script, and it
        # must not be filed next to a crash. The kernel answers E2BIG both when
        # a program is genuinely too long AND when the verifier gives up having
        # processed more than a million instructions -- and BCC turns that into
        # "Argument list too long" plus a "at most 4096 insns" string whose
        # 4096 is a stale constant in BCC itself. A program of 1 120
        # instructions refused with that text hit the COMPLEXITY ceiling, not
        # the size one; see docs/testing.md on P3's budget for the same trap.
        refused = ("Argument list too long" in msg
                   or "too large" in msg
                   or "Permission denied" in msg)
        out = {"ok": False, "skipped": False, "refused": refused,
               "detail": msg}
    print(json.dumps(out))
    return 0


def bench_cell(pipeline, cell, repeat, trials):
    """One cell, isolated. A fatal LLVM abort or a verifier refusal kills only
    the child."""
    spec = dict(cell, dims=list(cell["dims"]), repeat=repeat, trials=trials)
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--_worker", pipeline,
         json.dumps(spec)],
        capture_output=True, text=True)
    last = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None
    if last:
        try:
            return json.loads(last)
        except json.JSONDecodeError:
            pass
    err = proc.stderr.strip().splitlines()
    return {"ok": False, "skipped": False,
            "detail": (err[-1][:110] if err else
                       f"exit {proc.returncode} (abort fatale: stack o verifier)")}



# ==========================================================================
# HEAD TO HEAD: the two P1 variants, on their own scale
# ==========================================================================
# Every other figure draws four pipelines, and P2/P3 sit an order of magnitude
# above the two P1s -- so the comparison between THOSE TWO, which is a question
# on its own, is squashed into the bottom of the plot. This figure drops the
# other two and gives the duel the whole canvas.
#
# Four panels, because the answer has four parts and they do not all point the
# same way: size collapses, native code collapses harder, speed barely moves,
# and with sparse weights the advantage disappears altogether.
DUEL_PANELS = [
    ("nodes", "insns", "nodi della rete", "istruzioni eBPF",
     "la dipendenza dalla taglia della rete sparisce"),
    ("nodes", "jited", "nodi della rete", "codice nativo (byte)",
     "e nel codice generato il divario e' anche piu' largo"),
    ("width", "lat_ns", "neuroni per strato nascosto", "latenza (ns/pacchetto)",
     "la velocita', invece, si muove appena"),
    ("sparsity", "insns", "frazione di pesi a zero", "istruzioni eBPF",
     "e con pesi sparsi il vantaggio si annulla"),
]


def plot_duel(in_dir, fmt):
    """One figure, four panels: P1 specialised against P1.5."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(2, 2, figsize=(9.6, 6.4))
    drawn = 0
    for ax, (axis, metric, xlab, ylab, note) in zip(axes.ravel(), DUEL_PANELS):
        path = os.path.join(in_dir, f"scaling_{axis}.csv")
        if not os.path.exists(path):
            ax.set_visible(False)
            continue
        with open(path, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        for pipe in ("p1_static", "hardcoded"):
            pts = sorted((float(r["x"]), float(r[metric]))
                         for r in rows
                         if r["pipeline"] == pipe and r.get(metric))
            if not pts:
                continue
            xs, ys = zip(*pts)
            ax.plot(xs, ys, linewidth=1.8, markersize=6, **STYLE[pipe])
            drawn += 1
        ax.set_xlabel(xlab, fontsize=9)
        ax.set_ylabel(ylab, fontsize=9)
        ax.set_title(note, fontsize=9, loc="left", color="#444444")
        ax.tick_params(labelsize=8)
        ax.grid(True, linewidth=0.4, alpha=0.4)
        ax.set_ylim(bottom=0)
    if not drawn:
        plt.close(fig)
        print(f"  {GREY}niente da disegnare: mancano i CSV{NC}")
        return 0
    axes.ravel()[0].legend(frameon=False, fontsize=9)
    fig.tight_layout()
    out = os.path.join(in_dir, "duel_p1_vs_p15." + fmt)
    fig.savefig(out, dpi=160)
    plt.close(fig)
    print(f"  {GREEN}scritto{NC} {out}")
    print(f"           {GREY}P1 specializzata contro P1.5, sulla loro scala{NC}")
    return 1


# ==========================================================================
# SWEEP
# ==========================================================================
def _warn_contaminated(rows, factor=2.0):
    """Say so when a latency cannot be a property of the x axis.

    P2 and P3 compile a source that does not mention the model, so along the
    nodes, width, descriptor and sparsity axes their program is byte-identical
    at every point -- same instruction count, same jited size. If the latency
    of an IDENTICAL program swings by more than `factor` across the axis, the
    swing is the machine, not the variable on the x axis: another process, CPU
    frequency, a noisy neighbour on the hypervisor.

    Taking the min of N trials protects against a spike inside a cell. It does
    nothing when the whole cell was measured during a busy period, which is
    what this catches. Without it the reader is invited to explain a 3x jump
    that has no cause in the model."""
    for pipe in PIPELINES:
        groups = {}
        for r in rows:
            if not r.get("lat_ns"):
                continue
            if r["pipeline"] == pipe:
                # Grouped by (instructions, TAIL CALLS), not by instructions
                # alone. P3's program is byte-identical at every depth -- that
                # is its whole design -- but it executes one more tail call per
                # layer, so its latency legitimately doubles across the depth
                # axis. Keyed on instructions only, this check called that real
                # result contamination, which is the worst thing a check can
                # do: cry wolf on the finding. Identical code AND identical
                # hops is what makes a latency swing impossible to attribute to
                # the x axis.
                key = (r["insns"], r.get("tail"))
                groups.setdefault(key, []).append((r["x"], r["lat_ns"]))
        for (insns, tail), pts in groups.items():
            if len(pts) < 2:
                continue
            lats = [p[1] for p in pts]
            lo, hi = min(lats), max(lats)
            if lo > 0 and hi / lo > factor:
                worst = max(pts, key=lambda p: p[1])
                print(f"\n  {RED}SOSPETTO{NC} {pipe}: programma identico "
                      f"({insns} istruzioni, {tail} tail call) a ogni x, "
                      f"ma la latenza va da {lo:.0f} a {hi:.0f} ns "
                      f"({hi / lo:.1f}x).")
                print(f"  {GREY}Il binario non cambia lungo questo asse, "
                      f"quindi lo scarto e' la macchina, non la variabile. "
                      f"Il punto peggiore e' x={worst[0]}. Rimisura a macchina "
                      f"scarica prima di metterlo in un grafico.{NC}")


def _give_back(path):
    """Hand a file or directory created under sudo back to the invoking user.

    The measuring run needs root; plotting does not, and the documented next
    step is to run --plot WITHOUT sudo. Without this, that second command dies
    with `PermissionError: 'results/scaling_nodes_insns.pdf'`, because root
    owns the directory the plots go into. Silently ignored when not running
    under sudo, or if the chown is refused."""
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid or os.name != "posix":
        return
    try:
        os.chown(path, int(uid), int(gid or uid))
    except OSError:
        pass



# ==========================================================================
# EQUIVALENCE: the specialised P1 must DECIDE the same thing as P1.5
# ==========================================================================
def _build_p1(cell, static_node):
    """Build and load one P1 variant (the AOT object); returns (maps,
    dispatcher fd, shape)."""
    import p1_aot
    from verify_prog_run import _install_mac_table

    dims = cell["dims"]
    shape = shape_of(cell)
    n_in, n_out = shape["n_in"], shape["n_out"]
    nw = weight_count(n_in, dims, n_out)
    # `seed` esiste solo per il controllo negativo di verify_ports: la misura
    # usa sempre il pool di default, altrimenti l'asse cambierebbe due cose.
    weights = make_weights(nw, cell["sparsity"], seed=cell.get("seed", 42))
    setup = p1_aot.load_p1(
        [(0, weights, SCALE)], features=shape["features"],
        n_out=n_out, hidden_dims=tuple(dims), static_node=static_node,
        static_ports=(cell.get("static_ports")
                      if static_node is not None else None))
    b = setup["b"]
    _install_mac_table(b, "mac_table")
    return b, setup["disp"].fd, shape


def _decide(b, disp_fd, n_in, n_out, ttl, links):
    """Run ONE packet and report which class fired. Counters are cleared
    first, so the answer describes this packet and not the run before it."""
    from verify_prog_run import (prog_test_run, build_frame_sparse,
                                 _read_u64)
    from common import write_vector_map
    # Sizes come from the maps, not from literals here. pkt_stats has 3
    # entries (hit / miss / drop) and cls_stats has n_out; writing range(4)
    # into the first of them raised `IndexError: Array index out of range`
    # from BCC, which is the right error for the wrong reason: the number was
    # never this file's to know.
    for c in range(len(b["cls_stats"])):
        b["cls_stats"][ct.c_int(c)] = ct.c_ulonglong(0)
    for k in range(len(b["pkt_stats"])):
        b["pkt_stats"][ct.c_int(k)] = ct.c_ulonglong(0)
    write_vector_map(b, "link_state", list(links))
    frame = build_frame_sparse(model_id=0, ttl=ttl, scale=SCALE,
                               n_in=n_in, n_out=n_out)
    retval, _ = prog_test_run(disp_fd, frame, repeat=1)
    fired = -1
    for c in range(len(b["cls_stats"])):
        if _read_u64(b["cls_stats"], c) > 0:
            fired = c
            break
    return retval, fired


def verify_static(node=None):
    """P1 with the node index FROZEN must decide exactly what P1.5 decides
    with that same index installed in the node_id map.

    This is the check that makes every speed number in the p1_static column
    mean something. Folding the node one-hot picks ONE column out of the
    first layer's weight matrix at code-generation time; picking the wrong
    column produces a program that is smaller, faster, and computes a
    different model -- and nothing else in this sweep would notice, because
    the sweep measures cost, not correctness.

    Two programs, the same packets, the same class every time, or it fails."""
    node = STATIC_NODE if node is None else node
    cell = cell_of("nodes", 52)
    n_if = N_INTERFACES

    b_s, fd_s, shape = _build_p1(cell, static_node=node)
    b_d, fd_d, _ = _build_p1(cell, static_node=None)
    # P1.5 learns the node at runtime; the frozen build already knows it.
    b_d["node_id"][ct.c_uint(0)] = ct.c_uint(node)

    n_in, n_out = shape["n_in"], shape["n_out"]
    print(f"{YELLOW}{'=' * 70}{NC}")
    print(f"{YELLOW} P1 specializzata (nodo {node} congelato) contro P1.5 "
          f"(nodo da mappa){NC}")
    print(f"{YELLOW}{'=' * 70}{NC}\n")

    cases = []
    for ttl in range(2, 12):
        for pattern in (0, 1, 2, 3, 5, 7, 0b101010, 0b111111):
            links = [(pattern >> i) & 1 for i in range(n_if)]
            cases.append((ttl, tuple(links)))

    bad = 0
    for ttl, links in cases:
        rv_s, cl_s = _decide(b_s, fd_s, n_in, n_out, ttl, links)
        rv_d, cl_d = _decide(b_d, fd_d, n_in, n_out, ttl, links)
        if (rv_s, cl_s) != (rv_d, cl_d):
            bad += 1
            if bad <= 6:
                ls = "".join(map(str, links))
                print(f"  {RED}DIVERGE{NC} ttl={ttl:2d} link={ls}: "
                      f"congelata retval={rv_s} classe={cl_s}, "
                      f"P1.5 retval={rv_d} classe={cl_d}")

    n = len(cases)
    if bad:
        print(f"\n  {RED}{bad}/{n} casi divergono{NC} -- la colonna di pesi "
              f"congelata NON e' quella del nodo {node}.")
        print(f"  {GREY}Finche' questo non passa, ogni numero della colonna "
              f"p1_static misura un modello diverso.{NC}")
        return 1
    print(f"  {GREEN}{n}/{n} casi identici{NC} (ttl 2-11 x 8 pattern di link).")
    print(f"  {GREY}Congelare il nodo cambia il codice, non la decisione.{NC}")
    return 0


def verify_ports(ports=None, node=None):
    """La P1 che NON genera le colonne delle porte assenti deve decidere
    esattamente come la stessa P1 che le genera, purche' quegli slot valgano 0.

    E' il gemello di verify_static, e per la stessa ragione: togliere colonne
    dal primo layer produce un programma piu' piccolo che calcola un modello
    diverso, se la colonna tolta non era davvero nulla. Lo sweep misura costo,
    non correttezza, e non se ne accorgerebbe.

    Le due build differiscono SOLO per static_ports -- il nodo e' congelato in
    entrambe -- cosi' una divergenza e' attribuibile a questa modifica e a
    nient'altro.

    Il controllo negativo in fondo e' cio' che rende credibile il resto: se si
    accende uno slot assente le due DEVONO divergere. Un test che passa anche
    quando la condizione e' violata non sta verificando la condizione.
    """
    node = STATIC_NODE if node is None else node
    n_if = N_INTERFACES
    ports = {0, 1, 4} if ports is None else set(ports)
    assenti = sorted(set(range(n_if)) - ports)

    cell = dict(cell_of("nodes", 52), static_ports=sorted(ports))
    b_s, fd_s, shape = _build_p1(cell, static_node=node)
    b_f, fd_f, _ = _build_p1(dict(cell, static_ports=None), static_node=node)

    n_in, n_out = shape["n_in"], shape["n_out"]
    print(f"{YELLOW}{'=' * 70}{NC}")
    print(f"{YELLOW} P1 con le sole porte {sorted(ports)} generate, contro P1 "
          f"a larghezza piena{NC}")
    print(f"{GREY} slot senza interfaccia su questo nodo: {assenti} "
          f"-- strutturalmente 0, non link caduti{NC}")
    print(f"{YELLOW}{'=' * 70}{NC}\n")

    def mask(v):
        """Il riferimento vede 0 dove il nodo non ha interfaccia.

        E' la condizione sotto cui l'equivalenza vale, e va imposta qui
        esplicitamente perche' _seed_link_state semina 1 su ogni slot."""
        return tuple(0 if i in assenti else x for i, x in enumerate(v))

    casi = sorted({(ttl, mask([(p >> i) & 1 for i in range(n_if)]))
                   for ttl in range(2, 12) for p in range(1 << n_if)})

    bad = 0
    for ttl, links in casi:
        r_s = _decide(b_s, fd_s, n_in, n_out, ttl, links)
        r_f = _decide(b_f, fd_f, n_in, n_out, ttl, links)
        if r_s != r_f:
            bad += 1
            if bad <= 6:
                ls = "".join(map(str, links))
                print(f"  {RED}DIVERGE{NC} ttl={ttl:2d} link={ls}: "
                      f"specializzata retval={r_s[0]} classe={r_s[1]}, "
                      f"piena retval={r_f[0]} classe={r_f[1]}")

    n = len(casi)
    if bad:
        print(f"\n  {RED}{bad}/{n} casi divergono{NC} -- le colonne eliminate "
              f"NON erano nulle.")
        print(f"  {GREY}Finche' questo non passa, ogni numero della colonna "
              f"p1_static sull'asse degree misura un modello diverso.{NC}")
        return 1
    print(f"  {GREEN}{n}/{n} casi identici{NC} (ttl 2-11 x "
          f"{1 << len(ports)} pattern realizzabili).")

    # --- controllo negativo -------------------------------------------------
    # Senza questo, il blocco sopra e' compatibile con un test che non prova
    # nulla: se su questi pesi le colonne assenti non spostano mai l'argmax,
    # allora "le due build concordano" e' vero anche per una build sbagliata.
    #
    # Il primo run reale e' finito esattamente li': 80/80 e controllo muto. La
    # causa e' che una colonna di link_state contribuisce `1 * w` contro un
    # accumulatore che somma 65 colonne, quindi puo' benissimo non ribaltare
    # l'argmax. Non e' una proprieta' del codice ma dei PESI, e allora i pesi
    # si cercano: il seme del pool e' un parametro di make_weights, e cambiarlo
    # per il CONTROLLO non tocca la misura, che resta sul seme di sempre.
    if not assenti:
        print(f"  {GREY}Nessuno slot assente: controllo negativo non "
              f"applicabile.{NC}")
        return 0

    def morde(seed):
        """Su questi pesi, accendere uno slot assente cambia la decisione?"""
        c = dict(cell, seed=seed)
        bs, fs, sh = _build_p1(c, static_node=node)
        bf, ff, _ = _build_p1(dict(c, static_ports=None), static_node=node)
        ni, no = sh["n_in"], sh["n_out"]
        n = 0
        for ttl in range(2, 12):
            for i in assenti:
                links = tuple(1 if k == i else 0 for k in range(n_if))
                if _decide(bs, fs, ni, no, ttl, links) != \
                   _decide(bf, ff, ni, no, ttl, links):
                    n += 1
        return n

    semi = [42, 1, 2, 3, 7, 123, 999]
    for seed in semi:
        visto = morde(seed)
        if visto:
            extra = "" if seed == 42 else f" (pool seed {seed})"
            print(f"  {GREEN}controllo negativo{NC}: accendendo uno slot "
                  f"assente le due divergono in {visto} casi{extra} -- la "
                  f"condizione \"slot assenti a 0\" e' portante, non "
                  f"decorativa.")
            print(f"  {GREY}Togliere le colonne cambia il codice, non la "
                  f"decisione.{NC}")
            return 0

    print(f"\n  {RED}controllo negativo MUTO su {len(semi)} insiemi di pesi{NC}: "
          f"nemmeno accendendo uno slot assente le due build divergono mai.")
    print(f"  {GREY}Il {n}/{n} qui sopra e' quindi compatibile anche con una "
          f"specializzazione sbagliata, e non va citato come prova finche' "
          f"questo non morde. Prova un descrittore con meno colonne (dove "
          f"link_state pesa di piu' sull'accumulatore) o un modello piu' "
          f"stretto.{NC}")
    return 1


def _write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    _give_back(path)
    print(f"\n  {GREEN}scritto{NC} {path}  ({len(rows)} righe)")


def run_axis(axis, repeat, trials, out_dir, write=True, lookups=False):
    """Un asse. Restituisce le righe; `write=False` le lascia al chiamante,
    che e' come i quattro assi della campagna finiscono in un CSV solo."""
    spec = AXES[axis]
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} asse x: {spec['xlabel']}{NC}")
    print(f"{GREY} {spec['note']}{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}\n")

    rows = []
    hdr = (f"  {'x':>5s} {'pipeline':11s} {'forma':>16s} {'pesi':>6s} "
           f"{'insns':>7s} {'ns':>7s} {'update ms':>10s} {'build ms':>9s} "
           f"{'mappe B':>8s} {'tail':>4s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))

    # La baseline e' il pavimento del confronto MAC-contro-latenza, quindi
    # entra negli assi della campagna. Gli assi storici restano a quattro
    # pipeline, cosi' i loro CSV conservano le stesse righe di prima.
    pipelines = (("baseline",) + PIPELINES) if spec.get("campaign") else PIPELINES

    for v in spec["values"]:
        cell = cell_of(axis, v)
        cell["lookups"] = lookups     # viaggia in JSON fino al worker
        dims = cell["dims"]
        # Computed here, not read back from the result: a cell that was
        # skipped or that crashed has no n_in to report, and printing "?-4-7"
        # made a structural note look like a broken measurement.
        shape = shape_of(cell)
        n_in = shape["n_in"]
        shape_str = f"{n_in}-{'-'.join(map(str, dims))}-{N_OUT}"
        # Descrittive della cella, uguali per tutte le pipeline: la forma non
        # cambia a seconda di chi la esegue. `macs` e `macs_eff` divergono
        # quando l'ingresso ha one-hot -- vedi mac_count_eff.
        forma = dict(n_out=N_OUT, depth=len(dims),
                     width=(max(dims) if dims else 0),
                     macs=mac_count(n_in, dims, N_OUT),
                     macs_eff=mac_count_eff(shape, dims, N_OUT))
        for pipe in pipelines:
            # Fuori dai soffitti compilati NON si misura. P3 non rifiuta il
            # caricamento, risponde XDP_PASS a runtime: la misura uscirebbe
            # come una latenza plausibile di un programma che non calcola.
            oltre = ceiling_refusal(pipe, shape, dims)
            if oltre:
                r = {"ok": False, "refused": True,
                     "detail": f"soffitto compilato: {oltre}"}
            else:
                r = bench_cell(pipe, cell, repeat, trials)
            if r.get("ok"):
                # La baseline non moltiplica niente: `forma` descrive la
                # cella, non quello che questa pipeline esegue.
                if pipe == "baseline":
                    r = dict(r)
                    forma_riga = dict(forma, macs=0, macs_eff=0)
                else:
                    forma_riga = forma
                print(f"  {str(v):>5s} {pipe:11s} {shape_str:>16s} {r['nw']:6d} "
                      f"{r['insns']:7d} {r['lat_ns']:7.1f} "
                      f"{r['update_ms']:10.2f} {r['build_ms']:9.1f} "
                      f"{r['map_bytes']:8d} {r['tail']:4d}")
                rows.append(dict(axis=axis, x=v, pipeline=pipe,
                                 shape=shape_str, **forma_riga, **{
                                     k: r[k] for k in
                                     ("nw", "n_in", "insns", "jited",
                                      "map_bytes", "n_maps", "tail",
                                      "build_ms", "update_ms",
                                      "lat_ns", "lat_p50", "lat_max",
                                      "mpps",
                                      # requested vs achieved: the weights are
                                      # a prefix of a shuffled pool, so the
                                      # zero fraction of a short prefix is a
                                      # sample of the pool's, not equal to it.
                                      # Recorded so the x label can be checked
                                      # rather than trusted.
                                      "sparsity_real", "lookups")}))
            else:
                if r.get("skipped"):
                    mark = f"{GREY}n/d{NC}"
                elif r.get("refused"):
                    mark = f"{YELLOW}RIFIUTATO{NC}"     # dato, non guasto
                else:
                    mark = f"{RED}CRASH{NC}"
                print(f"  {str(v):>5s} {pipe:11s} {shape_str:>16s} {'':6s} "
                      f"{mark} {GREY}{r.get('detail', '')[:90]}{NC}")

    _warn_contaminated(rows)

    if out_dir and write:
        os.makedirs(out_dir, exist_ok=True)
        _give_back(out_dir)
        if rows:
            _write_csv(os.path.join(out_dir, f"scaling_{axis}.csv"), rows)
        else:
            print(f"\n  {RED}nessuna riga da scrivere per {axis}{NC}")
    return rows


# ==========================================================================
# PLOTS -- read the CSV, never re-measure. No root, no BCC.
# ==========================================================================
# (colonna, etichetta y, nome file, asse y logaritmico)
#
# update_ms is log: P1 sits around 1500 ms and P2/P3 around a millisecond, so
# on a linear axis the two cheap pipelines collapse onto the zero line and the
# graph shows one curve instead of three. The whole finding is the DISTANCE
# between them, which is what a log axis is for.
# Every (metric, axis) pair this sweep can draw -- 7 metrics x 5 axes = 35
# figures. Most of them say nothing: map memory does not depend on any axis,
# build_ms is the same compile every time, and a log twin of a metric whose
# range is one decade adds no reading.
#
# KEEP lists the pairs that carry a result, and it is what gets drawn by
# default. --all-plots draws the whole matrix, for looking rather than for
# publishing.
PLOTS = [
    ("insns", "istruzioni del programma", "scaling_{axis}_insns", False),
    # The log twin exists for one figure only. P1 runs at ~10^3 instructions
    # and P2/P3 at ~10^4, so on a LINEAR axis P1's curve is pinned to the
    # bottom and its collapse with sparser weights -- 1 071 to 224, the
    # sharpest result in the sweep -- is invisible. On a LOG axis that is
    # plain, but P2's rise with depth (1.3x) flattens out. Neither scale
    # serves both readings, so each figure takes the one that shows what it
    # is about.
    ("insns", "istruzioni del programma (scala log)", "scaling_{axis}_insns_log", True),
    ("lat_ns", "latenza (ns/pacchetto, minimo)", "scaling_{axis}_latenza", False),
    ("lat_ns", "latenza (ns/pacchetto, scala log)", "scaling_{axis}_latenza_log", True),
    ("mpps", "pacchetti al secondo teorici (1 / latenza)", "scaling_{axis}_mpps", False),
    ("update_ms", "installare un modello nuovo (ms)", "scaling_{axis}_update", True),
    ("build_ms", "compilare il programma, una volta (ms)", "scaling_{axis}_build", False),
    ("map_bytes", "memoria delle tabelle (byte)", "scaling_{axis}_mappe", False),
]

# (axis, metric) -> the one-line reading that figure supports. Keeping the
# claim next to the selection is deliberate: a figure nobody can state a
# conclusion for does not belong in a thesis, and this list is where that
# question gets asked.
KEEP = {
    ("depth", "insns"):
        "P2 cresce di ~780 istruzioni per layer, P3 di ZERO: riusa layer_hidden",
    ("depth", "lat_ns"):
        "e P3 lo paga in tempo, ~70 ns per layer, che sono le sue tail call",
    ("depth", "update_ms"):
        "installare un modello: P1 ricompila (~1,4 s), P2 e P3 scrivono in mappa (~7 ms)",
    ("nodes", "insns"):
        "la taglia della rete entra nel programma solo in P1.5; congelando il "
        "nodo (P1 specializzata) la dipendenza SPARISCE",
    # Lo stesso dato su scala log: in lineare le due P1 (600-1700) restano
    # schiacciate contro le 14 628 di P2, e il confronto fra loro -- che e'
    # il punto della figura -- non si vede.
    ("nodes", "insns_log"):
        "lo stesso, leggibile: P1.5 sale 2,3x fra 10 e 100 nodi, la "
        "specializzata resta piatta",
    ("nodes", "lat_ns"):
        "ma a runtime non costa a nessuna: la one-hot legge UNA colonna, e lo "
        "switch ne esegue UN caso",
    ("width", "lat_ns"):
        "allargare i layer NASCOSTI invece si paga, su tutte e quattro",
    ("sparsity", "insns_log"):
        "con pesi sparsi P1 crolla e le due P1 CONVERGONO: sparsita' e nodo "
        "congelato sono due strade alla stessa riduzione, non si sommano",
    ("isoparam", "insns"):
        "a PARITA' di parametri (~592 pesi): quanto costa in dimensione "
        "spalmarli su piu' layer invece che su uno largo",
    ("isoparam", "lat_ns"):
        "e quanto costa in tempo -- e' qui che si risponde a 'larga o profonda'",
    ("isoparam", "mpps"):
        "lo stesso in throughput teorico, l'unita' in cui la domanda si pone",
    ("descriptor", "insns"):
        "il controllo: senza feature 'node' le due P1 sono IDENTICHE, con "
        "essa divergono -- il divario e' tutto li' e nient'altro",
}

STYLE = {
    "baseline":  dict(color="#7f8c8d", marker="x", label="baseline (0 MAC)"),
    "p1_static": dict(color="#8e44ad", marker="D", label="P1 specializzata"),
    "hardcoded": dict(color="#c0392b", marker="o", label="P1.5 hardcoded"),
    "template": dict(color="#2980b9", marker="s", label="P2 template"),
    "modular": dict(color="#27ae60", marker="^", label="P3 modular"),
}


# Un marcatore per ASSE, non per pipeline: nella figura della campagna il
# colore dice gia' quale pipeline e', e serve poter vedere se i quattro assi
# cadono sulla stessa retta oppure no -- che e' l'intera domanda.
CAMPAIGN_MARKERS = {
    "iv_dense":   ("o", "IV densa"),
    "iv_onehot":  ("s", "IV one-hot"),
    "width_camp": ("D", "larghezza"),
    "depth_camp": ("^", "profondita'"),
}


def _fit(xs, ys):
    """Minimi quadrati a mano: (pendenza, intercetta, r2).

    Senza numpy di proposito -- sono quattro righe e questo file gira anche
    dove c'e' solo matplotlib."""
    n = len(xs)
    if n < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None
    m = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    q = my - m * mx
    sst = sum((y - my) ** 2 for y in ys)
    ssr = sum((y - (m * x + q)) ** 2 for x, y in zip(xs, ys))
    return m, q, (1.0 - ssr / sst) if sst else 1.0


def plot_campaign(in_dir, fmt):
    """MAC contro latenza, i quattro assi della campagna sovrapposti.

    Disegna la stessa figura due volte, con le MAC NOMINALI e con quelle
    ESEGUITE. Non e' ridondanza: una feature one-hot occupa `size` colonne
    della matrice dei pesi ma nel datapath ne attiva una sola, quindi le
    nominali sovrastimano -- e di quanto dipende da quanta one-hot c'e'
    nell'ingresso, cioe' cambia da asse ad asse. Il risultato e' che con le
    nominali i quattro assi NON stanno sulla stessa retta e con le eseguite
    si'. Mettere solo la seconda vorrebbe dire chiedere al lettore di fidarsi.

    La baseline non entra in nessuna retta: ha 0 MAC su ogni cella, quindi e'
    una nuvola verticale a x = 0. Va disegnata come pavimento -- il costo del
    framework XDP che ogni pipeline paga prima di moltiplicare qualunque
    cosa -- e non come un punto da interpolare."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    path = os.path.join(in_dir, CAMPAIGN_CSV)
    if not os.path.exists(path):
        print(f"  {GREY}salto la campagna: {path} non c'e'{NC}")
        return 0
    with open(path, encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r.get("lat_ns")]
    if not rows:
        print(f"  {GREY}salto la campagna: CSV vuoto{NC}")
        return 0
    if "macs_eff" not in rows[0]:
        print(f"  {GREY}salto la campagna: manca la colonna macs_eff "
              f"(rimisura per averla){NC}")
        return 0

    made = 0
    for col, nome, unita, stem in (
            ("macs_eff", "MAC eseguite per pacchetto", "ns/MAC",
             "campaign_macs_eff_latenza"),
            ("macs", "MAC nominali per pacchetto (n_in x h1 + ...)", "ns/MAC",
             "campaign_macs_nominali_latenza"),
            ("insns", "istruzioni del programma", "ns/istruzione",
             "campaign_insns_latenza")):
        fig, ax = plt.subplots(figsize=(6.4, 4.0))
        print(f"\n  {YELLOW}{nome}{NC}")
        for pipe in PIPELINES:
            px, py = [], []
            for r in rows:
                if r["pipeline"] != pipe:
                    continue
                mk = CAMPAIGN_MARKERS.get(r["axis"], ("o", r["axis"]))[0]
                x, y = float(r[col]), float(r["lat_ns"])
                px.append(x)
                py.append(y)
                ax.plot([x], [y], marker=mk, markersize=6, linestyle="none",
                        color=STYLE[pipe]["color"], alpha=0.9)
            f = _fit(px, py)
            if not f:
                # x costante su tutte le celle: non c'e' nessuna retta da
                # stimare. E' il caso di P3 sulle istruzioni -- 12349 ovunque,
                # perche' non ricompila mai -- ed e' un RISULTATO, non un
                # dato mancante. Senza questa voce la figura mostrerebbe una
                # nuvola di punti senza nome in legenda.
                if px:
                    ax.plot([], [], marker=STYLE[pipe]["marker"],
                            linestyle="none", color=STYLE[pipe]["color"],
                            label=f"{STYLE[pipe]['label']}: x costante "
                                  f"({px[0]:.0f}), nessuna pendenza")
                    print(f"    {STYLE[pipe]['label']:22s} x costante a "
                          f"{px[0]:.0f}: {GREY}la latenza varia "
                          f"{min(py):.0f}-{max(py):.0f} ns a parita' di x{NC}")
                continue
            m, q, r2 = f
            xs = [min(px), max(px)]
            ax.plot(xs, [m * x + q for x in xs], linewidth=1.4,
                    color=STYLE[pipe]["color"],
                    label=f"{STYLE[pipe]['label']}: {m:.3f} {unita}  "
                          f"(r2 {r2:.2f})")
            # Il residuo medio PER ASSE: se un asse non sta sulla retta lo si
            # legge qui invece di indovinarlo dalla figura. Su `depth` ci si
            # aspetta che non ci stia -- P2 ricompila e P3 aggiunge una tail
            # call a ogni layer, e ne' l'una ne' l'altra e' una MAC.
            fuori = []
            for axe in CAMPAIGN_MARKERS:
                res = [abs(float(r["lat_ns"]) - (m * float(r[col]) + q))
                       for r in rows
                       if r["pipeline"] == pipe and r["axis"] == axe
                       and r.get("lat_ns")]
                if res:
                    fuori.append((sum(res) / len(res), axe))
            fuori.sort(reverse=True)
            detta = "  ".join(f"{a} {v:.0f}ns" for v, a in fuori)
            print(f"    {STYLE[pipe]['label']:22s} {m:.3f} {unita}  "
                  f"r2 {r2:.2f}   {GREY}residuo medio: {detta}{NC}")

        # Il pavimento: la baseline, che di MAC ne fa zero.
        base = [float(r["lat_ns"]) for r in rows if r["pipeline"] == "baseline"]
        if base:
            lo, hi = min(base), max(base)
            ax.axhspan(lo, hi, color=STYLE["baseline"]["color"], alpha=0.18)
            ax.axhline(sum(base) / len(base), linewidth=1.0, linestyle=":",
                       color=STYLE["baseline"]["color"])
            print(f"    {'baseline (0 MAC)':22s} pavimento {lo:.0f}-{hi:.0f} ns "
                  f"{GREY}(framework XDP, nessuna inferenza){NC}")

        ax.set_xlabel(nome)
        ax.set_ylabel("latenza (ns/pacchetto, minimo)")
        ax.grid(True, linewidth=0.4, alpha=0.4)
        ax.set_ylim(bottom=0)
        prima = ax.legend(frameon=False, fontsize=7.5, loc="upper left")
        # Seconda legenda, per i marcatori: quale asse e' quale punto. Senza,
        # la figura mostra una nuvola e non si puo' dire se un asse devia.
        ax.add_artist(prima)
        ax.legend(handles=[Line2D([], [], marker=mk, linestyle="none",
                                  color="#555555", markersize=6, label=lab)
                           for mk, lab in CAMPAIGN_MARKERS.values()],
                  fontsize=7.5, loc="lower right", title="asse",
                  title_fontsize=7.5,
                  # Riquadro opaco e non trasparente: qui sotto passano le
                  # rette di P1, e senza sfondo le voci diventano illeggibili.
                  frameon=True, framealpha=0.95, edgecolor="none",
                  facecolor="white")
        fig.tight_layout()
        out = os.path.join(in_dir, stem + "." + fmt)
        fig.savefig(out, dpi=160)
        plt.close(fig)
        print(f"  {GREEN}scritto{NC} {out}")
        made += 1
    return made


def plot_axis(axis, in_dir, fmt, draw_all=False):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    path = os.path.join(in_dir, f"scaling_{axis}.csv")
    if not os.path.exists(path):
        print(f"  {GREY}salto {axis}: {path} non c'e'{NC}")
        return 0
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print(f"  {GREY}salto {axis}: CSV vuoto{NC}")
        return 0

    cat = AXES[axis]["kind"] == "cat"
    # Categorical x (the descriptor axis) is drawn as grouped bars, not a
    # curve. A line from "no_onehot" to "big_onehot" would draw a slope
    # between two names, implying intermediate descriptors that do not exist.
    order = [str(v) for v in AXES[axis]["values"]]

    made = 0
    for metric, ylabel, stem, logy in PLOTS:
        # "insns_log" and "insns" are the same column with different scales;
        # KEEP is keyed on the figure, not the column.
        fig_key = metric + ("_log" if logy and stem.endswith("_log") else "")
        if not draw_all and (axis, fig_key) not in KEEP:
            continue
        fig, ax = plt.subplots(figsize=(6.2 if cat else 5.6, 3.6))
        drawn = False
        if metric not in rows[0]:
            # A CSV written by an older version of this script: it simply does
            # not have this column. Say so and move on -- crashing with a
            # KeyError would make an out-of-date file look like a broken
            # plotter, and re-measuring is the fix either way.
            print(f"  {GREY}salto {metric} per {axis}: colonna assente nel CSV "
                  f"(rimisura per averla){NC}")
            plt.close(fig)
            continue
        for slot, pipe in enumerate(PIPELINES):
            vals = {r["x"]: r[metric] for r in rows
                    if r["pipeline"] == pipe and r.get(metric)}
            if not vals:
                continue
            if cat:
                idx = [i for i, k in enumerate(order) if k in vals]
                ys = [float(vals[order[i]]) for i in idx]
                w = 0.26
                ax.bar([i + (slot - 1) * w for i in idx], ys, width=w,
                       color=STYLE[pipe]["color"], label=STYLE[pipe]["label"])
            else:
                pts = sorted((float(k), float(v)) for k, v in vals.items())
                xs, ys = zip(*pts)
                # A single point cannot show a slope, so it is drawn as a lone
                # marker: that is P2 on the depth axis when its compiled layer
                # ceiling is 2, and the gap IS the result.
                ax.plot(xs, ys, linestyle="-" if len(xs) > 1 else "none",
                        linewidth=1.6, markersize=6, **STYLE[pipe])
            drawn = True
        if not drawn:
            plt.close(fig)
            continue
        if cat:
            ax.set_xticks(range(len(order)))
            ax.set_xticklabels(order, fontsize=8)
        else:
            # Integer x values get integer ticks. Matplotlib's default put
            # 1.5 and 2.5 on the hidden-layer axis, and half a layer does not
            # exist.
            vals = [float(v) for v in AXES[axis]["values"]]
            if all(v == int(v) for v in vals):
                ax.set_xticks([int(v) for v in vals])
        ax.set_xlabel(AXES[axis]["xlabel"])
        ax.set_ylabel(ylabel)
        ax.grid(True, linewidth=0.4, alpha=0.4)
        ax.legend(frameon=False, fontsize=8)
        if logy:
            ax.set_yscale("log")      # set_ylim(bottom=0) is invalid on a log axis
        else:
            ax.set_ylim(bottom=0)
        fig.tight_layout()
        out = os.path.join(in_dir, stem.format(axis=axis) + "." + fmt)
        fig.savefig(out, dpi=160)
        plt.close(fig)
        why = KEEP.get((axis, fig_key))
        print(f"  {GREEN}scritto{NC} {out}")
        if why:
            print(f"           {GREY}{why}{NC}")
        made += 1
    return made


# ==========================================================================
def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("USAGE")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--axis", choices=list(AXES) + ["all", "campaign"],
                   default="all",
                   help="`all` = i sette assi storici; `campaign` = le "
                        "architetture della campagna, tutte in "
                        + CAMPAIGN_CSV)
    p.add_argument("--repeat", type=int, default=100000,
                   help="ripetizioni bersaglio per misura; vengono spezzate "
                        "in chunk da 200 con un frame nuovo ciascuno, e "
                        "limitate a TEST_RUN_MAX_CHUNKS chunk")
    p.add_argument("--trials", type=int, default=7,
                   help="misure indipendenti per cella; si tiene il minimo")
    p.add_argument("--lookups", action="store_true",
                   help="misura anche le letture di mappa per pacchetto. "
                        "Spento di default: e' una SECONDA compilazione per "
                        "cella (su P1 ~1,5 s di clang in piu' ognuna), e la "
                        "build strumentata non e' quella cronometrata")
    p.add_argument("--out", default=os.path.join(SHARED_DIR, "..", "results"),
                   help="dove scrivere i CSV")
    p.add_argument("--plot", metavar="DIR", default=None,
                   help="non misurare: genera i grafici dai CSV in DIR")
    p.add_argument("--format", default="pdf", choices=["pdf", "png"])
    p.add_argument("--verify", action="store_true",
                   help="non misurare: verifica che la P1 specializzata decida "
                        "come la P1.5 con lo stesso nodo installato")
    p.add_argument("--verify-ports", action="store_true", dest="verify_ports",
                   help="non misurare: verifica che la P1 che non genera le "
                        "porte assenti decida come quella a larghezza piena")
    p.add_argument("--ports", default=None,
                   help="porte presenti per --verify-ports, es. '0,1,4' "
                        "(default 0,1,4)")
    p.add_argument("--all-plots", action="store_true",
                   help="disegna tutte le combinazioni metrica x asse, non "
                        "solo quelle che portano un risultato")
    p.add_argument("--_worker", nargs=2, help=argparse.SUPPRESS)
    a = p.parse_args()

    if a._worker:
        return _worker(a._worker[0], a._worker[1])

    if a.plot:
        import importlib.util
        if importlib.util.find_spec("matplotlib") is None:
            sys.exit("serve matplotlib per i grafici: pip install matplotlib")
        n = sum(plot_axis(ax, a.plot, a.format, a.all_plots)
                for ax in LEGACY_AXES)
        n += plot_duel(a.plot, a.format)
        n += plot_campaign(a.plot, a.format)
        print(f"\n{GREEN}{n} grafici{NC} in {a.plot}")
        return 0

    if sys.platform != "linux":
        sys.exit(f"la misura richiede Linux, non {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("serve root: sudo python3 ipa/test/bench_scaling.py")

    if a.verify:
        os.chdir(SHARED_DIR)
        return verify_static()

    if a.verify_ports:
        os.chdir(SHARED_DIR)
        sel = ({int(x) for x in a.ports.split(",") if x.strip()}
               if a.ports else None)
        return verify_ports(sel)

    # Resolved BEFORE the chdir: a relative --out is relative to where the
    # USER ran the command, not to ipa/. Resolving it after the chdir put
    # `--out results/` inside ipa/results/, which is not where anyone typing
    # that meant it to go.
    out_dir = os.path.abspath(a.out)
    os.chdir(SHARED_DIR)
    if a.axis == "all":
        axes = LEGACY_AXES          # invariato: i sette assi di sempre
    elif a.axis == "campaign":
        axes = CAMPAIGN_AXES
    else:
        axes = [a.axis]

    # Gli assi della campagna confluiscono in un file solo, perche' sono
    # quattro tagli della STESSA domanda e un grafico MAC-contro-latenza li
    # vuole tutti insieme. Gli altri continuano a scrivere scaling_<asse>.csv.
    campagna = []
    for ax in axes:
        e_campagna = bool(AXES[ax].get("campaign"))
        righe = run_axis(ax, a.repeat, a.trials, out_dir,
                         write=not e_campagna, lookups=a.lookups)
        if e_campagna:
            campagna += righe
    if campagna and out_dir:
        os.makedirs(out_dir, exist_ok=True)
        _give_back(out_dir)
        _write_csv(os.path.join(out_dir, CAMPAIGN_CSV), campagna)

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(" Grafici (non serve root, basta matplotlib):")
    print(f"   python3 ipa/test/bench_scaling.py --plot {out_dir}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
