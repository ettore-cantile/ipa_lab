#!/usr/bin/env python3
"""traffic_models.py -- i modelli degli assi parametrici, da misurare sotto
traffico vero.

bench_scaling misura larghezza, profondita', pari pesi e sparsita' sotto
BPF_PROG_TEST_RUN (il programma da solo). Qui gli stessi punti diventano
cartelle di modello sintetico (ipa/synth, model.json + weights.json) che
bench_throughput carica con `--model <cartella>`: stesso descrittore del
checkpoint (link_state 6, ingress_iface 6, ttl/30, node 52), 7 classi con la
DROP sull'ultima, quindi compatibili con Germany50 senza --topology.

Gli assi, con i punti di bench_scaling.AXES:

    width     65-v-v-7, v = 2, 4, 6, 8   (8: soffitto compilato di P2 e P3)
    depth     65-4x d-7, d = 1..6
    isoparam  le cinque forme a ~592 pesi (bench_scaling.ISOPARAM_DIMS)
    sparsity  65-4-4-7 con il 0 / 50 / 90 % dei pesi a zero (i bias no)
    nodes     (13+n)-4-4-7, rete di n = 10, 25, 52, 75, 100 nodi: cambia solo
              la larghezza della one-hot che identifica il nodo
    iv_dense  n-8-8-7, n = 5, 9, 13, 17: link_state(k) + queue_occupancy(k) +
              ttl, k = 2, 4, 6, 8; ogni colonna costa h1 moltiplicazioni
    iv_onehot n-8-8-7, n = 16, 32, 65: node(n-5) + ttl + queue_occupancy(4);
              la one-hot costa h1 addizioni a ogni taglia. bench_scaling
              allarga ingress_iface, ma una rete con piu' di 8 interfacce
              sfonda IPA_MAX_IFACES e non si puo' cablare sul fabric: la
              one-hot del nodo e' la stessa aritmetica (un arm, h1
              addizioni) su una rete valida

I primi quattro usano la rete del checkpoint (Germany50). Gli ultimi tre
hanno una rete diversa per punto: la cartella porta la sua
topology_config.json, che si passa al banco con --topology.

    python3 ipa/test/traffic_models.py                 # genera tutto, stampa
    python3 ipa/test/traffic_models.py --list depth    # le cartelle di un asse

Le cartelle vanno in ipa/synth/traffic/<asse>_<punto>/; si
rigenerano solo se mancano (--force per rifarle). Stesso seme per tutti i
punti, come bench_scaling, tranne dove quel seme da' un modello che il banco
non puo' misurare: il pacchetto di xdp_gen (TTL 32, nodo 7, porta 1) deve
essere INOLTRATO in almeno uno stato dei link (bench_throughput.
_forwarding_inputs), altrimenti le pipeline vengono saltate. Con pesi
casuali succede: il 2026-10-06 width_6, depth_4 e isoparam_3 al seme comune
decidevano DROP in tutti i 64 stati. Li' si prova il seme successivo, e il
seme usato si stampa.
"""
import argparse
import contextlib
import io
import os
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_SHARED = os.path.dirname(_TEST_DIR)
for _p in (_SHARED, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from synth.spec import (FeatureSet, FeatureSpec, ModelSpec,  # noqa: E402
                        ipa_feature_set)
from synth.generate import generate_scenario  # noqa: E402

# Fuori da synth/scenarios: verify_synth_kernel --all prende ogni cartella
# di li' come uno scenario (2026-10-06: FileNotFoundError su traffic/).
ROOT = os.path.join(_SHARED, "synth", "traffic")
SEED = 20261006

# Copiate da bench_scaling.ISOPARAM_DIMS (che importa BCC): stesse forme.
ISOPARAM_DIMS = {
    1: (8,),
    2: (8, 4),
    3: (8, 3, 3),
    4: (7, 5, 5, 5),
    5: (7, 4, 4, 4, 4),
}

INITIAL_TTL = 30


def _ttl():
    return FeatureSpec("ttl", "real", lo=1, hi=INITIAL_TTL, scale=INITIAL_TTL,
                       code=0x03)


def _queues(n):
    # "binary" solo per come si campionano gli ingressi di prova
    # (expected.json): il datapath legge queue_state per quello che vale, e
    # il costo per pacchetto non dipende dai valori.
    return FeatureSpec("queue_occupancy", "binary", size=n, code=0x05)


def _iv_dense(k):
    return FeatureSet([
        FeatureSpec("link_state", "binary", size=k, min_ones=1, code=0x01),
        _queues(k), _ttl()])


def _iv_onehot(k):
    return FeatureSet([
        FeatureSpec("node", "onehot", size=k, code=0x04),
        _ttl(), _queues(4)])


def _topo(name, n_interfaces=6, n_nodes=52, n_queues=4):
    return {"topology": name, "n_interfaces": n_interfaces,
            "n_nodes": n_nodes, "n_queues": n_queues,
            "initial_ttl": INITIAL_TTL}


# Un punto: (valore, kw di ModelSpec, feature, rete). feature None = il
# descrittore del checkpoint; rete None = Germany50, nessun file da scrivere.
AXES = {
    "width": [(v, dict(hidden=[v, v]), None, None) for v in (2, 4, 6, 8)],
    "depth": [(d, dict(hidden=[4] * d), None, None) for d in range(1, 7)],
    "isoparam": [(k, dict(hidden=list(v)), None, None)
                 for k, v in ISOPARAM_DIMS.items()],
    "sparsity": [(p, dict(hidden=[4, 4], weight_init="sparse",
                          sparsity=p / 100.0), None, None)
                 for p in (0, 50, 90)],
    "nodes": [(n, dict(hidden=[4, 4]), ipa_feature_set(6, n, INITIAL_TTL),
               _topo(f"traffic_nodes_{n}", n_nodes=n))
              for n in (10, 25, 52, 75, 100)],
    "iv_dense": [(2 * k + 1, dict(hidden=[8, 8]), _iv_dense(k),
                  _topo(f"traffic_iv_dense_{2 * k + 1}", n_interfaces=k,
                        n_queues=k))
                 for k in (2, 4, 6, 8)],
    "iv_onehot": [(n, dict(hidden=[8, 8]), _iv_onehot(n - 5),
                   _topo(f"traffic_iv_onehot_{n}", n_nodes=n - 5))
                  for n in (16, 32, 65)],
}
TOPOLOGY_FILE = "topology_config.json"


def spec_of(axis, point, kw, seed=SEED, features=None):
    return ModelSpec(f"traffic_{axis}_{point}",
                     features or ipa_feature_set(6, 52, INITIAL_TTL),
                     n_out=7, seed=seed, drop_class=6, **kw)


def topology_of(d):
    """La rete di una cartella: il suo topology_config.json, o None
    (Germany50)."""
    p = os.path.join(d, TOPOLOGY_FILE)
    return p if os.path.exists(p) else None


def path_of(axis, point):
    return os.path.join(ROOT, f"{axis}_{point}")


TRAFFIC_TTL = 32        # il TTL del pacchetto dei generatori (bench_throughput)
MAX_SEED_TRIES = 50


def forwards(d):
    """Il modello in `d` inoltra il pacchetto dei generatori in almeno uno
    stato dei link? Lo stesso controllo di bench_throughput._forwarding_inputs,
    con il riferimento Python (niente kernel)."""
    import itertools
    import model_source as ms
    import pipeline_setup as PS
    import test_fabric as TF
    topo = topology_of(d)
    m = ms.load_model(d, topology=ms.load_topology(topo) if topo else None)
    node = PS.node_index_for(m, TF.FABRIC_NODE_INDEX)
    slot = PS.ingress_slot_for(m, TF.FABRIC_INGRESS_SLOT)
    n_ls = {f["type"]: f["size"] for f in m.features}.get("link_state", 0)
    for ls in itertools.product([1, 0], repeat=n_ls):
        c, _ = PS.reference(m, TRAFFIC_TTL, link_state=list(ls) or None,
                            ingress_port=slot or 0, node_index=node)
        if m.semantics.action_of(c) == "FORWARD":
            return True
    return False


def generate(axes=None, force=False):
    """[(asse, punto, cartella, forma, pesi)] per gli assi chiesti."""
    out = []
    import json
    for axis in axes or AXES:
        for point, kw, feats, topo in AXES[axis]:
            d = path_of(axis, point)
            if topo is not None:
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, TOPOLOGY_FILE), "w") as f:
                    json.dump(topo, f, indent=2)
            have = os.path.exists(os.path.join(d, "model.json"))
            seed = SEED
            if have and not force and forwards(d):
                with open(os.path.join(d, "model.json")) as f:
                    seed = json.load(f).get("seed", SEED)
            else:
                for seed in range(SEED, SEED + MAX_SEED_TRIES):
                    with contextlib.redirect_stdout(io.StringIO()):
                        generate_scenario(spec_of(axis, point, kw, seed,
                                                  feats), d, n_inputs=300)
                    if forwards(d):
                        break
                else:
                    raise RuntimeError(f"{axis}_{point}: nessun seme fra "
                                       f"{SEED} e {seed} inoltra il "
                                       f"pacchetto dei generatori")
            spec = spec_of(axis, point, kw, seed, feats)
            out.append((axis, point, d, spec.shape_str, spec.weight_count(),
                        seed))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--list", choices=list(AXES), default=None,
                    help="stampa solo le cartelle di un asse, una per riga")
    ap.add_argument("--topology", metavar="CARTELLA", default=None,
                    help="stampa la rete di una cartella (il suo "
                         "topology_config.json), o niente se e' Germany50")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    if a.topology:
        t = topology_of(a.topology)
        if t:
            print(t)
        return
    if a.list:
        for _, _, d, _, _, _ in generate([a.list], a.force):
            print(d)
        return
    for axis, point, d, shape, nw, seed in generate(force=a.force):
        print(f"{axis:9s} {str(point):>3s}  {shape:16s} {nw:5d} pesi  "
              f"seme {seed}{'' if seed == SEED else ' (*)'}  "
              f"{os.path.relpath(d)}")


if __name__ == "__main__":
    main()
