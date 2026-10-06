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

L'asse dei nodi resta a BPF_PROG_TEST_RUN: sotto traffico servirebbe una rete
diversa per punto, e il ppt mostra gia' che la taglia della rete non cambia
il lavoro per pacchetto.

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

from synth.spec import ModelSpec, ipa_feature_set  # noqa: E402
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

AXES = {
    "width": [(v, dict(hidden=[v, v])) for v in (2, 4, 6, 8)],
    "depth": [(d, dict(hidden=[4] * d)) for d in range(1, 7)],
    "isoparam": [(k, dict(hidden=list(v))) for k, v in ISOPARAM_DIMS.items()],
    "sparsity": [(p, dict(hidden=[4, 4], weight_init="sparse",
                          sparsity=p / 100.0)) for p in (0, 50, 90)],
}


def spec_of(axis, point, kw, seed=SEED):
    return ModelSpec(f"traffic_{axis}_{point}", ipa_feature_set(6, 52, 30),
                     n_out=7, seed=seed, drop_class=6, **kw)


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
    m = ms.load_model(d)
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
    for axis in axes or AXES:
        for point, kw in AXES[axis]:
            d = path_of(axis, point)
            have = os.path.exists(os.path.join(d, "model.json"))
            seed = SEED
            if have and not force and forwards(d):
                import json
                with open(os.path.join(d, "model.json")) as f:
                    seed = json.load(f).get("seed", SEED)
            else:
                for seed in range(SEED, SEED + MAX_SEED_TRIES):
                    with contextlib.redirect_stdout(io.StringIO()):
                        generate_scenario(spec_of(axis, point, kw, seed), d,
                                          n_inputs=300)
                    if forwards(d):
                        break
                else:
                    raise RuntimeError(f"{axis}_{point}: nessun seme fra "
                                       f"{SEED} e {seed} inoltra il "
                                       f"pacchetto dei generatori")
            spec = spec_of(axis, point, kw, seed)
            out.append((axis, point, d, spec.shape_str, spec.weight_count(),
                        seed))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--list", choices=list(AXES), default=None,
                    help="stampa solo le cartelle di un asse, una per riga")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
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
