#!/usr/bin/env python3
"""model_population.py -- the population of synthetic models every measurement
runs on.

Five families in ipa/synth/population/: base (input layouts x depths x
widths), replica (same shapes, other seeds), sparsita (weights at zero),
imbuto (same weights, 1-5 layers), strati (1-6 layers, same multiplications).
The manifest population.csv lists every model and the subsets the long tests
use.

    python3 ipa/test/model_population.py               # generate
    python3 ipa/test/model_population.py --list        # folders, one per line
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


# --- input layouts ---
def _ttl():
    return FeatureSpec("ttl", "real", lo=1, hi=INITIAL_TTL, scale=INITIAL_TTL,
                       code=0x03)


def _link(k):
    return FeatureSpec("link_state", "binary", size=k, min_ones=1, code=0x01)


def _queues(k):
    return FeatureSpec("queue_occupancy", "binary", size=k, code=0x05)


def _iface(k):
    return FeatureSpec("ingress_iface", "onehot", size=k, code=0x02)


def _node(k):
    return FeatureSpec("node", "onehot", size=k, code=0x04)


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

ISOPARAM_DIMS = {1: (8,), 2: (8, 4), 3: (8, 3, 3), 4: (7, 5, 5, 5),
                 5: (7, 4, 4, 4, 4)}
ISOPARAM_LAYOUTS = ("ipa65", "dense17")
STRATI_MAC = 108
STRATI_DIMS = {
    "dense17": (5, [(5,), (5, 2), (5, 2, 2), (4, 3, 3, 3),
                    (3, 3, 3, 3, 3), (3, 3, 3, 3, 3, 3)]),
    "mixed33": (5, [(7,), (7, 3), (5, 4, 4), (4, 4, 4, 4),
                    (5, 3, 3, 3, 3), (7, 2, 2, 2, 2, 2)]),
    "ipa65": (4, [(8,), (8, 3), (6, 4, 4), (8, 2, 2, 2),
                  (8, 2, 2, 2, 2), (5, 3, 3, 3, 3, 3)]),
}

REPLICA_CONFIGS = [("dense5", 1, 2), ("ipa17", 2, 4), ("mixed33", 3, 4),
                   ("ipa65", 2, 8), ("onehot105", 4, 8), ("dense17", 6, 8)]
REPLICA_SEEDS = 3
SPARSE_CONFIGS = [("ipa65", 2, 4), ("dense17", 2, 8), ("mixed33", 4, 4),
                  ("ipa117", 1, 8)]
SPARSITIES = (0.5, 0.9)

SUBSETS = {
    "carico":  (4,   6,   8),
    "lpe":     (6,   14,  20),
    "core2":   (4,   8,   10),
    "classi":  (4,   8,   10),
    "mix":     (6,   12,  16),
    "taglie":  (3,   6,   8),
}
PROXY_PER_LAYER = 150


# --- the design ---
def _n_out(li, si):
    return N_OUTS[(li + si) % len(N_OUTS)]


def design(tier="base"):
    """[dict] of the models to generate, in a stable order."""
    if tier not in TIERS:
        raise ValueError(f"tier {tier!r}: valid {TIERS}")
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
        for lay, (n_out, forms) in STRATI_DIMS.items():
            for dims in forms:
                add("strati", lay, dims, n_out)
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


# --- model quantities the report uses as variables ---
def describe(spec, weights_int=None):
    """Shape, MACs and zero weights of the model."""
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


# --- generation ---
TRAFFIC_TTL = 32


def _forwards(d):
    """Does the model in `d` forward the generator's packet in at least one
    link state?"""
    import itertools
    import model_source as ms
    import pipeline_setup as PS
    import test_forwarding as TF
    topo = os.path.join(d, TOPOLOGY_FILE)
    topo = topo if os.path.exists(topo) else None
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


def _quiet():
    return contextlib.redirect_stdout(io.StringIO())


def _generate_one(entry, root, force):
    from synth.generate import generate_scenario
    d = folder_of(entry, root)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, TOPOLOGY_FILE), "w") as f:
        json.dump(_topology(entry), f, indent=2)
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
                raise RuntimeError(f"{entry['id']}: no seed between "
                                   f"{entry['seed0']} and {seed} forwards the "
                                   f"generators' packet")
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
    """Subsets of the base family, at the quantiles of the estimated cost."""
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
                  f"{r['shape']:22s} {r['weights']:5d} weights  MAC "
                  f"{r['mac_exec']:4d}/{r['mac_shape']:4d}  classes "
                  f"{r['classes_reached']}  seed {r['seed']}"
                  + (f" (+{r['seed_retries']})" if r["seed_retries"] else "")
                  + (f"  [not for {', '.join(nope)}]" if nope else ""))
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
                    help="regenerate also the folders already present")
    ap.add_argument("--list", action="store_true",
                    help="print the folders (from the manifest), one per line")
    ap.add_argument("--subset", choices=list(SUBSETS), default=None,
                    help="with --list: only the models of one subset")
    ap.add_argument("--family", default=None,
                    help="with --list: only one family (base, replica, "
                         "sparsita, imbuto, strati)")
    ap.add_argument("--manifest", metavar="CSV", default=None,
                    help="copy the manifest here (next to the results)")
    a = ap.parse_args(argv)
    if a.list:
        rows = read_manifest()
        if not rows:
            sys.exit("no manifest: generate the population first")
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
            sys.exit("no manifest: generate the population first")
        os.makedirs(os.path.dirname(os.path.abspath(a.manifest)),
                    exist_ok=True)
        shutil.copyfile(src, a.manifest)
        return
    rows = generate(a.tier, force=a.force)
    fam = {}
    for r in rows:
        fam[r["family"]] = fam.get(r["family"], 0) + 1
    print(f"\n{len(rows)} models ({', '.join(f'{k} {v}' for k, v in fam.items())}); "
          f"manifest in {os.path.relpath(os.path.join(ROOT, MANIFEST))}")
    for name in SUBSETS:
        ids = [r["id"] for r in rows if r[f"sub_{name}"]]
        print(f"  subset {name:7s} {len(ids):3d}: {' '.join(ids)}")


if __name__ == "__main__":
    main()
