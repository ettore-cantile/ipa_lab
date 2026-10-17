#!/usr/bin/env python3
"""
verify_model_swap.py -- che cosa vedono i pacchetti mentre P2 o P3 cambiano
modello, e quanto costa installarne uno.

    sudo python3 ipa/test/verify_model_swap.py                 # P2 e P3
    sudo python3 ipa/test/verify_model_swap.py --pipeline modular --seconds 5

Due modi di cambiare il modello A con il modello B su un nodo in servizio:

  riscrittura al posto   le tabelle di A riscritte con B allo stesso
                         model_id (register_model_id). Pesi, forme e
                         descrizione cambiano una tabella alla volta: un
                         pacchetto a meta' puo' vedere un modello misto.
  make-before-break      B installato sotto un model_id nuovo, in una zona
                         libera dei pesi, con il registro scritto per ultimo
                         (install_model); poi il mittente passa al nuovo id;
                         poi il vecchio si ritira (retire_model).

Un thread esegue il programma di continuo su un core (BPF_PROG_TEST_RUN, un
pacchetto per chiamata, gli ingressi del traffico), un altro cambia il modello
su un altro core, per --seconds secondi. Alla fine si contano le decisioni:
quelle di A, quelle di B, e le ALTRE -- una classe che ne' A ne' B darebbero a
quel pacchetto, o un pacchetto non elaborato (XDP_PASS) mentre il suo id era
registrato. Le altre sono i pacchetti che hanno visto un modello misto.
Con make-before-break devono essere zero; un pacchetto con un id appena
ritirato e' contato a parte (non elaborato, mai calcolato a meta').

In piu', in un processo nuovo, il tempo di registrare un modello la prima
volta e le volte dopo sullo stesso programma: la prima paga il piano di
controllo che si prepara (oggetti delle tabelle, moduli Python), non il
kernel.

Serve root (carica programmi eBPF). Esce con 1 se make-before-break mostra
anche un solo pacchetto misto.
"""
import argparse
import ctypes as ct
import json
import os
import subprocess
import sys
import threading
import time

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

XDP_PASS, XDP_DROP, XDP_REDIRECT = 2, 1, 4
POP = os.path.join(SHARED_DIR, "synth", "population")


# --------------------------------------------------------------------------
# i due modelli
# --------------------------------------------------------------------------
def load(d):
    import contextlib
    import io
    import model_source as ms
    with contextlib.redirect_stdout(io.StringIO()):
        return ms.load_model(d, topology=ms.load_topology(d))


def inputs_of(PS, model):
    """Lo stato dei link che fa inoltrare `model` al pacchetto del traffico
    (TTL 32, nodo e porta del fabric), e la classe che decide."""
    import itertools
    import test_fabric as TF
    import bench_throughput as BT
    node = PS.node_index_for(model, TF.FABRIC_NODE_INDEX)
    slot = PS.ingress_slot_for(model, TF.FABRIC_INGRESS_SLOT)
    n_ls = {f["type"]: f["size"] for f in model.features}.get("link_state", 0)
    for ls in [[1] * n_ls] + [list(b) for b in
                              itertools.product([1, 0], repeat=n_ls)]:
        c, _ = PS.reference(model, BT.TRAFFIC_TTL, link_state=ls or None,
                            ingress_port=slot or 0, node_index=node)
        if model.semantics.action_of(c) == "FORWARD":
            return ls, node, slot, c
    return None


def pick_pair(pipeline):
    """Due modelli della popolazione con la stessa composizione
    dell'ingresso e la stessa profondita' (P2 e' compilata per una), larghezze
    diverse, e classi diverse per lo stesso pacchetto: cosi' un modello misto
    ha buone probabilita' di decidere una terza classe, e si vede."""
    import csv
    import pipeline_setup as PS
    import pipeline_limits
    rows = list(csv.DictReader(open(os.path.join(POP, "population.csv"))))
    rows = [r for r in rows if r["family"] in ("base", "replica")
            and int(r["weights"]) <= 450]
    for a in rows:
        for b in rows:
            if (a["id"] >= b["id"] or a["layout"] != b["layout"]
                    or a["depth"] != b["depth"] or a["hidden"] == b["hidden"]):
                continue
            da = os.path.join(SHARED_DIR, "..", a["folder"])
            A = load(da)
            B = load(os.path.join(SHARED_DIR, "..", b["folder"]))
            if any(pipeline_limits.why_not(pipeline, M.hidden, M.n_in, M.n_out)
                   for M in (A, B)):
                continue
            ia = inputs_of(PS, A)
            if not ia:
                continue
            ls, node, slot, ca = ia
            import bench_throughput as BT
            cb, _ = PS.reference(B, BT.TRAFFIC_TTL, link_state=ls or None,
                                 ingress_port=slot or 0, node_index=node)
            if cb != ca:
                return A, B, (ls, node, slot, ca, cb), da
    raise SystemExit("nessuna coppia di modelli adatta nella popolazione")


# --------------------------------------------------------------------------
# il programma che gira, e il modello che cambia
# --------------------------------------------------------------------------
def counters(setup, n=16):
    from stats_maps import read_counter
    cs = setup["cls_stats"]
    return [read_counter(cs, k) for k in range(min(n, len(cs)))]


def run(pipeline, A, B, inputs, mode, seconds, cpu_r, cpu_w):
    import pipeline_setup as PS
    import verify_prog_run as V
    from verify_prog_run import prog_test_run, build_frame_sparse
    ls, node, slot, ca, cb = inputs
    setup = PS.build(pipeline, A)
    PS.set_node(setup, node)
    PS.set_ingress(setup, V.TEST_RUN_DEFAULT_INGRESS_IFINDEX, slot)
    PS.seed_inputs(setup, link_state=ls or None)
    fd = setup["disp"].fd

    frames = {}

    def frame(mid, M):
        # per (id, modello): nel make-before-break gli id 0 e 1 passano
        # alternativamente da A a B
        k = (mid, M.name)
        if k not in frames:
            frames[k] = build_frame_sparse(model_id=mid, ttl=32,
                                           scale=M.scale, n_in=M.n_in,
                                           n_out=M.n_out)
        return frames[k]

    # (id, modello) in UNA variabile: il lettore li prende insieme, come un
    # mittente che scrive un id nel pacchetto
    state = dict(cur=(0, A), stop=False)
    rets = {}
    retired_pass = [0]
    live = {0}

    def reader():
        os.sched_setaffinity(0, {cpu_r})
        while not state["stop"]:
            mid, M = state["cur"]
            r, _ = prog_test_run(fd, frame(mid, M), repeat=1)
            if r == XDP_PASS and mid not in live:
                retired_pass[0] += 1
            else:
                rets[r] = rets.get(r, 0) + 1

    changes = [0]

    def writer():
        os.sched_setaffinity(0, {cpu_w})
        t_end = time.time() + seconds
        cur_id, cur_M, other = 0, A, B
        while time.time() < t_end:
            if mode == "al posto":
                PS.register_model_id(setup, 0, other, offset=0)
                cur_M, other = other, cur_M
            else:
                new_id = 1 - cur_id
                PS.install_model(setup, other, new_id)
                live.add(new_id)
                state["cur"] = (new_id, other)             # il mittente passa
                time.sleep(0.0005)                         # i pacchetti in volo
                live.discard(cur_id)
                PS.retire_model(setup, cur_id)
                cur_id, cur_M, other = new_id, other, cur_M
            changes[0] += 1
        state["stop"] = True

    import contextlib
    import io
    before = counters(setup)
    tr, tw = threading.Thread(target=reader), threading.Thread(target=writer)
    with contextlib.redirect_stdout(io.StringIO()):      # i print dei loader
        tr.start()
        tw.start()
        tw.join()
        tr.join()
    after = counters(setup)
    cls = {k: a - b for k, (a, b) in enumerate(zip(after, before)) if a - b}
    n = sum(rets.values())
    expected = cls.get(ca, 0) + cls.get(cb, 0)
    classified = sum(cls.values())
    other_cls = classified - expected
    passed = rets.get(XDP_PASS, 0)
    return dict(pipeline=pipeline, mode=mode, packets=n, changes=changes[0],
                class_a=ca, class_b=cb, classes=cls, mixed=other_cls + passed,
                other_class=other_cls, not_processed=passed,
                retired_id_pass=retired_pass[0])


# --------------------------------------------------------------------------
# prima e seconda registrazione, in un processo nuovo
# --------------------------------------------------------------------------
def _timing_child(pipeline, d):
    """Gira nel processo figlio: compila la pipeline SENZA registrare
    modelli, poi registra lo stesso modello tre volte (id 0, 1, 2, zone
    diverse) e stampa i tre tempi in ms."""
    import contextlib
    import io
    from bcc import BPF
    M = load(d)
    if pipeline == "template":
        from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                        build_arch_leaf, load_arch_weights)
        b = BPF(text="#define IPA_ARCH_COMBINED 1\n"
                + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n"
                + build_arch_leaf(len(M.hidden)))
        b.load_func("ipa_switch_template", BPF.XDP)
        b.load_func("arch_generic_2layer", BPF.XDP)
        h = M.hidden

        def reg(i):
            load_arch_weights(b, M.weights, model_id=i,
                              weight_offset=i * len(M.weights),
                              scale=M.scale, n_h1=h[0],
                              n_h2=h[1] if len(h) > 1 else h[0],
                              features=M.features, n_in=M.n_in,
                              semantics=M.semantics, n_hidden=len(h))
    else:
        from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
        b = BPF(text=EBPF_MODULAR_FULL)
        for f in ("modular_dispatcher", "layer_first", "layer_hidden"):
            b.load_func(f, BPF.XDP)

        def reg(i):
            load_modular_weights(b, M.weights, model_id=i,
                                 base_offset=i * len(M.weights),
                                 scale=M.scale, layer_dims=M.layer_dims,
                                 features=M.features, semantics=M.semantics)
    out = []
    for i in range(3):
        t0 = time.perf_counter()
        with contextlib.redirect_stdout(io.StringIO()):
            reg(i)
        out.append((time.perf_counter() - t0) * 1000.0)
    print(json.dumps(out))


def timing(pipeline, d):
    r = subprocess.run([sys.executable, os.path.abspath(__file__),
                        "--_timing", pipeline, d],
                       capture_output=True, text=True)
    last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    try:
        return json.loads(last)
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--pipeline", default="all",
                   choices=("template", "modular", "all"))
    p.add_argument("--seconds", type=float, default=3.0)
    p.add_argument("--cpu-reader", type=int, default=6)
    p.add_argument("--cpu-writer", type=int, default=8)
    p.add_argument("--out", default=None, help="scrive swap.json qui")
    p.add_argument("--_timing", nargs=2, help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    if a._timing:
        _timing_child(*a._timing)
        return 0
    if os.geteuid() != 0:
        sys.exit("serve root: sudo python3 ipa/test/verify_model_swap.py")
    pipes = ("template", "modular") if a.pipeline == "all" else (a.pipeline,)
    results, ok = [], True
    for pl in pipes:
        A, B, inputs, folder_a = pick_pair(pl)
        print(f"\n== {pl}: A = {A.name} ({A.describe()}),\n"
              f"   B = {B.name} ({B.describe()}); classe di A {inputs[3]}, "
              f"di B {inputs[4]} per lo stesso pacchetto")
        for mode in ("al posto", "make-before-break"):
            r = run(pl, A, B, inputs, mode, a.seconds, a.cpu_reader,
                    a.cpu_writer)
            results.append(r)
            print(f"  {mode:18s} {r['packets']:>9} pacchetti, "
                  f"{r['changes']:>5} cambi: classi {r['classes']}; "
                  f"misti {r['mixed']} (classe estranea {r['other_class']}, "
                  f"non elaborati {r['not_processed']}); id appena ritirato "
                  f"{r['retired_id_pass']}")
            if mode == "make-before-break" and r["mixed"]:
                ok = False
        t = timing(pl, folder_a)
        if t:
            print(f"  registrare lo stesso modello in un processo nuovo: "
                  f"1a {t[0]:.2f} ms, 2a {t[1]:.2f} ms, 3a {t[2]:.2f} ms")
            results.append(dict(pipeline=pl, mode="registrazione",
                                ms=t))
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "swap.json"), "w") as f:
            json.dump(results, f, indent=1)
    print("\nmake-before-break: " + ("nessun pacchetto misto" if ok else
                                     "PACCHETTI MISTI, vedi sopra"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
