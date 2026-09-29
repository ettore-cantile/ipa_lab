"""
model_under_test.py -- which model, on which network, a test or a bench runs.

    --model REF      checkpoint | checkpoint:<file.pt> | synth:<preset> |
                     <directory> | <file.pt>   (see model_source.py)
    --topology NAME  a scenario under topologies/, or a topology_config.json

or, for a child process, the same through $IPA_MODEL and $IPA_TOPOLOGY_CONFIG.

With neither given nothing is active, and every hook in verify_prog_run
returns None: the configured checkpoint runs through the historical code
paths, byte for byte. With one given, the model is loaded by model_source,
checked against the network (feature widths, initial TTL) BEFORE anything is
compiled, and verify_prog_run's load_weights / setup_* / ref_infer /
count_lookups answer for it through pipeline_setup.

`--model checkpoint` is not the same as no --model: it sends the checkpoint
through the new path, which is how that path is checked against the old one.
"""
import os
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import model_source as ms  # noqa: E402

ENV_MODEL = "IPA_MODEL"
ENV_TOPOLOGY = "IPA_TOPOLOGY_CONFIG"

XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT = 0, 1, 2, 3, 4
# What the pipelines return for each action (see the class_action lookup in
# the eBPF sources): a redirect -- 0 is what bpf_redirect reports under
# BPF_PROG_TEST_RUN -- XDP_DROP, and XDP_PASS for a class declared UNUSED.
RETVALS = {"FORWARD": frozenset({XDP_ABORTED, XDP_REDIRECT}),
           "DROP": frozenset({XDP_DROP}),
           "UNUSED": frozenset({XDP_PASS})}

_cache = {}


def add_args(parser):
    parser.add_argument(
        "--model", default=None,
        help="modello: checkpoint, checkpoint:<file.pt>, synth:<preset> "
             "(ipa_like, deep, ...), una cartella, o un .pt. Senza: il "
             "checkpoint configurato, per la strada di sempre")
    parser.add_argument(
        "--topology", default=None,
        help="scenario (rete): un nome in topologies/ o un "
             "topology_config.json. Senza: lo scenario compatibile con il "
             "modello (germany50 se lo e')")


def select(model_arg=None, topology_arg=None, quiet=False):
    """Resolve --model/--topology, export them for child processes, and
    return the active Model -- or None when neither was given (or --model is
    the configured checkpoint's own .pt, which is the same thing).

    Exits with the reason if the model does not fit the network."""
    import model_meta as mm
    ref = model_arg
    if ref and ref.endswith(".pt"):
        same = os.path.abspath(ref) == os.path.abspath(mm.default_checkpoint())
        ref = None if same else "checkpoint:" + os.path.abspath(ref)
    if ref is None and topology_arg is None:
        os.environ.pop(ENV_MODEL, None)
        return None
    ref = ref or "checkpoint"
    if os.path.isdir(ref):
        ref = os.path.abspath(ref)       # a child process may run elsewhere
    try:
        topo = _choose_topology(ref, topology_arg)
        m = ms.load_model(ref, topology=topo)
    except ms.ModelError as e:
        sys.exit(f"[modello] {e}")
    why = ms.mismatches(m, topo)
    if why:
        sys.exit(f"[modello] {m.name} non e' compatibile con lo scenario "
                 f"{topo['topology']}:\n  " + "\n  ".join(why))
    os.environ[ENV_MODEL] = ref
    os.environ[ENV_TOPOLOGY] = topo["_path"]
    mm.reset_topology_announcements()
    _cache.clear()
    if not quiet:
        print(f"[modello] {m.name}: {m.describe()}")
        print(f"[modello] scenario {topo['topology']}: "
              f"{topo['n_interfaces']} interfacce, {topo['n_nodes']} nodi, "
              f"{topo.get('n_queues', '-')} code, TTL iniziale "
              f"{topo.get('initial_ttl', '-')}")
    return m


def _choose_topology(ref, topology_arg):
    if topology_arg:
        return ms.load_topology(topology_arg)
    fits = []
    for name in ms.list_topologies():
        topo = ms.load_topology(name)
        try:
            m = ms.load_model(ref, topology=topo)
        except ms.ModelError:
            continue
        if not ms.mismatches(m, topo):
            fits.append(topo)
    if not fits:
        raise ms.ModelError(
            f"nessuno scenario in topologies/ e' compatibile con {ref}: "
            f"creane uno con le dimensioni del modello, o passa --topology")
    for t in fits:
        if t["topology"] == "germany50":
            return t
    if len(fits) > 1:
        raise ms.ModelError(
            f"piu' scenari compatibili con {ref} "
            f"({', '.join(t['topology'] for t in fits)}): scegli con "
            f"--topology")
    return fits[0]


def active():
    """The model under test, or None (the historical checkpoint path)."""
    ref = os.environ.get(ENV_MODEL)
    if not ref:
        return None
    key = (ref, os.environ.get(ENV_TOPOLOGY))
    if key not in _cache:
        topo = active_topology()
        _cache[key] = ms.load_model(ref, topology=topo)
    return _cache[key]


def active_topology():
    p = os.environ.get(ENV_TOPOLOGY)
    return ms.load_topology(p) if p else None


def expected_retvals(model, cls):
    """What the program must return after deciding `cls`."""
    return RETVALS[model.semantics.action_of(cls)]


def initial_ttl(model):
    f = model.feature("ttl")
    return int(f["scale"]) if f else 30
