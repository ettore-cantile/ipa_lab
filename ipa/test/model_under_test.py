"""model_under_test.py -- the --model and --topology options shared by tests and
benches (or $IPA_MODEL / $IPA_TOPOLOGY_CONFIG for a child process).
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
RETVALS = {"FORWARD": frozenset({XDP_ABORTED, XDP_REDIRECT}),
           "DROP": frozenset({XDP_DROP}),
           "UNUSED": frozenset({XDP_PASS})}

_cache = {}


def add_args(parser):
    parser.add_argument(
        "--model", default=None,
        help="model: checkpoint, checkpoint:<file.pt>, synth:<preset> "
             "(ipa_like, deep, ...), a directory, or a .pt. Without it: the "
             "configured checkpoint, through the default path")
    parser.add_argument(
        "--topology", default=None,
        help="scenario (network): a name in topologies/ or a "
             "topology_config.json. Without it: the scenario compatible with "
             "the model (germany50 if it is)")


def select(model_arg=None, topology_arg=None, quiet=False):
    """Resolve --model/--topology, export them for child processes, and return
    the active Model -- or None when neither was given (or --model is the
    configured checkpoint's own .pt, which is the same thing)."""
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
        ref = os.path.abspath(ref)
    try:
        topo = _choose_topology(ref, topology_arg)
        m = ms.load_model(ref, topology=topo)
    except ms.ModelError as e:
        sys.exit(f"[model] {e}")
    why = ms.mismatches(m, topo)
    if why:
        sys.exit(f"[model] {m.name} is not compatible with scenario "
                 f"{topo['topology']}:\n  " + "\n  ".join(why))
    os.environ[ENV_MODEL] = ref
    os.environ[ENV_TOPOLOGY] = topo["_path"]
    mm.reset_topology_announcements()
    _cache.clear()
    if not quiet:
        print(f"[model] {m.name}: {m.describe()}")
        print(f"[model] scenario {topo['topology']}: "
              f"{topo['n_interfaces']} interfaces, {topo['n_nodes']} nodes, "
              f"{topo.get('n_queues', '-')} queues, initial TTL "
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
            f"no scenario in topologies/ is compatible with {ref}: "
            f"create one with the model's dimensions, or pass --topology")
    for t in fits:
        if t["topology"] == "germany50":
            return t
    if len(fits) > 1:
        raise ms.ModelError(
            f"several scenarios compatible with {ref} "
            f"({', '.join(t['topology'] for t in fits)}): choose with "
            f"--topology")
    return fits[0]


def active():
    """The model under test, or None (the default checkpoint path)."""
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
