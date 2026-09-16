# Experiment: Kathara + Germany50

The concrete environment the IPA engine has been evaluated on. Everything that
is true only of *this* setup lives here; nothing under [`ipa/`](../../ipa/)
imports anything from this directory.

## What belongs here, and why

| | |
|---|---|
`germany50.xml` | SNDlib topology, 50 backbone routers / 88 links ([sndlib.zib.de](http://sndlib.zib.de/)) |
`topology_config.json` | **The scenario's dimensions**: `n_interfaces=6`, `n_nodes=52`, `n_queues=4` |
`scenario.json` | Host attachment points, image, traffic defaults, initial TTL |
`genera_lab.py` | Emits `lab/lab.conf` + one `lab/<node>.startup` from the XML |
`importSNDLib.py` | Loads the XML into NetworkX, for topology statistics |
`make_lab.py` | Assembles `lab/shared/` (the `/shared` mount) from the core |
`Dockerfile` | The `kathara/frr_ebpf` image (FRR + BCC + eBPF headers) |
`host_setup/` | `fix_bpf.sh`, `fetch_host_headers.sh`, `install_headers.sh` |
`traffic/` | `send_ipa.py`, `recv_ipa.py`, `test_ipa.py`, `test_kathara_send_recv.sh` |
`lab/` | **Generated, not tracked.** `lab.conf`, `<node>.startup`, and an assembled `shared/` |

`lab/` used to be 53 committed files (`lab.conf` + 52 `<node>.startup`, 5.5 MB).
They are byte-identical output of `genera_lab.py` reading `germany50.xml`, so
they are now gitignored. A fresh clone runs the two generator steps below.

## The 6 and the 52

These two numbers used to be `DEFAULT_TOPOLOGY_CONFIG` inside the engine, applied
to any caller that supplied nothing. They are properties of this topology:

- `n_nodes = 52` — 50 SNDlib routers, plus `h_src` and `h_dst`.
- `n_interfaces = 6` — the **largest node degree** in the network, not any
  node's own degree. Bare Germany50 tops out at 5; attaching `h_src` to
  Karlsruhe makes it the unique degree-6 node. Every other node pads the unused
  `link_state` slots with zeros.

Change `scenario.json`'s `hosts` and `n_interfaces` may change with them. The
engine reads these from `topology_config.json` (or `$IPA_TOPOLOGY_CONFIG`, or
the model descriptor's `trained_on` block) and has no fallback of its own — a
missing config raises `ScenarioError` naming the three places it looked.

## Running it

```bash
cd experiments/kathara_germany50

python3 genera_lab.py            # lab/lab.conf + lab/<node>.startup
python3 make_lab.py              # lab/shared/  <- copied from ../../ipa
cd lab && kathara lstart         # 52 nodes; FRR/OSPF converges in ~90 s
```

`make_lab.py` copies rather than symlinks, and `lab/shared/` is regenerated
from scratch each run. **Edit the core in `ipa/`, never in `lab/shared/`** —
the next `make_lab.py` overwrites it.

BCC on the nodes compiles against the *host's* kernel headers:

```bash
bash host_setup/fetch_host_headers.sh        # on the Linux host, once
python3 make_lab.py --link-headers <tree>    # place them at lab/shared/host_headers
```

Deploy the scenario config to each node (the startups can do this, or copy by
hand to `/etc/ipa/topology_config.json`); without it the engine falls back to
the descriptor's `trained_on` block, which for the checked-in checkpoint holds
the same 6/52.

## Attaching a pipeline and sending traffic

```bash
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method template --iface eth1
kathara exec frankfurt -- python3 /shared/recv_ipa.py
kathara exec darmstadt -- python3 /shared/send_ipa.py --dst frankfurt --count 100
bash traffic/test_kathara_send_recv.sh 20 template 42
```

`darmstadt`/`frankfurt` are `scenario.json` defaults for the traffic scripts,
not engine constants.

## Why this is an experiment and not the project

Kathara mounts a directory named `shared/` in the lab root at `/shared` in every
machine. That convention is what used to pin the whole engine at
`<repo>/shared/`: the emulator's layout dictated the project's. `make_lab.py`
inverts it — the core sits in `ipa/`, and this experiment copies what it needs
into its own mount. The dependency now points one way only, and that is
checkable:

```bash
grep -rn "kathara\|germany50\|genera_lab\|importSNDLib" ipa/ --include=*.py
```

should return only prose — comments recording what was removed — never an
import or a path.

## Not verified here

`kathara lstart` has not been run against this layout. The assembly step
(`make_lab.py`) is verified; the lab boot is not, and needs one run on the Linux
host. The generated `lab.conf` and `<node>.startup` files are byte-identical to
the ones previously committed at the repo root, and the startups still reference
`/shared/fix_bpf.sh`, which `make_lab.py` places.
