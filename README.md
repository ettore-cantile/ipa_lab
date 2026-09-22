# IPA Lab — Intelligent PAckets with eBPF

This repository contains the lab implementation of **Intelligent PAckets (IPA)** with an eBPF-accelerated data plane, verified on a real Linux kernel datapath. The goal is to embed compact machine learning models directly inside packet headers and execute per-hop inference to achieve adaptive, mission-driven forwarding decisions — without any control-plane signaling.

The work extends the original proof-of-concept by Polverini, Cianfrani, and Listanti (Sapienza University of Rome / University of Molise) with a kernel-space eBPF/XDP forwarding engine that performs MLP inference at line rate.

---

## Background: Intelligent PAckets (IPA)

IPA is a packet-centric networking paradigm in which a lightweight ML model is serialized, quantized to 8-bit integers, and embedded directly in the packet header. At each hop, the receiving node:

1. **Parses** the IPA header and extracts the model weights.
2. **Builds** an input vector from local state: `model_id`, `ip->ttl`, `ingress_ifindex`, `input_size`.
3. **Runs inference** to compute a forwarding key via integer dot-product.
4. **Forwards** the packet without any interaction with a centralized controller.

This approach allows the network to react to changing conditions purely in the data plane. Different missions (e.g., failure recovery, deadline-constrained delivery, congestion management) can be associated with different models embedded in the packet header, enabling per-packet adaptive behavior without requiring operators to reconfigure forwarding rules or tunnels.

---

## Topology: Germany50

The experimental setup uses the **Germany50** topology from the [SNDlib repository](http://sndlib.zib.de/), a real-world backbone network with:

| Property | Value |
|---|---|
| Backbone routers | 50 |
| End hosts | 2 (`h_src`, `h_dst`) |
| Nodes in the emulated lab | **52** |
| Links | 90 (88 backbone + 2 access) |
| Max node degree | **6** (`karlsruhe`, interfaces `eth0`..`eth5`) |
| Source host | `h_src` attached to **Karlsruhe** |
| Destination host | `h_dst` attached to **Flensburg** |
| Max simultaneous failures | 10 |

> **Why 52 and 6, and why they are not arbitrary.** The checked-in checkpoint is
> trained with `n_interfaces=6` and `n_nodes=52`, which is where its input width
> comes from: `N_IN = 6 + 6 + 1 + 52 = 65`, `n_out = 6 + 1 = 7`. Both numbers are
> properties of the topology the model was trained on, which
> `importSNDLib.load_sndlib_topology()` builds as the 50 SNDlib routers **plus
> the two end hosts**:
>
> ```python
> load_sndlib_topology('germany50.xml',
>                      attach_h_src_to='Karlsruhe',
>                      attach_h_dst_to='Flensburg')
> # -> 52 nodes, max degree 6
> ```
>
> Karlsruhe has degree 5 in bare Germany50; attaching `h_src` makes it the unique
> degree-6 node. So `n_interfaces=6` is Karlsruhe-with-its-host, and `n_nodes=52`
> is `50 + 2`. The model and the environment agree exactly — there is no padding
> and no mismatch to explain away.
>
> These two numbers are recorded in `topologies/germany50/topology_config.json`
> and in the checkpoint's own `trained_on` block, and the engine reads them from
> there. They are properties of the network the model was trained on, not
> constants of the engine.
>
> ```
> Max node degree: 6 (karlsruhe, interfaces eth0..eth5)
> Model compatibility: n_nodes=52, n_interfaces=6 -> N_IN = 6 + 6 + 1 + 52 = 65, n_out = 7
> ```
>
> `--no-hosts` still generates the bare 50-router backbone, byte-identical to the
> old output, for comparison — but that lab does **not** match the checkpoint.

Germany50 is not regular: node degrees range from 2 to 6, so `karlsruhe` is the
only node that can use all six egress classes. A degree-2 node cannot forward
through classes 2..5, and `link_state[2..5]` has no interface behind it there.
That is inherent to one model serving every node of a non-regular topology — it
is not the 6-vs-topology mismatch described above, which is gone. The code names
it rather than letting it look like a fault:

- `link_state_monitor` seeds only slots backed by a real interface to `up`, and
  reports the rest **once** as `slots with no interface on this node ... --
  structurally 0, not a link failure`, instead of listing them in the per-poll
  `down=[...]` set where they were indistinguishable from a link that had just
  failed — the exact signal this lab measures.
- `install_mac_per_class` separates *absent* egress classes from *present but
  unusable* ones, and prints the node's degree alongside.
- `n_fwd` comes from the model's `n_out - 1`, not a literal 6.

All of this lives in [`topologies/germany50/`](topologies/germany50/), not in the engine. `germany50.xml` is the SNDlib topology the checked-in checkpoint was trained on, kept because it is the provenance of that model: delete it and `n_nodes=52` / `n_interfaces=6` become numbers with no origin. `importSNDLib.py` loads it into a NetworkX graph, for topology statistics and as the way to feed a real topology to the test fabric.

The dimensions those files imply — `n_interfaces=6`, `n_nodes=52` — are written once, in `topologies/germany50/topology_config.json`, and read by the engine through `$IPA_TOPOLOGY_CONFIG` or `/etc/ipa/topology_config.json`. They are no longer constants inside `model_meta.py`.

---

## Repository Structure

Three layers, and the dependency only ever points downward.

```
ipa_lab/
├── ipa/                             # 1. CORE ENGINE — no topology, no emulator
│   ├── execute_pipeline.py          #    SINGLE ENTRY POINT: --method hardcoded|template|modular
│   ├── ebpf_program.py              #    P1 codegen (weights as C literals, BCC dialect)
│   ├── ebpf_template_arch.py        #    P2 eBPF source + arch_weights control plane
│   ├── ebpf_modular.py              #    P3 eBPF source + layer_weights control plane
│   ├── class_semantics.py           #    class -> action -> logical port (declared, never inferred)
│   ├── node_config.py               #    logical port -> ifindex / MAC (per node)
│   ├── label_mapping.py             #    dataset label -> class, declared and verified
│   ├── model_meta.py                #    2. CONFIG LAYER: feature catalog, scenario resolution,
│   │                                #       shape derivation, checkpoint resolution
│   ├── common.py                    #    map helpers, MAC/ifindex resolution, XDP attach/detach
│   ├── link_state_monitor.py        #    seeds link_state[] from real carrier state
│   ├── queue_state_monitor.py       #    seeds queue_state[] (demo feature)
│   ├── extract_weights.py           #    .pt -> weights.json / weights_float.json
│   ├── FRR_model.py                 #    PyTorch MLP definition (training-side)
│   ├── model_meta.json              #    THE MODEL DESCRIPTOR: n_out, class_semantics,
│   │                                #       label_mapping, trained_on, checkpoint
│   ├── weights.json / weights_float.json
│   ├── methods/                     #    per-pipeline deploy entry points
│   ├── poc_aot/                     #    AOT-literal generator + static libbpf loader
│   ├── synth/                       #    synthetic model generator (scenarios/ is
│   │                                #       generated output, not tracked)
│   └── test/                        #    engine tests, topology-agnostic
│       ├── test_suite.py            #      core/pktstats/extract/quant/robust/kernel
│       ├── test_class_semantics.py  #      53 checks, five class layouts, none Germany50
│       ├── test_synth.py            #      50 checks on generated models, incl.
│       │                            #        synth reference == P1's generated C
│       ├── p1_c_eval.py             #      evaluates P1's C from its text (no kernel)
│       ├── verify_prog_run.py       #      per-pipeline kernel verifier (BPF_PROG_TEST_RUN)
│       ├── verify_multi_model.py    #      concurrent multi-model registration
│       └── bench_*.py               #      model-add cost, depth-vs-width, tail-call cost
│
├── topologies/                      # 3. SCENARIO DATA — one directory per network
│   └── germany50/                   #    the network the checked-in model was trained on
│       ├── germany50.xml            #      SNDlib topology, 50 routers / 88 links
│       ├── topology_config.json     #      n_interfaces=6, n_nodes=52, n_queues=4
│       └── importSNDLib.py          #      XML -> NetworkX
│
└── docs/
    ├── testing.md                   # Test guide + measured results
    ├── metodologia_test.tex/.pdf    # How this class of model is tested in the literature
    └── tesi_ipa.tex                 # Thesis text
```

### What "the core does not depend on the scenario" means, concretely

`ipa/` contains no topology numbers, no hostnames, no `germany50.xml`, and no
emulator paths. Where `n_interfaces` and `n_nodes` are needed they are resolved,
in order, from:

1. `$IPA_TOPOLOGY_CONFIG`
2. `/etc/ipa/topology_config.json`
3. the model descriptor's `trained_on` block

and exhausting that raises `ScenarioError` naming all three. There is
deliberately **no built-in default**: `DEFAULT_TOPOLOGY_CONFIG = {6, 52, 4}` used
to sit in `model_meta.py` and silently apply to any caller that supplied
nothing, which made every such caller quietly correct for Germany50 and quietly
wrong everywhere else.

The same holds for the model: `n_out`, which class is DROP, which classes
forward and onto which logical port all come from `ipa/model_meta.json`. None of
it is derived from `n_interfaces + 1`, `n_out - 1` or `max(label) + 1`.

You can check both claims:

```bash
# no code-level dependency on the experiment
grep -rniE "import importSNDLib|germany50|kathara|topologies/" ipa/ --include=*.py

# generate a full P1 pipeline for a topology that is not Germany50
cat > /tmp/tiny.json <<'JSON'
{"topology":"tiny-ring","n_interfaces":3,"n_nodes":8,"n_queues":2}
JSON
IPA_TOPOLOGY_CONFIG=/tmp/tiny.json python3 - <<'PY'
import sys; sys.path.insert(0, "ipa")
import model_meta as m, ebpf_program as E
from class_semantics import ClassSemantics
cfg = m.load_topology_config()
sh = m.derive_shape({"features": ["link_state","ingress_iface","ttl","node"],
                     "n_out": 4, "hidden_dims": [3,3]}, topology_config=cfg)
print("n_in =", sh["n_in"], " n_out =", sh["n_out"])      # 15, 4
sem = ClassSemantics.forward_then_drop(3, drop_class=3, n_out=4)
src = E.build_combined_hardcoded_source(
    models=[(0, [1]*sum(a*b+b for a,b in zip([sh["n_in"],3,3],[3,3,4])), 24, [2,3,4])],
    features=sh["features"], n_out=4, hidden_dims=(3,3), semantics=sem)
print("link_state width:", "v[3]" in src)                  # True
PY
```

### Running against a real datapath

There is no emulator. The tests build their own network out of `veth` pairs on
the host, attach XDP in **native** mode, inject a frame and read which
interface it came out of:

```bash
sudo python3 ipa/test/test_fabric.py          # P1/P2/P3, real attach + redirect
sudo python3 ipa/test/netns_fabric.py --hold  # just the fabric, to deploy onto
sudo bash ipa/test/probe_env.sh               # what this machine can support
```

`veth` supports native XDP, so the attach mode is the deployment mode rather
than a stand-in for it. What is not covered: a physical NIC's driver and DMA,
and multi-hop forwarding across several nodes.

---

> **Historical note.** The preliminary phase of this project was organised around
> `switch_core.py` and four *methods* (PTQ / QAT / OpenFlow-like / IPA-demo)
> exploring quantization and table-population strategies, with a deliberately
> minimal four-term dot product in the kernel and two maps (`model_cache`,
> `fwd_table`). That code is preserved, with its own README, on the
> **`ipa-poc-preliminar`** branch. `main` is organised instead around a **design
> space of three eBPF pipelines** that all run the *same* quantized multi-layer
> model and differ only in *where the weights live and what can change without
> recompiling*. The two branches are successive stages of one project, not
> alternatives; the narrative link between them is in `docs/tesi_ipa.tex`.

---

## The three pipelines

All three parse `Ethernet → IP → UDP:9999 → IPA header`, build the model's input
vector **locally on the node**, run the same integer MLP, take the argmax, and
resolve it to a physical action through a `mac_table` (class → `{ifindex,
src_mac, dst_mac}` → `bpf_redirect`). The last class is DROP.

| | **P1 hardcoded** | **P2 template** | **P3 modular** |
|---|---|---|---|
| Where the weights live | C literals in the program | `arch_weights` map | `layer_weights` map |
| Changeable without recompiling | nothing | layer **widths** | widths **and** depth |
| Compiled eBPF programs | one per model | one per architecture family | two, generic |
| Tail calls per packet | 1 | 1 | N (= depth) |
| Intermediate state | none (fully unrolled) | none | per-CPU scratch |
| Strength reduction | yes | no | no |
| Model update cost | recompile + reload | one map write | one map write |
| Per-packet cost | lowest | middle | highest |

The trade-off is structural, not an implementation defect: per-packet cost and
model-update cost move in **opposite** directions along the progression. Which
pipeline wins depends on the scenario, not on code quality.

---

## Input vector (descriptor-driven)

The input vector is **not** carried in the packet. It is built on the node from a
per-model *descriptor* — an ordered list of feature types from
`model_meta.FEATURE_CATALOG`:

| Feature type | Kind | Read from | Default size |
|---|---|---|---|
| `link_state` | dense vector map | `link_state` BPF map (real carrier state) | `n_interfaces` = 6 |
| `ingress_iface` | one-hot | `ctx->ingress_ifindex` | `n_interfaces` = 6 |
| `ttl` | scalar | `ip->ttl` | 1 |
| `node` | one-hot | `ipa->model_id` | `n_nodes` = 52 |
| `queue_occupancy` | dense vector map | `queue_state` BPF map (synthetic) | `n_queues` = 4 |

Feature **sizes** are a property of the network topology, read from
`topology_config.json` (falling back to 6 / 52 / 4). Feature **types and order**
are a property of the model, read from `model_meta.json`. The default descriptor
`[link_state, ingress_iface, ttl, node]` with `n_out = n_interfaces + 1` gives
the historical `65-4-4-7` shape.

> **Known limitation — `node` is driven by `model_id`, not by node identity.**
> The datapath sets the node one-hot index from `ipa->model_id`
> (`__u32 _node = (__u32)ipa->model_id;` in all three pipelines), not from any
> per-node identifier. With a single registered model (`--model-id 0`, the
> default) the one-hot therefore fires slot 0 on **every** node, so the feature
> contributes the same constant everywhere and carries no topological
> information. Making it a real node feature means seeding a per-node id at
> startup (from the node's own hostname or configuration) and reading that
> instead of `model_id`.

> **`ingress_iface` used to be inert, and now is not.** The one-hot was indexed
> by `ctx->ingress_ifindex` directly (P2/P3) or by a switch over a compile-time
> `[2, 3, ...]` table (P1). Kernel ifindexes are assigned by the kernel and are
> arbitrary — 205, 217, 229 on a box that has created a few veths — so neither
> resolved to anything and a trained feature contributed **zero**, with every
> test still green because none of them checked that it contributed anything.
> All three pipelines now resolve the kernel ifindex through a runtime
> `ingress_port` map, filled by the control plane from the node's own
> interfaces: the mirror of `mac_table` on the ingress side. `test_fabric.py`
> installs it and the per-class inputs it finds changed accordingly, which is
> the evidence the feature is live.

---

## TTL: normalised, exactly as the model was trained

The `ttl` feature is **not** the raw hop count. The training pipeline builds the
column as `ttl_value / initial_ttl` with `initial_ttl = 30`
(`IPA_dataset_gen.py`), so the model was trained on a value in `(0, 1]` that
starts at 1.0 and decreases with every hop: the *fraction of the journey
remaining*. The dataset confirms it — the `ttl` column of
`dataset_germany50_5.csv` ranges over `[0.3333, 1.0]` in steps of 1/30.

The datapath used to feed the raw TTL (30-64). Since `link_state` enters the dot
product as 0 or 1, that gave the TTL term 30-64x more leverage per unit of
weight and buried the failure signal. Measured over the trained range:

| | raw TTL | normalised |
|---|---|---|
| reacts to a link failure | **0.0%** | **35.2%** |
| redirects onto the DEAD link | **16.7%** | **0.7%** |
| egress classes ever used | 1 of 7 | 5 of 7 |

The model was never the problem — it was being fed the feature at the wrong
scale. `model_meta.DEFAULT_TTL_SCALE` holds the divisor; all three pipelines and
the AOT generator divide the TTL **product** by it (dividing the TTL itself would
collapse the 10..30 range onto 0 or 1 and throw the resolution away), and the
Python reference uses `_trunc_div` so it matches C's truncate-toward-zero on
negative weights. `send_ipa.py` sends with `INITIAL_TTL = 30` for the same
reason: a higher TTL normalises above 1.0, outside anything the model saw.

Run `ipa/test/diag_model_decisions.py` to see the numbers for the current
weights — no root, no BCC, no kernel needed.

## TTL: the hop behaves like a router

All three pipelines decrement `ip->ttl` before `bpf_redirect`, and fix the IP
header checksum incrementally (RFC 1624, the same `ipa_ttl_dec()` helper the
kernel's own `samples/bpf/xdp_fwd_kern.c` uses). A packet whose TTL would reach
zero is **not** forwarded: it is counted as MISS and returned with `XDP_PASS`,
so the kernel is the one that drops it and emits ICMP Time Exceeded.

This was missing. The datapath read `ip->ttl` as a model feature and never wrote
it, so a redirected packet kept its TTL forever and a forwarding loop could never
expire. On this topology that was not hypothetical: with `link_state` all-up the
model selects class 0 for every TTL from 2 upward, so every node forwarded out
`eth0` and a packet entered a permanent two-node loop between `duesseldorf` and
`essen`.

The decrement happens **after** inference, so the model still sees the TTL as
received — which is what the Python reference replicates, keeping the
equivalence check valid.

`test_suite.py --only kernel` verifies this against the packet the program
actually emitted (`BPF_PROG_TEST_RUN` writes it back), not against the source:
TTL 5 must come out as TTL 4 with a valid checksum, and TTL 1 must not be
forwarded at all. A missing checksum fix would otherwise pass every
return-code-only test while producing packets that each downstream router
silently discards.

> **This makes looping safe, not correct.** The datapath never reads the
> destination IP — the model's features are `[link_state, ingress_iface, ttl,
> node]`, with no destination among them — so the egress class does not depend
> on where the packet is addressed. The TTL now bounds the damage to at most 64
> hops instead of forever, which is exactly what TTL is for, but destination-
> based forwarding needs a model trained with a destination feature. See the
> known limitations above.

---

## IPA header (21 bytes, on UDP port 9999)

```
model_id:1  model_type:1  param_size:1  scale_factor:2(BE)
input_size:1  output_size:1  hidden_layers:1  neurons_per_layer:1
n_feature_types:1  (feat_code, feat_count) x 4 = 8
n_output_types:1  out0_code:1  out0_count:1
```

The datapath reads only `model_id` from this header — it selects which registered
model to run. **The weight payload that follows is not read by any of the three
pipelines**: weights are loaded out-of-band by the control plane at registration
time. The payload exists to keep packets realistically sized. Making the weights
travel in-band (a true IPA cache-miss path) is future work; see the discussion in
`docs/tesi_ipa.tex`.

---

## How to Run

### First run after cloning

Nothing to fetch. The engine compiles eBPF with BCC against the host's own
kernel headers, so a box with `bcc`, `clang` and `linux-headers-$(uname -r)`
installed is ready. Check what the machine supports:

```bash
sudo bash ipa/test/probe_env.sh
```

It reports virtualisation, the kernel options that matter (`VETH`, `NET_PKTGEN`,
BTF), the toolchain, and — the decisive one — whether **native** XDP attaches to
a `veth`.

### Build a network to attach to

```bash
sudo python3 ipa/test/netns_fabric.py --n-ports 5 --hold
```

One `veth` pair per logical port plus a dedicated ingress, each peer carrying an
`XDP_PASS` stub so `bpf_redirect` into a veth works. Ctrl-C tears it all down;
`--cleanup` removes what a killed run left behind.

### Attach a pipeline (XDP, on the ingress interface)

```bash
sudo IPA_XDP_MODE=native IPA_IFACE_PATTERN='ipa{i}' \
  python3 ipa/execute_pipeline.py --method template --iface ipain
```

`--method` is `hardcoded` | `template` | `modular`. `--xdp-mode` picks the attach
mode: `native` (the default; runs in the driver, before the `sk_buff` exists),
`generic` (runs in `netif_receive_skb`, after it), or `auto` (the kernel decides,
which means it may quietly give you generic). The mode actually in effect is
read back from the kernel and printed — a native attach that fails is an error,
not a silent downgrade, because a silent one makes every measurement
unattributable.

Which interface realises which logical port is a node fact, not a model fact:

```bash
IPA_PORT_MAP="0=ipa0,1=ipa1,4=enp0s3"   # exact, per port
IPA_IFACE_PATTERN="ipa{i}"              # a naming convention
```

If a stale program is left on an interface: `sudo ip link set dev ipain xdp off`.

### Send traffic

```bash
sudo python3 ipa/send_ipa.py --dst <host> --count 100 --model-id 0
sudo python3 ipa/recv_ipa.py
sudo python3 ipa/test/test_ipa.py --dest <host> --count 100 --model-id 0
```

## Testing

Full guide with expected output in [`docs/testing.md`](docs/testing.md).

```bash
# userspace suites (torch + numpy, no root)
python3 ipa/test/test_suite.py --only core

# in-kernel metrics + dispatch correctness (Linux + BCC + root)
sudo python3 ipa/test/test_suite.py --only kernel

# per-pipeline verifier
sudo python3 ipa/test/verify_prog_run.py --method hardcoded|template|modular|sparse-hetero

# concurrent multi-model registration
sudo python3 ipa/test/verify_multi_model.py
```

Correctness criterion, identical across pipelines: pre-install `mac_table`, run
the program, require the return value to be a redirect or a drop **and** the
per-class counter of the chosen class to increment, with the chosen class
compared against an independent integer Python reference that replicates the same
arithmetic. Accuracy is deliberately an *invariant*, not a variable: all three
pipelines compute the same integer MLP on the same weights.

Latency is reported as the **minimum of N independent trials**, not the mean:
system noise here is one-sided (scheduling and interrupts can only slow a sample
down, never speed it below its true cost), the same reasoning behind `hyperfine`
and Google Benchmark.

---

## References

- M. Polverini, A. Cianfrani, M. Listanti, *"Intelligent Packets: Embedding Machine Learning Models into Network Packets"*, submitted to IEEE INFOCOM Workshops ICCN 2026.
- M. Polverini, *"IPA Prototype"*, [github.com/marcopolverini/ipa-prototype](https://github.com/marcopolverini/ipa-prototype), 2026.
- S. Miano, F. Risso, *"Extended Berkeley Packet Filter"*, CNIT Technical Report 06 — Network Programmability, 2020.
- S. Orlowski et al., *"SNDlib 1.0 — Survivable Network Design Library"*, Networks, vol. 55, no. 3, 2010.
