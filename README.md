# IPA Lab — Intelligent PAckets with eBPF

This repository contains the lab implementation of **Intelligent PAckets (IPA)** with an eBPF-accelerated data plane, developed on top of the [Kathara](https://github.com/KatharaFramework/Kathara) network emulator. The goal is to embed compact machine learning models directly inside packet headers and execute per-hop inference to achieve adaptive, mission-driven forwarding decisions — without any control-plane signaling.

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
> `genera_lab.py` previously emitted only the 50 routers, giving a lab of 50
> nodes with max degree 5. That made the checkpoint's 6/52 look like dimensions
> invented for no reason, with `link_state[5]` permanently 0 and egress class 5
> a permanent MISS on every node. The generator now emits the hosts, so the lab
> is the topology the model was trained for. Run `genera_lab.py` and it reports
> the check explicitly:
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

The topology lives in `germany50.xml` (SNDlib format). `genera_lab.py` parses it and emits the Kathara lab: `lab.conf` (collision domains and interface assignment) plus one `<node>.startup` per node (IP addressing, loopbacks, `/etc/hosts`, FRR/OSPF configuration). `importSNDLib.py` is a separate analysis helper that loads the same XML into a NetworkX graph for topology statistics and plotting.

---

## Repository Structure

```
ipa_lab/
├── genera_lab.py                    # Generates lab.conf + <node>.startup from germany50.xml
├── importSNDLib.py                  # SNDlib XML -> NetworkX topology (analysis helper)
├── germany50.xml                    # SNDlib Germany50 topology
├── lab.conf, <node>.startup         # Generated Kathara lab (52 nodes, 90 links)
├── Dockerfile                       # kathara/frr_ebpf image (FRR + BCC + eBPF headers)
├── docs/
│   ├── testing.md                   # Test guide + measured results
│   └── tesi_ipa.tex                 # Thesis text
└── shared/                          # Bind-mounted into every Kathara node as /shared
    ├── execute_pipeline.py          # SINGLE ENTRY POINT: --method hardcoded|template|modular
    ├── model_meta.py                # Feature catalog, topology_config, shape derivation
    ├── ebpf_program.py              # Pipeline 1 codegen (weights as C literals, BCC dialect)
    ├── ebpf_template_arch.py        # Pipeline 2 eBPF source + arch_weights control plane
    ├── ebpf_modular.py              # Pipeline 3 eBPF source + layer_weights control plane
    ├── common.py                    # mac_table install, ARP refresh, XDP attach/detach
    ├── fix_bpf.sh                   # (per node, at boot) symlinks host_headers for BCC
    ├── fetch_host_headers.sh        # (on the host, once) populates host_headers/
    ├── link_state_monitor.py        # Seeds link_state[] from real carrier state
    ├── queue_state_monitor.py       # Seeds queue_state[] (synthetic, demo feature)
    ├── extract_weights.py           # .pt -> weights.json / weights_float.json
    ├── FRR_model.py                 # PyTorch MLP definition (training-side)
    ├── frr_germany50_5_model_4x2.pt # Trained checkpoint (65-4-4-7)
    ├── weights.json                 # int8 weights (319 values, scale=24)
    ├── weights_float.json           # float weights + scale_factor
    ├── send_ipa.py                  # Single/N-packet IPA sender (struct.pack)
    ├── recv_ipa.py                  # IPA listener (use only with XDP detached)
    ├── methods/
    │   ├── method4_hardcoded.py     # P1 compile-and-verify (BCC, no attach)
    │   ├── method4_hardcoded_aot.py # P1 deploy: AOT-literal .o + libbpf loader
    │   ├── method5_template.py      # P2 deploy
    │   └── method6_modular.py       # P3 deploy
    ├── poc_aot/
    │   ├── gen_full_c.py            # Descriptor-driven libbpf-dialect literal generator
    │   ├── loader_aot.c             # Static libbpf loader (bench + live attach)
    │   └── nn_aot_arch.o            # Prebuilt object, deployed to nodes without clang
    └── test/
        ├── test_suite.py            # All suites: core/pktstats/extract/quant/robust/kernel
        ├── verify_prog_run.py       # Per-pipeline kernel verifier (BPF_PROG_TEST_RUN)
        ├── verify_multi_model.py    # Concurrent multi-model registration proof
        ├── bench_model_add.py       # Real cost of registering a new model_id
        ├── bench_depth_vs_width.py  # Width-vs-depth trade-off sweep (P1)
        ├── bench_tailcall_overhead.py # Isolated bpf_tail_call cost
        └── test_ipa.py              # Scapy multi-packet sender
```

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
> startup (each node knows its own name from the Kathara lab) and reading that
> instead of `model_id`.

> **Known limitation — `ingress_iface` is inert on this lab.** P1 maps the kernel
> ifindex to a logical port through an `ifindex_table` defaulting to `[2..7]`;
> P2/P3 use the raw ifindex clamped to `[1, n_interfaces]`. Real Kathara nodes get
> ifindexes like 201/209/217/223, which match neither — so this feature contributes
> zero on all three pipelines in the live lab. Under `BPF_PROG_TEST_RUN` the
> sandbox ifindex is 1, which P2/P3 *do* accept and P1 does not, so the two
> semantics also disagree there (`verify_prog_run.py` models this explicitly with
> `ref_ifindex = 0 if pipeline == 1 else 1`). Fixing it means resolving real
> ifindexes at startup and giving P2/P3 an ifindex→port map.

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

The Kathara nodes compile eBPF with BCC against the **host's** kernel headers,
bind-mounted through `shared/`. Those headers are ~114 MB of generated files
pinned to one exact kernel version, so they are **not tracked in git**. Populate
them once per machine (and again after a kernel upgrade):

```bash
bash shared/fetch_host_headers.sh     # copies /usr/src/linux-headers-$(uname -r)
```

Without this, every pipeline fails at BPF compilation and `fix_bpf.sh` prints
the command to run.

### Start the lab

```bash
kathara lstart      # 52 nodes (50 routers + h_src/h_dst), germany50 topology
kathara linfo
kathara lclean      # tear down
```

### Attach a pipeline (XDP, on the ingress interface)

```bash
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method template  --iface eth1 --model-id 0
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method modular   --iface eth1 --model-id 0
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method hardcoded --iface eth1

# load + verifier check only, no attach
sudo python3 shared/execute_pipeline.py --method hardcoded --verify-only

# detach a stale program
kathara exec frankfurt -- ip link set dev eth1 xdp off
```

All three populate `mac_table` and `link_state` themselves at startup and print
live `HIT | MISS | DROP` counters. XDP only sees **ingress** traffic, so attach on
the interface the traffic arrives on (check with `tcpdump -i any -n udp port 9999`).

A failed XDP attach raises — it does not print a warning and carry on — so if a
pipeline prints `running`, the program really is on the wire. All three detach
the program and stop the carrier monitor on **any** exit path, not only Ctrl-C.

**Concurrent models are capped by the shared weight block.** `--model-ids` packs
every registered model into one BPF map entry, so the cap is
`MAX_WEIGHT_ENTRIES / weights-per-model`:

| | block size | per model (65-4-4-7) | max concurrent models |
|---|---|---|---|
| P2 template | `MAX_WEIGHT_ENTRIES` = 1024 | 319 | **3** |
| P3 modular | `MAX_LAYER_WEIGHT_ENTRIES` = 2048 | 319 | **6** |

Both are checked before the eBPF program is compiled, so asking for more fails
immediately with the numbers rather than part-way through registration. Raising
a cap means changing the Python constant **and** the matching `#define` in the
eBPF source together (keep it a power of two — the datapath masks its weight
index with `size - 1` to keep a runtime-variable index verifier-safe), and it
changes the map-memory figures reported by `test_suite.py --only kernel`.

**Pipeline 1 deploys via AOT only.** The BCC live-attach path was removed; the
`.o` is built offline on a box with clang and the statically linked `loader_aot`
attaches it on nodes that have neither clang nor `libbpf.so`. Build both once on
the host — `shared/` is bind-mounted, so they appear on every node:

```bash
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev libzstd-dev liblzma-dev
python3 shared/methods/method4_hardcoded_aot.py     # builds .o + loader, then benches
```

### Send traffic

```bash
# end-to-end, the way the topology is meant to be driven
kathara exec h_src -- python3 /shared/send_ipa.py --dst h_dst --count 100

# or router-to-router, to exercise a specific hop
kathara exec darmstadt -- python3 /shared/send_ipa.py --dst frankfurt --count 100
kathara exec darmstadt -- python3 /shared/test/test_ipa.py --dest frankfurt --count 100 --model-id 0
```

`recv_ipa.py` is only meaningful with **XDP detached**: a TRUE HIT means the
packet was redirected and never reaches the local IP stack, so the listener
correctly sees nothing while a pipeline is attached.

---

## Testing

Full guide with expected output in [`docs/testing.md`](docs/testing.md).

```bash
# userspace suites (torch + numpy, no root)
python3 shared/test/test_suite.py --only core

# in-kernel metrics + dispatch correctness (Linux + BCC + root)
sudo python3 shared/test/test_suite.py --only kernel

# per-pipeline verifier
sudo python3 shared/test/verify_prog_run.py --method hardcoded|template|modular|sparse-hetero

# concurrent multi-model registration
sudo python3 shared/test/verify_multi_model.py
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

## Regenerating the lab

```bash
python3 genera_lab.py                      # rewrites lab.conf + every <node>.startup
python3 genera_lab.py --xml other.xml --out /tmp/lab   # different topology / output dir
python3 genera_lab.py --host h_src=berlin              # attach a host elsewhere
python3 genera_lab.py --no-hosts                       # bare 50-router backbone
```

`--host` and `--no-hosts` change the topology the lab presents to the model.
The defaults (`h_src=karlsruhe`, `h_dst=flensburg`) are the attachment points the
checked-in checkpoint was trained on; anything else changes `n_nodes` or the max
degree and the checkpoint no longer matches. The generator prints the resulting
`N_IN` so the mismatch is visible immediately.

Runs from any working directory and only writes when invoked as a script
(importing it has no side effects). It prints the node count, link count and max
node degree it produced — a quick check that the lab matches what the model and
the docs assume.

---

## References

- M. Polverini, A. Cianfrani, M. Listanti, *"Intelligent Packets: Embedding Machine Learning Models into Network Packets"*, submitted to IEEE INFOCOM Workshops ICCN 2026.
- M. Polverini, *"IPA Prototype"*, [github.com/marcopolverini/ipa-prototype](https://github.com/marcopolverini/ipa-prototype), 2026.
- S. Miano, F. Risso, *"Extended Berkeley Packet Filter"*, CNIT Technical Report 06 — Network Programmability, 2020.
- S. Orlowski et al., *"SNDlib 1.0 — Survivable Network Design Library"*, Networks, vol. 55, no. 3, 2010.
