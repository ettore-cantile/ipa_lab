# IPA Lab — a neural network inside the Linux kernel, with eBPF/XDP

This repository runs a small neural network **inside the Linux kernel**, at the
first point a packet reaches (XDP), to decide which port the packet leaves
from. It is the lab implementation of **Intelligent PAckets (IPA)**: the packet
carries which model to use, and every node runs the inference on its own local
state, with no control plane reconfiguring routes.

The same network is written in **four versions**, from fully compiled to fully
configurable, and the repository measures what each choice costs: per packet,
in instructions, under real traffic, and on different kinds of CPU core.

> This work extends the proof of concept by Polverini, Cianfrani and Listanti
> (Sapienza University of Rome / University of Molise). The code of the
> preliminary phase is on the `ipa-poc-preliminar` branch.
>
> The documents in `docs/` (test guide, claims, notebook, slides) are in
> Italian; this README and the code comments are in English.

---

## Contents

1. [Results at a glance](#results-at-a-glance)
2. [The four versions](#the-four-versions)
3. [Repository layout](#repository-layout)
4. [Installation](#installation)
5. [First steps: the tests in ten minutes](#first-steps-the-tests-in-ten-minutes)
6. [How the measurements work](#how-the-measurements-work)
7. [Running measurements](#running-measurements)
8. [All the tests](#all-the-tests)
9. [Running a pipeline on an interface](#running-a-pipeline-on-an-interface)
10. [How the datapath works](#how-the-datapath-works)
11. [Other models, other networks](#other-models-other-networks)
12. [Documentation](#documentation)
13. [Limitations](#limitations)
14. [References](#references)

---

## Results at a glance

Model 65-4-4-7 (319 weights), 64-byte packets, `xdp_gen` traffic generator,
one node core at 3.5 GHz. Campaign of 6 October 2026, all data in
[`results/campagna_2026-10-06/`](results/campagna_2026-10-06/) (summary in
`sintesi.md`).

| | baseline | P1 static | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| **million packets/s, P-core** | 15.27 | 8.56 | 8.04 | 3.45 | 2.36 |
| CPU ns per packet | 66 | 117 | 124 | 290 | 425 |
| neural network cost (above the baseline) | — | +51 ns | +58 ns | +224 ns | +359 ns |
| instructions executed per packet | 606 | 1 220 | 1 426 | 4 556 | 6 573 |
| instructions per cycle (IPC), P-core | 2.7 | 3.0 | 3.3 | 4.5 | 4.4 |
| **million packets/s, E-core** | 9.39 | 6.35 | 5.84 | 2.83 | 1.94 |
| E-core relative to P-core | 0.61 | 0.74 | 0.73 | 0.82 | 0.82 |
| program alone (`BPF_PROG_TEST_RUN`) | 14 ns | 46 ns | 52 ns | 194 ns | 318 ns |

In five lines:

- **Configurability is paid per packet**: about 50–60 ns of neural network
  with compiled-in weights, 225–360 ns with weights read from maps.
- **The bottleneck is the program**: above capacity, packets are lost at the
  program's input queue, never after it; two cores carry twice the traffic.
- **On a slow core the code is the same, the IPC is not**: an E-core executes
  the same instructions but mostly slows down the node's fixed work, much less
  the neural network.
- **The program alone predicts the shape, not the full cost**: under traffic
  the inference alone costs 10–40 ns more (P1, P1.5) and 40–110 ns more (P2,
  P3) than `BPF_PROG_TEST_RUN` reports, with the same trends on every axis
  (campaign of 10 October, [`results/campagna_2026-10-10/`](results/campagna_2026-10-10/)).
- **Changing the model costs milliseconds for every pipeline**: P1 is compiled
  off the node and loaded in ~1 ms; P2 and P3 write a map in ~10 ms.

---

## The four versions

All four compute the same integer network (8-bit weights) and take the same
decision on the same packet. What changes is what is written into the program
at compile time and what the program reads from eBPF maps while it runs.

| | **P1 static** (`p1_static`) | **P1.5** (`hardcoded`) | **P2** (`template`) | **P3** (`modular`) |
|---|---|---|---|---|
| weights | in the code | in the code | in a map | in a map |
| node identity | in the code | in a map | in a map | in a map |
| network shape | in the code | in the code | in a map, within compiled ceilings | in a map |
| number of layers | in the code | in the code | in the code | in a map |
| one binary per | node | model | family of architectures | everything |
| tail calls per packet | 1 | 1 | 1 | 1 + layers |
| changing the model | recompile (off the node) | recompile (off the node) | write a map | write a map |

P1 and P1.5 ship as a **precompiled (AOT) object**: the C source with the
weights inside is compiled with clang on any machine, and the node loads the
ready file with a small static loader, without a compiler. P2 and P3 are
compiled once with BCC when the node starts and are never touched again.

Two reference programs complete the comparisons: **baseline** (parses the
header, decrements the TTL and forwards, without a neural network) and
**rxonly** (receives and drops: the cost of reception alone).

---

## Repository layout

Three layers, and the dependency always points upwards: the engine knows
nothing about the network it is measured on.

```
ipa_lab/
├── ipa/                          ENGINE: pipelines, inference, control plane
│   ├── execute_pipeline.py       entry point: attaches a pipeline to an interface
│   ├── ebpf_program.py           P1/P1.5: generates C with the weights as literals
│   ├── ebpf_template_arch.py     P2: eBPF source and loading of the weights into maps
│   ├── ebpf_modular.py           P3: eBPF source, one program per layer
│   ├── p1_aot.py                 P1 as a precompiled object (build + loader)
│   ├── poc_aot/                  C generator (gen_full_c.py), loader_aot.c, Makefile
│   ├── methods/                  per-pipeline entry points (used by execute_pipeline)
│   ├── class_semantics.py        class → action → logical port, declared by the model
│   ├── node_config.py            logical port → interface, ifindex and MAC (per node)
│   ├── model_meta.py / .json     the model card: features, scale, classes, network
│   ├── model_source.py           loads any model (checkpoint, synthetic, directory)
│   ├── pipeline_limits.py        which shapes each pipeline can run
│   ├── link_state_monitor.py     real link state → link_state map
│   ├── queue_state_monitor.py    queue occupancy → queue_state map
│   ├── common.py, stats_maps.py, pinned_maps.py   maps, XDP attach, per-CPU counters
│   ├── FRR_model.py, extract_weights.py, label_mapping.py   training side: .pt → weights
│   ├── frr_germany50_5_model_4x2.pt, weights.json          the trained model
│   ├── synth/                    synthetic model generator (generated scenarios: not in git)
│   └── test/                     tests, benches, campaign scripts (below)
│
├── topologies/                   SCENARIOS: one directory per network
│   ├── germany50/                SNDlib Germany50 (the network of the trained model)
│   └── germany50_ttl16/, synth_*/   the networks of the synthetic models
│
├── results/                      MEASUREMENTS: one directory per campaign
│   ├── campagna_2026-10-06/      full campaign: CSV, machine conditions, sintesi.md
│   └── campagna_2026-10-10/      30 parametric models under traffic (incl. network size and
│                                 input composition), with the inference alone (T2−T1)
│
└── docs/                         DOCUMENTS (in Italian)
    ├── testing.md                the test guide, with every result
    ├── claims.md                 every claim, its evidence and how to reproduce it
    ├── september_notebook.tex/.pdf   the notebook: how it works and what it costs
    ├── *.pptx + "- spiegazione.pdf"  the slides, and a slide-by-slide explanation
    ├── slides_src/               build.py and the explanation texts
    └── figures/                  the notebook's charts
```

`ipa/test/` holds five families of files:

| family | files | purpose |
|---|---|---|
| tests without root | `test_suite.py`, `test_class_semantics.py`, `test_synth.py`, `test_model_source.py`, `test_host_conditions.py`, `test_bitrate_math.py`, `test_steady_window.py`, `p1_c_eval.py` | arithmetic, class semantics, synthetic models, bench logic |
| kernel tests | `verify_prog_run.py`, `verify_multi_model.py`, `verify_per_model_semantics.py`, `verify_synth_kernel.py`, `test_fabric.py`, `test_host_kernel.py`, `diag_verifier.py` | the real programs loaded in the kernel, the `veth` fabric, the machine |
| benches | `bench_throughput.py`, `bench_bitrate.py`, `bench_scaling.py`, `bench_depth_vs_width.py`, `bench_tailcall_overhead.py` | capacity, curves under growing traffic, parametric analysis |
| infrastructure | `host_conditions.py`, `hw_counters.py`, `xdp_gen.py`, `netns_fabric.py`, `pipeline_setup.py`, `model_under_test.py`, `traffic_models.py`, `campaign_report.py`, `plot_bitrate.py` | machine conditions, hardware counters, generator, fabric, models |
| campaigns | `remeasure_campagna.sh`, `remeasure_all.sh` | reproduce every number in the documents |

---

## Installation

You need **Linux on a physical machine** (not a virtual machine: see
[Limitations](#limitations)), with BCC. On Ubuntu 24.04:

```bash
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r) \
                 clang libbpf-dev libelf-dev zlib1g-dev libzstd-dev liblzma-dev \
                 python3-numpy python3-matplotlib python3-networkx
# optional: PyTorch, only for the tests on the trained checkpoint (weight extraction)
pip install --user --break-system-packages torch
```

Nothing else to download or build: the engine compiles the eBPF programs
itself, against the headers of the running kernel. The documents are rebuilt
with `pdflatex` (notebook) and with LibreOffice, `pdftoppm` and Chrome (slide
explanations; `pip install python-pptx` to edit the slides).

---

## First steps: the tests in ten minutes

Run every command from the repository root.

**1. Without root** (one minute): the P1 C code computes the model, the class
semantics hold, the synthetic models are consistent.

```bash
python3 ipa/test/test_synth.py               # 60 checks, including P1's C evaluated from its text
python3 ipa/test/test_class_semantics.py     # 69 checks
python3 ipa/test/test_model_source.py        # 62 checks: models, networks, compatibility
python3 ipa/test/test_suite.py               # weight extraction and quantization (needs torch)
```

Without root, `test_suite.py` reports the kernel suite as `SKIP`.

**2. The machine** (no root for the first command):

```bash
python3 ipa/test/host_conditions.py --show   # core types, role plan, current conditions
sudo python3 ipa/test/test_host_kernel.py    # conditions are applied, measured and removed
```

**3. The kernel** (a few minutes):

```bash
sudo python3 ipa/test/test_suite.py --only kernel   # metrics and decisions of the four pipelines
sudo python3 ipa/test/test_fabric.py                # the packet really crosses a veth fabric
sudo python3 ipa/test/verify_synth_kernel.py --all --n 300   # 8 synthetic models, 2 400 decisions
```

If these pass, the repository works on that machine.

---

## How the measurements work

### The bench

One machine plays every role: the traffic generator, the node running the
neural network, and the next node receiving the forwarded packets. They are
connected by virtual cables (`veth`) with native XDP, so the node's program
sees every packet at the first point in the kernel it reaches, as with a real
network card. Each role has its own physical core: by default the node on
CPU 6, the egress (next node) on CPU 8, the generator on CPU 10.

### The traffic generator: `xdp_gen`

`xdp_gen` hands the node **raw XDP frames**, in the same form a network card
driver with native XDP produces: no `skb`, no copy. It uses
`BPF_PROG_TEST_RUN` with live frames (kernel ≥ 5.18) and a pacing program, so
it can either push as hard as possible or keep a fixed, evenly spaced rate.
pktgen is available as an alternative (`--generator pktgen`), but it adds a
per-packet copy on `veth` that a real card does not have.

### Four ways of measuring

Each answers a different question. All of them run with the machine in known
conditions (below) and write those conditions next to the numbers.

| method | command | what it measures | question |
|---|---|---|---|
| **full load** | `bench_throughput.py --mode compare` | the generator offers more than the node can process; the node core is busy 100% of the time. Capacity (packets/s), **CPU time per packet**, and hardware counters: instructions, cycles, IPC, cache misses | how much does a packet cost the node? |
| **growing load** | `bench_bitrate.py` | 0.5 → 12 Mpps; packets sent, received by the program, forwarded; end-to-end latency | where are packets lost, and when does latency grow? |
| **three clocks** | `bench_throughput.py --mode rates` | an instrumented build stamps the clock at program entry (T1), just before `bpf_redirect` (T2) and on arrival at the next node (T3). **T2−T1 is the program alone**, T3−T2 the transport. Minimum, mean, maximum and percentiles per window | how much of the cost is the inference, under real traffic? |
| **program alone** | `test_suite.py --only kernel`, `bench_scaling.py` | `BPF_PROG_TEST_RUN`: the kernel runs the program on a prepared packet, thousands of times in a loop, without receiving or transmitting. Minimum of 7 trials | program size, map lookups, model install time, dense sweeps |

Where the time goes (P-core, 3.5 GHz, model 65-4-4-7):

- **receiving the frame**: ~41 ns (rxonly);
- **parsing, TTL, redirect**: +25 ns; together the 66 ns of the baseline, the
  node's fixed cost;
- **the neural network**: what each pipeline adds above the baseline, ~50 ns
  (P1) to ~360 ns (P3). Inside it, the arithmetic is cheap (~0.3 ns per
  multiply-accumulate with compiled weights); the cost of configurability is
  in **map lookups** (5 → 29 per packet) and **tail calls** (1 → 3);
- **transport to the next node**: ~210 ns (redirect, `veth`, reception). It
  adds to the packet's latency; the reception is paid by the egress core.

The methods cross-check each other. On the checkpoint, the inference alone
(ns above the baseline, P1 / P2 / P3) is 32 / 180 / 304 with
`BPF_PROG_TEST_RUN`; under traffic the **minimum** of T2−T1 is 34 / 195 / 313
(the packet that finds everything in cache) and the **mean** is 44 / 229 / 364,
which matches the CPU time above the baseline at full load, 51 / 224 / 359.

### Machine conditions

A laptop left alone changes frequency, puts cores to sleep and schedules
processes anywhere. `host_conditions.py` puts the machine in known conditions
for the duration of a bench and **restores** them at the end (also after an
error or Ctrl-C):

- node, generator and next node on **distinct physical cores**, one thread per
  core; the SMT sibling of each, and the other three cores of an E-core
  module, stay idle;
- **fixed and measured frequency** (3.5 GHz by default, checked with
  APERF/MPERF);
- deep idle states off; desktop, IRQs and kernel threads moved to the other
  CPUs; a temperature and throttling monitor always on. A window with
  throttling, battery power or a frequency more than 5% off is counted and
  reported as *disturbed*, not discarded.

The traffic benches apply it themselves; for any other command:
`sudo python3 ipa/test/host_conditions.py --run -- <command>`. After a killed
run: `sudo python3 ipa/test/host_conditions.py --restore`.

---

## Running measurements

### A full campaign

```bash
bash ipa/test/remeasure_campagna.sh                 # everything, about 2 hours
bash ipa/test/remeasure_campagna.sh pcore ecore     # only some sections
python3 ipa/test/campaign_report.py results/campagna_<date> > sintesi.md   # summary tables
```

The script asks for `sudo` once and keeps it alive. Results go to
`results/campagna_<date>/` (`CAMPAGNA=<dir>` to choose another directory):
one CSV per measurement, the machine conditions (`env.csv`,
`host_monitor.csv`), the logs in `log/`, and `sintesi.md`.

| section | what it measures | time |
|---|---|---:|
| `pcore` | node on a P-core: capacity on 1 and 2 cores, per class, per frame size, three clocks, bit-rate curves | ~12 min |
| `ecore` | the same node on an E-core (same frequency) | ~7 min |
| `lpe` | node on an LP E-core (2.5 GHz) | ~4 min |
| `assi` | under traffic, on P-core and E-core: the inference alone (T2−T1) of the checkpoint, then CPU time and T2−T1 for 30 synthetic models — width, depth, equal weights, sparsity, network size (nodes), dense and one-hot inputs | ~70 min |
| `kernel` | everything that does not use real traffic (`remeasure_all.sh`) | ~15 min |

Options of the `assi` section, as environment variables:

```bash
ASSI_CORES=P bash ipa/test/remeasure_campagna.sh assi             # P-core only (P, E, L)
ASSI_SOLO="depth_1 width_6" bash ipa/test/remeasure_campagna.sh assi   # only these points
ASSI_T2=0 bash ipa/test/remeasure_campagna.sh assi                # skip T2−T1
ASSI_RATES=0.3,0.6 bash ipa/test/remeasure_campagna.sh assi       # rates for T2−T1, in Mpps
ASSI_AXES="nodes iv_dense" bash ipa/test/remeasure_campagna.sh assi   # only these axes
```

### A single measurement

```bash
# capacity at full load: node on P-core 6 (or --dut-cpus 12 for an E-core)
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --egress-cpu 8 --out results/try_compare

# the inference alone under traffic (T1/T2/T3), for any model
sudo python3 ipa/test/bench_throughput.py --mode rates --generator xdp --frames 64 \
    --rounds 3 --gen-cpus 10 --dut-cpus 6 --rates 0.3,0.6 \
    --model ipa/synth/traffic/depth_6 --out results/try_t2

# growing traffic: where packets are lost, and the latency
sudo python3 ipa/test/bench_bitrate.py --generator xdp --gen-cpus 10 --dut-cpus 6 \
    --egress-cpu 8 --out results/try_bitrate

# the program alone, varying the shape of the network
sudo python3 ipa/test/host_conditions.py --run -- \
    python3 ipa/test/bench_scaling.py --axis all --out results/try_axes
```

Every bench accepts `--model` (see [Other models](#other-models-other-networks))
and `--help` lists the CPU, frequency and isolation options.

### Reading the results

- **CPU time per packet** (`ns_cpu`, `compare.csv`): node core occupancy ×
  1 / packets processed, in the same 300 ms steady window.
- **Instructions, cycles, IPC per packet** (`instr_pkt`, `cycles_pkt`, `ipc`):
  from the node core's hardware counters (`hw_counters.py`), in the same
  reading. They say *why* a packet costs what it costs.
- **T2−T1** (`pipe_min_ns`, `pipe_avg_ns`, `rates_raw.csv`): the program alone
  under traffic. Subtract the baseline's value to get the neural network. The
  minimum is the best case (warm caches), the mean the typical cost; the
  maximum tells whether a single long stall is skewing the mean.
- **Where packets are lost**: sent, received by the program, forwarded. Packets
  missing before the program mean the program is the bottleneck; missing after
  it, the transmission.

---

## All the tests

| command | root | what it checks | expected |
|---|:---:|---|---|
| `test_suite.py` | no | weight extraction, quantization | PASS (needs torch); kernel suite SKIP |
| `test_class_semantics.py` | no | class → action on five class schemes | 69/69 |
| `test_synth.py` | no | synthetic models; P1's C against the reference | 60/60 |
| `test_model_source.py` | no | models, networks, compatibility, pipeline limits | 62/62 |
| `test_host_conditions.py` | no | roles, E-core modules, apply and restore on a fake /sys | 95/95 |
| `test_bitrate_math.py` | no | formulas and loss attribution | 100/100 |
| `test_steady_window.py` | no | the steady window, with a simulated generator | 18 (one is timing-sensitive and may fail on a busy machine) |
| `test_suite.py --only kernel` | yes | metrics, TTL dispatch, TTL and checksum, reroute | PASS |
| `verify_prog_run.py --method <p>` | yes | verifier and decisions of one pipeline | 9/9 |
| `verify_multi_model.py` | yes | several models registered together | PASS |
| `verify_per_model_semantics.py` | yes | different semantics per model in P2 and P3 | 53/53 |
| `verify_synth_kernel.py --all` | yes | integer reference and eBPF identical on 8 models | 8/8 |
| `test_model_source.py --kernel` | yes | every network × model × pipeline | 110/110 |
| `test_fabric.py` (`--method aot`, `--sweep`) | yes | delivery over veth, P1 as deployed, five topologies | 29/29, 11/11, 34/34 |
| `test_host_kernel.py --bench` | yes | the machine conditions on the real kernel | 25/25 |
| `diag_verifier.py` | yes | verifier statistics, ReLU with and without a branch | — |

The correctness criterion is the same for every pipeline: the real programs run
in the kernel, and a test requires a redirect (or a drop, if the model decides
so) **and** the increment of the right class counter, compared with an
independent integer Python reference that replicates the same arithmetic.

---

## Running a pipeline on an interface

```bash
# a veth network to attach to (Ctrl-C tears it down)
sudo python3 ipa/test/netns_fabric.py --n-ports 5 --hold

# a pipeline on the ingress interface
sudo IPA_IFACE_PATTERN='ipa{i}' python3 ipa/execute_pipeline.py --method template --iface ipain
sudo python3 ipa/execute_pipeline.py --method hardcoded --iface ipain   # P1: the AOT object
```

`--method` is `hardcoded`, `template` or `modular`; the node prints HIT, MISS
and DROP live. Which interface implements which logical port is a property of
the node: `IPA_PORT_MAP="0=ipa0,1=ipa1,4=enp0s3"` (explicit) or
`IPA_IFACE_PATTERN="ipa{i}"` (by name). Attachment is **native** by default,
and the mode actually in use is read back from the kernel: a native attach
that fails is an error, not a silent fallback to generic. To remove a leftover
program: `sudo ip link set dev ipain xdp off`.

---

## How the datapath works

```
Ethernet → IP → UDP:9999 → IPA header (model_id)
   │
   ├── input vector, built ON THE NODE from the model descriptor:
   │     link_state · ingress_iface (ingress port)
   │     ttl (normalized) · node (node identity) · queue_occupancy
   │
   ├── integer neural network (8-bit weights, branch-free ReLU), argmax
   │
   └── class → action (FORWARD on a logical port / DROP / UNUSED)
                → logical port → interface (mac_table) → bpf_redirect
```

- **The input vector does not travel in the packet**: the node builds it from
  its own state. The widths come from the network (`topology_config.json`),
  the type and order of the features from the model (`model_meta.json`).
- **The class is not the port**: what each class means is declared by the
  model, which interface implements each port is declared by the node. In P2
  and P3 the class → action map is keyed by `(model_id, class)`: models with
  different meanings coexist in the same program.
- **The TTL enters normalized**, as in training (`ttl / 30`): the division is
  applied to the product with the weight, so no resolution is lost. The scale
  is a property of the model.
- **The node behaves as a router**: it decrements the TTL after the inference
  and updates the checksum; a packet that would expire goes to the stack (ICMP
  Time Exceeded).
- **The ReLU has no branch** (`x & ~(x >> 63)` behind a compiler barrier):
  with one branch per neuron the kernel verifier would reject P2 beyond two
  layers.
- **The IPA header** (21 bytes, UDP port 9999) selects the model with
  `model_id`; the weights are loaded by the control plane, not read from the
  packet.

The deposited model is trained on **Germany50** (SNDlib): 50 routers plus two
hosts, so 52 nodes, and maximum degree 6 (Karlsruhe with its host). Hence the
shape: 6 + 6 + 1 + 52 = **65 inputs**, 7 outputs. These numbers live in
`topologies/germany50/topology_config.json` and in the model card, never in
the engine.

---

## Other models, other networks

Every test and every bench accepts `--model` and `--topology`, including the
instrumented build of `--mode rates`:

```bash
python3 ipa/test/traffic_models.py                    # the 30 axis models, in ipa/synth/traffic/
python3 ipa/test/traffic_models.py --list nodes       # the directories of one axis
sudo python3 ipa/test/test_suite.py --only kernel --model synth:deep
sudo python3 ipa/test/test_fabric.py --model synth:small --topology synth_small
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp \
    --model ipa/synth/traffic/depth_3 --out results/depth_3
```

The axis models for network size and input composition come with their own
network: pass `--topology <dir>/topology_config.json` (the campaign does it
for you; `traffic_models.py --topology <dir>` prints the file, or nothing for
Germany50).

`--model` accepts `checkpoint`, `synth:<preset>` (ipa_like, deep, sparse,
ipa_ttl16, small, mixed, large, ones), a directory or another `.pt`. Without
`--model` the configured checkpoint runs; `--model checkpoint` sends the same
checkpoint through the generic path, which is how that path is checked against
the default one. The model must fit the network: every feature as wide as the
dimension it depends on, the TTL scale equal to the initial TTL. Otherwise the
test stops before compiling and says why; a pipeline that cannot run the shape
is reported as "not applicable", not as an error.

Compiled shape ceilings (`ipa/pipeline_limits.py`): at most 128 inputs and 32
outputs for every pipeline; P2 at most 8 neurons per hidden layer and 1 024
weights; P3 at most 16 layers, 8 neurons per layer and 2 048 weights.

---

## Documentation

| document | for whom |
|---|---|
| [`docs/testing.md`](docs/testing.md) | the complete guide to the tests and benches, with every figure |
| [`docs/claims.md`](docs/claims.md) | every claim of the thesis: hypothesis, measurement, number, command to reproduce it |
| [`docs/september_notebook.pdf`](docs/september_notebook.pdf) | the notebook: how it works and what it costs, explained from scratch |
| `docs/Inferenza … eBPF XDP.pptx` + `- spiegazione.pdf` | the results slides, and their explanation one by one, with a first page on how every measurement is taken |

To rebuild: `pdflatex september_notebook.tex` (from `docs/`), and
`python3 docs/slides_src/build.py` for the explanation PDF (the text is in
`docs/slides_src/spiegazione_inferenza.txt`).

---

## Limitations

- **Everything on one machine.** Generator, node and next node are cores of
  the same processor connected by `veth`: no network card, no DMA, no hardware
  interrupts. Absolute figures belong to this path at 3.5 GHz; the comparisons
  between pipelines hold. A virtual machine is not suitable: a virtual core can
  stall for milliseconds, longer than the ~170 µs the 256-slot queue allows.
- **The model does not decide on the destination**: the features do not
  contain the destination address. The TTL bounds loops, but routing by
  destination needs a model trained with that feature.
- **Weights do not travel in the packet**: the control plane loads them.
- **Networks up to ~115 nodes** in P2 and P3 (`MAX_N_IN` = 128); beyond that
  the ceiling must be raised and the measurements repeated.
- **Isolation at runtime**, not from boot (`isolcpus`, `nohz_full` not used).
- **Instrumented build**: T1/T2/T3 add two clock reads per packet; subtracting
  the baseline removes that cost, but the throughput of `--mode rates` is not a
  capacity. A single load of a program can occasionally land in an unfavourable
  code layout: an outlier point is re-measured before it is quoted.

---

## References

- M. Polverini, A. Cianfrani, M. Listanti, *"Intelligent Packets: Embedding Machine
  Learning Models into Network Packets"*, IEEE INFOCOM Workshops ICCN 2026 (submitted).
- M. Polverini, *"IPA Prototype"*,
  [github.com/marcopolverini/ipa-prototype](https://github.com/marcopolverini/ipa-prototype), 2026.
- S. Miano, F. Risso, *"Extended Berkeley Packet Filter"*, CNIT Technical Report 06 —
  Network Programmability, 2020.
- S. Orlowski et al., *"SNDlib 1.0 — Survivable Network Design Library"*, Networks,
  vol. 55, no. 3, 2010.
