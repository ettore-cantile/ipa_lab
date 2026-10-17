# IPA Lab — a neural network inside the Linux kernel, with eBPF/XDP

This repository runs a small neural network **inside the Linux kernel**, at the
first point a packet reaches (XDP), to decide which port the packet leaves
from. It is the lab implementation of **Intelligent PAckets (IPA)**: the packet
carries which model to use, and every node runs the inference on its own local
state.

The same network is written in **four versions**, from fully compiled to fully
configurable, and the repository measures what each choice costs: per packet,
in instructions, under real traffic, on different kinds of CPU core, over a
population of 109 models.

> This work extends the proof of concept by Polverini, Cianfrani and Listanti
> (Sapienza University of Rome / University of Molise). The documents in
> `docs/` are in Italian; this README and the code comments are in English.

## Contents

1. [The four versions](#the-four-versions)
2. [Results](#results)
3. [Repository layout](#repository-layout)
4. [Installation](#installation)
5. [Quick check: the tests](#quick-check-the-tests)
6. [Measurements](#measurements)
7. [Running a pipeline on an interface](#running-a-pipeline-on-an-interface)
8. [How the datapath works](#how-the-datapath-works)
9. [Documentation](#documentation)
10. [Limitations](#limitations)
11. [References](#references)

---

## The four versions

All four compute the same integer network (8-bit weights) and take the same
decision on the same packet. What changes is what is compiled into the program
and what the program reads from eBPF maps while it runs.

| | **P1** (`p1_static`) | **P1.5** (`hardcoded`) | **P2** (`template`) | **P3** (`modular`) |
|---|---|---|---|---|
| weights | in the code | in the code | in a map | in a map |
| node identity | in the code | in a map | in a map | in a map |
| layer widths | in the code | in the code | in a map (up to 8) | in a map (up to 8) |
| number of layers | in the code | in the code | in the code | in a map |
| tail calls per packet | 1 | 1 | 1 | 1 + layers |
| changing the model | recompile (off the node) | recompile (off the node) | write a map | write a map |

P1 and P1.5 are compiled offline with clang and the node only loads the object
(no compiler on the node). P2 and P3 are compiled once when the node starts.
Two reference programs complete the comparison: **baseline** (parse, TTL,
forward, no network) and **rxonly** (receive and drop).

---

## Results

Population campaign of October 2026: **109 synthetic models** (5–117 inputs,
1–6 hidden layers, 2–8 neurons per layer, 21–1 349 weights), every one measured
on every version. Data in [`results/popolazione_2026-10/`](results/popolazione_2026-10/),
summary in [`sintesi.md`](results/popolazione_2026-10/sintesi.md). Figures are
**median [min–max] over the models**; one node core at 3.5 GHz, 64-byte packets.

| | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| million packets/s, P-core | 15.0 | 8.4 [4.5–11.7] | 8.0 [4.5–11.6] | 3.4 [2.0–5.1] | 2.1 [1.1–3.3] |
| million packets/s, E-core | 9.4 | 6.4 [3.9–8.3] | 6.0 [3.8–8.3] | 2.8 [1.7–4.2] | 1.7 [0.9–2.6] |
| neural network, ns per packet (P-core) | — | 53 [19–155] | 58 [19–156] | 226 [129–446] | 421 [240–852] |
| table lookups per packet | — | 5 | 6 | 12 | 36 [23–54] |
| time to install a new model on a node | — | 0.6 ms | 0.9 ms | 0.3 ms | 0.3 ms |

In five lines:

- **Configurability is paid per packet**: P2 costs 4.4× P1 and P3 7.8× P1
  (medians), and the order P1 ≤ P2 ≤ P3 holds on every model.
- **The cost can be predicted before measuring**: network cost ≈ fixed +
  multiplications × cost of one + layers × cost of one, with 3–9 % error on
  models left out of the fit.
- **The bottleneck is the program**: above capacity packets are lost in the
  queue before the program; two cores carry twice the traffic.
- **An E-core runs the same instructions** (within 0.3 %) at lower IPC, and
  loses mostly in the node's fixed work.
- **Every version decides exactly like the integer reference** on every model
  it can run (P2 cannot run the 6 models with more than 1 024 weights).

---

## Repository layout

```
ipa_lab/
├── ipa/                     THE ENGINE: pipelines, inference, control plane
│   ├── ebpf_program.py        P1 / P1.5: C source with the weights as literals
│   ├── ebpf_template_arch.py  P2: one program per architecture, weights in maps
│   ├── ebpf_modular.py        P3: one program per layer, chained by tail calls
│   ├── execute_pipeline.py    attach a pipeline to an interface
│   ├── p1_aot.py, poc_aot/    P1 compiled offline and loaded with libbpf
│   ├── model_source.py        load any model (trained checkpoint or synthetic)
│   ├── class_semantics.py     what each output class means (forward / drop)
│   ├── node_config.py         logical port -> interface, per node
│   ├── synth/                 synthetic model generator
│   └── test/                  tests, benches and campaign scripts (below)
├── topologies/              network scenarios (Germany50 and synthetic ones)
├── results/                 measurements: one folder per campaign
└── docs/                    documents (Italian): test guide, claims, notebook
```

`ipa/test/` — the prefix says what a file is:

| prefix | what it is | files |
|---|---|---|
| `run_*.sh` | **entry points**: run a whole campaign | `run_population_campaign.sh`, `run_kernel_checks.sh` |
| `test_*.py` | **tests**; most need no root | `test_weights_and_metrics`, `test_class_semantics`, `test_synthetic_models`, `test_model_source`, `test_host_conditions`, `test_load_curve_math`, `test_capacity_window`, `test_forwarding` (root), `test_host_conditions_kernel` (root) |
| `check_*.py` | **checks on the programs loaded in the kernel** (root) | `check_pipelines`, `check_kernel_vs_reference`, `check_multi_model`, `check_semantics_per_model`, `check_model_swap`, `check_verifier_stats` |
| `bench_*.py` | **measurements** (root) | `bench_capacity` (full load), `bench_load_curve` (growing traffic), `bench_program_alone`, `bench_scaling`, `bench_depth_vs_width`, `bench_tail_call` |
| `report_*.py`, `plot_*.py` | **from CSV to conclusions and charts** (no root) | `report_population`, `report_population_facts`, `table_helpers`, `plot_load_curve` |
| no prefix | **libraries** used by the scripts above | `host_conditions`, `hw_counters`, `xdp_gen`, `netns_fabric`, `pipeline_setup`, `model_population`, `model_under_test`, `traffic_models`, `p1_c_eval`, `prog_census` |

Every script prints its usage with `--help`; its first lines say what it does.

---

## Installation

**Linux on a physical machine** (not a VM: see [Limitations](#limitations)).
On Ubuntu 24.04:

```bash
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r) \
                 clang libbpf-dev libelf-dev zlib1g-dev libzstd-dev liblzma-dev \
                 python3-numpy python3-matplotlib python3-networkx
pip install --user --break-system-packages torch   # optional: only to re-extract the checkpoint weights
```

Nothing else to build: the eBPF programs are compiled by the scripts against
the running kernel's headers.

---

## Quick check: the tests

From the repository root.

**Without root** (about a minute):

```bash
python3 ipa/test/test_synthetic_models.py     # 60 checks: synthetic models, P1's C against the reference
python3 ipa/test/test_class_semantics.py      # 69 checks: class -> action -> port
python3 ipa/test/test_model_source.py         # 62 checks: models, networks, compatibility
python3 ipa/test/test_weights_and_metrics.py  # weight extraction and quantization
python3 ipa/test/test_host_conditions.py      # 95 checks: machine conditions on a fake /sys
python3 ipa/test/test_load_curve_math.py      # 100 checks: the load-curve arithmetic
python3 ipa/test/test_capacity_window.py      # 18 checks (one is timing-sensitive)
```

**In the kernel** (root, a few minutes):

```bash
sudo python3 ipa/test/check_kernel_vs_reference.py --all --n 300   # eBPF = integer reference, 8 models
sudo python3 ipa/test/test_forwarding.py                           # packets leave by the right port
sudo python3 ipa/test/test_weights_and_metrics.py --only kernel    # program size, latency, lookups
```

Everything that needs no real traffic, in one go (~20 minutes, one line per
check, full logs in `/tmp/ipa_logs`):

```bash
bash ipa/test/run_kernel_checks.sh
```

The correctness criterion is the same for every version: the real program runs
in the kernel and must take the same decision as an independent integer Python
reference, and increment the right class counter.

---

## Measurements

### The bench

One machine plays every role: the traffic generator, the node running the
neural network, and the next node. They are connected by `veth` pairs with
native XDP, and each role has its own physical core (node on CPU 6, next node
on CPU 8, generator on CPU 10). The generator (`xdp_gen.py`) hands the node raw
XDP frames, as a network card with native XDP would.

`host_conditions.py` puts the machine in known conditions for the duration of
a measurement and restores it afterwards: fixed frequency (3.5 GHz, checked),
no deep idle states, everything else moved to other cores, and a monitor that
marks a measurement as *disturbed* if throttling, battery power or a wrong
frequency hit it.

### The population campaign

```bash
bash ipa/test/run_population_campaign.sh                    # everything, ~4.5 hours
bash ipa/test/run_population_campaign.sh genera pop         # only some sections
CAMPAGNA=results/popolazione_2026-10 bash ipa/test/run_population_campaign.sh sintesi
```

It asks for `sudo` once, prints one line per measurement (`ok` / `ERRORE`,
seconds, `[macchina disturbata]` when it applies) and writes:

```
results/popolazione_<date>/
├── population.csv           the models (shape, weights, multiplications, subsets)
├── corretto/corretto.csv    reference vs eBPF, every model and version
├── pop_Pcore/<model>/       full load on a P-core: compare.csv, env.csv, ...
├── pop_Ecore/<model>/       the same on an E-core
├── carico_*/, core2_*/, lpe/, classi/, mix/, taglie/   the subsets
├── solo/<model>/            the program alone
├── log/                     full output of every measurement
├── escluse.csv              measurements left out, and why
└── sintesi.md               the conclusions (report_population.py)
```

The campaign resumes where it stopped (a measurement already on disk is
skipped). A measurement hit by throttling keeps its clean rounds when enough of
them are left; otherwise it is listed in `escluse.csv`, and
`POP_RIFAI_DISTURBATE=1` measures exactly those again.

### A single measurement

```bash
# full load: capacity, CPU time, instructions per packet
sudo python3 ipa/test/bench_capacity.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --egress-cpu 8 --out results/try_compare

# growing traffic: where packets are lost, and the latency
sudo python3 ipa/test/bench_load_curve.py --generator xdp --gen-cpus 10 --dut-cpus 6 \
    --egress-cpu 8 --out results/try_load

# the program alone, for one model
sudo python3 ipa/test/bench_program_alone.py --model <model dir> --topology <model dir> --out results/try_solo
```

Every bench accepts `--model` (`checkpoint`, `synth:<preset>` or a model
directory, e.g. `ipa/synth/population/m037_...`) and `--topology`.

### Reading the results

- `compare.csv`: `rx_pps` packets per second, `ns_cpu` CPU time per packet,
  `instr_pkt` / `cycles_pkt` / `ipc` from the hardware counters.
- `env.csv`: the machine conditions of that measurement; `run_disturbed` says
  whether something disturbed it.
- Where packets are lost: before the program = the program is the bottleneck;
  after it = the transmission.

---

## Running a pipeline on an interface

```bash
sudo python3 ipa/test/netns_fabric.py --n-ports 5 --hold        # a veth network (Ctrl-C removes it)
sudo IPA_IFACE_PATTERN='ipa{i}' python3 ipa/execute_pipeline.py --method template --iface ipain
```

`--method` is `hardcoded` (P1, the AOT object), `template` (P2) or `modular`
(P3); the node prints forwarded, missed and dropped packets live. To remove a
leftover program: `sudo ip link set dev ipain xdp off`.

---

## How the datapath works

```
Ethernet -> IP -> UDP:9999 -> IPA header (model_id)
   |
   |-- input vector, built ON THE NODE: link state, ingress port,
   |   TTL (normalized), node identity, queue occupancy
   |-- integer neural network (8-bit weights, branch-free ReLU), argmax
   '-- class -> action (FORWARD on a logical port / DROP)
              -> logical port -> interface -> bpf_redirect
```

- The input vector does not travel in the packet: the node builds it from its
  own state. Feature widths come from the network (`topology_config.json`),
  their type and order from the model (`model_meta.json`).
- What a class means is declared by the model; which interface implements a
  port is declared by the node.
- A model is changed without stopping the packets: the new one is installed
  under a new `model_id`, senders switch, the old one is retired
  (`check_model_swap.py`).
- The trained model is for **Germany50** (SNDlib, 52 nodes, max degree 6):
  6 + 6 + 1 + 52 = 65 inputs, 7 outputs.

Shape limits (`ipa/pipeline_limits.py`): at most 128 inputs and 32 outputs; P2
at most 8 neurons per hidden layer and 1 024 weights; P3 at most 16 layers,
8 neurons per layer and 2 048 weights.

---

## Documentation

| document | content |
|---|---|
| [`docs/testing.md`](docs/testing.md) | every test and bench, with its results |
| [`docs/claims.md`](docs/claims.md) | every claim: hypothesis, measurement, number, command to reproduce it |
| [`docs/september_notebook.pdf`](docs/september_notebook.pdf) | the notebook: how it works and what it costs, from scratch |

The notebook is rebuilt with `pdflatex september_notebook.tex` (in `docs/`);
its cost-law chart with
`python3 ipa/test/report_population_facts.py results/popolazione_2026-10 --figura`.

---

## Limitations

- **Everything on one machine**: generator, node and next node are cores of
  the same processor connected by `veth`. Absolute figures belong to this path;
  the comparison between versions holds. A virtual machine is not suitable (a
  virtual core can stall for milliseconds).
- **Synthetic models**: they cover shapes, inputs and weights, not the accuracy
  of a trained model.
- **The model does not see the destination**: the features do not include it.
- **Isolation at runtime**, not from boot (`isolcpus`, `nohz_full` not used).

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
