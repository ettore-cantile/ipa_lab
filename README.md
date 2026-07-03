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
| Nodes | 50 (+ 2 virtual hosts) |
| Max node degree | 6 |
| Total nodes in emulation | 52 |
| Source host | `h_src` attached to **Karlsruhe** |
| Destination host | `h_dst` attached to **Flensburg** |
| Max simultaneous failures | 10 |

The topology is imported from `germany50.xml` via `importSNDLib.py`, which also generates the Kathara-compatible `germany_kathara.xml` lab configuration.

---

## Repository Structure

```
ipa_lab/
├── shared/
│   ├── switch_core.py          # Entry point: selects and runs the chosen method
│   ├── ebpf_program.py         # eBPF/XDP C code shared by all methods
│   ├── common.py               # Shared helpers (load_bpf, populate tables, stats_loop…)
│   ├── send_ipa.py             # Scapy sender: builds and sends a single IPA packet
│   ├── test_ipa.py             # Scapy sender: performance tester (N packets)
│   ├── weights.json            # Int8 weights — PTQ (Method 1)
│   ├── weights_float.json      # Float weights + scale_factor — PTQ reference
│   ├── weights_method2.json    # Int8 weights — QAT (Method 2, 3, 4)
│   └── methods/
│       ├── method1_ptq.py      # Method 1 — Post-Training Quantization
│       ├── method2_qat.py      # Method 2 — Quantization-Aware Training
│       ├── method3_openflow.py # Method 3 — OpenFlow-like on-demand CP
│       └── method4_ipa_demo.py # Method 4 — IPA Demo (model travels in packet)
├── execute_pipeline.py          # Training pipeline (PTQ or QAT)
└── extract_weights.py          # Exports float/int8 weights to JSON
```

---

## How to Run

All commands are run **inside the Kathara containers** from `/shared`.
`switch_core.py` is launched on the **router node** (e.g. `frankfurt`);
`test_ipa.py` is launched on a **sender node** (e.g. `darmstadt`).

```bash
# Method 1 — PTQ (default)
python3 /shared/switch_core.py ptq

# Method 2 — QAT
python3 /shared/switch_core.py qat

# Method 3 — OpenFlow-like
python3 /shared/switch_core.py openflow

# Method 4 — IPA Demo
python3 /shared/switch_core.py ipa_demo

# Custom model_id (any method)
python3 /shared/switch_core.py qat 99
```

---

## Testing

### Method 1 — PTQ

```bash
# Router (frankfurt)
python3 /shared/switch_core.py ptq

# Sender (darmstadt) — nessun payload di pesi
python3 /shared/test_ipa.py --dest frankfurt --count 30 --model-id 42
```

**Atteso:** FAKE HIT elevati (errore PTQ), pochi TRUE HIT, qualche MISS.

---

### Method 2 — QAT

```bash
# Router (frankfurt)
python3 /shared/switch_core.py qat

# Sender (darmstadt)
python3 /shared/test_ipa.py --dest frankfurt --count 30 --model-id 42
```

**Atteso:** TRUE HIT ~100%, FAKE HIT = 0, MISS = 0.

---

### Method 3 — OpenFlow

```bash
# Router (frankfurt)
python3 /shared/switch_core.py openflow

# Sender (darmstadt) — primo round: MISS mentre la fwd_table si popola
python3 /shared/test_ipa.py --dest frankfurt --count 30 --model-id 42

# Sender (darmstadt) — secondo round: TRUE HIT sui TTL gia' visti
python3 /shared/test_ipa.py --dest frankfurt --count 30 --model-id 42
```

**Atteso primo round:** tutti MISS + log `[CP] FWD MISS | TTL=X -> INSTALLED` sul router.
**Atteso secondo round:** TRUE HIT crescenti, MISS solo per TTL mai visti.

---

### Method 4 — IPA Demo

```bash
# Router (frankfurt) — model_cache e fwd_table partono vuote
python3 /shared/switch_core.py ipa_demo

# Sender (darmstadt) — primo pacchetto con pesi nel payload
python3 /shared/test_ipa.py --dest frankfurt --count 30 \
        --model-id 42 --weights-file /shared/weights_method2.json
```

Il primo pacchetto triggera sul router:
```
[CP] MODEL MISS | model_id=42 | weights extracted from packet: [42, 35, 127, -58]
[cache] Model 42 loaded | 4 weights | scale_factor=128
[CP] model_id=42 LOADED & rule INSTALLED | key=XXXXX | TTL=YY | elapsed=1.XX ms
[CP] Next packets for model_id=42 -> TRUE HIT (<1 ms)
```

I pacchetti successivi con lo stesso TTL producono TRUE HIT direttamente dal kernel.
TTL non ancora visti producono `[CP] FWD MISS (safety net)` finché non sono installati.

**Atteso alla fine:** TRUE HIT crescenti, FAKE HIT = 0.

---

### Invio pacchetto singolo (`send_ipa.py`)

```bash
# Pacchetto senza pesi (model gia' in cache)
python3 /shared/send_ipa.py frankfurt 42

# Pacchetto con pesi nel payload (Method 4, primo pacchetto)
python3 /shared/send_ipa.py frankfurt 42 /shared/weights_method2.json

# model_id personalizzato
python3 /shared/send_ipa.py frankfurt 99 /shared/weights_method2.json
```

---

## Training Pipeline

Run the full pipeline from your local machine (requires Python 3.10+, PyTorch, pandas, networkx, scikit-learn):

```bash
# Method 1 — standard float training (PTQ)
python execute_pipeline.py

# Method 2 — Quantization-Aware Training
python execute_pipeline.py --method qat
```

The pipeline produces:
- `frr_germany50_5_model_4x2.pt` (Method 1) or `frr_qat_model.pt` (Method 2)
- `weights.json` — int8 quantized weights for the eBPF switch
- `weights_float.json` — float weights + `scale_factor` (PTQ reference)

Copy `weights.json` (and `weights_float.json` for Method 1) into `shared/` before starting the Kathara lab.

---

## eBPF Kernel Architecture

`ebpf_program.py` contains the XDP C program shared by all four methods. The kernel:

1. Parses Ethernet → IP → UDP → IPA header from each incoming packet on port 9999.
2. Looks up the model weights in `model_cache` (keyed by `model_id`).
3. If the model is **not** in cache, emits a `model_miss_event` to userspace carrying the raw weight bytes extracted from the packet payload (Method 4 only).
4. Computes the forwarding key via integer dot-product:

```c
iv[0] = ipa->model_id;   iv[1] = ip->ttl;
iv[2] = ingress_ifindex; iv[3] = ipa->input_size;

output_raw = sum(iv[i] * (signed char)weights[i]);
key        = (output_raw + OUTPUT_OFFSET * scale) / scale;
```

5. Looks up `key` in `fwd_table` → redirects with `bpf_redirect()` or sends a `miss_event` to userspace.
6. Classifies the packet using `valid_keys` (TTL → correct CP key):

| Result | Condition |
|---|---|
| **TRUE HIT** | `fwd_table[key]` found **and** `valid_keys[ttl] == key` |
| **FAKE HIT** | `fwd_table[key]` found **but** `valid_keys[ttl] != key` |
| **MISS** | `fwd_table[key]` not found |

---

## Forwarding Methods

### Method 1 — Post-Training Quantization (PTQ)

The model is trained in float32 and quantized *a posteriori*. The Control Plane uses the **original float weights** to populate `fwd_table` and `valid_keys`, while the kernel uses the int8 weights. This **intentional asymmetry** produces measurable FAKE HIT and MISS — which quantify the accuracy loss of PTQ.

```python
# Intentionally uses float weights -> diverges from kernel
populate_fwd_and_valid_keys(b, action, cp_weights, SCALE_FACTOR,
                            integer_arithmetic=False)
```

**Experimental results (30 packets):**

| TRUE HIT | FAKE HIT | MISS |
|---|---|---|
| 0 (0%) | 18 (60%) | 12 (40%) |

---

### Method 2 — Quantization-Aware Training (QAT)

The model is trained directly with int8 weights using fake-quantization (STE). `SCALE_FACTOR` is fixed at 128. Kernel and CP use identical **pure integer arithmetic** → keys always match.

```python
# Pure integer arithmetic — identical to kernel
populate_fwd_and_valid_keys(b, action, int8_weights, SCALE_FACTOR,
                            integer_arithmetic=True)

# key = (sum(iv[i] * int8(w[i])) + OFFSET * scale) // scale
```

The `//` operator in Python replicates the C integer division exactly, eliminating the ±1 rounding error that floats introduce.

**Experimental results (30 packets):**

| TRUE HIT | FAKE HIT | MISS |
|---|---|---|
| 30 (100%) | 0 (0%) | 0 (0%) |

---

### Method 3 — OpenFlow-like (Control Plane on-demand)

`fwd_table` starts **empty**. On every MISS the kernel sends a `miss_event` to the CP via `BPF_PERF_OUTPUT`. The CP installs the rule using `ev.key` directly — no recomputation in user space, zero risk of mismatch.

```python
def handle_miss(cpu, data, size):
    ev  = MissEvent.from_buffer_copy(...)
    key = ev.key  # already computed by kernel — use directly
    fwd[ctypes.c_ulonglong(key)] = action
    vk[ctypes.c_uint8(ev.ttl)]   = ctypes.c_ulonglong(key)
```

**Packet lifecycle:**
- **First packet** (new TTL) → MISS → CP installs rule → `XDP_PASS`
- **Subsequent packets** (same TTL) → TRUE HIT → `bpf_redirect`
- **Warm-up FAKE HIT** → accidental key collisions while table is filling; disappear after convergence

Unlike Methods 1/2, this approach scales to **any** IV combination without hardcoded TTL ranges.

**Experimental results (30 packets — warm-up snapshot):**

| TRUE HIT | FAKE HIT | MISS |
|---|---|---|
| 5 (17%) | 14 (47%) | 11 (37%) |

> After convergence (all distinct TTLs seen at least once): TRUE HIT grow steadily, MISS plateau at the number of distinct TTLs in traffic.

---

### Method 4 — IPA Demo ("Wow Factor")

This is the **core demonstration of the IPA paradigm** as described in IPA_Demo.pdf. It is a direct evolution of Method 3: both start with empty tables and install rules on-demand, but Method 4 takes one step further — the **model itself travels inside the packet payload** and is unknown to the router at boot time.

#### How it works

`model_cache` **and** `fwd_table` start completely empty. No model is pre-loaded, no rules are pre-installed.

When the **first packet** for a new `model_id` arrives:
1. The kernel detects the model is missing from `model_cache`.
2. It reads the 4 raw int8 weight bytes embedded in the UDP payload immediately after the IPA header.
3. It emits a `model_miss_event` to userspace carrying those weights.
4. The CP extracts the weights, loads them into `model_cache`, and installs the forwarding rule for that TTL — all in a single callback (~2 ms).
5. Subsequent TTL values not yet seen trigger `FWD MISS` → safety net installs rules on-demand.

From the **second packet** onwards (same TTL):
- The kernel finds the model in cache, computes the key, finds the rule → **TRUE HIT** (<1 ms). The CP is never involved again.

#### Sending packets

```bash
# First packet — embeds the model weights in the payload
python3 /shared/send_ipa.py frankfurt 99 /shared/weights_method2.json

# Output on the router:
# [CP] MODEL MISS | model_id=99 | weights extracted from packet: [42, 35, 127, -58]
# Model 99 loaded into eBPF cache (scale_factor=128)
# [CP] model_id=99 LOADED & rule INSTALLED | key=100221 | TTL=64 | elapsed=1.89 ms
# [CP] Next packets for model_id=99 -> TRUE HIT (<1 ms)

# Subsequent packets — no weights needed, model already in cache
python3 /shared/send_ipa.py frankfurt 99

# Output on the router:
# TRUE HIT counter increments directly — CP is silent
```

#### Why the verifier accepts this

eBPF forbids pointer arithmetic on `data_end`. The weight copy uses **4 fixed-offset reads** with a single bound check instead of a loop:

```c
__u8 *w = (__u8 *)(ipa + 1);
if ((void *)(w + 4) > data_end) return XDP_PASS;  // one check
mev.w0 = w[0]; mev.w1 = w[1]; mev.w2 = w[2]; mev.w3 = w[3];
```

#### Method 3 vs Method 4

| | Method 3 (OpenFlow) | Method 4 (IPA Demo) |
|---|---|---|
| `model_cache` at boot | Pre-populated | **Empty** |
| `fwd_table` at boot | Empty | Empty |
| Model source | Local file at boot | **Packet payload** |
| First packet | Fwd MISS → rule install | **Model MISS → extract + install** |
| Subsequent packets | TRUE HIT | TRUE HIT |
| Latency (1st pkt) | ~1 ms | ~2 ms |
| Latency (2nd+ pkt) | <1 ms | <1 ms |

Method 4 is the proof that the IPA paradigm works end-to-end: the intelligence is in the packet, the router learns it on the fly, and from that moment on it forwards autonomously at kernel speed.

---

## Comparative Summary

| | Method 1 (PTQ) | Method 2 (QAT) | Method 3 (OpenFlow) | Method 4 (IPA Demo) |
|---|---|---|---|---|
| **CP weights** | Float originals | Int8 raw | N/A — uses `ev.key` | Extracted from packet |
| **CP/kernel alignment** | ✗ Intentional | ✓ Perfect | ✓ Perfect | ✓ Perfect |
| **model_cache at boot** | Pre-populated | Pre-populated | Pre-populated | **Empty** |
| **Table population** | Static at startup | Static at startup | Dynamic on-demand | Dynamic on-demand |
| **Model source** | Local file | Local file | Local file | **Packet payload** |
| **TRUE HIT** | ~0% | ~100% | ~100% post warm-up | ~100% post 1st pkt |
| **FAKE HIT** | High (PTQ error) | 0% | Warm-up only | 0% |
| **MISS** | Medium | 0% | One per new TTL | One (very first pkt) |
| **Scalability** | Fixed TTL range | Fixed TTL range | Unlimited | Unlimited |
| **SCALE_FACTOR** | Fixed 128 | Fixed 128 | Fixed 128 | Fixed 128 |

---

## Implementation Notes

### BCC: `__u8`/`__u64` not recognized
The installed BCC version cannot auto-generate a Python class from `struct miss_event` because it does not recognize kernel types `__u8`, `__u32`, `__u64`. Solution: `MissEvent` and `ModelMissEvent` are defined manually as `ctypes.Structure` with `from_buffer_copy()` parsing.

### C struct padding
The compiler inserts implicit padding in the (non-packed) `miss_event`:
- 2 bytes after `ttl` to align `__u32 ingress_ifindex`
- 7 bytes after `input_size` to align `__u64 key` at offset 16

Total: 24 bytes. The Python struct replicates this with `_pack_=1` and explicit `_pad` fields.

### Float rounding error (±1)
Computing the key with floats produces results that differ by ±1 from the kernel's integer division. Methods 2, 3, and 4 use `//` (Python integer division) to replicate the C truncation exactly. In Method 1 this divergence is intentional — it is the PTQ error metric.

### eBPF verifier: no pointer arithmetic on `data_end`
The eBPF verifier rejects any loop where the bound check involves incrementing a pointer derived from `data_end`. Method 4 avoids this by reading exactly 4 weight bytes at fixed offsets with a single static bound check.

---

## References

- M. Polverini, A. Cianfrani, M. Listanti, *"Intelligent Packets: Embedding Machine Learning Models into Network Packets"*, submitted to IEEE INFOCOM Workshops ICCN 2026.
- M. Polverini, *"IPA Prototype"*, [github.com/marcopolverini/ipa-prototype](https://github.com/marcopolverini/ipa-prototype), 2026.
- S. Miano, F. Risso, *"Extended Berkeley Packet Filter"*, CNIT Technical Report 06 — Network Programmability, 2020.
- S. Orlowski et al., *"SNDlib 1.0 — Survivable Network Design Library"*, Networks, vol. 55, no. 3, 2010.
