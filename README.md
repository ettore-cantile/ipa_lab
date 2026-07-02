# IPA Lab — Intelligent PAckets with eBPF

This repository contains the lab implementation of **Intelligent PAckets (IPA)** with an eBPF-accelerated data plane, developed on top of the [Katharà](https://github.com/KatharaFramework/Kathara) network emulator. The goal is to embed compact machine learning models directly inside packet headers and execute per-hop inference to achieve adaptive, mission-driven forwarding decisions — without any control-plane signaling.

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

The topology is imported from `germany50.xml` via `importSNDLib.py`, which also generates the Katharà-compatible `germany_kathara.xml` lab configuration.

---

## Repository Structure

```
ipa_lab/
├── shared/
│   ├── switch_core.py          # Entry point: selects and runs the chosen method
│   ├── ebpf_program.py         # eBPF/XDP C code shared by all methods
│   ├── common.py               # Shared helpers (load_bpf, populate tables, stats_loop…)
│   ├── weights.json            # Int8 weights — PTQ (Method 1 & 3)
│   ├── weights_float.json      # Float weights + scale_factor — PTQ reference
│   ├── weights_method2.json    # Int8 weights — QAT (Method 2)
│   └── methods/
│       ├── method1_ptq.py      # Method 1 — Post-Training Quantization
│       ├── method2_qat.py      # Method 2 — Quantization-Aware Training
│       └── method3_openflow.py # Method 3 — OpenFlow-like on-demand CP
├── esegui_pipeline.py          # Training pipeline (PTQ or QAT)
└── extract_weights.py          # Exports float/int8 weights to JSON
```

---

## How to Run

```bash
# Method 1 — PTQ
python3 /shared/switch_core.py

# Method 2 — QAT
python3 /shared/switch_core.py weights_method2.json

# Method 3 — OpenFlow-like
python3 /shared/switch_core.py weights.json openflow
```

---

## Training Pipeline

Run the full pipeline from your local machine (requires Python 3.10+, PyTorch, pandas, networkx, scikit-learn):

```bash
# Method 1 — standard float training (PTQ)
python esegui_pipeline.py

# Method 2 — Quantization-Aware Training
python esegui_pipeline.py --method qat
```

The pipeline produces:
- `frr_germany50_5_model_4x2.pt` (Method 1) or `frr_qat_model.pt` (Method 2)
- `weights.json` — int8 quantized weights for the eBPF switch
- `weights_float.json` — float weights + `scale_factor` (PTQ reference)

Copy `weights.json` (and `weights_float.json` for Method 1/3) into `shared/` before starting the Katharà lab.

---

## eBPF Kernel Architecture

`ebpf_program.py` contains the XDP C program shared by all three methods. The kernel:

1. Parses Ethernet → IP → UDP → IPA header from each incoming packet on port 9999.
2. Looks up the model weights in `model_cache` (keyed by `model_id`).
3. Computes the forwarding key via integer dot-product:

```c
iv[0] = ipa->model_id;   iv[1] = ip->ttl;
iv[2] = ingress_ifindex; iv[3] = ipa->input_size;

output_raw = sum(iv[i] * (signed char)weights[i]);
key        = (output_raw + OUTPUT_OFFSET * scale) / scale;
```

4. Looks up `key` in `fwd_table` → redirects with `bpf_redirect()` or sends a `miss_event` to userspace.
5. Classifies the packet using `valid_keys` (TTL → correct CP key):

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

> After convergence (all distinct TTLs seen at least once): TRUE HIT grow steadily, MISS plateau at the number of distinct TTLs in traffic, FAKE HIT drop to 0.

---

## Comparative Summary

| | Method 1 (PTQ) | Method 2 (QAT) | Method 3 (OpenFlow) |
|---|---|---|---|
| **CP weights** | Float originals | Int8 raw | N/A — uses `ev.key` |
| **CP/kernel alignment** | ✗ Intentional | ✓ Perfect | ✓ Perfect |
| **Table population** | Static at startup | Static at startup | Dynamic on-demand |
| **TRUE HIT** | ~0% | ~100% | ~100% post warm-up |
| **FAKE HIT** | High (PTQ error metric) | 0% | Warm-up only |
| **MISS** | Medium | 0% | One per new TTL |
| **Scalability** | Fixed TTL range | Fixed TTL range | Unlimited |
| **SCALE_FACTOR** | Auto (e.g. 24) | Fixed 128 | Auto (e.g. 24) |

---

## Implementation Notes

### BCC: `__u8`/`__u64` not recognized
The installed BCC version cannot auto-generate a Python class from `struct miss_event` because it does not recognize kernel types `__u8`, `__u32`, `__u64`. Solution: `MissEvent` is defined manually as a `ctypes.Structure` with `from_buffer_copy()` parsing.

### C struct padding
The compiler inserts implicit padding in the (non-packed) `miss_event`:
- 2 bytes after `ttl` to align `__u32 ingress_ifindex`
- 7 bytes after `input_size` to align `__u64 key` at offset 16

Total: 24 bytes. The Python struct replicates this with `_pack_=1` and explicit `_pad` fields.

### Float rounding error (±1)
Computing the key with floats produces results that differ by ±1 from the kernel's integer division. Methods 2 and 3 use `//` (Python integer division) to replicate the C truncation exactly. In Method 1 this divergence is intentional — it is the PTQ error metric.

---

## References

- M. Polverini, A. Cianfrani, M. Listanti, *"Intelligent Packets: Embedding Machine Learning Models into Network Packets"*, submitted to IEEE INFOCOM Workshops ICCN 2026.
- M. Polverini, *"IPA Prototype"*, [github.com/marcopolverini/ipa-prototype](https://github.com/marcopolverini/ipa-prototype), 2026.
- S. Miano, F. Risso, *"Extended Berkeley Packet Filter"*, CNIT Technical Report 06 — Network Programmability, 2020.
- S. Orlowski et al., *"SNDlib 1.0 — Survivable Network Design Library"*, Networks, vol. 55, no. 3, 2010.
