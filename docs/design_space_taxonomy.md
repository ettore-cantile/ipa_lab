# IPA/eBPF Design Space Taxonomy

## Overview

This document formalises the three implementation points in the IPA/eBPF design space, as discussed with the professor.
The central thesis is:

> IPA/eBPF does not have a single natural implementation. There exists a design space in which one can choose how much to specialise the model in the datapath versus how much runtime flexibility to maintain.

The evaluation question therefore becomes: **what is the cost of making IPA more flexible in the datapath?**

---

## Design Space — Three Levels

### Level 1 — Hardcoded Model (baseline)

| Property | Value |
|---|---|
| eBPF programs | 1 per model (`model_<id>.o`) |
| Weights | Hardcoded in C |
| Tail calls | 1 (dispatcher → model) |
| Intermediate state | None |
| Flexibility | Low |
| Expected performance | Maximum |

Each model is compiled into a dedicated eBPF program that contains feature extraction, hardcoded weights, full inference, argmax, and action selection. Updating the model requires code regeneration, recompilation, and program reload.

**Pipeline:**
```
packet → dispatcher --tail call--> model_<id> → action
```

---

### Level 2 — Pre-built Architecture Template

| Property | Value |
|---|---|
| eBPF programs | 1 per architecture shape (`arch_<shape>.o`) |
| Weights | BPF map (model-specific, quantized) |
| Tail calls | 1 (dispatcher → arch template) |
| Intermediate state | Local to program |
| Flexibility | Medium |
| Expected performance | High / intermediate |

One eBPF program per common architecture (e.g. `arch_8_6_6_4`). A BPF map maps `model_id → arch_id + weight_offset + alpha`. Weights are read from the map at inference time. No recompilation needed for weight updates.

**Pipeline:**
```
packet → dispatcher → model_registry[model_id] --tail call--> arch_<shape>
       → reads weights from BPF map → full inference → action
```

---

### Level 3 — Modular Neural Pipeline

| Property | Value |
|---|---|
| eBPF programs | 1 per layer block (`layer_N_to_M.o`) |
| Weights | BPF map (per-layer) |
| Tail calls | ≥ 1 per layer (chained) |
| Intermediate state | BPF_PERCPU_ARRAY scratch map |
| Flexibility | Maximum |
| Expected performance | Lower |

Inference is decomposed into reusable layer blocks connected through tail calls. Intermediate activations pass through a `BPF_PERCPU_ARRAY` scratch map. A new model/architecture is deployed by changing layer sequence and weights only.

**Pipeline:**
```
packet → dispatcher → layer_block_1 --scratch+tail call-->
       layer_block_2 --scratch+tail call--> layer_block_3 → argmax/action
```

---

## Trade-off Summary

| Solution | eBPF code | Weights | Tail calls | Intermediate state | Flexibility | Expected perf |
|---|---|---|---|---|---|---|
| Hardcoded model | 1 prog/model | Hardcoded | 1 | None | Low | Maximum |
| Arch template | 1 prog/arch | BPF map | 1 | Local to program | Medium | High/intermediate |
| Layer modules | 1 prog/block | BPF map | > 1 | Scratch map/header | High | Lower |

As flexibility increases:
- Code specialisation decreases
- Map lookups, tail calls, and state passing increase
- Maximum achievable performance decreases

---

## Experimental Metrics

To demonstrate the trade-off empirically, measure:

- Latency per packet (ns)
- Maximum throughput (Mpps)
- CPU utilisation (%)
- eBPF instruction count
- Number of tail calls per packet
- Number of map lookups per packet
- Model update time (control plane cost)
- Memory footprint (programs + maps)

### Control-plane flexibility cost

| Solution | Model update procedure |
|---|---|
| Hardcoded | Recompile + reload eBPF program |
| Arch template | Update weight BPF map |
| Layer modules | Change layer sequence + update weight maps |

---

## Paper-style Formulation

> We consider three implementation points in the IPA/eBPF design space. The first one hardcodes each neural model into a dedicated eBPF program, maximizing datapath performance at the cost of requiring code regeneration and program reloading for each model update. The second one relies on pre-built architectural templates, where each eBPF program implements a common neural architecture and retrieves model-specific quantized parameters from BPF maps. This reduces recompilation needs while preserving a statically verifiable inference structure. The third one decomposes neural inference into reusable eBPF layer modules connected through tail calls, using a per-CPU scratch map to exchange intermediate activations. This maximizes architectural flexibility, but introduces additional tail calls and map accesses, thus reducing the maximum achievable packet processing rate.
