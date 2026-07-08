# IPA/eBPF Design Space: Performance vs Flexibility Trade-off

## Overview

This document captures the three-point design space for IPA (In-Packet Autonomy) inference
implemented via eBPF/XDP, as defined in the professor's taxonomy.

The central thesis is:
> IPA/eBPF does not have a single natural implementation. There exists a design space
> in which one can choose how much to specialise the model in the datapath and how much
> to maintain runtime flexibility.

The evaluation question is not merely "how fast is eBPF", but:
> **What is the cost of making IPA more flexible in the datapath?**

---

## The Three Pipelines

### Pipeline 1 — Hardcoded Model (baseline)

**File:** `shared/ebpf_program.py`

Each model is compiled into a dedicated eBPF program. Weights are baked as C constants
at code-generation time. The dispatcher uses a single tail call to `model_<id>`.

```
packet → dispatcher → (tail call) model_<id> → action
```

| Dimension | Value |
|---|---|
| eBPF programs | 1 per model |
| Weights | hardcoded in C source |
| Tail calls | 1 |
| Intermediate state | none |
| Flexibility | **low** |
| Expected perf | **maximum** |

**Update cost:** recompile + reload the eBPF program.

---

### Pipeline 2 — Pre-built Architectural Template

**File:** `shared/ebpf_template_arch.py`

One eBPF program exists *per architecture shape* (e.g. `arch_8_6_6_4`, `arch_65_4_4_7`).
Multiple models with the same architecture share the same program; the dispatcher
looks up `model_registry[model_id]` to obtain `arch_id + weight_offset + scale_factor`,
then tail-calls the matching architectural template.
The template reads weights from a `BPF_ARRAY` map at runtime.

```
packet → dispatcher → model_registry[model_id]
       → (tail call) arch_<shape>
       → reads weights from BPF map
       → full inference → action
```

| Dimension | Value |
|---|---|
| eBPF programs | 1 per architecture shape |
| Weights | BPF map (loadable at runtime) |
| Tail calls | 1 |
| Intermediate state | local to the program frame |
| Flexibility | **medium** |
| Expected perf | **high / intermediate** |

**Update cost:** update the weight map (no recompile needed).

---

### Pipeline 3 — Modular Neural Pipeline

**File:** `shared/ebpf_modular.py`

Inference is decomposed into reusable eBPF layer-block programs.
Each block implements one linear transformation `N_in → N_out` with ReLU.
Intermediate activations are exchanged via a `BPF_PERCPU_ARRAY` scratch map.
The dispatcher chains blocks via successive tail calls.

```
packet → dispatcher
       → layer_block_1 → (scratch map write + tail call)
       → layer_block_2 → (scratch map write + tail call)
       → layer_block_N → argmax → action
```

| Dimension | Value |
|---|---|
| eBPF programs | 1 per layer shape (reusable across models) |
| Weights | BPF map |
| Tail calls | N (one per hidden layer + output) |
| Intermediate state | `BPF_PERCPU_ARRAY` scratch map |
| Flexibility | **maximum** |
| Expected perf | **lower** |

**Update cost:** update weight map + change layer chain sequence (no recompile).

---

## Comparative Summary

| Solution | eBPF code | Weights | Tail calls | Intermediate state | Flexibility | Perf |
|---|---|---|---|---|---|---|
| Hardcoded model | 1 prog/model | hardcoded | 1 | none | low | **max** |
| Arch template | 1 prog/arch | BPF map | 1 | local frame | medium | high |
| Modular pipeline | 1 prog/layer | BPF map | N | scratch map | **max** | lower |

---

## Experimental Metrics to Measure

The benchmark (`shared/pipeline_benchmark.py`) collects:

- **Datapath metrics** (per packet):
  - Latency (ns/pkt)
  - Throughput (Mpps)
  - CPU utilisation
  - Number of eBPF instructions executed
  - Number of tail calls
  - Number of BPF map lookups

- **Control-plane flexibility metrics**:
  - Model update time (hardcoded: recompile+reload; template: map update; modular: map update + chain swap)
  - Memory footprint (programs + maps)

The key insight is that flexibility has a *cost* and this cost must be *measured*, not assumed.

---

## Paper Formulation (from professor)

> We consider three implementation points in the IPA/eBPF design space. The first one
> hardcodes each neural model into a dedicated eBPF program, maximizing datapath
> performance at the cost of requiring code regeneration and program reloading for each
> model update. The second one relies on pre-built architectural templates, where each
> eBPF program implements a common neural architecture and retrieves model-specific
> quantized parameters from BPF maps. This reduces recompilation needs while preserving
> a statically verifiable inference structure. The third one decomposes neural inference
> into reusable eBPF layer modules connected through tail calls, using a per-CPU scratch
> map to exchange intermediate activations. This maximizes architectural flexibility, but
> introduces additional tail calls and map accesses, thus reducing the maximum achievable
> packet processing rate.

---

## Implementation Notes

### eBPF Verifier Constraints
- No loops over runtime variables (all layer dimensions must be compile-time constants or bounded)
- Maximum 33 consecutive tail calls (Linux kernel limit)
- `BPF_PERCPU_ARRAY` for scratch map avoids lock contention across CPUs
- All array accesses need explicit bounds checks for the verifier
- **BPF stack is capped at 512 bytes** per program — large per-neuron
  lookup tables or unrolled feature vectors overflow this budget
  (see Pipeline 1 case study below)
- **CFG path explosion**: branching on a runtime value (`switch`/`if`
  chains) multiplies the number of paths the verifier must explore.
  Repeating the same branch *per loop iteration* (e.g. once per hidden
  neuron) makes this multiplicative across iterations, not additive —
  it can blow past the verifier's 1,000,000-instruction exploration
  budget ("Permission denied") well before any real complexity limit
  is reached
- **BCC (non-CO-RE) cannot relocate arbitrary global/`.rodata` data**
  for XDP programs — a `static const` array declared inside a BCC C
  function is not backed by a real map, so its address may collapse to
  a literal `0` at load time, and any access is rejected by the
  verifier ("invalid mem access 'scalar'"). Genuine read-only lookup
  tables must live in a `BPF_ARRAY` map (as Pipelines 2 and 3 already
  do), or be avoided entirely on the "hardcoded" path.

#### Case study: Pipeline 1 hardcoded-weight verifier fix
Encoding `fc1` for the 65-4-4-7 model only needs 3 live features per
packet (`ttl`, ingress-iface one-hot, node one-hot), so the weight
associated with each one-hot feature depends on a runtime-bounded index
(`_iface` ∈ 1..6, `_node` ∈ 0..51). Two implementations were tried and
rejected before landing on the current one:

1. **`switch(_iface){...}` + `switch(_node){...}` once per hidden
   neuron.** With `N_H1=4` neurons, the two switches (7 × 52 branches)
   are repeated 4 times in sequence without ever letting the verifier
   collapse the state back to a bounded range, so the explored path
   count grows as `(7·52)^4 ≈ 1.75·10^10` — far past the verifier's
   budget → load fails with `Permission denied`.
2. **Per-neuron `static const __s64 W_IFACE_j[7]` / `W_NODE_j[64]`
   arrays**, indexed with a masked variable. This avoids the path
   explosion (it's a single array read, not a branch tree), but BCC
   compiles these `static const` arrays as unrelocated global data for
   XDP, so the emitted load reads from address `0` → verifier rejects
   with `R1 invalid mem access 'scalar'`.
3. **Fix (current code):** emit **one** `switch(_iface)` and **one**
   `switch(_node)` for the *whole* program, where each `case` assigns
   the contribution for **all** `N_H1` neurons at once
   (`w_iface_0..w_iface_{N-1}`, `w_node_0..w_node_{N-1}`). The number of
   branches stays `O(7 + 52)` regardless of `N_H1` (no multiplicative
   blow-up), and every value lives in a plain stack scalar (8 ×
   `long long` = 64 B) — no globals, no maps, no map-lookup overhead.
   This preserves Pipeline 1's "zero weight-map-lookups" design point
   while satisfying the verifier.
4. **The same broken-global-array pattern reappeared** one step later,
   in the post-argmax action: `static const __u32 IFINDEX_TABLE[6]`
   indexed by `best_cls` (0..5). Identical symptom
   (`R7 invalid mem access 'scalar'`), identical root cause (BCC does
   not relocate `static`/global data for XDP), identical fix: a
   `switch (best_cls) { case 0: egress_ifindex = ...; break; ... }`.
   Since `best_cls` is a single scalar decided once per packet (not
   iterated per neuron), this switch was never at risk of the CFG
   explosion from point 1 — it only needed the array-vs-switch fix.
   **Lesson:** any `static const`/global lookup table indexed by a
   runtime value is unsafe under BCC for XDP, regardless of table size;
   the fix is always "switch over the bounded index," not "shrink the
   array."

### Quantization
- All pipelines use int8 quantization (7-bit signed) as in the existing codebase
- Scale factor stored in model_cache (Pipeline 1) or arch_registry (Pipelines 2 & 3)
- Dequantization: `output_float = output_int8 / scale_factor`

### Model used
- Network: `frr_germany50_5_model_4x2.pt` (FC-NN, architecture 65-4-4-7)
- Input: 65 features (6 link_state + 6 ingress_if + 1 ttl + 52 node_id)
- Output: 7 classes (6 interfaces + DROP)
- Weights: 319 int8 values (fc1: 260+4 bias, fc2: 16+4 bias, out: 28+7 bias)
