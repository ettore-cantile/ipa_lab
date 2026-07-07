# Hardcoded Model — Baseline Implementation

## Objective

This module implements **Level 1** of the IPA/eBPF design space: one dedicated eBPF program per model, with hardcoded weights, feature extraction, full inference, and argmax/action all specialised at compile time.

This is the **performance baseline** of the design space evaluation. All other levels will be compared against this.

## Architecture

```
src/hardcoded/
├── README.md                  # this file
├── ebpf/
│   ├── model_dispatcher.c     # XDP dispatcher: reads model_id from IPA header,
│   │                          #   performs tail call to model_<id>
│   └── model_42.c             # Example hardcoded model (FRR, germany50, 5 features → 2 actions)
├── user/
│   ├── load_hardcoded.py      # Loads dispatcher + model programs, attaches XDP
│   └── run_hardcoded_demo.py  # End-to-end demo using the existing germany50/Kathará scenario
└── config/
    └── hardcoded_models.json  # Model registry: model_id → program file + metadata
```

## Pipeline

```
packet
  ↓
dispatcher (model_dispatcher.c)
  ↓ tail call  [jump table: model_id → model prog]
model_42 (model_42.c)
  ↓
action (XDP_PASS / XDP_DROP / XDP_TX)
```

## Design Choices

- **No BPF map lookups for weights** — all weights are `const int` arrays in C, emitted directly as eBPF immediates after compilation.
- **No intermediate scratch maps** — the entire inference (matmul + ReLU + argmax) is unrolled inside the model program.
- **Single tail call** from dispatcher to model — minimises per-packet overhead.
- **Quantized INT8 weights** — consistent with the quantisation already present in `shared/weights.json`.

## Reuse from `shared/`

| File in `shared/` | Usage in hardcoded |
|---|---|
| `weights.json` | Source for hardcoded INT8 weight arrays in `model_42.c` |
| `weights_float.json` | Reference for float accuracy comparison |
| `extract_weights.py` | Can be extended to emit C `const int[]` literals |
| `common.py` | IPA header parsing utilities reused by `load_hardcoded.py` |
| `test_ipa.py` | Reused as-is for end-to-end correctness testing |
| `send_ipa.py` | Reused to inject IPA-tagged test traffic |

## Lab Scenario

This module runs on top of the existing **Kathará/Germany50** scenario defined in the repository root:
- `lab.conf` — topology definition
- `germany50.xml` — SNDLib network data
- `genera_lab.py` — lab generation script
- `shared/` — shared node scripts

No changes to the existing lab setup are needed.

## How to Run

```bash
# 1. Start the Kathará lab (from repo root)
kathara lstart

# 2. On the IPA node, load the hardcoded program
python3 /shared/src/hardcoded/user/load_hardcoded.py --iface eth0 --model 42

# 3. Run the demo / benchmark
python3 /shared/src/hardcoded/user/run_hardcoded_demo.py

# 4. Test correctness
python3 /shared/test_ipa.py
```

## Metrics to Collect (Baseline)

- Packets/second (via `bpftool prog profile` or `perf`)
- eBPF instruction count (`bpftool prog show`)
- Tail call count per packet: 1
- Map lookups per packet: 0
- Model update time: recompile + reload (`clang -O2 -target bpf ...`)
