# Hardcoded eBPF Models — Level 1 Baseline

This directory lives inside `shared/` so it is automatically available at `/shared/hardcoded/` inside every Kathara container.

## Directory layout

```
shared/hardcoded/
├── ebpf/
│   ├── model_dispatcher.c   # XDP entry point — reads model_id, tail-calls model program
│   └── model_42.c           # Fully hardcoded inference: 5→4→2, INT8 weights, no maps
├── user/
│   ├── load_hardcoded.py    # Compile + load + attach to XDP hook
│   └── run_hardcoded_demo.py # Send test IPA packets
└── config/
    └── hardcoded_models.json # Model registry
```

## Quick start (inside a Kathara container)

```bash
# 1. Load and attach on eth0
python3 /shared/hardcoded/user/load_hardcoded.py --iface eth0 --model 42

# 2. From another node, send test packets
python3 /shared/hardcoded/user/run_hardcoded_demo.py --target <IP_receiver> --iface eth0

# 3. Watch XDP decisions in real time
cat /sys/kernel/debug/tracing/trace_pipe

# 4. Detach when done
ip link set dev eth0 xdp off
```

## Pipeline

```
Packet arrives on eth0
  └─ XDP dispatcher (model_dispatcher.c)
       └─ reads model_id from IPA header (UDP/9999)
       └─ bpf_tail_call → model_42 (model_42.c)
            └─ feature extraction (5 INT8 values after IPA header)
            └─ Layer 1: linear + ReLU  (4 neurons, unrolled)
            └─ Layer 2: linear         (2 classes, unrolled)
            └─ argmax → XDP_PASS (class 0) or XDP_DROP (class 1)
```

## Before benchmarking

The weights in `model_42.c` are **placeholder values**. Replace them with real quantized weights:

```bash
# On the host, extract real INT8 weights from shared/weights.json
python3 /shared/extract_weights.py --model 42 --emit-c > /tmp/weights_42.h
# Then paste the arrays into model_42.c and recompile
```
