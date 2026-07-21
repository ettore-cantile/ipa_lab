# PoC: cut Pipeline 1's recompilation cost with an AOT-literal `.o`

## The problem

Pipeline 1 (hardcoded) bakes the model weights as **C literals** in the eBPF
source. BCC is clang-at-runtime, so **every new or modified model triggers a
full clang recompile** — measured at ~99.8% of the load cost (verifier + load
itself is a few ms). Retraining the same 65-4-4-7 model changes only 319
integers, yet the whole program is recompiled from scratch (~1660 ms).

## The idea under test

Compile the program **once, offline** into a plain BPF `.o`, with the weights
still as **C literals**. To deploy a model of the same architecture on the
datapath node, the loader only does `bpf_object__open_file` + `bpf_object__load`
— **no clang** — so deploy cost drops to a load (~ms). Because the weights are
literals compiled by `clang -O2`, the per-weight strength reduction (`x*0`
folded away, `x*8` → shift) is baked into the `.o`, so the datapath keeps the
**full literal performance, identical to BCC**.

The program is **architecture-faithful**: dispatcher + `PROG_ARRAY` tail-call +
a model that re-parses (the double parse), i.e. the exact BCC topology
(`ipa_switch_hardcoded` → `model_progs.call` → `model_<id>`). So the bench is
apples-to-apples with `test_suite --kernel` hardcoded.

## Files

| file | role |
|---|---|
| `gen_full_c.py` | emits `nn_aot_arch.bpf.c` (dispatcher + tail-call + model, weights as literals) from the real 65-4-4-7 weights |
| `loader_aot.c` | libbpf loader: times the runtime open+load (deploy cost), populates `model_progs`, seeds `link_state`/`mac_table`, and `BPF_PROG_TEST_RUN`s the dispatcher (perf) |
| `Makefile` | compiles the `.bpf.c` **once** and builds the loader |

Usually you don't run these by hand — `shared/methods/method4_hardcoded_aot.py`
orchestrates generate → clang → loader and prints the comparison vs BCC.

## Run (on the Linux host / Kathara — needs root)

```sh
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)   # once
sudo python3 shared/methods/method4_hardcoded_aot.py
```

or manually:

```sh
cd shared/poc_aot
python3 gen_full_c.py   # -> nn_aot_arch.bpf.c
make                    # clang compiles it ONCE, builds loader_aot
sudo ./loader_aot nn_aot_arch.o
```

## What to read in the output

1. **`[deploy]` total** — runtime open+load of the prebuilt `.o`, no clang
   (~ms). Compare against `method4_hardcoded.py`'s BCC compile (~1660 ms) to see
   the recompile saved.
2. **`[perf]`** — xlated insns / latency / throughput on the dispatcher, same
   methodology as `test_suite --kernel`. These land on the BCC hardcoded
   numbers (perf is preserved, not improved).

## Future work

`gen_full_c.py` is currently wired to the default FRR descriptor (65-4-4-7). The
BCC path (`ebpf_program.py`) already supports arbitrary sparse descriptors; to
cover them here, port the three `_gen_feature_*` generators from BCC dialect to
libbpf dialect so any model precompiles to a `.o` once and never recompiles at
runtime.
