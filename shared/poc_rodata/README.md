# PoC: cut Pipeline 1's recompilation cost with AOT + `.rodata` weights

## The problem

Pipeline 1 (hardcoded) bakes the model weights as **C literals** in the eBPF
source. BCC is clang-at-runtime, so **every new or modified model triggers a
full clang recompile** — measured at ~99.8% of the load cost (the verifier +
load itself is ~3 ms). Retraining the same 65-4-4-7 model changes only 319
integers, yet the whole program is recompiled from scratch.

## The idea under test

Compile the program **once per architecture** (offline → a `.o`). Put the
weights in a `const volatile __s8 W[N]` array that lands in the `.rodata`
section. To deploy a new/modified model of the **same architecture**, the
loader overwrites `W` via `bpf_map__set_initial_value()` **before** load and
libbpf freezes `.rodata` read-only. No clang runs — deploy cost drops to a
load (~ms).

**Honest caveat (this is what the PoC measures):** `.rodata` weights are NOT
free vs literals. With `volatile`, each weight stays a real read from the
frozen map plus the multiply; the verifier knows the value for *safety* but
does not rewrite the arithmetic the way clang folds a literal. So the rodata
build has *more* xlated instructions than the literal build. The question is
**how many more** — a small gap means we buy recompile-free redeploys almost
for free; a large gap means we need bytecode-level immediate patching instead.

## Files

| file | role |
|---|---|
| `gen_nn_c.py` | emits `nn_literal.bpf.c` (literals) and `nn_rodata.bpf.c` (`.rodata` weights) from the real 65-4-4-7 weights, plus `weights.bin` / `weights2.bin` (two models, same architecture) |
| `loader.c` | libbpf loader: loads both, prints xlated insn counts (perf gap), then times a recompile-free redeploy of a *different* model from the prebuilt `.o` |
| `Makefile` | compiles each `.bpf.c` **once**, builds the loader |

## Run (on the Linux host / Kathara — needs root)

```sh
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)   # once
cd shared/poc_rodata
python3 gen_nn_c.py     # generate C + weight blobs
make                    # clang compiles the two .bpf.c ONE time
sudo ./loader           # prints the two numbers we care about
```

## What to read in the output

1. **`[perf]` xlated instructions** — literal vs rodata for the identical NN.
   The delta is the per-packet cost of choosing `.rodata` over literals.
   Compare both against the template pipeline (~5951 insns from
   `verify_prog_run.py`): even the rodata build should sit far below it.
2. **`[redeploy]` load time** — deploying a *modified* model from the prebuilt
   `.o`, no clang. Compare against `method4_hardcoded.py`'s BCC compile
   (seconds) to see the recompile saved.

## If the gap is acceptable

Next step is to teach `ebpf_program.py` to emit the `.rodata` variant per
architecture and add a small libbpf loader path alongside BCC, keyed by an
architecture-descriptor hash so "models known a priori" precompile to `.o`
once and never recompile at runtime. Not done yet — gated on this PoC's
numbers.
