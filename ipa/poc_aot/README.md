# AOT-literal `.o`: Pipeline 1 without a compiler on the node

## The problem

Pipeline 1 (hardcoded) bakes the model weights as **C literals** in the eBPF
source. Compiled with BCC, i.e. clang at runtime on the node, every new or
modified model would trigger a full recompile on the node: ~75 ms of clang
against ~1 ms of kernel load (verifier + JIT).
Retraining the same 65-4-4-7 model changes only 319 integers, yet the whole
program is compiled from scratch, and the node needs a compiler.

## The idea

Compile the program **once, offline** into a plain BPF `.o`, with the weights
still as **C literals**. To deploy it on the datapath node the loader only does
`bpf_object__open_file` + `bpf_object__load` — **no clang** — so the deploy
cost is a load. Because the weights are literals compiled by `clang -O2`, the
per-weight strength reduction (`x*0` folded away, `x*8` → shift) is baked into
the `.o`, so the datapath keeps the full literal performance.

The program is **architecture-faithful**: dispatcher + `PROG_ARRAY` tail-call +
a model that re-parses, the same topology the tests measure. This object *is*
Pipeline 1 everywhere: every P1 number in `docs/` comes from it, through
`ipa/p1_aot.py`.

## Measured (2026-09-28, `docs/testing.md` §4 and Results)

| | |
|---|---|
| offline build (clang → `.o`) | 75.8 ms, once, on the build machine |
| deploy on the node (open + verify + JIT) | **1.12 ms** |
| xlated instructions | 1 064 (dispatch 29 + model 1 035) |
| latency (forwarding path, retval 4) | **51 ns/pkt** at 3.5 GHz, as in `test_suite --only kernel` (52) |

## Files

| file | role |
|---|---|
| `gen_full_c.py` | emits the libbpf C (dispatcher + tail-call + model, weights as literals) for any feature descriptor; `ipa/p1_aot.py` calls it with the same arguments as the test generator |
| `loader_aot.c` | libbpf loader. Bench: times the runtime open+load (deploy cost), populates `model_progs`, seeds `link_state`/`mac_table`, and `BPF_PROG_TEST_RUN`s the dispatcher (perf). Deploy (`--attach --pin-dir`): seeds nothing, pins the maps for the Python control plane and attaches only after it confirms — protocol at the top of the file |
| `Makefile` | compiles the `.bpf.c` once and builds the loader |

Usually you don't run these by hand: `ipa/methods/method4_hardcoded_aot.py`
orchestrates generate → clang → loader, and `ipa/execute_pipeline.py --method
hardcoded` deploys.

## Run (Linux + root)

```sh
sudo apt-get install clang libbpf-dev libelf-dev zlib1g-dev libzstd-dev liblzma-dev   # once
python3 ipa/methods/method4_hardcoded_aot.py        # build .o and loader, as a normal user
sudo python3 ipa/methods/method4_hardcoded_aot.py   # bench
```

or manually:

```sh
cd ipa/poc_aot
python3 gen_full_c.py   # -> nn_aot_arch.bpf.c
make                    # clang compiles it once, builds loader_aot
sudo ./loader_aot nn_aot_arch.o
```

With `-target bpf` clang does not search the Debian/Ubuntu multiarch directory
where `asm/types.h` lives (`linux-libc-dev`); the Makefile and the Python build
add `-I/usr/include/$(uname -m)-linux-gnu`.

The loader is linked **statically** (no `libbpf.so` needed at runtime): the
static libbpf pulls in `libelf`, `zlib`, `libzstd` and `liblzma`, and the build
tries the 3-library line first, then the 5-library one. Build it as a normal
user: files created by root under `ipa/poc_aot/` make a later user build fail.

## What to read in the output

1. **`[deploy]` total** — runtime open+load of the prebuilt `.o`, no clang.
2. **`[perf]`** — xlated insns / latency / throughput on the dispatcher, same
   methodology as `test_suite --only kernel` (frame refreshed every 200 runs
   from TTL 255, minimum of the chunk averages).

## Limit

Around ~1 200 weights the object is rejected by the kernel verifier
(`processed 1000001 insns (limit 1000000)`, `E2BIG`) for every shape but the
deepest one: see `docs/testing.md` §6.
