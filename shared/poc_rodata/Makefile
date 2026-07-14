# PoC: compile the two BPF programs ONCE (offline) and build the libbpf loader.
#
# Deps (Debian/Ubuntu / Kathara host):
#   sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
# (BCC already pulls clang/llvm; libbpf-dev is the only likely-missing one.)
#
# Usage:
#   python3 gen_nn_c.py     # generate the .bpf.c + weights.bin (once per model set)
#   make                    # clang -> nn_literal.o, nn_rodata.o ; cc -> loader
#   sudo ./loader           # prints the perf gap + recompile-free redeploy time
#
# Key point the Makefile embodies: `make` compiles the .bpf.c a SINGLE time.
# Deploying a different model of this architecture afterwards does NOT re-run
# clang -- loader.c injects new weights into nn_rodata.o's .rodata and reloads.

CLANG    ?= clang
CC       ?= cc
# -O2 is what makes clang fold the literals in the literal build (fair fight).
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

.PHONY: all clean run
all: nn_literal.o nn_rodata.o loader

nn_literal.o: nn_literal.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

nn_rodata.o: nn_rodata.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

loader: loader.c
	$(CC) -O2 loader.c -o loader -lbpf

run: all
	sudo ./loader

clean:
	rm -f nn_literal.o nn_rodata.o loader
