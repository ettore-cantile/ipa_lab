# PoC: compile the AOT-literal BPF program ONCE (offline) + build the loader.
#
# Deps (Debian/Ubuntu / Kathara host):
#   sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
# (BCC already pulls clang/llvm; libbpf-dev is the only likely-missing one.)
#
# Usage:
#   python3 gen_full_c.py       # generate nn_aot_arch.bpf.c (once per model)
#   make                        # clang -> nn_aot_arch.o ; cc -> loader_aot
#   sudo ./loader_aot nn_aot_arch.o
#
# Key point: `make` compiles the .bpf.c a SINGLE time. Deploying a model of
# this architecture afterwards is just an open+load of the prebuilt .o -- no
# clang. The weights stay C literals, so perf equals the BCC literal path.

CLANG    ?= clang
CC       ?= cc
# -O2 is what makes clang fold/strength-reduce the literal weights.
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

.PHONY: all clean run
all: nn_aot_arch.o loader_aot

nn_aot_arch.o: nn_aot_arch.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

loader_aot: loader_aot.c
	$(CC) -O2 loader_aot.c -o loader_aot -lbpf

run: all
	sudo ./loader_aot nn_aot_arch.o

clean:
	rm -f nn_aot_arch.o loader_aot nn_aot_arch.bpf.c
