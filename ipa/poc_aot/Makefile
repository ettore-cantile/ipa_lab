# PoC: compile the AOT-literal BPF program ONCE (offline) + build the loader.
#
# Deps (Debian/Ubuntu / Kathara host):
#   sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
# (BCC already pulls clang/llvm; libbpf-dev is the only likely-missing one.)
#
# Usage:
#   python3 gen_full_c.py       # generate nn_aot_arch.bpf.c + nn_aot_meta.h
#                               # (once per model; nn_aot_meta.h carries the
#                               #  class semantics the loader seeds against)
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

.PHONY: all clean run p2 p3 pipelines vmlinux
all: nn_aot_arch.o loader_aot

nn_aot_arch.o: nn_aot_arch.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

loader_aot: loader_aot.c nn_aot_meta.h
	$(CC) -O2 loader_aot.c -o loader_aot -lbpf

run: all
	sudo ./loader_aot nn_aot_arch.o

# ---------------------------------------------------------------------------
# Pipelines 2 and 3 through libbpf (no clang, no Python on the node).
#
# Unlike Pipeline 1 these need no per-model codegen: their C is a fixed
# template and the model arrives through maps. The only thing that was in the
# way was the DIALECT -- BCC's BPF_ARRAY()/map.lookup() sugar -- so
# bcc_to_libbpf.py translates the SAME source rather than a second copy of the
# datapath being maintained by hand.
#
#   make vmlinux      # once per kernel: types from the running kernel's BTF
#   make pipelines    # translate + compile both to .o
#
# vmlinux.h is a build artefact of THIS kernel, not project source: it is
# regenerated, never committed.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

vmlinux: vmlinux.h

ipa_template.bpf.c ipa_modular.bpf.c: bcc_to_libbpf.py ../ebpf_template_arch.py ../ebpf_modular.py
	python3 bcc_to_libbpf.py

ipa_template.o: ipa_template.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ipa_modular.o: ipa_modular.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

p2: ipa_template.o
p3: ipa_modular.o
pipelines: ipa_template.o ipa_modular.o
	@echo "[poc_aot] P2/P3 compiled offline. Neither .o needs clang on the node."

clean:
	rm -f nn_aot_arch.o loader_aot nn_aot_arch.bpf.c nn_aot_meta.h \
	      ipa_template.o ipa_modular.o ipa_template.bpf.c ipa_modular.bpf.c

# vmlinux.h survives `clean`: regenerating it needs bpftool and a BTF-enabled
# kernel, and it does not change between builds on the same machine.
distclean: clean
	rm -f vmlinux.h
