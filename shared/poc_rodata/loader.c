// loader.c -- PoC libbpf loader for the recompilation study.
//
// Answers two questions with hard numbers:
//   (1) PERFORMANCE COST of moving weights out of C literals into a frozen
//       .rodata region: prints the xlated instruction count of the literal
//       build vs the rodata build (same NN, same weights). Fewer xlated
//       insns == cheaper per packet -- the same proxy verify_prog_run.py
//       uses. The gap is what ".rodata instead of literals" costs.
//   (2) REDEPLOY COST without clang: from the prebuilt nn_rodata.o, inject a
//       different weight set with bpf_map__set_initial_value() and load. No
//       clang runs -- this is the whole point. Times it, averaged over N
//       loads, so you can compare against method4's BCC compile (~seconds).
//
// Build:  see Makefile (needs libbpf + clang-built .o files + weights.bin).
// Run  :  sudo ./loader
//
// Note: we only load/verify the programs (never attach) -- the numbers we
// want (xlated insns, load time) are available at load time and this keeps
// the PoC from touching interfaces or the fragile VM's datapath.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define N_WEIGHTS 319

static long read_blob(const char *path, signed char *buf, long cap) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return -1; }
    long n = (long)fread(buf, 1, (size_t)cap, f);
    fclose(f);
    return n;
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// The .rodata map is the read-only ARRAY map libbpf synthesizes for the
// object's const globals. Name is "<obj>.rodata" but truncated, so match by
// role instead of by exact name.
static struct bpf_map *find_rodata(struct bpf_object *obj) {
    struct bpf_map *m;
    bpf_object__for_each_map(m, obj) {
        const char *nm = bpf_map__name(m);
        if (nm && strstr(nm, ".rodata"))
            return m;
    }
    return NULL;
}

static int first_prog_fd(struct bpf_object *obj) {
    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) return -1;
    return bpf_program__fd(prog);
}

// Load an object file, optionally injecting `weights` into .rodata first.
// Returns xlated insn count (>=0) or -1; *out_ms gets the load() duration.
static long load_once(const char *path, const signed char *weights,
                      double *out_ms) {
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "open_file %s failed\n", path);
        return -1;
    }

    if (weights) {
        struct bpf_map *ro = find_rodata(obj);
        if (!ro) { fprintf(stderr, "no .rodata map in %s\n", path); goto err; }
        size_t vsz = bpf_map__value_size(ro);
        // buffer sized to the map value; weights go at offset 0 (W is the
        // only global, so it starts the .rodata blob), rest stays zero.
        unsigned char *buf = calloc(1, vsz);
        memcpy(buf, weights, vsz < N_WEIGHTS ? vsz : N_WEIGHTS);
        int e = bpf_map__set_initial_value(ro, buf, vsz);
        free(buf);
        if (e) { fprintf(stderr, "set_initial_value: %d\n", e); goto err; }
    }

    double t0 = now_ms();
    int e = bpf_object__load(obj);
    double t1 = now_ms();
    if (e) { fprintf(stderr, "load %s failed: %d (%s)\n", path, e, strerror(-e)); goto err; }
    if (out_ms) *out_ms = t1 - t0;

    int fd = first_prog_fd(obj);
    struct bpf_prog_info info; __u32 len = sizeof(info);
    memset(&info, 0, sizeof(info));
    long insns = -1;
    if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0)
        insns = info.xlated_prog_len / 8;   // 8 bytes per BPF insn

    bpf_object__close(obj);
    return insns;

err:
    bpf_object__close(obj);
    return -1;
}

int main(int argc, char **argv) {
    const char *lit_o  = argc > 1 ? argv[1] : "nn_literal.o";
    const char *rod_o  = argc > 2 ? argv[2] : "nn_rodata.o";
    const char *w1     = argc > 3 ? argv[3] : "weights.bin";
    const char *w2     = argc > 4 ? argv[4] : "weights2.bin";
    int reps = argc > 5 ? atoi(argv[5]) : 20;

    signed char wa[N_WEIGHTS], wb[N_WEIGHTS];
    if (read_blob(w1, wa, N_WEIGHTS) != N_WEIGHTS) return 1;
    if (read_blob(w2, wb, N_WEIGHTS) != N_WEIGHTS) return 1;

    printf("================================================================\n");
    printf(" PoC: weights-as-literal vs weights-in-.rodata (65-4-4-7 XDP MLP)\n");
    printf("================================================================\n\n");

    // (1) performance: xlated insn count, literal vs rodata (same weights).
    double ms_lit = 0, ms_rod = 0;
    long insn_lit = load_once(lit_o, NULL, &ms_lit);       // literals baked in .o
    long insn_rod = load_once(rod_o, wa,   &ms_rod);       // weights injected
    if (insn_lit < 0 || insn_rod < 0) return 1;

    printf("[perf] xlated instructions (per-packet cost proxy):\n");
    printf("   literal build : %5ld insns\n", insn_lit);
    printf("   rodata  build : %5ld insns   (+%ld, %.1f%% vs literal)\n",
           insn_rod, insn_rod - insn_lit,
           100.0 * (insn_rod - insn_lit) / (double)insn_lit);
    printf("   -> this gap is what moving weights to frozen .rodata costs.\n\n");

    // (2) redeploy without clang: reload nn_rodata.o with a DIFFERENT model.
    // Each iteration = open(.o) + inject weights + load. NO clang anywhere.
    double sum = 0, mn = 1e9, mx = 0;
    for (int i = 0; i < reps; i++) {
        double ms = 0;
        const signed char *wset = (i & 1) ? wb : wa;   // alternate the two models
        long insn = load_once(rod_o, wset, &ms);
        if (insn < 0) return 1;
        sum += ms; if (ms < mn) mn = ms; if (ms > mx) mx = ms;
    }
    printf("[redeploy] deploy a modified model from the prebuilt .o (NO clang):\n");
    printf("   loads         : %d\n", reps);
    printf("   load time     : avg %.2f ms  (min %.2f, max %.2f)\n",
           sum / reps, mn, mx);
    printf("   -> compare against Pipeline 1's BCC path (clang recompile),\n");
    printf("      which method4_hardcoded pays in full on every weight change.\n");
    return 0;
}
