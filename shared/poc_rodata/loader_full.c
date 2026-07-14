// loader_full.c -- FULL-PATH latency of the recompilation PoC.
//
// Loads nn_full_{literal,rodata}.o (the entire per-packet Pipeline-1 work:
// parse + link_state map lookups + one-hot switches + inference + mac_table +
// stats + redirect), seeds link_state and mac_table, crafts a real UDP/IPA
// frame, and BPF_PROG_TEST_RUNs each 1e6 times. This is the same methodology
// as test_suite --kernel, so the literal-vs-rodata latency is the production
// full-path cost of frozen .rodata weights (not the inference-only figure).
//
// Note: we do NOT forge ctx->ingress_ifindex (some kernels reject a nonzero
// one in test-run), so the ingress_iface one-hot takes its default path
// (w_iface = 0). That drops just 4 weight accesses/packet from BOTH builds --
// negligible next to the 6 link_state map lookups, the 52-case node switch and
// fc2/out. Everything else is the full production path.
//
// Build: cc -O2 loader_full.c -o loader_full -lbpf
// Run  : sudo ./loader_full            (defaults to nn_full_*.o + weights.bin)

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define N_WEIGHTS 319

struct fwd_action { __u32 ifindex; __u8 src_mac[6]; __u8 dst_mac[6]; } __attribute__((packed));

static long read_blob(const char *path, signed char *buf, long cap) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "open %s\n", path); return -1; }
    long n = (long)fread(buf, 1, (size_t)cap, f);
    fclose(f);
    return n;
}

static struct bpf_map *find_rodata(struct bpf_object *obj) {
    struct bpf_map *m;
    bpf_object__for_each_map(m, obj)
        if (bpf_map__name(m) && strstr(bpf_map__name(m), ".rodata")) return m;
    return NULL;
}

// Build a minimal Ethernet/IPv4/UDP/IPA frame (63 bytes) into buf.
static int build_frame(unsigned char *buf) {
    memset(buf, 0, 128);
    unsigned char *p = buf;
    // eth (14): dst[6], src[6], ethertype=0x0800
    p[12] = 0x08; p[13] = 0x00;
    // ip (20) at offset 14
    unsigned char *ip = p + 14;
    ip[0] = 0x45;          // version 4, ihl 5
    ip[8] = 64;            // ttl
    ip[9] = 17;            // protocol UDP
    // udp (8) at offset 34
    unsigned char *udp = p + 34;
    udp[2] = (9999 >> 8) & 0xff; udp[3] = 9999 & 0xff;   // dest port 9999 (BE)
    // ipa (21) at offset 42
    unsigned char *ipa = p + 42;
    ipa[0] = 1;            // model_id = 1 -> node one-hot case 1 executes
    return 63;
}

static int seed_maps(struct bpf_object *obj) {
    struct bpf_map *ls = bpf_object__find_map_by_name(obj, "link_state");
    struct bpf_map *mt = bpf_object__find_map_by_name(obj, "mac_table");
    if (!ls || !mt) { fprintf(stderr, "missing link_state/mac_table\n"); return -1; }
    int lsfd = bpf_map__fd(ls), mtfd = bpf_map__fd(mt);
    for (__u32 k = 0; k < 6; k++) {           // link_state[0..5] = 1..6
        __u32 v = k + 1;
        bpf_map_update_elem(lsfd, &k, &v, BPF_ANY);
    }
    for (__u32 c = 0; c < 6; c++) {           // mac_table classes 0..5
        struct fwd_action a; memset(&a, 0, sizeof(a));
        a.ifindex = 1;
        bpf_map_update_elem(mtfd, &c, &a, BPF_ANY);
    }
    return 0;
}

static int bench(const char *path, const signed char *weights,
                 long *insns, double *ns, double *mpps) {
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (!obj || libbpf_get_error(obj)) { fprintf(stderr, "open %s\n", path); return -1; }
    if (weights) {
        struct bpf_map *ro = find_rodata(obj);
        if (!ro) { fprintf(stderr, "no .rodata in %s\n", path); goto err; }
        size_t vsz = bpf_map__value_size(ro);
        unsigned char *b = calloc(1, vsz);
        memcpy(b, weights, vsz < N_WEIGHTS ? vsz : N_WEIGHTS);
        int e = bpf_map__set_initial_value(ro, b, vsz);
        free(b);
        if (e) { fprintf(stderr, "set_initial_value %d\n", e); goto err; }
    }
    if (bpf_object__load(obj)) { fprintf(stderr, "load %s\n", path); goto err; }
    if (seed_maps(obj)) goto err;

    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    int fd = bpf_program__fd(prog);
    struct bpf_prog_info info; __u32 len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) *insns = info.xlated_prog_len / 8;

    unsigned char in[128], out[256];
    build_frame(in);
    LIBBPF_OPTS(bpf_test_run_opts, o,
        .data_in = in, .data_size_in = 63,
        .data_out = out, .data_size_out = sizeof(out),
        .repeat = 1000000);
    if (bpf_prog_test_run_opts(fd, &o)) { fprintf(stderr, "test_run %s\n", path); goto err; }
    *ns = (double)o.duration;
    *mpps = *ns > 0 ? 1000.0 / *ns : 0.0;
    printf("   (%s: test-run retval=%u)\n", path, o.retval);

    bpf_object__close(obj);
    return 0;
err:
    bpf_object__close(obj);
    return -1;
}

int main(int argc, char **argv) {
    const char *lit = argc > 1 ? argv[1] : "nn_full_literal.o";
    const char *rod = argc > 2 ? argv[2] : "nn_full_rodata.o";
    const char *wf  = argc > 3 ? argv[3] : "weights.bin";

    signed char w[N_WEIGHTS];
    if (read_blob(wf, w, N_WEIGHTS) != N_WEIGHTS) return 1;

    printf("================================================================\n");
    printf(" PoC FULL-PATH: literal vs rodata, entire per-packet Pipeline-1 work\n");
    printf(" (parse + link_state map + one-hots + MLP + mac_table + redirect)\n");
    printf("================================================================\n\n");

    long il = -1, ir = -1;
    double nl = 0, nr = 0, ml = 0, mr = 0;
    if (bench(lit, NULL, &il, &nl, &ml)) return 1;
    if (bench(rod, w,    &ir, &nr, &mr)) return 1;

    printf("\n[perf] full-path per-packet cost (BPF_PROG_TEST_RUN, 1e6 reps):\n");
    printf("   %-10s %10s %12s %10s\n", "build", "xlated", "latency", "throughput");
    printf("   %-10s %10s %12s %10s\n", "", "insns", "ns/pkt", "Mpps");
    printf("   %-10s %10ld %11.1f %10.2f\n", "literal", il, nl, ml);
    printf("   %-10s %10ld %11.1f %10.2f\n", "rodata",  ir, nr, mr);
    if (nl > 0)
        printf("   delta      %+10ld %+10.1f%% %9.1f%%\n",
               ir - il, 100.0 * (nr - nl) / nl, 100.0 * (mr - ml) / ml);
    printf("\n   This is the production full-path delta (same methodology as\n");
    printf("   test_suite --kernel): the .rodata weight loads are diluted by\n");
    printf("   the parse/map/redirect work shared by both builds.\n");
    return 0;
}
