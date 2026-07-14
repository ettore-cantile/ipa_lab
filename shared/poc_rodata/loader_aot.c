// loader_aot.c -- AOT-literal deploy bench for Pipeline 1 (alternative to BCC).
//
// The BCC hardcoded path (method4_hardcoded.py) compiles the weights-literal C
// with clang AT RUNTIME on every (re)load -> ~1660 ms of clang on the datapath
// node for each new/modified model. This loader demonstrates the alternative
// for the "models known a priori" case (the hardcoded assumption): the literal
// .o is built OFFLINE (once, on a build box); at runtime the datapath node only
// does bpf_object__open_file + bpf_object__load -- no clang -> a few ms.
//
// It loads a PREBUILT literal .o, TIMES the open+load (the real deploy cost),
// seeds link_state/mac_table, crafts a UDP/IPA frame and BPF_PROG_TEST_RUNs it
// 1e6 times (same methodology as test_suite --kernel) to report that the AOT
// build keeps the FULL literal performance (clang strength-reduction preserved,
// unlike frozen .rodata -- see loader_full.c for that comparison).
//
// Build: cc -O2 loader_aot.c -o loader_aot -lbpf
// Run  : sudo ./loader_aot <literal.o>        (defaults to nn_full_literal.o)

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct fwd_action { __u32 ifindex; __u8 src_mac[6]; __u8 dst_mac[6]; } __attribute__((packed));

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// Build a minimal Ethernet/IPv4/UDP/IPA frame (63 bytes) into buf.
static int build_frame(unsigned char *buf) {
    memset(buf, 0, 128);
    unsigned char *p = buf;
    p[12] = 0x08; p[13] = 0x00;               // ethertype IPv4
    unsigned char *ip = p + 14;
    ip[0] = 0x45; ip[8] = 64; ip[9] = 17;      // ihl 5, ttl 64, proto UDP
    unsigned char *udp = p + 34;
    udp[2] = (9999 >> 8) & 0xff; udp[3] = 9999 & 0xff;  // dest port 9999 (BE)
    unsigned char *ipa = p + 42;
    ipa[0] = 1;                                // model_id = 1 (node one-hot case 1)
    return 63;
}

static int seed_maps(struct bpf_object *obj) {
    struct bpf_map *ls = bpf_object__find_map_by_name(obj, "link_state");
    struct bpf_map *mt = bpf_object__find_map_by_name(obj, "mac_table");
    if (!ls || !mt) { fprintf(stderr, "missing link_state/mac_table\n"); return -1; }
    int lsfd = bpf_map__fd(ls), mtfd = bpf_map__fd(mt);
    // link_state: single struct-valued entry {u32 v[6]} at key 0 (vector-map
    // layout, matches ebpf_program.py / gen_full_c.py single-lookup read).
    struct { __u32 v[6]; } lv;
    for (int i = 0; i < 6; i++) lv.v[i] = i + 1;
    __u32 z = 0;
    bpf_map_update_elem(lsfd, &z, &lv, BPF_ANY);
    for (__u32 c = 0; c < 6; c++) {           // mac_table classes 0..5
        struct fwd_action a; memset(&a, 0, sizeof(a));
        a.ifindex = 1;
        bpf_map_update_elem(mtfd, &c, &a, BPF_ANY);
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *lit = argc > 1 ? argv[1] : "nn_full_literal.o";

    // --- deploy cost: open + load a prebuilt literal .o (no clang) ---
    double t0 = now_ms();
    struct bpf_object *obj = bpf_object__open_file(lit, NULL);
    if (!obj || libbpf_get_error(obj)) { fprintf(stderr, "open %s\n", lit); return 1; }
    double t1 = now_ms();
    if (bpf_object__load(obj)) { fprintf(stderr, "load %s\n", lit); goto err; }
    double t2 = now_ms();

    if (seed_maps(obj)) goto err;

    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    int fd = bpf_program__fd(prog);
    long insns = -1;
    struct bpf_prog_info info; __u32 len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) insns = info.xlated_prog_len / 8;

    unsigned char in[128], out[256];
    build_frame(in);
    LIBBPF_OPTS(bpf_test_run_opts, o,
        .data_in = in, .data_size_in = 63,
        .data_out = out, .data_size_out = sizeof(out),
        .repeat = 1000000);
    if (bpf_prog_test_run_opts(fd, &o)) { fprintf(stderr, "test_run %s\n", lit); goto err; }
    double ns = (double)o.duration;
    double mpps = ns > 0 ? 1000.0 / ns : 0.0;

    printf("================================================================\n");
    printf(" AOT-literal deploy bench (Pipeline 1, full path, prebuilt .o)\n");
    printf("================================================================\n\n");
    printf("[deploy] runtime cost of loading a prebuilt literal .o (NO clang):\n");
    printf("   open_file           : %8.3f ms\n", t1 - t0);
    printf("   load (verify+JIT)   : %8.3f ms\n", t2 - t1);
    printf("   total deploy        : %8.3f ms\n", t2 - t0);
    printf("   (BCC method4 recompile for the same model: ~1660 ms of clang)\n\n");
    printf("[perf] full-path per-packet cost (BPF_PROG_TEST_RUN, 1e6 reps, retval=%u):\n", o.retval);
    printf("   xlated insns        : %8ld\n", insns);
    printf("   latency             : %8.1f ns/pkt\n", ns);
    printf("   throughput          : %8.2f Mpps\n", mpps);
    printf("\n   AOT keeps the FULL literal perf (clang strength-reduction baked\n");
    printf("   into the .o), unlike frozen .rodata weights.\n");

    bpf_object__close(obj);
    return 0;
err:
    bpf_object__close(obj);
    return 1;
}
