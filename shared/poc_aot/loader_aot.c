// loader_aot.c -- AOT-literal deploy bench for Pipeline 1 (alternative to BCC).
//
// The BCC hardcoded path (method4_hardcoded.py) compiles the weights-literal C
// with clang AT RUNTIME on every (re)load -> ~1660 ms of clang on the datapath
// node for each new/modified model. This loader demonstrates the alternative
// for the "models known a priori" case (the hardcoded assumption): the literal
// .o is built OFFLINE (once, on a build box); at runtime the datapath node only
// does bpf_object__open_file + bpf_object__load -- no clang -> a few ms.
//
// ARCHITECTURE-FAITHFUL: the .o contains the SAME topology as the BCC path --
// a dispatcher (xdp_dispatch) that parses and bpf_tail_calls into the model
// (xdp_model), which RE-parses (the double parse) and infers. We populate the
// model_progs PROG_ARRAY, seed the descriptor's feature maps + mac_table, and BPF_PROG_TEST_RUN the
// DISPATCHER, so this measures the identical per-packet work test_suite
// --kernel measures (dispatcher + tail call + double parse + full path). The
// reported instruction count is the SUM of both programs' xlated length, to
// match test_suite (ipa_switch_hardcoded + model_0).
//
// Build: cc -O2 loader_aot.c -o loader_aot -lbpf
// Run  : sudo ./loader_aot <literal.o>                 (bench: TEST_RUN)
//        sudo ./loader_aot <literal.o> --attach <ifidx> (LIVE deploy: attach
//              xdp_dispatch to the interface, stay resident until Ctrl-C, then
//              detach -- the AOT alternative to method4_hardcoded's BCC attach)

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

struct fwd_action { __u32 ifindex; __u8 src_mac[6]; __u8 dst_mac[6]; } __attribute__((packed));

/* Set by SIGINT/SIGTERM so the live-attach deploy mode can detach cleanly. */
static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// Ethernet/IPv4/UDP/IPA frame (63 bytes), model_id=0 to match test_suite.
static int build_frame(unsigned char *buf) {
    memset(buf, 0, 128);
    unsigned char *p = buf;
    p[12] = 0x08; p[13] = 0x00;               // ethertype IPv4
    unsigned char *ip = p + 14;
    ip[0] = 0x45; ip[8] = 64; ip[9] = 17;      // ihl 5, ttl 64, proto UDP
    unsigned char *udp = p + 34;
    udp[2] = (9999 >> 8) & 0xff; udp[3] = 9999 & 0xff;  // dest port 9999 (BE)
    unsigned char *ipa = p + 42;
    ipa[0] = 0;                                // model_id = 0 (node one-hot case 0)
    return 63;
}

static long prog_insns(int fd) {
    struct bpf_prog_info info; __u32 len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(fd, &info, &len)) return -1;
    return info.xlated_prog_len / 8;
}

// Seed a dense_vector_map feature map ({u32 v[N]} at key 0) if it exists in the
// loaded object. Size is taken from the map's value_size, so it adapts to any
// topology; absent maps (descriptor doesn't use that feature) are skipped.
static void seed_vec_map(struct bpf_object *obj, const char *name, __u32 fill) {
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if (!m) return;                                  // not used by this descriptor
    __u32 vsz = bpf_map__value_size(m);
    unsigned char buf[512];
    if (vsz > sizeof(buf)) vsz = sizeof(buf);
    memset(buf, 0, sizeof(buf));
    for (__u32 i = 0; i + 4 <= vsz; i += 4) *(__u32 *)(buf + i) = fill;   // u32 slots
    __u32 z = 0;
    bpf_map_update_elem(bpf_map__fd(m), &z, buf, BPF_ANY);
}

// Descriptor-agnostic seeding: dense-feature maps are seeded only when present,
// mac_table forward classes are 0..n_out-2 (n_out read from cls_stats), the last
// class being DROP (no entry).
static int seed_maps(struct bpf_object *obj) {
    struct bpf_map *mt = bpf_object__find_map_by_name(obj, "mac_table");
    struct bpf_map *cs = bpf_object__find_map_by_name(obj, "cls_stats");
    if (!mt) { fprintf(stderr, "missing mac_table\n"); return -1; }
    seed_vec_map(obj, "link_state",  1);    // all-up baseline (matches test_suite ref)
    seed_vec_map(obj, "queue_state", 1);    // nonzero occupancy baseline
    __u32 n_out = cs ? bpf_map__max_entries(cs) : 7;
    __u32 n_fwd = n_out > 0 ? n_out - 1 : 0;
    int mtfd = bpf_map__fd(mt);
    for (__u32 c = 0; c < n_fwd; c++) {      // mac_table forward classes 0..n_out-2
        struct fwd_action a; memset(&a, 0, sizeof(a));
        a.ifindex = 1;
        bpf_map_update_elem(mtfd, &c, &a, BPF_ANY);
    }
    return 0;
}

int main(int argc, char **argv) {
    // Args: <literal.o> [--attach <ifindex>]
    //   no --attach  -> bench mode  (BPF_PROG_TEST_RUN, deploy-cost + perf)
    //   --attach N   -> deploy mode (attach xdp_dispatch to ifindex N, stay
    //                   resident until Ctrl-C, then detach). This is the LIVE
    //                   datapath alternative to BCC's method4_hardcoded attach.
    const char *lit = "nn_aot_arch.o";
    int attach_ifindex = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--attach") && i + 1 < argc) attach_ifindex = atoi(argv[++i]);
        else lit = argv[i];
    }

    // --- deploy cost: open + load a prebuilt literal .o (no clang) ---
    double t0 = now_ms();
    struct bpf_object *obj = bpf_object__open_file(lit, NULL);
    if (!obj || libbpf_get_error(obj)) { fprintf(stderr, "open %s\n", lit); return 1; }
    double t1 = now_ms();
    if (bpf_object__load(obj)) { fprintf(stderr, "load %s\n", lit); goto err; }
    double t2 = now_ms();

    // wire the tail-call: model_progs[0] = fd(xdp_model), exactly as the BCC
    // control plane does b["model_progs"][0] = model_fn.fd.
    struct bpf_program *disp = bpf_object__find_program_by_name(obj, "xdp_dispatch");
    struct bpf_program *model = bpf_object__find_program_by_name(obj, "xdp_model");
    struct bpf_map *progs = bpf_object__find_map_by_name(obj, "model_progs");
    if (!disp || !model || !progs) { fprintf(stderr, "missing dispatch/model/model_progs\n"); goto err; }
    int disp_fd = bpf_program__fd(disp), model_fd = bpf_program__fd(model);
    __u32 mid = 0, mfd = (__u32)model_fd;
    if (bpf_map_update_elem(bpf_map__fd(progs), &mid, &mfd, BPF_ANY)) {
        fprintf(stderr, "prog_array update\n"); goto err;
    }

    if (seed_maps(obj)) goto err;

    // --- LIVE DEPLOY mode: attach xdp_dispatch to a real interface and stay
    // resident (the AOT alternative to BCC's method4_hardcoded live attach).
    // Requires libbpf >= 0.7 for bpf_xdp_attach/detach. ---
    if (attach_ifindex >= 0) {
        if (bpf_xdp_attach(attach_ifindex, disp_fd, 0, NULL)) {
            fprintf(stderr, "bpf_xdp_attach(ifindex=%d) failed\n", attach_ifindex);
            goto err;
        }
        signal(SIGINT,  on_signal);
        signal(SIGTERM, on_signal);
        printf("================================================================\n");
        printf(" AOT-literal LIVE deploy (Pipeline 1) -- NO clang on this node\n");
        printf("================================================================\n");
        printf("[deploy] open+load (verify+JIT): %.3f ms  "
               "(BCC method4 recompile for the same model: ~1660 ms of clang)\n", t2 - t0);
        printf("[deploy] xdp_dispatch attached to ifindex %d. Ctrl-C to detach.\n",
               attach_ifindex);
        /* Flush now: when stdout is a pipe (e.g. under `kathara exec`, not a
         * TTY) C stdio is fully buffered, so without this the messages above
         * would sit in the buffer -- invisible -- while the loader blocks in
         * pause(), making a working, attached deploy look like a hang. */
        fflush(stdout);
        while (!g_stop) pause();
        bpf_xdp_detach(attach_ifindex, 0, NULL);
        printf("\n[deploy] detached from ifindex %d.\n", attach_ifindex);
        bpf_object__close(obj);
        return 0;
    }

    long insn_disp = prog_insns(disp_fd), insn_model = prog_insns(model_fd);
    long insn_total = insn_disp + insn_model;   // matches test_suite (disp + model)

    // run the DISPATCHER (parse -> tail call -> model re-parse -> infer -> action)
    unsigned char in[128], out[256];
    build_frame(in);
    LIBBPF_OPTS(bpf_test_run_opts, o,
        .data_in = in, .data_size_in = 63,
        .data_out = out, .data_size_out = sizeof(out),
        .repeat = 1000000);
    if (bpf_prog_test_run_opts(disp_fd, &o)) { fprintf(stderr, "test_run %s\n", lit); goto err; }
    double ns = (double)o.duration;
    double mpps = ns > 0 ? 1000.0 / ns : 0.0;

    printf("================================================================\n");
    printf(" AOT-literal deploy bench (Pipeline 1, ARCH-FAITHFUL)\n");
    printf(" dispatcher + tail-call + double-parse == BCC hardcoded topology\n");
    printf("================================================================\n\n");
    printf("[deploy] runtime cost of loading a prebuilt literal .o (NO clang):\n");
    printf("   open_file           : %8.3f ms\n", t1 - t0);
    printf("   load (verify+JIT)   : %8.3f ms\n", t2 - t1);
    printf("   total deploy        : %8.3f ms\n", t2 - t0);
    printf("   (BCC method4 recompile for the same model: ~1660 ms of clang)\n\n");
    printf("[perf] full-path per-packet cost (BPF_PROG_TEST_RUN on dispatcher, 1e6 reps, retval=%u):\n", o.retval);
    printf("   xlated insns        : %8ld   (dispatch %ld + model %ld)\n", insn_total, insn_disp, insn_model);
    printf("   latency             : %8.1f ns/pkt\n", ns);
    printf("   throughput          : %8.2f Mpps\n", mpps);
    printf("\n   Same topology and methodology as test_suite --kernel hardcoded,\n");
    printf("   so these are directly comparable to the BCC numbers. AOT keeps the\n");
    printf("   full literal perf (clang strength-reduction baked into the .o).\n");

    bpf_object__close(obj);
    return 0;
err:
    bpf_object__close(obj);
    return 1;
}
