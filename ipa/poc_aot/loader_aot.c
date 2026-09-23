// loader_aot.c -- AOT-literal deploy bench for Pipeline 1 (alternative to BCC).
//
// The BCC hardcoded path (method4_hardcoded.py) compiles the weights-literal C
// with clang AT RUNTIME on every (re)load -> ~1.3 s of clang on the datapath
// node for each new/modified model (machine-dependent; 1.26-1.66 s observed --
// the live figure is the "[M1 update timing]" line printed by
// test_suite.py --only kernel). This loader demonstrates the alternative
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
// Run  : sudo ./loader_aot <literal.o> [--node-id N]   (bench: TEST_RUN)
//        sudo ./loader_aot <literal.o> --attach <ifidx> --pin-dir /sys/fs/bpf/<dir>
//              [--xdp-mode native|generic|auto]
//              (LIVE deploy, driven by method4_hardcoded_aot.py over stdin/stdout)
//
// LIVE DEPLOY PROTOCOL. The loader does NOT seed the datapath maps in deploy
// mode: mac_table, link_state, ingress_port and node_id are node facts, and
// the Python control plane that P2 and P3 already use owns them. So:
//
//   loader  -> load the .o, wire model_progs, pin every map under --pin-dir,
//              print "READY <dir>"
//   python  -> open the pinned maps (pinned_maps.PinnedObject), install
//              mac_table / ingress_port / node_id, start the link_state
//              monitor and the ARP refresh, then write "ATTACH"
//   loader  -> attach xdp_dispatch, print "ATTACHED <mode>"
//   python  -> "DETACH", or EOF on stdin (the control plane died), or a
//              SIGINT/SIGTERM -> the loader detaches, unpins and exits
//
// Until 2026-09-23 the deploy seeded mac_table here with ifindex 1 and zero
// MACs for every logical port, and nothing ever replaced it: every FORWARD
// decision was bpf_redirect()ed to ifindex 1, which is `lo` in every netns.
// The program is attached only AFTER the control plane has written the maps,
// so no packet ever sees them empty.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>   // XDP_FLAGS_* / XDP_ATTACHED_*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include "nn_aot_meta.h"   // GENERATED: class semantics (see gen_full_c.py)

struct fwd_action { __u32 ifindex; __u8 src_mac[6]; __u8 dst_mac[6]; } __attribute__((packed));

/* The interface being attached to, or -1 in bench mode. seed_maps() needs it
 * to fill ingress_port, and it is parsed before seed_maps() runs. */
static int g_attach_ifindex = -1;

/* This node's index in the node one-hot, or -1 for "unknown".
 *
 * An AOT object is built on a build machine, so it cannot carry this: it is
 * supplied at load time by --node-id or $IPA_NODE_ID, exactly as the Python
 * control plane resolves it. Left unset, the node one-hot stays empty, which
 * is honest -- the alternative, defaulting to 0, would make every
 * unconfigured node claim to be node 0. That was the previous behaviour, via
 * ipa->model_id, and it is what this replaces. */
static int g_node_id = -1;

/* ifindex del kernel -> slot del one-hot ingress_iface, cosi' come lo ha
 * risolto il control plane (common.ingress_port_slots): logical_port -> nome
 * dell'interfaccia via NodeConfig, nome -> ifindex via if_nametoindex, e lo
 * slot e' il RANGO della porta fra quelle che il modello puo' scegliere.
 *
 * Passato invece che dedotto qui perche' il .o e' costruito su una macchina di
 * build che non sa quali ifindex il nodo assegnera', e perche' la convenzione
 * deve avere UNA definizione sola: e' la stessa funzione Python che riempie
 * ingress_port_t2 e ingress_port_t3 per le altre due pipeline. */
#define MAX_INGRESS_ENTRIES 64
static __u32 g_ingress_ifx[MAX_INGRESS_ENTRIES];
static __u32 g_ingress_slot[MAX_INGRESS_ENTRIES];
static int   g_n_ingress = 0;

/* "207=1,209=2,..." -- ritorna 0, oppure -1 con un messaggio. */
static int parse_ingress_ports(const char *spec) {
    const char *p = spec;
    while (*p) {
        char *end;
        long ifx = strtol(p, &end, 10);
        if (end == p || *end != '=') {
            fprintf(stderr, "--ingress-port: attese coppie IFINDEX=SLOT "
                            "separate da virgola, trovato \"%s\"\n", p);
            return -1;
        }
        p = end + 1;
        long slot = strtol(p, &end, 10);
        if (end == p) {
            fprintf(stderr, "--ingress-port: manca lo slot dopo ifindex %ld\n", ifx);
            return -1;
        }
        if (ifx <= 0 || slot < 1 || slot > 0xffff) {
            fprintf(stderr, "--ingress-port: %ld=%ld fuori intervallo "
                            "(ifindex > 0, slot in [1, 65535])\n", ifx, slot);
            return -1;
        }
        if (g_n_ingress >= MAX_INGRESS_ENTRIES) {
            fprintf(stderr, "--ingress-port: piu' di %d voci\n", MAX_INGRESS_ENTRIES);
            return -1;
        }
        g_ingress_ifx[g_n_ingress]  = (__u32)ifx;
        g_ingress_slot[g_n_ingress] = (__u32)slot;
        g_n_ingress++;
        p = end;
        if (*p == ',') p++;
        else if (*p) {
            fprintf(stderr, "--ingress-port: carattere inatteso \"%s\"\n", p);
            return -1;
        }
    }
    return 0;
}

/* Set by SIGINT/SIGTERM so the live-attach deploy mode can detach cleanly. */
static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* bpffs directory the deploy pins the object's maps into (--pin-dir). */
static const char *g_pin_dir = NULL;

/* One line from stdin, read with read(2) rather than stdio: the control plane
 * talks to this process over a pipe, and a stdio buffer could hold the very
 * line this loop waits for. Returns its length, or -1 on EOF, on an error, or
 * on a stop signal -- all three mean "the control plane is gone, stand down".
 * The signal handler is installed WITHOUT SA_RESTART, so a Ctrl-C interrupts
 * the read instead of leaving it blocked. */
static int read_line(char *buf, int cap) {
    int n = 0;
    for (;;) {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r == 1) {
            if (c == '\n') break;
            if (n < cap - 1) buf[n++] = c;
            continue;
        }
        if (r < 0 && errno == EINTR && !g_stop) continue;
        return -1;
    }
    buf[n] = 0;
    return n;
}

/* Remove what a previous run left pinned under `dir`: a crash or a kill -9
 * skips the unpin at the end of the deploy, and bpf_object__pin_maps() refuses
 * to pin over an existing file. Only the names THIS object would pin are
 * touched. libbpf turns '.' into '_' in pin paths (bpffs forbids periods), so
 * the same is done here; the directory itself is refused if it has one. */
static void unlink_stale_pins(struct bpf_object *obj, const char *dir) {
    struct bpf_map *m;
    bpf_object__for_each_map(m, obj) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, bpf_map__name(m));
        if (n < 0 || n >= (int)sizeof(path)) continue;
        for (char *p = path + strlen(dir) + 1; *p; p++)
            if (*p == '.') *p = '_';
        if (unlink(path) == 0)
            fprintf(stderr, "removed stale pin %s\n", path);
    }
}

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

// Descriptor-driven seeding: dense-feature maps are seeded only when present,
// and mac_table is seeded for the LOGICAL PORTS the generated switch can
// select -- AOT_LOGICAL_PORTS in nn_aot_meta.h, emitted by gen_full_c.py from
// the same ClassSemantics object the datapath switch is generated from.
//
// It used to seed classes 0..n_out-2, with n_out taken from cls_stats' size:
// "the last class is DROP" and "class k is a forwarding class" re-derived here,
// in a third language. For the checked-in model both are wrong -- DROP is
// class 5 and class 6 is untrained -- so the loop installed a next-hop for the
// DROP class, and it keyed mac_table by class where the datapath keys it by
// logical port.
static int seed_maps(struct bpf_object *obj) {
    struct bpf_map *mt = bpf_object__find_map_by_name(obj, "mac_table");
    if (!mt) { fprintf(stderr, "missing mac_table\n"); return -1; }
    seed_vec_map(obj, "link_state",  1);    // all-up baseline (matches test_suite ref)
    seed_vec_map(obj, "queue_state", 1);    // nonzero occupancy baseline
    const __u32 ports[AOT_N_PORTS] = AOT_LOGICAL_PORTS;
    int mtfd = bpf_map__fd(mt);
    for (int i = 0; i < AOT_N_PORTS; i++) {
        struct fwd_action a; memset(&a, 0, sizeof(a));
        a.ifindex = 1;
        bpf_map_update_elem(mtfd, &ports[i], &a, BPF_ANY);
    }
    fprintf(stderr, "seeded mac_table for %d logical port(s) of %d class(es)\n",
            AOT_N_PORTS, AOT_N_OUT);

    /* Kernel ingress ifindex -> LOGICAL PORT. The program no longer carries a
     * compiled-in [2, 3, ...] table: an AOT object is built on a build machine,
     * possibly long before the node it runs on exists, so it cannot know what
     * ifindexes that node will hand out. Without an entry here the
     * ingress_iface one-hot stays empty and a trained feature contributes
     * nothing -- silently, which is how it went unnoticed for so long.
     *
     * La tabella arriva da --ingress-port, risolta dal control plane. Prima
     * veniva inventata qui: una sola voce, l'interfaccia di attach, slot 1
     * fisso, con un commento che diceva "logical port 1 unless the deployment
     * says otherwise" -- ma non c'era modo per il deployment di dire
     * altrimenti. Su un nodo con piu' di una porta quello e' un mapping
     * sbagliato che non rompe niente: fa contribuire la colonna di pesi di
     * un'altra porta. Adesso senza --ingress-port non si indovina.
     *
     * In bench mode non c'e' interfaccia, quindi non si semina nulla e la
     * feature resta vuota -- che e' anche quello che viene detto al
     * riferimento, cosi' le due parti confrontano la stessa cosa. */
    struct bpf_map *ip_map = bpf_object__find_map_by_name(obj, "ingress_port");
    if (ip_map && g_n_ingress > 0) {
        int done = 0;
        for (int i = 0; i < g_n_ingress; i++) {
            if (bpf_map_update_elem(bpf_map__fd(ip_map), &g_ingress_ifx[i],
                                    &g_ingress_slot[i], BPF_ANY)) {
                fprintf(stderr, "WARNING: could not seed ingress_port for ifindex "
                                "%u (%s)\n", g_ingress_ifx[i], strerror(errno));
            } else {
                fprintf(stderr, "seeded ingress_port: ifindex %u -> one-hot slot %u\n",
                        g_ingress_ifx[i], g_ingress_slot[i]);
                done++;
            }
        }
        if (!done)
            fprintf(stderr, "WARNING: ingress_port is empty after seeding, so the "
                            "ingress_iface feature contributes nothing\n");
    } else if (ip_map && g_attach_ifindex >= 0) {
        fprintf(stderr, "ingress_port left empty: --attach without --ingress-port, "
                        "and which logical port an ifindex realises is a NODE fact "
                        "this loader cannot derive. The ingress_iface one-hot "
                        "contributes nothing to any decision.\n");
    } else if (ip_map) {
        fprintf(stderr, "ingress_port left empty (bench mode: no interface), so "
                        "the ingress_iface one-hot contributes nothing\n");
    }

    /* This node's own index. Bounded to a byte because the generated program
     * bounds it too -- the verifier needs that range to reason about the
     * switch cheaply, so an index it cannot represent is refused here rather
     * than truncated into a different node. */
    struct bpf_map *nid_map = bpf_object__find_map_by_name(obj, "node_id");
    if (nid_map) {
        int nid = g_node_id;
        if (nid < 0) {
            const char *env = getenv("IPA_NODE_ID");
            if (env && *env) nid = atoi(env);
        }
        if (nid < 0) {
            fprintf(stderr, "node_id left empty (no --node-id and no "
                            "$IPA_NODE_ID), so the node one-hot contributes "
                            "nothing\n");
        } else if (nid > 0xff) {
            fprintf(stderr, "node id %d is outside [0, 255], which is what the "
                            "datapath can represent; leaving node_id empty "
                            "rather than truncating it\n", nid);
        } else {
            __u32 k = 0, v = (__u32)nid;
            if (bpf_map_update_elem(bpf_map__fd(nid_map), &k, &v, BPF_ANY))
                fprintf(stderr, "WARNING: could not seed node_id (%s); the node "
                                "one-hot will contribute nothing\n",
                        strerror(errno));
            else
                fprintf(stderr, "seeded node_id: this node is index %u\n", v);
        }
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
    // XDP attach mode. This used to be a bare 0, which means "kernel decides"
    // -- and the kernel decides by trying native and SILENTLY falling back to
    // generic. A deploy that lands on the generic path (inside
    // netif_receive_skb, after the sk_buff is allocated) is not the path being
    // measured, and nothing in the output said so. Native is the default now,
    // the mode actually in effect is read back from the kernel, and a failed
    // native attach is an error rather than a quiet downgrade.
    __u32 xdp_flags = XDP_FLAGS_DRV_MODE;
    const char *mode_name = "native";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--attach") && i + 1 < argc) g_attach_ifindex = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--node-id") && i + 1 < argc) {
            g_node_id = atoi(argv[++i]);
        }
        else if (!strcmp(argv[i], "--ingress-port") && i + 1 < argc) {
            if (parse_ingress_ports(argv[++i])) return 2;
        }
        else if (!strcmp(argv[i], "--pin-dir") && i + 1 < argc) g_pin_dir = argv[++i];
        else if (!strcmp(argv[i], "--xdp-mode") && i + 1 < argc) {
            mode_name = argv[++i];
            if (!strcmp(mode_name, "native"))       xdp_flags = XDP_FLAGS_DRV_MODE;
            else if (!strcmp(mode_name, "generic")) xdp_flags = XDP_FLAGS_SKB_MODE;
            else if (!strcmp(mode_name, "auto"))    xdp_flags = 0;
            else { fprintf(stderr, "--xdp-mode: expected native|generic|auto, got %s\n",
                           mode_name); return 2; }
        }
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

    // --- LIVE DEPLOY mode: pin, hand the maps to the control plane, attach
    // only when it says so, stay resident. See the protocol at the top.
    // Requires libbpf >= 0.7 for bpf_xdp_attach/detach. ---
    if (g_attach_ifindex >= 0) {
        int rc = 1;
        char line[64];
        if (!g_pin_dir || !*g_pin_dir) {
            fprintf(stderr, "--attach needs --pin-dir: the maps are filled by "
                            "the Python control plane through bpffs, not by this "
                            "loader (see the header of loader_aot.c)\n");
            goto err;
        }
        if (strchr(g_pin_dir, '.')) {
            fprintf(stderr, "--pin-dir %s: bpffs paths cannot contain '.'\n",
                    g_pin_dir);
            goto err;
        }
        if (g_node_id >= 0 || g_n_ingress > 0) {
            fprintf(stderr, "--node-id / --ingress-port are bench-mode options. "
                            "In deploy the control plane writes node_id and "
                            "ingress_port itself -- one resolver, not two.\n");
            goto err;
        }
        if (mkdir(g_pin_dir, 0700) && errno != EEXIST) {
            fprintf(stderr, "mkdir %s: %s\n", g_pin_dir, strerror(errno));
            goto err;
        }
        unlink_stale_pins(obj, g_pin_dir);
        if (bpf_object__pin_maps(obj, g_pin_dir)) {
            fprintf(stderr, "pinning the maps under %s failed: %s. Is it on "
                            "bpffs? (mount -t bpf bpf /sys/fs/bpf)\n",
                    g_pin_dir, strerror(errno));
            goto err;
        }
        {
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = on_signal;       /* no SA_RESTART: see read_line() */
            sigaction(SIGINT,  &sa, NULL);
            sigaction(SIGTERM, &sa, NULL);
        }
        printf("READY %s\n", g_pin_dir);
        fflush(stdout);
        if (read_line(line, sizeof(line)) < 0 || strcmp(line, "ATTACH")) {
            fprintf(stderr, "the control plane did not confirm the maps "
                            "(no ATTACH on stdin): not attaching\n");
            goto unpin;
        }
        if (bpf_xdp_attach(g_attach_ifindex, disp_fd, xdp_flags, NULL)) {
            fprintf(stderr, "bpf_xdp_attach(ifindex=%d, mode=%s) failed: %s\n",
                    g_attach_ifindex, mode_name, strerror(errno));
            if (xdp_flags == XDP_FLAGS_DRV_MODE)
                fprintf(stderr,
                        "  This interface's driver may not support native XDP "
                        "(emulated NICs such as e1000 do not; veth, virtio_net "
                        "and most physical drivers do).\n"
                        "  To deploy on the generic path instead, say so "
                        "explicitly: --xdp-mode generic\n");
            goto unpin;
        }
        /* Trust the kernel, not the flags we passed: with --xdp-mode auto the
         * kernel chooses, and every number from this run describes whichever
         * path it actually chose. */
        {
            LIBBPF_OPTS(bpf_xdp_query_opts, q);
            const char *actual = "unknown";
            if (!bpf_xdp_query(g_attach_ifindex, xdp_flags, &q)) {
                if      (q.attach_mode == XDP_ATTACHED_DRV)   actual = "native";
                else if (q.attach_mode == XDP_ATTACHED_SKB)   actual = "generic";
                else if (q.attach_mode == XDP_ATTACHED_HW)    actual = "offload";
                else if (q.attach_mode == XDP_ATTACHED_MULTI) actual = "multi";
            }
            if (strcmp(actual, mode_name) && strcmp(mode_name, "auto"))
                printf("[deploy] WARNING: asked for %s mode, kernel reports %s. "
                       "Every measurement from this run describes the %s path.\n",
                       mode_name, actual, actual);
            else
                printf("[deploy] XDP attach mode in effect: %s\n", actual);
            printf("ATTACHED %s\n", actual);
        }
        printf("================================================================\n");
        printf(" AOT-literal LIVE deploy (Pipeline 1) -- NO clang on this node\n");
        printf("================================================================\n");
        printf("[deploy] open+load (verify+JIT): %.3f ms  "
               "(BCC recompile of the same model: ~1.3 s, reference not measured here)\n",
               t2 - t0);
        printf("[deploy] xdp_dispatch attached to ifindex %d, maps pinned under "
               "%s. Ctrl-C to detach.\n", g_attach_ifindex, g_pin_dir);
        /* Flush now: when stdout is a pipe rather than a TTY, C stdio is
         * fully buffered, and the control plane is waiting for ATTACHED. */
        fflush(stdout);
        while (!g_stop) {
            if (read_line(line, sizeof(line)) < 0 || !strcmp(line, "DETACH"))
                break;
        }
        bpf_xdp_detach(g_attach_ifindex, xdp_flags, NULL);
        printf("[deploy] detached from ifindex %d.\n", g_attach_ifindex);
        fflush(stdout);
        rc = 0;
unpin:
        bpf_object__unpin_maps(obj, g_pin_dir);
        rmdir(g_pin_dir);
        bpf_object__close(obj);
        return rc;
    }

    // Bench mode only: seed the maps the TEST_RUN reads. In deploy the
    // control plane does this, see above.
    if (seed_maps(obj)) goto err;

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
    printf("   (BCC recompile of the same model: ~1.3 s -- reference value, NOT\n");
    printf("    measured by this loader; see '[M1 update timing]' in --only kernel)\n\n");
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
