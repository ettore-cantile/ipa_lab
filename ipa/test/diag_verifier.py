#!/usr/bin/env python3
"""
diag_verifier.py -- perche' P2 oltre due strati e P1 oltre ~300 pesi non
caricano: le statistiche del verificatore, forma per forma.

Il banco (bench_scaling, bench_depth_vs_width) registra solo l'esito: carica o
RIFIUTATO. Qui ogni programma si carica con log_level = 4 (BPF_LOG_STATS), che
costa quasi niente e riporta, anche quando il verificatore rinuncia:

  processed  istruzioni percorse (limite 1 000 000)
  total      stati salvati per la potatura
  peak       stati vivi al massimo
  max/insn   stati salvati sulla stessa istruzione

Quando `processed` cresce molto piu' delle istruzioni del programma, il
verificatore percorre gli stessi blocchi su molti cammini e la potatura non li
riunisce: e' un'esplosione di cammini, non un programma troppo lungo.

La causa, misurata il 2026-09-28 su 6.8.0-142: la ReLU scritta
`a > 0 ? a : 0` diventava un salto condizionale per neurone, e il verificatore
li percorreva su entrambi i lati. P2 a 1 strato: 799 563 istruzioni percorse
(56x il programma), da 3 strati oltre il limite; P1 1x16: 1 000 001 (287x).
Con la ReLU senza salto (ipa_relu: a & ~(a >> 63), dietro una barriera asm
perche' clang non la rifaccia salto) P2 sta fra 120 000 e 137 000 da 1 a 6
strati e P1 tier B fra 5 700 e 12 000.

Ogni forma si prova in due varianti:

  attuale  il sorgente del progetto, con ipa_relu
  salto    la vecchia ReLU `a > 0 ? a : 0` rimessa al suo posto: riproduce
           il problema, cosi' il confronto resta ripetibile

Uso (root):
  sudo python3 ipa/test/diag_verifier.py            # P2 1..6 strati, P3, P1 tier A/B
  sudo python3 ipa/test/diag_verifier.py --only p2
  sudo python3 ipa/test/diag_verifier.py --only p1
  sudo python3 ipa/test/diag_verifier.py --only p3
"""
import argparse
import ctypes as ct
import os
import platform
import random
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SHARED = os.path.dirname(HERE)
for _p in (HERE, SHARED, os.path.join(SHARED, "poc_aot"),
           os.path.join(SHARED, "methods")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

BPF_PROG_LOAD = 5
BPF_PROG_TYPE_XDP = 6
LOG_STATS = 4
LOG_SIZE = 1 << 20

_libc = ct.CDLL(None, use_errno=True)
_libc.syscall.restype = ct.c_long


# ---------------------------------------------------------------------------
# le due trasformazioni "nobranch"
_P2_RELU = re.compile(r"ipa_relu\(([^()]*(?:\([^()]*\))?[^()]*)\)")
_P1_RELU = re.compile(r"ipa_relu\((a\w+)\)")


def _old_relu(src, rx, what):
    """ipa_relu(x) -> ((x) > 0 ? (x) : 0) dentro la funzione del modello."""
    out, n = rx.subn(lambda m: f"(({m.group(1)}) > 0 ? ({m.group(1)}) : 0)", src)
    if n == 0:
        raise RuntimeError(f"variante 'salto' di {what}: nessuna chiamata a "
                           f"ipa_relu trovata -- aggiornare diag_verifier")
    return out


def p2_leaf_variant(leaf, variant):
    if variant == "attuale":
        return leaf
    if variant == "salto":
        head, body = leaf.split("int arch_generic_2layer(", 1)
        return head + "int arch_generic_2layer(" + _old_relu(body, _P2_RELU, "P2")
    raise ValueError(variant)


def p3_variant(src, variant):
    if variant == "attuale":
        return src
    if variant == "salto":
        at = src.index("static __always_inline long long ipa_relu(")
        head, rest = src[:at], src[at:]
        end = rest.index("\n}\n") + 3          # dopo la definizione
        return head + rest[:end] + _old_relu(rest[end:], _P2_RELU, "P3")
    raise ValueError(variant)


def p1_variant(src, variant):
    if variant == "attuale":
        return src
    if variant == "salto":
        return _old_relu(src, _P1_RELU, "P1")
    raise ValueError(variant)


# ---------------------------------------------------------------------------
_STATS_RE = re.compile(
    r"processed (\d+) insns \(limit (\d+)\) max_states_per_insn (\d+) "
    r"total_states (\d+) peak_states (\d+)")


def parse_log(log):
    m = _STATS_RE.search(log)
    tail = [l for l in log.strip().splitlines() if l.strip()][-4:]
    if not m:
        return {"processed": None, "tail": tail}
    return {"processed": int(m.group(1)), "max_per_insn": int(m.group(3)),
            "total": int(m.group(4)), "peak": int(m.group(5)), "tail": tail}


def raw_load(insns: bytes, name: str):
    """BPF_PROG_LOAD diretto, log_level=4. -> (fd o -errno, log)."""
    buf = ct.create_string_buffer(LOG_SIZE)
    lic = ct.create_string_buffer(b"GPL")
    ibuf = ct.create_string_buffer(insns, len(insns))
    attr = ct.create_string_buffer(144)
    struct.pack_into("IIQQIIQII16s", attr, 0,
                     BPF_PROG_TYPE_XDP, len(insns) // 8,
                     ct.addressof(ibuf), ct.addressof(lic),
                     LOG_STATS, LOG_SIZE, ct.addressof(buf), 0, 0,
                     name.encode()[:15])
    fd = _libc.syscall(321, BPF_PROG_LOAD, attr, ct.c_uint(144))
    err = ct.get_errno()
    log = buf.value.decode(errors="replace")
    if fd >= 0:
        os.close(fd)
        return 0, log
    return -err, log


def libbpf_load(o_path, prog="xdp_model"):
    """Carica l'oggetto AOT con libbpf, log_level=4 sul programma `prog`."""
    lb = ct.CDLL("libbpf.so.1", use_errno=True)
    lb.bpf_object__open_file.restype = ct.c_void_p
    lb.bpf_object__open_file.argtypes = [ct.c_char_p, ct.c_void_p]
    lb.bpf_object__next_program.restype = ct.c_void_p
    lb.bpf_object__next_program.argtypes = [ct.c_void_p, ct.c_void_p]
    lb.bpf_program__name.restype = ct.c_char_p
    lb.bpf_program__name.argtypes = [ct.c_void_p]
    lb.bpf_program__set_log_level.argtypes = [ct.c_void_p, ct.c_uint]
    lb.bpf_program__set_log_buf.argtypes = [ct.c_void_p, ct.c_char_p,
                                            ct.c_size_t]
    lb.bpf_object__load.argtypes = [ct.c_void_p]
    lb.bpf_object__close.argtypes = [ct.c_void_p]
    # zittisce le stampe di libbpf: il log che serve e' nel buffer
    PRINT = ct.CFUNCTYPE(ct.c_int, ct.c_int, ct.c_char_p, ct.c_void_p)
    lb.libbpf_set_print.argtypes = [PRINT]
    lb.libbpf_set_print.restype = ct.c_void_p
    keep = PRINT(lambda *a: 0)
    lb.libbpf_set_print(keep)

    obj = lb.bpf_object__open_file(o_path.encode(), None)
    if not obj:
        raise RuntimeError(f"libbpf: apertura di {o_path} fallita")
    buf = ct.create_string_buffer(LOG_SIZE)
    p = lb.bpf_object__next_program(obj, None)
    while p:
        if lb.bpf_program__name(p).decode() == prog:
            lb.bpf_program__set_log_level(p, LOG_STATS)
            lb.bpf_program__set_log_buf(p, buf, LOG_SIZE)
        p = lb.bpf_object__next_program(obj, p)
    rc = lb.bpf_object__load(obj)
    lb.bpf_object__close(obj)
    return rc, buf.value.decode(errors="replace")


def insn_count_of(o_path, section_prog="xdp_model"):
    """Istruzioni di xdp_model nell'oggetto (llvm-objdump), per il rapporto
    processed / istruzioni."""
    for tool in ("llvm-objdump-18", "llvm-objdump"):
        try:
            r = subprocess.run([tool, "-d", "--no-show-raw-insn", o_path],
                               capture_output=True, text=True)
        except FileNotFoundError:
            continue
        n, on = 0, False
        for line in r.stdout.splitlines():
            m = re.match(r"^[0-9a-f]+ <(\w+)>:", line)
            if m and not m.group(1).startswith("LBB"):
                on = m.group(1) == section_prog
            elif on and re.match(r"^\s+\d+:", line):
                n += 1
        return n
    return None


# ---------------------------------------------------------------------------
def row(label, variant, n_insns, rc, st):
    esito = "carica" if rc == 0 else f"RIFIUTATO ({os.strerror(-rc) if rc < 0 else rc})"
    if st.get("processed") is None:
        print(f"  {label:14s} {variant:9s} {str(n_insns or '?'):>7s} "
              f"{'?':>9s} {'':>7s} {'':>7s} {'':>6s}  {esito}")
        for l in st["tail"]:
            print(f"      | {l}")
        return
    ratio = (st["processed"] / n_insns) if n_insns else 0
    print(f"  {label:14s} {variant:9s} {str(n_insns or '?'):>7s} "
          f"{st['processed']:>9d} {st['total']:>7d} {st['peak']:>7d} "
          f"{ratio:>6.0f}x  {esito}")
    if rc != 0:
        for l in st["tail"]:
            if "processed" not in l and "verification time" not in l:
                print(f"      | {l}")


HDR = (f"  {'forma':14s} {'variante':9s} {'insns':>7s} {'processed':>9s} "
       f"{'total':>7s} {'peak':>7s} {'proc/insn':>6s}  esito")


def p2_cell(d, v):
    """Una forma di P2, nel processo figlio: un errore fatale di LLVM (lo
    stack BPF sforato) termina il processo e non si puo' intercettare."""
    from bcc import BPF
    from ebpf_template_arch import EBPF_TEMPLATE_ARCH_DISPATCHER, build_arch_leaf

    src = ("#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
           + "\n" + p2_leaf_variant(build_arch_leaf(d), v))
    b = BPF(text=src)
    insns = b.dump_func("arch_generic_2layer")
    rc, log = raw_load(insns, "arch_generic")
    row(f"{d} strati", v, len(insns) // 8, rc, parse_log(log))
    b.cleanup()


def p3_cell(v):
    """P3 nel processo figlio: layer_first e layer_hidden. La profondita' non
    entra nel programma (un layer generico rientrato con i tail call), quindi
    una sola forma."""
    from bcc import BPF
    from ebpf_modular import EBPF_MODULAR_FULL

    b = BPF(text=p3_variant(EBPF_MODULAR_FULL, v))
    for fn in ("layer_first", "layer_hidden"):
        insns = b.dump_func(fn)
        rc, log = raw_load(insns, fn[:15])
        row(fn, v, len(insns) // 8, rc, parse_log(log))
    b.cleanup()


def run_p3(variants):
    print("\nP3 (modular), i due programmi con la ReLU")
    print(HDR)
    for v in variants:
        r = subprocess.run([sys.executable, os.path.abspath(__file__),
                            "--p3-cell", v], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            print(r.stdout.rstrip(), flush=True)
            continue
        err = [l for l in r.stderr.splitlines() if l.strip()]
        why = next((l for l in err if "error:" in l), err[-1] if err else "?")
        print(f"  {'P3':14s} {v:9s} non compila -- {why[:90]}", flush=True)


def run_p2(depths, variants):
    print("\nP2 (template), leaf arch_generic_2layer, larghezza 4, descrittore "
          "default")
    print(HDR)
    for d in depths:
        for v in variants:
            r = subprocess.run([sys.executable, os.path.abspath(__file__),
                                "--p2-cell", str(d), v],
                               capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                print(r.stdout.rstrip(), flush=True)
                continue
            err = [l for l in r.stderr.splitlines() if l.strip()]
            why = next((l for l in err if "error:" in l), err[-1] if err else "?")
            if "stack limit" in why:
                why = "clang: stack BPF oltre 512 byte"
            print(f"  {f'{d} strati':14s} {v:9s} non compila -- {why[:90]}",
                  flush=True)


def run_p1(tiers, variants):
    import bench_depth_vs_width as DW
    import p1_aot

    for desc in ("default", "no_onehot"):
        shape = DW.build_shape(desc)
        print(f"\nP1 (oggetto AOT), descrittore {desc} (n_in={shape['n_in']})")
        print(HDR)
        for tier, label, dims in DW.shapes_for(shape):
            if tier[0] not in tiers:
                continue
            nw = DW.weight_count(shape["n_in"], dims, shape["n_out"])
            rng = random.Random(42)
            w = [rng.randint(-100, 100) for _ in range(nw)]
            base = p1_aot.p1_source([(0, w, 128)], features=shape["features"],
                                    n_out=shape["n_out"], hidden_dims=dims)
            for v in variants:
                try:
                    o, _ = p1_aot.compile_object(p1_variant(base, v))
                except RuntimeError as e:
                    print(f"  {tier[0]} {label.strip():11s} {v:9s} clang: "
                          f"{str(e).splitlines()[-1][:80]}")
                    continue
                rc, log = libbpf_load(o)
                row(f"{tier[0]} {label.split()[-1]}", v, insn_count_of(o), rc,
                    parse_log(log))


def environment():
    def rd(p):
        try:
            with open(p) as f:
                return f.read().strip()
        except OSError:
            return "?"
    cap = [l.split()[1] for l in rd("/proc/self/status").splitlines()
           if l.startswith("CapEff")]
    print(f"kernel {platform.release()}  CapEff {cap[0] if cap else '?'}  "
          f"virt {subprocess.run(['systemd-detect-virt'], capture_output=True, text=True).stdout.strip() or '?'}")
    print(f"mitigazioni: spectre_v1 = "
          f"{rd('/sys/devices/system/cpu/vulnerabilities/spectre_v1')}")
    print(f"             spec_store_bypass = "
          f"{rd('/sys/devices/system/cpu/vulnerabilities/spec_store_bypass')}")
    print(f"cmdline: {rd('/proc/cmdline')}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", choices=("p1", "p2", "p3"))
    ap.add_argument("--depths", default="1,2,3,4,5,6")
    ap.add_argument("--tiers", default="AB")
    ap.add_argument("--p2-cell", nargs=2, metavar=("STRATI", "VARIANTE"),
                    help=argparse.SUPPRESS)
    ap.add_argument("--p3-cell", metavar="VARIANTE", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.p3_cell:
        p3_cell(args.p3_cell)
        return
    if args.p2_cell:
        p2_cell(int(args.p2_cell[0]), args.p2_cell[1])
        return
    if os.geteuid() != 0:
        sys.exit("serve root: sudo python3 ipa/test/diag_verifier.py")
    environment()
    if args.only in (None, "p2"):
        run_p2([int(x) for x in args.depths.split(",")],
               ("attuale", "salto"))
    if args.only in (None, "p3"):
        run_p3(("attuale", "salto"))
    if args.only in (None, "p1"):
        run_p1(set(args.tiers), ("attuale", "salto"))


if __name__ == "__main__":
    main()
