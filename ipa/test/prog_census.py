"""
prog_census.py -- quanti programmi BPF, e quanto grandi, ha caricato un passo.

    before = snapshot()
    setup = build_pipeline(...)
    size = loaded_since(before)    # {"n_progs", "xlated", "jited", "names"}

Perche' cosi' e non dai descrittori delle pipeline: ogni pipeline carica i
suoi programmi in un modo diverso (BCC, oggetto AOT con libbpf, una catena di
programmi per P3, il dispatcher piu' il programma del modello per P1.5), e
bench_scaling._totals li elenca a mano pipeline per pipeline. Qui si chiede al
kernel quali programmi esistono prima e dopo (BPF_PROG_GET_NEXT_ID): i nuovi
sono quelli del passo, qualunque sia la strada con cui sono stati caricati, e
la somma delle loro istruzioni e' la "dimensione caricata" del confronto fra
istruzioni caricate ed eseguite, misurata sullo stesso caricamento che poi va
sotto traffico.

Mai fatale: senza permessi o su un kernel che rifiuta una chiamata si
restituisce None, e il banco va avanti senza la colonna.
"""
import ctypes as ct
import os

_NR_BPF = 321                      # x86_64
_BPF_PROG_GET_NEXT_ID = 11
_BPF_PROG_GET_FD_BY_ID = 13
_BPF_OBJ_GET_INFO_BY_FD = 15

try:
    _libc = ct.CDLL(None, use_errno=True)
except OSError:                    # pragma: no cover (non Linux)
    _libc = None


class _AttrId(ct.Structure):
    # BPF_PROG_GET_NEXT_ID usa (start_id, next_id); BPF_PROG_GET_FD_BY_ID
    # (prog_id, next_id, open_flags). Stesso layout.
    _fields_ = [("id", ct.c_uint32), ("next_id", ct.c_uint32),
                ("open_flags", ct.c_uint32)]


class _AttrInfo(ct.Structure):
    _fields_ = [("bpf_fd", ct.c_uint32), ("info_len", ct.c_uint32),
                ("info", ct.c_uint64)]


def _bpf(cmd, attr):
    return _libc.syscall(_NR_BPF, cmd, ct.byref(attr), ct.sizeof(attr))


def snapshot():
    """Gli id dei programmi caricati ora, o None se non si possono leggere."""
    if _libc is None:
        return None
    ids, cur = set(), 0
    while True:
        a = _AttrId(id=cur)
        if _bpf(_BPF_PROG_GET_NEXT_ID, a) != 0:
            # ENOENT = fine della lista; altro = niente permessi
            return ids if ct.get_errno() == 2 else None
        cur = a.next_id
        ids.add(cur)


def _info(prog_id):
    fd = _bpf(_BPF_PROG_GET_FD_BY_ID, _AttrId(id=prog_id))
    if fd < 0:
        return None
    try:
        buf = (ct.c_uint8 * 256)()
        a = _AttrInfo(bpf_fd=fd, info_len=ct.sizeof(buf),
                      info=ct.cast(buf, ct.c_void_p).value)
        if _bpf(_BPF_OBJ_GET_INFO_BY_FD, a) != 0:
            return None
        raw = bytes(buf)
        jited = int.from_bytes(raw[16:20], "little")
        xlated = int.from_bytes(raw[20:24], "little") // 8
        name = raw[64:80].split(b"\0", 1)[0].decode("ascii", "replace")
        return xlated, jited, name
    finally:
        os.close(fd)


def loaded_since(before):
    """I programmi comparsi dopo `before` (uno snapshot()): quanti, la somma
    delle istruzioni tradotte (xlated, quelle che il verificatore ha
    accettato) e dei byte JIT, e i nomi. None se il censimento non si fa."""
    if before is None:
        return None
    after = snapshot()
    if after is None:
        return None
    out = dict(n_progs=0, xlated=0, jited=0, names=[])
    for pid in sorted(after - before):
        inf = _info(pid)
        if inf is None:
            continue
        x, j, name = inf
        out["n_progs"] += 1
        out["xlated"] += x
        out["jited"] += j
        out["names"].append(f"{name}:{x}")
    return out
