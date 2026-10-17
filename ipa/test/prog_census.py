"""prog_census.py -- how many BPF programs, and how large, a step has loaded
(the kernel's program list before and after).
"""
import ctypes as ct
import os

_NR_BPF = 321
_BPF_PROG_GET_NEXT_ID = 11
_BPF_PROG_GET_FD_BY_ID = 13
_BPF_OBJ_GET_INFO_BY_FD = 15

try:
    _libc = ct.CDLL(None, use_errno=True)
except OSError:  # pragma: no cover (non Linux)
    _libc = None


class _AttrId(ct.Structure):
    _fields_ = [("id", ct.c_uint32), ("next_id", ct.c_uint32),
                ("open_flags", ct.c_uint32)]


class _AttrInfo(ct.Structure):
    _fields_ = [("bpf_fd", ct.c_uint32), ("info_len", ct.c_uint32),
                ("info", ct.c_uint64)]


def _bpf(cmd, attr):
    return _libc.syscall(_NR_BPF, cmd, ct.byref(attr), ct.sizeof(attr))


def snapshot():
    """The ids of the programs loaded now, or None if they cannot be read."""
    if _libc is None:
        return None
    ids, cur = set(), 0
    while True:
        a = _AttrId(id=cur)
        if _bpf(_BPF_PROG_GET_NEXT_ID, a) != 0:
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
    """The programs that appeared after `before` (a snapshot())."""
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
