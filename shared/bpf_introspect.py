#!/usr/bin/env python3
"""
bpf_introspect.py -- dump a LIVE BPF array map's contents by NAME, without
bpftool.

Why this exists: `bpftool` is not installed in the Kathara node images used
by this lab ("executable file not found in $PATH", confirmed in testing
session), so `bpftool map dump name X` -- the command this project's docs
and shared/test/test_frr_linkstate.py originally relied on to read a live
pipeline's pkt_stats/cls_stats counters from a SEPARATE process -- does not
work here. This module reimplements exactly the part needed (find a map by
its kernel-visible name, read all its slots) using nothing but the raw
`bpf()` syscall via ctypes, the same mechanism shared/test/verify_prog_run.py
already uses for BPF_PROG_TEST_RUN and BPF_OBJ_GET_INFO_BY_FD -- so if that
works on this node (it does, it's how every kernel test in this project
runs), this works too. No BCC, no bpftool, no dependency beyond libc.

Usage (as a library):
    from bpf_introspect import dump_array_map_by_name
    values = dump_array_map_by_name("cls_stats_t2", max_entries=7)
    # -> {0: 1000, 1: 0, 2: 340, ...} or None if not found

Usage (as a CLI, e.g. from a second `kathara exec` shell):
    python3 shared/bpf_introspect.py cls_stats_t2 7
    python3 shared/bpf_introspect.py pkt_stats 3
"""
import ctypes as ct
import os
import sys

_libc = ct.CDLL("libc.so.6", use_errno=True)
_SYS_bpf = 321   # x86_64; see shared/test/verify_prog_run.py's identical constant

# bpf_cmd values (include/uapi/linux/bpf.h) -- stable ABI since Linux 4.x.
BPF_MAP_LOOKUP_ELEM     = 1
BPF_PROG_GET_NEXT_ID    = 11
BPF_MAP_GET_NEXT_ID     = 12
BPF_PROG_GET_FD_BY_ID   = 13
BPF_MAP_GET_FD_BY_ID    = 14
BPF_OBJ_GET_INFO_BY_FD  = 15

BPF_OBJ_NAME_LEN = 16


class _AttrGetNextId(ct.Structure):
    _fields_ = [("start_id", ct.c_uint32), ("next_id", ct.c_uint32), ("open_flags", ct.c_uint32)]


class _AttrGetFdById(ct.Structure):
    _fields_ = [("map_id", ct.c_uint32), ("next_id", ct.c_uint32), ("open_flags", ct.c_uint32)]


class _AttrObjInfo(ct.Structure):
    _fields_ = [("bpf_fd", ct.c_uint32), ("info_len", ct.c_uint32), ("info", ct.c_uint64)]


class _BpfMapInfo(ct.Structure):
    """Matches struct bpf_map_info's stable prefix (type/id/key_size/value_size/
    max_entries/map_flags/name) -- fields after `name` vary more across kernel
    versions and are not needed here, so the struct (and the buffer backing
    it) is intentionally over-allocated rather than modeling them."""
    _fields_ = [
        ("map_type",    ct.c_uint32),
        ("id",          ct.c_uint32),
        ("key_size",    ct.c_uint32),
        ("value_size",  ct.c_uint32),
        ("max_entries", ct.c_uint32),
        ("map_flags",   ct.c_uint32),
        ("name",        ct.c_char * BPF_OBJ_NAME_LEN),
    ]


class _AttrLookupElem(ct.Structure):
    _fields_ = [("map_fd", ct.c_uint32), ("pad0", ct.c_uint32),
               ("key", ct.c_uint64), ("value_or_next_key", ct.c_uint64), ("flags", ct.c_uint64)]


def _bpf(cmd, attr):
    r = _libc.syscall(_SYS_bpf, cmd, ct.byref(attr), ct.sizeof(attr))
    if r < 0:
        e = ct.get_errno()
        raise OSError(e, os.strerror(e))
    return r


def _map_info(fd):
    buf = (ct.c_uint8 * 256)()
    info = ct.cast(buf, ct.POINTER(_BpfMapInfo)).contents
    attr = _AttrObjInfo(bpf_fd=fd, info_len=ct.sizeof(buf), info=ct.cast(buf, ct.c_void_p).value)
    _bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
    return info


def find_map_id_by_name(name: str):
    """Iterate every live BPF map on this node (BPF_MAP_GET_NEXT_ID) and
    return the id of the HIGHEST-numbered (most recently created) one whose
    kernel-visible name matches -- if a stale map from an earlier crashed/
    killed test run with the same name is still around (map ids are never
    reused while any reference to the map is held), the newest one is the
    one an active pipeline is actually using. Returns None if no match.
    Requires CAP_SYS_ADMIN/CAP_BPF (root)."""
    wanted = name.encode()[:BPF_OBJ_NAME_LEN - 1]
    start = 0
    best_id = None
    while True:
        attr = _AttrGetNextId(start_id=start)
        try:
            _bpf(BPF_MAP_GET_NEXT_ID, attr)
        except OSError as e:
            if e.errno == 2:   # ENOENT: no more maps
                return best_id
            raise
        map_id = attr.next_id
        start = map_id
        try:
            fd_attr = _AttrGetFdById(map_id=map_id)
            fd = _bpf(BPF_MAP_GET_FD_BY_ID, fd_attr)
        except OSError:
            continue   # map disappeared between enumeration and open; skip
        try:
            info = _map_info(fd)
            if info.name == wanted:
                best_id = map_id   # ids increase monotonically -> last match wins
        finally:
            os.close(fd)


def dump_array_map_by_name(name: str, max_entries: int):
    """Returns {key: u64_value} for a BPF_MAP_TYPE_ARRAY (or HASH with u32
    keys 0..max_entries-1) map named `name`, or None if no such map is
    currently loaded. Values are read as a raw 8-byte little-endian u64 --
    matches every stats map in this project (pkt_stats*/cls_stats*, all
    BPF_ARRAY(__u64))."""
    map_id = find_map_id_by_name(name)
    if map_id is None:
        return None
    fd_attr = _AttrGetFdById(map_id=map_id)
    fd = _bpf(BPF_MAP_GET_FD_BY_ID, fd_attr)
    try:
        out = {}
        for key in range(max_entries):
            key_buf = ct.c_uint32(key)
            val_buf = ct.c_uint64(0)
            attr = _AttrLookupElem(
                map_fd=fd,
                key=ct.cast(ct.byref(key_buf), ct.c_void_p).value,
                value_or_next_key=ct.cast(ct.byref(val_buf), ct.c_void_p).value,
            )
            try:
                _bpf(BPF_MAP_LOOKUP_ELEM, attr)
                out[key] = val_buf.value
            except OSError:
                pass   # key not present (HASH map) -- leave it out
        return out
    finally:
        os.close(fd)


def main():
    import json
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <map_name> <max_entries>")
    name, max_entries = sys.argv[1], int(sys.argv[2])
    result = dump_array_map_by_name(name, max_entries)
    if result is None:
        sys.exit(f"[bpf_introspect] no live map named {name!r} found (is a pipeline attached?)")
    print(json.dumps(result))   # int keys -> JSON string keys; caller casts back to int


if __name__ == "__main__":
    main()
