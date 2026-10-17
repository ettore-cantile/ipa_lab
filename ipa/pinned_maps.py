#!/usr/bin/env python3
"""pinned_maps.py -- drive a prebuilt BPF object through its pinned maps, with the
same interface as a BCC object, so one control plane serves every pipeline.
"""
import ctypes as ct
import os
import platform

_BPF_SYSCALL_NR = {"x86_64": 321, "aarch64": 280}
_BPF_MAP_LOOKUP_ELEM = 1
_BPF_MAP_UPDATE_ELEM = 2
_BPF_MAP_DELETE_ELEM = 3
_BPF_MAP_GET_NEXT_KEY = 4
_BPF_OBJ_GET = 7
_BPF_OBJ_GET_INFO_BY_FD = 15
_BPF_ANY = 0
_PERCPU_TYPES = (5, 6, 10, 21)
_ARRAY_TYPES = (2, 6)


def possible_cpus() -> int:
    """How many per-CPU slots the kernel copies."""
    with open("/sys/devices/system/cpu/possible") as f:
        spec = f.read().strip()
    n = 0
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        n += (int(hi) - int(lo) + 1) if hi else 1
    return n

_libc = None


def _get_libc():
    global _libc
    if _libc is None:
        _libc = ct.CDLL("libc.so.6", use_errno=True)
    return _libc


class PinnedMapError(RuntimeError):
    """A pinned map could not be opened, read or written."""


class FwdAction(ct.Structure):
    """struct fwd_action, as every P1 source declares it (packed, 16 bytes)."""
    _pack_ = 1
    _fields_ = [("ifindex", ct.c_uint32),
                ("src_mac", ct.c_uint8 * 6),
                ("dst_mac", ct.c_uint8 * 6)]


class _AttrObj(ct.Structure):
    _fields_ = [("pathname", ct.c_uint64),
                ("bpf_fd", ct.c_uint32),
                ("file_flags", ct.c_uint32)]


class _AttrMapElem(ct.Structure):
    """union bpf_attr for MAP_*_ELEM."""
    _fields_ = [("map_fd", ct.c_uint32),
                ("_pad", ct.c_uint32),
                ("key", ct.c_uint64),
                ("value", ct.c_uint64),
                ("flags", ct.c_uint64)]


class _MapInfo(ct.Structure):
    _fields_ = [("type", ct.c_uint32), ("id", ct.c_uint32),
                ("key_size", ct.c_uint32), ("value_size", ct.c_uint32),
                ("max_entries", ct.c_uint32), ("map_flags", ct.c_uint32),
                ("name", ct.c_char * 16), ("ifindex", ct.c_uint32),
                ("btf_vmlinux_value_type_id", ct.c_uint32),
                ("netns_dev", ct.c_uint64), ("netns_ino", ct.c_uint64),
                ("btf_id", ct.c_uint32), ("btf_key_type_id", ct.c_uint32),
                ("btf_value_type_id", ct.c_uint32)]


class _AttrObjInfo(ct.Structure):
    _fields_ = [("bpf_fd", ct.c_uint32), ("info_len", ct.c_uint32),
                ("info", ct.c_uint64)]


def _syscall(cmd, attr):
    machine = platform.machine()
    nr = _BPF_SYSCALL_NR.get(machine)
    if nr is None:
        raise PinnedMapError(f"bpf(2) syscall number unknown for {machine!r}; "
                             f"add it to _BPF_SYSCALL_NR")
    return _get_libc().syscall(nr, cmd, ct.byref(attr), ct.sizeof(attr))


def obj_get(path: str) -> int:
    """File descriptor for the map or program pinned at `path`."""
    buf = ct.create_string_buffer(path.encode())
    attr = _AttrObj(pathname=ct.cast(buf, ct.c_void_p).value, bpf_fd=0,
                    file_flags=0)
    fd = _syscall(_BPF_OBJ_GET, attr)
    if fd < 0:
        err = ct.get_errno()
        raise PinnedMapError(
            f"BPF_OBJ_GET({path}) failed: {os.strerror(err)}. Is bpffs mounted "
            f"(mount -t bpf bpf /sys/fs/bpf) and did the loader pin the maps "
            f"there (loader_aot --pin-dir)?")
    return fd


def map_info(fd: int) -> _MapInfo:
    info = _MapInfo()
    attr = _AttrObjInfo(bpf_fd=fd, info_len=ct.sizeof(info),
                        info=ct.cast(ct.byref(info), ct.c_void_p).value)
    if _syscall(_BPF_OBJ_GET_INFO_BY_FD, attr) < 0:
        raise PinnedMapError(
            f"BPF_OBJ_GET_INFO_BY_FD({fd}) failed: "
            f"{os.strerror(ct.get_errno())}")
    return info


def _u32vec(value_size: int):
    """A struct of N __u32 sized from the map itself (link_state, queue_state)."""
    if value_size % 4:
        raise PinnedMapError(f"value of {value_size} bytes is not a u32 vector")
    return type("U32Vec", (ct.Structure,),
                {"_fields_": [("v", ct.c_uint32 * (value_size // 4))]})


class PinnedMap:
    """One pinned map, indexable the way a BCC table is."""

    def __init__(self, path: str):
        self.path = path
        self.map_fd = obj_get(path)
        info = map_info(self.map_fd)
        self.name = info.name.decode(errors="replace")
        self.key_size = int(info.key_size)
        self.value_size = int(info.value_size)
        self.max_entries = int(info.max_entries)
        self.type = int(info.type)
        self.percpu = self.type in _PERCPU_TYPES
        self.ncpu = possible_cpus() if self.percpu else 1
        self._stride = ((self.value_size + 7) // 8) * 8 if self.percpu \
            else self.value_size
        self._buf_size = self._stride * self.ncpu
        self.Leaf = None

    def __repr__(self):
        return (f"<PinnedMap {self.name!r} type={self.type} key={self.key_size} "
                f"value={self.value_size} @{self.path}>")

    def _as_bytes(self, obj, size, what):
        if isinstance(obj, (bytes, bytearray)):
            raw = bytes(obj)
        elif isinstance(obj, int):
            raw = obj.to_bytes(size, "little", signed=obj < 0)
        elif isinstance(obj, (ct._SimpleCData, ct.Structure, ct.Array)):
            raw = ct.string_at(ct.addressof(obj), ct.sizeof(obj))
        else:
            raise PinnedMapError(
                f"{self.name}: cannot marshal {type(obj).__name__} as a {what}")
        if len(raw) != size:
            raise PinnedMapError(
                f"{self.name}: {what} is {len(raw)} bytes, the map takes "
                f"{size}. Refused: a short write would leave the rest of the "
                f"entry as it was, a long one would be cut.")
        return raw

    def _elem(self, cmd, key, value_buf, flags):
        k = ct.create_string_buffer(self._as_bytes(key, self.key_size, "key"),
                                    self.key_size)
        attr = _AttrMapElem(map_fd=self.map_fd, _pad=0,
                            key=ct.cast(k, ct.c_void_p).value,
                            value=ct.cast(value_buf, ct.c_void_p).value,
                            flags=flags)
        return _syscall(cmd, attr)

    def _value_buf(self, value):
        """The update buffer. Per-CPU: a list/tuple gives one value per cpu; a
        single value is written to EVERY cpu (what zeroing needs)."""
        if not self.percpu:
            return self._as_bytes(value, self.value_size, "value")
        if isinstance(value, (list, tuple)):
            if len(value) != self.ncpu:
                raise PinnedMapError(f"{self.name}: {len(value)} per-cpu values, "
                                     f"the map has {self.ncpu} cpus")
            parts = value
        else:
            parts = [value] * self.ncpu
        pad = b"\x00" * (self._stride - self.value_size)
        return b"".join(self._as_bytes(v, self.value_size, "value") + pad
                        for v in parts)

    def __setitem__(self, key, value):
        v = ct.create_string_buffer(self._value_buf(value), self._buf_size)
        if self._elem(_BPF_MAP_UPDATE_ELEM, key, v, _BPF_ANY) < 0:
            raise PinnedMapError(
                f"update {self.name}: {os.strerror(ct.get_errno())}")

    def _decode(self, raw):
        if self.Leaf is not None:
            out = self.Leaf()
            ct.memmove(ct.byref(out), raw, ct.sizeof(out))
            return out
        return raw

    def __getitem__(self, key):
        """Plain map: the value (Leaf if declared, else raw bytes). Per-CPU
        map: a list with one value per cpu -- ints for u32/u64 values, as
        the elements of a BCC per-cpu leaf read back."""
        v = ct.create_string_buffer(self._buf_size)
        if self._elem(_BPF_MAP_LOOKUP_ELEM, key, v, 0) < 0:
            raise KeyError(f"{self.name}: no entry "
                           f"({os.strerror(ct.get_errno())})")
        raw = bytes(v)
        if not self.percpu:
            return self._decode(raw)
        cells = [raw[i * self._stride: i * self._stride + self.value_size]
                 for i in range(self.ncpu)]
        if self.Leaf is None and self.value_size in (4, 8):
            return [int.from_bytes(c, "little") for c in cells]
        return [self._decode(c) for c in cells]

    def clear(self):
        """Zero every entry of an array, delete every key of a hash -- what
        BCC's table.clear() does."""
        if self.type in _ARRAY_TYPES:
            zero = bytes(self.value_size)
            for k in range(self.max_entries):
                self[ct.c_uint32(k)] = zero
            return
        for k in self.keys():
            kb = ct.create_string_buffer(k, self.key_size)
            attr = _AttrMapElem(map_fd=self.map_fd, _pad=0,
                                key=ct.cast(kb, ct.c_void_p).value,
                                value=0, flags=0)
            _syscall(_BPF_MAP_DELETE_ELEM, attr)

    def __len__(self):
        """max_entries, as len() of a BCC array table."""
        return self.max_entries

    def keys(self):
        """Every key, as raw bytes (BCC-like iteration for registries)."""
        out, prev = [], None
        while True:
            nxt = ct.create_string_buffer(self.key_size)
            if prev is None:
                attr = _AttrMapElem(map_fd=self.map_fd, _pad=0, key=0,
                                    value=ct.cast(nxt, ct.c_void_p).value,
                                    flags=0)
                rc = _syscall(_BPF_MAP_GET_NEXT_KEY, attr)
            else:
                rc = self._elem(_BPF_MAP_GET_NEXT_KEY, prev, nxt, 0)
            if rc < 0:
                return out
            prev = bytes(nxt)
            out.append(prev)

    def attach_leaf_type(self, ctype):
        """Declare the value's ctypes layout, so `.Leaf()` works and reads come
        back structured (per cpu, on a per-CPU map)."""
        if ct.sizeof(ctype) != self.value_size:
            raise PinnedMapError(
                f"{self.name}: leaf type {ctype.__name__} is "
                f"{ct.sizeof(ctype)} bytes, the map's value is "
                f"{self.value_size}")
        self.Leaf = ctype
        return self


class PinnedObject:
    """`b[name]` over a directory of pinned maps, like a BCC BPF object."""

    def __init__(self, pin_dir: str, leaf_types: dict = None):
        self.pin_dir = pin_dir
        if not os.path.isdir(pin_dir):
            raise PinnedMapError(
                f"{pin_dir} does not exist: the loader pins the maps there "
                f"before it prints READY (loader_aot --pin-dir)")
        self._leaf_types = dict(leaf_types or {})
        self._maps = {}

    def __getitem__(self, name):
        if name not in self._maps:
            path = os.path.join(self.pin_dir, name)
            if not os.path.exists(path):
                raise PinnedMapError(
                    f"no map pinned at {path}. Pinned here: "
                    f"{', '.join(sorted(os.listdir(self.pin_dir))) or '(nothing)'}")
            m = PinnedMap(path)
            lt = self._leaf_types.get(name)
            if lt == "u32vec":
                lt = _u32vec(m.value_size)
            if lt is not None:
                m.attach_leaf_type(lt)
            self._maps[name] = m
        return self._maps[name]

    def __contains__(self, name):
        return os.path.exists(os.path.join(self.pin_dir, name))

    def get_table(self, name):
        """BCC compatibility: some control-plane code calls this instead."""
        return self[name]

    def prog_fd(self, name):
        """File descriptor of a pinned PROGRAM (loader_aot pins them next to
        the maps), for BPF_PROG_TEST_RUN and instruction counts."""
        path = os.path.join(self.pin_dir, name)
        if not os.path.exists(path):
            raise PinnedMapError(f"no program pinned at {path}")
        return obj_get(path)

    def close(self):
        for m in self._maps.values():
            try:
                os.close(m.map_fd)
            except OSError:
                pass
        self._maps.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def main():
    import argparse
    p = argparse.ArgumentParser(
        description="List what is pinned in a bpffs directory and how it is shaped.")
    p.add_argument("pin_dir")
    a = p.parse_args()
    try:
        obj = PinnedObject(a.pin_dir)
    except PinnedMapError as e:
        raise SystemExit(str(e))
    names = sorted(os.listdir(a.pin_dir))
    if not names:
        raise SystemExit(f"{a.pin_dir} is empty")
    for n in names:
        try:
            print(f"  {obj[n]}")
        except PinnedMapError as e:
            print(f"  {n}: {str(e).splitlines()[0]}")


if __name__ == "__main__":
    main()
