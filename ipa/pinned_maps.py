#!/usr/bin/env python3
"""
pinned_maps.py -- drive a PREBUILT BPF object from the existing control plane.

What this is for
----------------
Pipeline 1 deploys an AOT object (poc_aot/loader_aot + a .o built offline),
so there is no BCC `BPF` object on the node -- and every control-plane
function in the repo (install_mac_per_port, install_ingress_port_table,
install_node_id, the link-state monitor, the ARP refresh) is written against
one. Until 2026-09-23 the AOT deploy therefore ran none of them: the loader
seeded mac_table itself, with ifindex 1 and zero MACs for every port, and no
monitor ever touched link_state. Every FORWARD decision was redirected to
`lo` (ifindex 1 in every netns), never to the port the model chose.

The fix is not a second control plane in C. The loader pins the object's maps
in bpffs, `PinnedObject` presents them with the interface a BCC object has --
`b[name]` returning something you can index and assign, with `.map_fd` and
`.Leaf()` -- and the existing Python functions run unchanged, the same ones
P2 and P3 use. One control plane, two datapath builders.

    from pinned_maps import PinnedObject, FwdAction
    b = PinnedObject("/sys/fs/bpf/ipa_p1_eth0",
                     leaf_types={"mac_table": FwdAction,
                                 "link_state": "u32vec"})
    install_mac_per_port(b, "mac_table", node_cfg, semantics.logical_ports)

This file was deleted on 2026-09-16 with the bpftool-based P2 experiment it
was written for; it is restored here for P1. Needs Linux + root.
"""
import ctypes as ct
import os
import platform

# bpf(2) syscall number. Hardcoded because ctypes has no header to read it
# from; refused on an architecture it is not listed for rather than guessed.
_BPF_SYSCALL_NR = {"x86_64": 321, "aarch64": 280}

_BPF_MAP_LOOKUP_ELEM = 1
_BPF_MAP_UPDATE_ELEM = 2
_BPF_MAP_GET_NEXT_KEY = 4
_BPF_OBJ_GET = 7
_BPF_OBJ_GET_INFO_BY_FD = 15
_BPF_ANY = 0

# BPF_MAP_TYPE_PERCPU_HASH, PERCPU_ARRAY, LRU_PERCPU_HASH, PERCPU_CGROUP_STORAGE
_PERCPU_TYPES = (5, 6, 10, 21)

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
    """union bpf_attr for MAP_*_ELEM: u32 fd, pad, u64 key, value/next_key, flags."""
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
    """struct { __u32 v[N]; } sized from the map itself -- the dense feature
    vectors (link_state, queue_state), whose width is the topology's."""
    if value_size % 4:
        raise PinnedMapError(f"value of {value_size} bytes is not a u32 vector")
    return type("U32Vec", (ct.Structure,),
                {"_fields_": [("v", ct.c_uint32 * (value_size // 4))]})


class PinnedMap:
    """One pinned map, indexable the way a BCC table is.

    BCC types a table from the C source. Here there is no compiler in the
    loop, so sizes come from the kernel (BPF_OBJ_GET_INFO_BY_FD) and keys and
    values travel as raw bytes of exactly that size. An object of the wrong
    size raises instead of being truncated or padded into a partial write.
    """

    def __init__(self, path: str):
        self.path = path
        self.map_fd = obj_get(path)
        info = map_info(self.map_fd)
        self.name = info.name.decode(errors="replace")
        self.key_size = int(info.key_size)
        self.value_size = int(info.value_size)
        self.max_entries = int(info.max_entries)
        self.type = int(info.type)
        if self.type in _PERCPU_TYPES:
            # A per-CPU value is value_size rounded up to 8, times the number
            # of POSSIBLE cpus. Nothing P1 pins is per-CPU; supporting it
            # without a caller to test it would be guessing.
            raise PinnedMapError(f"{path}: per-CPU map (type {self.type}) not "
                                 f"supported by PinnedMap")
        self.Leaf = None                          # set by attach_leaf_type()

    def __repr__(self):
        return (f"<PinnedMap {self.name!r} type={self.type} key={self.key_size} "
                f"value={self.value_size} @{self.path}>")

    # -- byte marshalling --------------------------------------------------
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

    # -- mapping interface -------------------------------------------------
    def __setitem__(self, key, value):
        v = ct.create_string_buffer(
            self._as_bytes(value, self.value_size, "value"), self.value_size)
        if self._elem(_BPF_MAP_UPDATE_ELEM, key, v, _BPF_ANY) < 0:
            raise PinnedMapError(
                f"update {self.name}: {os.strerror(ct.get_errno())}")

    def __getitem__(self, key):
        v = ct.create_string_buffer(self.value_size)
        if self._elem(_BPF_MAP_LOOKUP_ELEM, key, v, 0) < 0:
            raise KeyError(f"{self.name}: no entry "
                           f"({os.strerror(ct.get_errno())})")
        raw = bytes(v)
        if self.Leaf is not None:
            out = self.Leaf()
            ct.memmove(ct.byref(out), raw, ct.sizeof(out))
            return out
        return raw

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
        back structured. BCC knows this from the C source; here the caller
        says it, and a layout of the wrong size is refused."""
        if ct.sizeof(ctype) != self.value_size:
            raise PinnedMapError(
                f"{self.name}: leaf type {ctype.__name__} is "
                f"{ct.sizeof(ctype)} bytes, the map's value is "
                f"{self.value_size}")
        self.Leaf = ctype
        return self


class PinnedObject:
    """`b[name]` over a directory of pinned maps, like a BCC BPF object.

    Opens lazily and caches, so a map a given model does not use costs nothing
    and a missing one is reported when it is asked for, naming the directory.

    leaf_types: {map name: ctypes type, or "u32vec"} -- the value layouts the
    control plane builds with `.Leaf()`. "u32vec" sizes the vector from the
    map, so link_state follows the topology without being told its width.
    """

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
