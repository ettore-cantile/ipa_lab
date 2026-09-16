#!/usr/bin/env python3
"""
pinned_maps.py -- drive a PREBUILT BPF object from the existing control plane.

What this is for
----------------
BCC is clang-at-runtime: deploying a model means a compiler and a matching set
of kernel headers on the forwarding node, ~1.3 s of compilation per model, and
a deploy that can fail because the headers do not match the kernel. That is the
thing worth removing.

Python is NOT that thing. The control plane runs once, at deploy or when a
model is updated, and never touches a packet. Rewriting it in C would buy
nothing and would leave two control planes to keep in agreement.

So the split is datapath vs control plane, not C vs Python:

    offline      clang -> ipa_template.o           (once, on a build machine)
    on the node  bpftool prog loadall ... pinmaps  (no compiler)
    on the node  this module + the existing Python control plane

`PinnedObject` presents the same interface BCC's `BPF` object does -- `b[name]`
returning something you can index and assign, with `.map_fd` and `.Leaf()` --
over maps pinned in bpffs. Every existing control-plane function
(load_arch_weights, install_mac_per_port, load_class_action,
install_ingress_port_table, the link-state monitor) then works unchanged.

No new dependency: the raw bpf(2) plumbing this needs already exists in
ebpf_template_arch.py, where it was added to write the weight block in one
syscall instead of 319.

    sudo bpftool prog loadall ipa_template.o /sys/fs/bpf/ipa \\
         pinmaps /sys/fs/bpf/ipa

    from pinned_maps import PinnedObject
    b = PinnedObject("/sys/fs/bpf/ipa")
    load_arch_weights(b, weights, model_id=0, scale=scale)

Needs Linux + root.
"""
import ctypes as ct
import os

# bpf(2) commands. BPF_OBJ_GET opens something pinned in bpffs by path -- the
# one piece ebpf_template_arch's plumbing did not need and this does.
_BPF_SYSCALL_NR = 321           # x86_64
_BPF_MAP_LOOKUP_ELEM = 1
_BPF_MAP_UPDATE_ELEM = 2
_BPF_OBJ_GET = 7
_BPF_OBJ_GET_INFO_BY_FD = 15
_BPF_ANY = 0

DEFAULT_PIN_DIR = "/sys/fs/bpf/ipa"

_libc = None


def _get_libc():
    global _libc
    if _libc is None:
        _libc = ct.CDLL("libc.so.6", use_errno=True)
    return _libc


class PinnedMapError(RuntimeError):
    """A pinned map could not be opened, read or written."""


class _AttrObj(ct.Structure):
    _fields_ = [("pathname", ct.c_uint64),
                ("bpf_fd", ct.c_uint32),
                ("file_flags", ct.c_uint32)]


class _AttrMapElem(ct.Structure):
    """union bpf_attr for MAP_LOOKUP/UPDATE_ELEM: u32 fd, pad, u64 k, v, flags."""
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
    return _get_libc().syscall(_BPF_SYSCALL_NR, cmd,
                               ct.byref(attr), ct.sizeof(attr))


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
            f"(mount -t bpf bpf /sys/fs/bpf) and was the object pinned there "
            f"(bpftool prog loadall <obj> <dir> pinmaps <dir>)?")
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


def _nr_cpus() -> int:
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1


class PinnedMap:
    """One pinned map, indexable the way a BCC table is.

    BCC's tables are typed by the compiler's view of the C source. Here there
    is no compiler in the loop, so the sizes come from the kernel's own
    BPF_OBJ_GET_INFO_BY_FD and keys/values are handled as raw bytes of exactly
    that size. A ctypes object of the wrong size raises rather than being
    silently truncated -- a short value would leave the rest of the entry as
    whatever was there before, which is the kind of thing that shows up much
    later as a wrong decision.
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
        # PERCPU maps store one value per CPU behind a single key, so a write
        # has to supply the whole array or the kernel rejects the length.
        self.percpu = self.type in (5, 6, 9)     # PERCPU_{HASH,ARRAY}, LRU_PERCPU_HASH
        self._value_bytes = (self.value_size * _nr_cpus() if self.percpu
                             else self.value_size)
        self.Leaf = None                          # set by attach_leaf_type()

    def __repr__(self):
        return (f"<PinnedMap {self.name!r} key={self.key_size} "
                f"value={self.value_size}"
                f"{' xcpu' if self.percpu else ''} @{self.path}>")

    # -- byte marshalling --------------------------------------------------
    def _as_bytes(self, obj, size, what):
        if isinstance(obj, (bytes, bytearray)):
            raw = bytes(obj)
        elif isinstance(obj, int):
            raw = obj.to_bytes(size, "little", signed=obj < 0)
        elif hasattr(obj, "_fields_") or hasattr(obj, "value") or hasattr(obj, "_length_"):
            raw = bytes(memoryview(obj).cast("B"))
        else:
            raise PinnedMapError(
                f"{self.name}: cannot marshal {type(obj).__name__} as a {what}")
        if len(raw) < size:
            raw = raw + b"\x00" * (size - len(raw))
        elif len(raw) > size:
            raise PinnedMapError(
                f"{self.name}: {what} is {len(raw)} bytes, the map takes "
                f"{size}. A truncated write would leave the rest of the entry "
                f"holding whatever was there before.")
        return raw

    # -- mapping interface -------------------------------------------------
    def __setitem__(self, key, value):
        k = ct.create_string_buffer(self._as_bytes(key, self.key_size, "key"),
                                    self.key_size)
        v = ct.create_string_buffer(
            self._as_bytes(value, self._value_bytes, "value"),
            self._value_bytes)
        attr = _AttrMapElem(map_fd=self.map_fd, _pad=0,
                            key=ct.cast(k, ct.c_void_p).value,
                            value=ct.cast(v, ct.c_void_p).value,
                            flags=_BPF_ANY)
        if _syscall(_BPF_MAP_UPDATE_ELEM, attr) < 0:
            raise PinnedMapError(
                f"update {self.name}: {os.strerror(ct.get_errno())}")

    def __getitem__(self, key):
        k = ct.create_string_buffer(self._as_bytes(key, self.key_size, "key"),
                                    self.key_size)
        v = ct.create_string_buffer(self._value_bytes)
        attr = _AttrMapElem(map_fd=self.map_fd, _pad=0,
                            key=ct.cast(k, ct.c_void_p).value,
                            value=ct.cast(v, ct.c_void_p).value,
                            flags=0)
        if _syscall(_BPF_MAP_LOOKUP_ELEM, attr) < 0:
            raise KeyError(f"{self.name}: no entry "
                           f"({os.strerror(ct.get_errno())})")
        raw = bytes(v)
        if self.Leaf is not None and not self.percpu:
            out = self.Leaf()
            ct.memmove(ct.byref(out), raw, min(len(raw), ct.sizeof(out)))
            return out
        return raw

    def attach_leaf_type(self, ctype):
        """Declare the value's ctypes layout, so reads come back structured.

        BCC knows this from the C source; without a compiler the caller has to
        say. Optional: without it, reads return raw bytes.
        """
        if ct.sizeof(ctype) not in (self.value_size, self._value_bytes):
            raise PinnedMapError(
                f"{self.name}: leaf type {ctype.__name__} is "
                f"{ct.sizeof(ctype)} bytes, the map's value is "
                f"{self.value_size}")
        self.Leaf = ctype
        return self


class PinnedObject:
    """`b[name]` over a directory of pinned maps, like a BCC BPF object.

    Opens lazily and caches, so a map that a given pipeline does not use costs
    nothing and a missing one is reported when it is asked for, naming the
    directory -- not at construction, where the message could only say that
    something somewhere was absent.
    """

    def __init__(self, pin_dir: str = DEFAULT_PIN_DIR):
        self.pin_dir = pin_dir
        if not os.path.isdir(pin_dir):
            raise PinnedMapError(
                f"{pin_dir} does not exist. Load the prebuilt object first:\n"
                f"  sudo mount -t bpf bpf /sys/fs/bpf   # if bpffs is not mounted\n"
                f"  sudo bpftool prog loadall <obj>.o {pin_dir} pinmaps {pin_dir}")
        self._maps = {}

    def __getitem__(self, name):
        if name not in self._maps:
            path = os.path.join(self.pin_dir, name)
            if not os.path.exists(path):
                raise PinnedMapError(
                    f"no map pinned at {path}. Pinned here: "
                    f"{', '.join(sorted(os.listdir(self.pin_dir))) or '(nothing)'}")
            self._maps[name] = PinnedMap(path)
        return self._maps[name]

    def __contains__(self, name):
        return os.path.exists(os.path.join(self.pin_dir, name))

    def get_table(self, name):
        """BCC compatibility: some control-plane code calls this instead."""
        return self[name]

    def prog_fd(self, name):
        """File descriptor of a pinned PROGRAM, for prog-array wiring.

        The control plane writes leaf_fn.fd into arch_progs/layer_chain; with a
        prebuilt object the programs are pinned next to the maps and this is
        where their fds come from.
        """
        return obj_get(os.path.join(self.pin_dir, name))

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
    p.add_argument("pin_dir", nargs="?", default=DEFAULT_PIN_DIR)
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
            print(f"  {n}: not a map ({str(e).splitlines()[0]})")


if __name__ == "__main__":
    main()
