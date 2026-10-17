"""stats_maps.py -- read and reset the per-CPU packet counters of the pipelines.
"""
import ctypes as ct


def _key(table, k):
    return ct.c_int(int(k))


def read_counter(table, k) -> int:
    """The value of counter `k`, summed over every CPU."""
    try:
        v = table[_key(table, k)]
    except (KeyError, IndexError):
        return 0
    if isinstance(v, (bytes, bytearray)):
        return int.from_bytes(v, "little")
    if isinstance(v, list):
        return sum(int(x) for x in v)
    if isinstance(v, ct.Array):
        return sum(int(x) for x in v)
    return int(getattr(v, "value", v))


def zero_counter(table, k) -> None:
    """Set counter `k` to zero on every CPU."""
    key = _key(table, k)
    leaf = getattr(table, "Leaf", None)
    if leaf is not None and issubclass(leaf, ct.Array):
        table[key] = leaf()
    elif getattr(table, "percpu", False):
        table[key] = bytes(table.value_size)
    else:
        table[key] = ct.c_ulonglong(0)


def zero_all(table, n=None) -> None:
    """Zero the first `n` counters (all of them when n is None)."""
    for k in range(len(table) if n is None else n):
        zero_counter(table, k)
