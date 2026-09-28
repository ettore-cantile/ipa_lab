"""
stats_maps.py -- read and zero the pipelines' packet counters.

pkt_stats ([0]=HIT [1]=MISS [2]=DROP) and cls_stats (one slot per class) are
PER-CPU arrays in every pipeline: with several receive queues each core
increments its own copy, with no atomic and no cache line shared between
cores. A reader therefore sums the cores, and a reset zeroes every core.

One function each, for the three ways a counter reaches Python:

  BCC table (baseline, P2, P3)   b["pkt_stats_t2"][k] -> ctypes array, one
                                 element per possible CPU
  pinned map (P1, AOT object)    pinned_maps.PinnedMap[k] -> list of ints
  plain array                    a single ctypes value or raw bytes (kept so
                                 an older object still reads correctly)
"""
import ctypes as ct


def _key(table, k):
    # BCC tables want a ctypes key; pinned maps accept one too.
    return ct.c_int(int(k))


def read_counter(table, k) -> int:
    """The value of counter `k`, summed over every CPU. A missing key reads
    as 0, like an untouched array slot."""
    try:
        v = table[_key(table, k)]
    except (KeyError, IndexError):
        return 0
    if isinstance(v, (bytes, bytearray)):
        return int.from_bytes(v, "little")
    if isinstance(v, list):                        # pinned per-CPU map
        return sum(int(x) for x in v)
    if isinstance(v, ct.Array):                    # BCC per-CPU table
        return sum(int(x) for x in v)
    return int(getattr(v, "value", v))


def zero_counter(table, k) -> None:
    """Set counter `k` to zero on every CPU."""
    key = _key(table, k)
    leaf = getattr(table, "Leaf", None)
    if leaf is not None and issubclass(leaf, ct.Array):   # BCC per-CPU
        table[key] = leaf()
    elif getattr(table, "percpu", False):                 # pinned per-CPU
        table[key] = bytes(table.value_size)
    else:
        table[key] = ct.c_ulonglong(0)


def zero_all(table, n=None) -> None:
    """Zero the first `n` counters (all of them when n is None)."""
    for k in range(len(table) if n is None else n):
        zero_counter(table, k)
