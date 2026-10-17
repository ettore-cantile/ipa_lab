#!/usr/bin/env python3
"""table_helpers.py -- markdown tables from the CSV files of a campaign; also the
CSV and table helpers report_population.py uses. No root.

    python3 ipa/test/table_helpers.py <campaign dir> > sintesi.md
"""
import csv
import os
import re
import statistics
import sys

NAME = {"rxonly": "rxonly", "baseline": "baseline", "p1_static": "P1",
        "hardcoded": "P1.5", "template": "P2", "modular": "P3"}
LOSS_OK = 0.1


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def fmt(v, spec=".0f"):
    return "-" if v is None else format(v, spec)


def table(head, rows):
    out = ["| " + " | ".join(head) + " |",
           "|" + "|".join("---:" if i else "---" for i in range(len(head)))
           + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def saturation(rows, frame="64"):
    """{method: row} of the saturation phase, for one frame size."""
    out = {}
    for r in rows:
        if r.get("phase", "saturazione") != "saturazione":
            continue
        if frame and r.get("frame") not in (None, "", frame):
            continue
        out[r["method"]] = r
    return out


def node_mpps(r):
    for k in ("proc_pps", "hit_pps", "rx_pps"):
        v = num(r.get(k))
        if v:
            return v / 1e6
    return None


def knee(rows, method):
    """(highest requested rate without loss, maximum forwarded) of a curve."""
    pts = [r for r in rows if r.get("method") == method]
    if not pts:
        return None, None, None
    clean = [num(r["rate_requested_pps"]) for r in pts
             if (num(r.get("loss_total_pct")) or 0) <= LOSS_OK
             and r.get("gen_limited") != "True"]
    key = "forwarded_pps" if method != "rxonly" else "rx_pps"
    best = max(pts, key=lambda r: num(r.get(key)) or 0)
    return (max(clean) / 1e6 if clean else None,
            (num(best.get(key)) or 0) / 1e6, best)


def _fit(xs, ys):
    """(slope, intercept, r2) of least squares, or None."""
    n = len(xs)
    if n < 3 or len(set(xs)) < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    m = sxy / sxx
    q = my - m * mx
    ss_res = sum((y - (m * x + q)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - my) ** 2 for y in ys)
    return m, q, (1 - ss_res / ss_tot) if ss_tot else 1.0
