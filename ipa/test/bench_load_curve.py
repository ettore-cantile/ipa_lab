#!/usr/bin/env python3
"""bench_load_curve.py -- the node under growing traffic.

The offered rate grows step by step; for each step the bench measures the
end-to-end delay, the packets the XDP program receives and forwards, and where
loss starts (before the program = the program is the bottleneck). Needs root.

    sudo python3 ipa/test/bench_load_curve.py --generator xdp --rates 0.5,1,2,4 \\
        --model <dir> --out <dir>
"""
import argparse
import contextlib
import csv
import ctypes as ct
import os
import re
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SHARED = os.path.dirname(HERE)
for _p in (SHARED, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")

XDP_RATES_MPPS = (0.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 5, 6, 7, 8, 9, 10, 11, 12)

DEFAULT_BITRATES_GBPS = (0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0,
                         2.5, 3.0)
AUTO_FRACTIONS = (0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
                  1.1, 1.25)
AUTO_CALIB_WINDOWS = 3
AUTO_STEP_PPS = 1000
DEFAULT_FRAME = 64
ETH_L1_OVERHEAD = 24
DEFAULT_ROUNDS = 5
DEFAULT_LOSS_THRESHOLD = 0.1
GEN_LIMITED_FRACTION = 0.95
GEN_BURST_FRACTION = 1.05
LAT_FINE_US = 1024
LAT_STEP_SHIFT = 6
LAT_MAX_US = 65536
LAT_CELLS = LAT_FINE_US + ((LAT_MAX_US - LAT_FINE_US) >> LAT_STEP_SHIFT)
LAT_TARGET_SAMPLES = 20000
PKTGEN_HDR_OFF = 14 + 20 + 8
OVERHEAD_REPS = 5
BPF_STATS_KNOB = "/proc/sys/kernel/bpf_stats_enabled"
SANITY_PPS = 100_000
SANITY_S = 0.1
DRAIN_S = 0.05
REFERENCE = "rxonly"
PIPELINES = ("baseline", "p1_static", "hardcoded", "template", "modular")
AOT_METHODS = ("p1_static", "hardcoded")
LABEL_NONE = "nessuna"
LABEL_PROG = "ingresso: programma eBPF"
LABEL_IN_UNSPLIT = "ingresso: programma o ricezione (manca rxonly)"
LABEL_OUT = "uscita: trasmissivo"
LABEL_BENCH = "banco: nodo non saturo"
NAPI_SATURATED_PCT = 90.0
LABEL_REF = "riferimento"

# --- the programs ---
ING_COUNTER_BCC = r"""
#include <uapi/linux/bpf.h>
BPF_PERCPU_ARRAY(ing_count, __u64, 2);
BPF_PROG_ARRAY(ing_next, 1);

int xdp_ing_count(struct xdp_md *ctx) {
    int k = 0;
    __u64 *v = ing_count.lookup(&k);
    if (v)
        *v += 1;
    ing_next.call(ctx, 0);
    int km = 1;
    __u64 *m = ing_count.lookup(&km);
    if (m)
        *m += 1;
    return XDP_DROP;
}
"""

ING_COUNTER_LIBBPF = r"""
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 2);
         __type(key, __u32); __type(value, __u64); } ing_count SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 1);
         __type(key, __u32); __type(value, __u32); } ing_next SEC(".maps");

SEC("xdp")
int xdp_ing_count(struct xdp_md *ctx) {
    __u32 k = 0;
    __u64 *v = bpf_map_lookup_elem(&ing_count, &k);
    if (v)
        *v += 1;
    bpf_tail_call(ctx, &ing_next, 0);
    k = 1;
    v = bpf_map_lookup_elem(&ing_count, &k);
    if (v)
        *v += 1;
    return XDP_DROP;
}
"""

EGRESS_LAT_BCC = r"""
#include <uapi/linux/bpf.h>

#define LAT_FINE_US %(fine)d
#define LAT_STEP_SHIFT %(shift)d
#define LAT_MAX_US %(maxus)d
#define LAT_CELLS %(cells)d
#define PG_OFF %(off)d

BPF_PERCPU_ARRAY(rx_count, __u64, 1);
BPF_ARRAY(lat_ctl, __u64, 3);
BPF_PERCPU_ARRAY(lat_acc, __u64, 6);
BPF_PERCPU_ARRAY(lat_hist, __u64, LAT_CELLS + 1);

int xdp_rx_lat(struct xdp_md *ctx) {
    int z = 0;
    __u64 *cnt = rx_count.lookup(&z);
    if (!cnt)
        return XDP_DROP;
    *cnt += 1;

    __u64 *gate = lat_ctl.lookup(&z);
    if (!gate || *gate == 0)
        return XDP_DROP;
    int k_mask = 2;
    __u64 *mask = lat_ctl.lookup(&k_mask);
    if (!mask || (*cnt & *mask))
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *p = data;
    int k_nostamp = 5;
    if ((void *)(p + PG_OFF + 16) > data_end) {
        __u64 *e = lat_acc.lookup(&k_nostamp);
        if (e)
            *e += 1;
        return XDP_DROP;
    }
    __u8 *h = p + PG_OFF;
    if (h[0] != 0xbe || h[1] != 0x9b || h[2] != 0xe9 || h[3] != 0x55) {
        __u64 *e = lat_acc.lookup(&k_nostamp);
        if (e)
            *e += 1;
        return XDP_DROP;
    }
    __u64 sec = ((__u32)h[8] << 24) | ((__u32)h[9] << 16) |
                ((__u32)h[10] << 8) | (__u32)h[11];
    __u64 usec = ((__u32)h[12] << 24) | ((__u32)h[13] << 16) |
                 ((__u32)h[14] << 8) | (__u32)h[15];
    int k_off = 1;
    __u64 *off = lat_ctl.lookup(&k_off);
    if (!off)
        return XDP_DROP;
    __u64 now_us = (bpf_ktime_get_ns() + *off) / 1000;
    __u64 stamp_us = sec * 1000000ULL + usec;
    if (now_us < stamp_us) {
        int k_neg = 4;
        __u64 *e = lat_acc.lookup(&k_neg);
        if (e)
            *e += 1;
        return XDP_DROP;
    }
    __u64 d = now_us - stamp_us;
    int bi;
    if (d < LAT_FINE_US)
        bi = (int)d;
    else if (d < LAT_MAX_US)
        bi = LAT_FINE_US + (int)((d - LAT_FINE_US) >> LAT_STEP_SHIFT);
    else
        bi = LAT_CELLS;
    __u64 *hb = lat_hist.lookup(&bi);
    if (hb)
        *hb += 1;
    int k0 = 0, k1 = 1, k2 = 2, k3 = 3;
    __u64 *n = lat_acc.lookup(&k0);
    if (n)
        *n += 1;
    __u64 *sum = lat_acc.lookup(&k1);
    if (sum)
        *sum += d;
    __u64 *mn = lat_acc.lookup(&k2);
    if (mn && (*mn == 0 || d + 1 < *mn))
        *mn = d + 1;
    __u64 *mx = lat_acc.lookup(&k3);
    if (mx && d > *mx)
        *mx = d;
    return XDP_DROP;
}
""" % {"fine": LAT_FINE_US, "shift": LAT_STEP_SHIFT, "maxus": LAT_MAX_US,
       "cells": LAT_CELLS, "off": PKTGEN_HDR_OFF}

# --- arithmetic (pure functions: test_load_curve_math.py checks them without a kernel) ---
def pps_for_gbps(gbps, frame):
    """Packets per second that make `gbps` Gbit/s of `frame`-byte frames."""
    return gbps * 1e9 / (frame * 8)


def gbps_of(pps, frame, l1=False):
    """Gbit/s di `pps` frame da `frame` byte;"""
    return pps * (frame + (ETH_L1_OVERHEAD if l1 else 0)) * 8 / 1e9


def auto_rates(rx_ceiling_pps, gen_ceiling_pps=None,
               fractions=AUTO_FRACTIONS, step=AUTO_STEP_PPS):
    """La scala calibrata, in pps."""
    if not rx_ceiling_pps or rx_ceiling_pps <= 0:
        return []
    cap = (gen_ceiling_pps * GEN_LIMITED_FRACTION
           if gen_ceiling_pps and gen_ceiling_pps > 0 else None)
    pts = set()
    for f in fractions:
        p = int(round(f * rx_ceiling_pps / step)) * step
        if cap is not None and p > cap:
            p = int(cap // step) * step
        if p > 0:
            pts.add(p)
    return sorted(pts)


def sample_mask(rate_pps, window_s, target=LAT_TARGET_SAMPLES):
    """Mask on pktgen's seq."""
    expected = max(0.0, float(rate_pps) * float(window_s))
    if target <= 0 or expected <= target:
        return 0
    step = 1
    while step * target < expected:
        step <<= 1
    return step - 1


def pct(part, whole):
    return round(100.0 * part / whole, 3) if whole else None


def lat_cell(us):
    """The histogram cell for `us` microseconds, as the egress program
    computes it."""
    us = int(us)
    if us < LAT_FINE_US:
        return us
    if us < LAT_MAX_US:
        return LAT_FINE_US + ((us - LAT_FINE_US) >> LAT_STEP_SHIFT)
    return LAT_CELLS


def lat_cell_value(i):
    """The microseconds cell i represents."""
    if i < LAT_FINE_US:
        return float(i)
    if i < LAT_CELLS:
        step = 1 << LAT_STEP_SHIFT
        return float(LAT_FINE_US + (i - LAT_FINE_US) * step + step // 2)
    return float(LAT_MAX_US)


def hist_percentile(hist, q):
    """Quantile q from the histogram (the last cell is the overflow)."""
    n = sum(hist)
    if n <= 0:
        return None, False
    target = q * n
    run = 0
    for i, c in enumerate(hist):
        run += c
        if run >= target:
            return lat_cell_value(i), i == len(hist) - 1
    return lat_cell_value(len(hist) - 1), True


def spin_per_packet_us(idle_us, attempts):
    """Mean pktgen wait between timestamp and transmission, per packet."""
    if idle_us is None or not attempts:
        return None
    return max(0.0, float(idle_us) / float(attempts))


def latency_stats(lat, spin_us, mask):
    """End-to-end latency statistics of ONE window, corrected for pktgen's
    wait."""
    hist = lat.get("hist") or []
    n = int(lat.get("n") or 0)
    out = dict(e2e_samples=n, e2e_sample_every=int(mask) + 1,
               e2e_spin_correction_us=(round(spin_us, 3)
                                       if spin_us is not None else None),
               e2e_over_range=(hist[-1] if hist else 0),
               e2e_negative=int(lat.get("neg") or 0),
               e2e_no_stamp=int(lat.get("nostamp") or 0),
               e2e_percentile_clipped=False)
    keys = ("e2e_latency_p50_us", "e2e_latency_p90_us", "e2e_latency_p99_us",
            "e2e_latency_mean_us", "e2e_latency_min_us",
            "e2e_latency_max_us", "e2e_latency_p50_raw_us")
    if n <= 0 or not hist:
        out.update({k: None for k in keys})
        return out
    corr = spin_us or 0.0

    def c(v):
        return None if v is None else round(max(0.0, float(v) - corr), 2)

    p = {}
    for q in (0.50, 0.90, 0.99):
        v, clipped = hist_percentile(hist, q)
        p[q] = v
        out["e2e_percentile_clipped"] |= clipped
    out.update(e2e_latency_p50_us=c(p[0.50]), e2e_latency_p90_us=c(p[0.90]),
               e2e_latency_p99_us=c(p[0.99]),
               e2e_latency_mean_us=c(float(lat["total_us"]) / n),
               e2e_latency_min_us=c(lat.get("min_us")),
               e2e_latency_max_us=c(lat.get("max_us")),
               e2e_latency_p50_raw_us=p[0.50])
    return out


def napi_sched(pids):
    """Cumulative scheduling statistics of the DUT's NAPI threads."""
    out = dict(napi_run_ns=0, napi_wait_ns=0, napi_vol_cs=0, napi_invol_cs=0)
    for pid in pids:
        try:
            with open(f"/proc/{pid}/schedstat") as f:
                run, wait, _ = (int(x) for x in f.read().split()[:3])
            out["napi_run_ns"] += run
            out["napi_wait_ns"] += wait
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("voluntary_ctxt_switches"):
                        out["napi_vol_cs"] += int(line.split()[1])
                    elif line.startswith("nonvoluntary_ctxt_switches"):
                        out["napi_invol_cs"] += int(line.split()[1])
        except (OSError, ValueError):
            pass
    return out


def hw_row(B, plan, run):
    """Instructions, cycles and IPC per packet of the window
    (hw_counters.per_packet)."""
    import hw_counters as HW
    d = run.dut or {}
    pkts = d.get("rx_xdp") or 0
    egress = getattr(plan, "egress", None)
    return HW.per_packet(d, plan.dut, pkts, run.window,
                         egress=B.HC.egress_cpus(egress))


def diag_columns(d, secs, sent):
    """The diagnostic columns of a window, from the napi_sched and XdpGen.diag
    counter differences."""
    ns = secs * 1e9
    out = {}
    if "napi_run_ns" in d:
        out.update(
            napi_run_pct=round(100.0 * d["napi_run_ns"] / ns, 2),
            napi_wait_pct=round(100.0 * d["napi_wait_ns"] / ns, 2),
            napi_sleeps_per_ms=round(d["napi_vol_cs"] / (secs * 1e3), 3),
            napi_preempt_per_ms=round(d["napi_invol_cs"] / (secs * 1e3), 3))
    if "gen_spin" in d:
        out.update(
            gen_spin_per_sent=(round(d["gen_spin"] / sent, 2) if sent
                               else None),
            gen_resets=int(d["gen_reset"]),
            gen_late_mean_ns=(round(d["gen_late_ns"] / sent, 1) if sent
                              else None),
            gen_gap_pct=round(100.0 * d["gen_gap_ns"] / ns, 3),
            gen_calls=int(d["gen_calls"]))
    return out


def window_row(method, frame, rnd, rate_req_pps, delay_ns, gen_threads, secs,
               wall_s, tx, rejected, d, lat, mask, idle_ok=True, host=None):
    """One steady window -> one row."""
    secs = secs if secs and secs > 0 else 1e-9
    sent = int(tx) + int(rejected)
    rx = int(d["rx_xdp"])
    ref = "hit" not in d
    row = dict(
        method=method, frame=frame, round=rnd,
        rate_requested_pps=int(rate_req_pps),
        bitrate_requested_gbps=round(gbps_of(rate_req_pps, frame), 4),
        delay_ns=delay_ns, gen_threads=gen_threads,
        duration_s=round(secs, 4), point_wall_s=round(wall_s, 3),
        packets_sent=sent, packets_accepted_by_veth=int(tx),
        rejected_by_ingress_queue=int(rejected),
        packets_received_by_xdp=rx, tail_call_miss=int(d.get("tail_miss", 0)),
        sent_pps=int(sent / secs), rx_pps=int(rx / secs),
        bitrate_sent_bps=int(sent / secs * frame * 8),
        bitrate_sent_gbps=round(gbps_of(sent / secs, frame), 4),
        bitrate_sent_l1_gbps=round(gbps_of(sent / secs, frame, l1=True), 4),
        rx_gbps=round(gbps_of(rx / secs, frame), 4),
        loss_before_xdp=sent - rx,
        lost_between_veth_and_xdp=int(tx) - rx,
        loss_before_xdp_pct=pct(sent - rx, sent),
        rejected_pct=pct(int(rejected), sent),
        reference=ref)
    row.update(diag_columns(d, secs, sent))
    row["gen_limited"] = bool(rate_req_pps and
                              row["sent_pps"] < GEN_LIMITED_FRACTION
                              * rate_req_pps)
    row["gen_burst"] = bool(rate_req_pps and
                            row["sent_pps"] > GEN_BURST_FRACTION
                            * rate_req_pps)
    if ref:
        for k in ("packets_forwarded", "forwarded_pps", "forwarded_gbps",
                  "packets_lost", "loss_in_pipeline", "loss_in_pipeline_pct",
                  "loss_total_pct", "pipeline_hit", "pipeline_miss",
                  "pipeline_drop", "not_forwarded_by_decision",
                  "decision_pct", "loss_after_xdp", "loss_after_xdp_pct",
                  "unaccounted_in_pipeline"):
            row[k] = None
    else:
        fwd = int(d["fwd"])
        hit, miss, drop = int(d["hit"]), int(d["miss"]), int(d["drop"])
        row.update(
            packets_forwarded=fwd, forwarded_pps=int(fwd / secs),
            forwarded_gbps=round(gbps_of(fwd / secs, frame), 4),
            packets_lost=sent - fwd,
            loss_in_pipeline=rx - fwd,
            loss_in_pipeline_pct=pct(rx - fwd, sent),
            loss_total_pct=pct(sent - fwd, sent),
            pipeline_hit=hit, pipeline_miss=miss, pipeline_drop=drop,
            not_forwarded_by_decision=miss + drop,
            decision_pct=pct(miss + drop, sent),
            loss_after_xdp=hit - fwd,
            loss_after_xdp_pct=pct(hit - fwd, sent),
            unaccounted_in_pipeline=rx - (hit + miss + drop))
    spin = spin_per_packet_us(d.get("idle_us"), sent) if idle_ok else None
    if ref:
        row.update(latency_stats({}, spin, mask))
    else:
        row.update(latency_stats(lat, spin, mask))
    if host:
        row.update(host)
    return row


MEDIAN_KEYS = (
    "bitrate_requested_gbps", "bitrate_sent_gbps", "bitrate_sent_l1_gbps",
    "sent_pps", "rx_pps", "forwarded_pps", "rx_gbps", "forwarded_gbps",
    "packets_sent", "packets_received_by_xdp", "packets_forwarded",
    "packets_lost", "loss_before_xdp", "loss_in_pipeline",
    "rejected_by_ingress_queue", "lost_between_veth_and_xdp",
    "not_forwarded_by_decision", "loss_after_xdp", "unaccounted_in_pipeline",
    "tail_call_miss", "loss_before_xdp_pct", "rejected_pct",
    "loss_in_pipeline_pct", "decision_pct", "loss_after_xdp_pct",
    "loss_total_pct", "e2e_latency_p50_us", "e2e_latency_p90_us",
    "e2e_latency_p99_us", "e2e_latency_mean_us", "e2e_latency_min_us",
    "e2e_latency_max_us", "e2e_latency_p50_raw_us", "e2e_samples",
    "e2e_spin_correction_us", "duration_s", "point_wall_s",
    "host_dut_mhz", "host_dut_busy_pct", "host_pkg_temp_c",
    "napi_run_pct", "instr_pkt", "cycles_pkt", "ipc", "llc_miss_pkt",
    "br_miss_pkt", "dut_ghz_busy", "egress_cycles_pkt", "egress_ipc")
SPREAD_KEYS = ("sent_pps", "rx_pps", "forwarded_pps", "bitrate_sent_gbps",
               "e2e_latency_p50_us", "e2e_latency_p99_us")


def _median(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


def classify(row, floor_pct, threshold=DEFAULT_LOSS_THRESHOLD):
    """The bottleneck of ONE summary row, by the ingress/egress rule, with
    the reception floor removed."""
    if row.get("reference"):
        return LABEL_REF
    before = row.get("loss_before_xdp_pct") or 0.0
    after = row.get("loss_after_xdp_pct") or 0.0
    excess = before - (floor_pct or 0.0)
    if excess <= threshold and after <= threshold:
        return LABEL_NONE
    if after > threshold and after > excess:
        return LABEL_OUT
    napi = row.get("napi_run_pct")
    if napi is not None and napi < NAPI_SATURATED_PCT:
        return LABEL_BENCH
    return LABEL_PROG if floor_pct is not None else LABEL_IN_UNSPLIT


def summarise(rows, threshold=DEFAULT_LOSS_THRESHOLD):
    """Median over rounds per (pipeline, frame, requested rate), then the
    bottleneck of every row against rxonly at the same rate."""
    groups = {}
    for r in rows:
        groups.setdefault((r["method"], r["frame"], r["rate_requested_pps"]),
                          []).append(r)
    out = []
    for (m, frame, rate), rs in groups.items():
        s = dict(method=m, frame=frame, rate_requested_pps=rate,
                 rounds=len(rs), reference=bool(rs[0].get("reference")),
                 gen_limited=any(r.get("gen_limited") for r in rs),
                 gen_limited_rounds=sum(bool(r.get("gen_limited"))
                                        for r in rs),
                 gen_burst_rounds=sum(bool(r.get("gen_burst")) for r in rs),
                 host_disturbed_rounds=sum(bool(r.get("host_disturbed"))
                                           for r in rs),
                 e2e_percentile_clipped=any(r.get("e2e_percentile_clipped")
                                            for r in rs))
        for k in MEDIAN_KEYS:
            v = _median([r.get(k) for r in rs])
            s[k] = round(v, 4) if isinstance(v, float) else v
        for k in SPREAD_KEYS:
            vals = [r.get(k) for r in rs if r.get(k) is not None]
            s[f"{k}_min"] = min(vals) if vals else None
            s[f"{k}_max"] = max(vals) if vals else None
        out.append(s)
    floors = {(s["frame"], s["rate_requested_pps"]): s.get("loss_before_xdp_pct")
              for s in out if s["method"] == REFERENCE}
    for s in out:
        floor = floors.get((s["frame"], s["rate_requested_pps"]))
        s["rxonly_loss_before_xdp_pct"] = floor
        s["excess_loss_before_xdp_pct"] = (
            None if s["reference"] or s.get("loss_before_xdp_pct") is None
            else round(s["loss_before_xdp_pct"] - (floor or 0.0), 3))
        s["bottleneck"] = classify(s, floor, threshold)
    order = {m: i for i, m in enumerate((REFERENCE,) + PIPELINES)}
    out.sort(key=lambda s: (s["frame"], order.get(s["method"], 99),
                            s["rate_requested_pps"]))
    return out


def onsets(summary):
    """Per pipeline e frame."""
    per = {}
    for s in summary:
        if s["reference"]:
            continue
        per.setdefault((s["method"], s["frame"]), []).append(s)
    out = []
    for (m, frame), rs in per.items():
        rs = sorted(rs, key=lambda s: s["rate_requested_pps"])
        lossy = [s["bottleneck"] != LABEL_NONE for s in rs]
        start = next((i for i in range(len(rs)) if all(lossy[i:])), None)
        first = rs[start] if start is not None else None
        below = rs if start is None else rs[:start]
        clean = [s for s, bad in zip(below, lossy) if not bad]
        sporadic = [s for s, bad in zip(below, lossy) if bad]
        fwd = [s.get("forwarded_pps") for s in rs
               if s.get("forwarded_pps") is not None]
        after = [abs(s["loss_in_pipeline_pct"]) for s in rs
                 if s.get("loss_in_pipeline_pct") is not None]
        out.append(dict(method=m, frame=frame,
                        last_clean=clean[-1] if clean else None,
                        first_loss=first, sporadic=sporadic,
                        lowest=rs[0] if rs else None,
                        highest=rs[-1] if rs else None,
                        max_forwarded_pps=max(fwd) if fwd else None,
                        max_abs_pipeline_loss_pct=max(after) if after else None))
    return out


class Probe:
    """The read Generator.steady does at the two marks of the window."""

    def __init__(self, read_counters, set_gate):
        self.read = read_counters
        self.set_gate = set_gate
        self.opened = False

    def __call__(self):
        if not self.opened:
            self.set_gate(1)
            self.opened = True
        return self.read()


def prog_stats(fd):
    """(run_time_ns, run_cnt) of a BPF program from its fdinfo, or (None,
    None)."""
    t = c = None
    try:
        with open(f"/proc/self/fdinfo/{fd}") as f:
            for line in f:
                k, _, v = line.partition(":")
                k = k.strip()
                if k == "run_time_ns":
                    t = int(v)
                elif k == "run_cnt":
                    c = int(v)
    except (OSError, ValueError):
        return None, None
    return t, c


def set_bpf_stats(value):
    """Writes kernel.bpf_stats_enabled."""
    try:
        with open(BPF_STATS_KNOB) as f:
            old = f.read().strip()
        with open(BPF_STATS_KNOB, "w") as f:
            f.write(str(value))
        return old
    except OSError:
        return None


def per_run_ns(before, after):
    """ns per program run between two prog_stats reads."""
    (t0, c0), (t1, c1) = before, after
    if None in (t0, c0, t1, c1) or c1 <= c0:
        return None
    return (t1 - t0) / (c1 - c0)


_IDLE_RE = re.compile(r"idle:\s*(\d+)us")


def parse_idle_us(text):
    """The `idle` counter (us) from the Current section of a pktgen device."""
    m = _IDLE_RE.search(text)
    return int(m.group(1)) if m else None


def realtime_minus_monotonic_ns(tries=7):
    """(CLOCK_REALTIME - CLOCK_MONOTONIC in ns, uncertainty in ns)."""
    best = None
    for _ in range(tries):
        m1 = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        r = time.clock_gettime_ns(time.CLOCK_REALTIME)
        m2 = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        if best is None or m2 - m1 < best[1]:
            best = (r - (m1 + m2) // 2, m2 - m1)
    return best


def _percpu_total(tab, key):
    """Sum over CPUs of a per-CPU cell, BCC or pinned map (AOT)."""
    v = tab[ct.c_int(key)]
    if isinstance(v, int):
        return v
    try:
        return sum(int(x) for x in v)
    except TypeError:
        return int(getattr(v, "value", v))


# --- loading ---
def _bcc_counter(target_fd):
    """Program 1 in its own BCC object, with the pipeline in the slot."""
    from bcc import BPF
    b = BPF(text=ING_COUNTER_BCC)
    fn = b.load_func("xdp_ing_count", BPF.XDP)
    if target_fd is not None:
        try:
            b["ing_next"][ct.c_int(0)] = ct.c_int(target_fd)
        except Exception as e:
            raise RuntimeError(
                f"the kernel refuses the pipeline as tail call target "
                f"({e}): type, JIT or expected_attach_type differ between "
                f"counter and pipeline") from e
    return b, fn


@contextlib.contextmanager
def _counter_in_aot_object():
    """build_pipeline loads P1/P1.5 with p1_aot.load_p1, which compiles
    p1_source(...)."""
    import p1_aot
    orig = p1_aot.p1_source

    def with_counter(*a, **k):
        return orig(*a, **k) + "\n" + ING_COUNTER_LIBBPF

    p1_aot.p1_source = with_counter
    try:
        yield
    finally:
        p1_aot.p1_source = orig


def load_method(B, method, model_path, fab, sem):
    """(pipeline setup or None, ingress counter) for a method."""
    if method == REFERENCE:
        b, fn = _bcc_counter(None)
        return None, dict(b=b, fn=fn, tab=b["ing_count"], kind="bcc")
    if method in AOT_METHODS:
        with _counter_in_aot_object():
            setup = B.build_pipeline(method, model_path, fab, sem)
        owner = setup.get("owner")
        fn = getattr(owner, "progs", {}).get("xdp_ing_count")
        if fn is None:
            raise RuntimeError(
                f"{method}: the AOT object does not contain xdp_ing_count -- "
                f"did the source not go through p1_aot.p1_source?")
        setup["b"]["ing_next"][ct.c_int(0)] = ct.c_int(setup["disp"].fd)
        return setup, dict(b=setup["b"], fn=fn, tab=setup["b"]["ing_count"],
                           kind="aot")
    setup = B.build_pipeline(method, model_path, fab, sem)
    b, fn = _bcc_counter(setup["disp"].fd)
    return setup, dict(b=b, fn=fn, tab=b["ing_count"], kind="bcc")


def attach_egress(B, fab):
    """The egress program on every peer, in place of the XDP_PASS stub."""
    from bcc import BPF
    from common import attach_xdp
    b = BPF(text=EGRESS_LAT_BCC)
    fn = b.load_func("xdp_rx_lat", BPF.XDP)
    attached = []
    for peer in fab.peer_of.values():
        try:
            B.raise_veth_ring(peer)
            with B._quiet():
                attach_xdp(b, fn, peer)
            attached.append(peer)
        except Exception as e:
            B.warn(f"egress counter not attached to {peer}: {e}")
    return b, attached


def read_latency(acc, hist_tab):
    cells = [[int(x) for x in acc[ct.c_int(i)]] for i in range(6)]
    mins = [c - 1 for c in cells[2] if c > 0]
    hist = [sum(int(x) for x in hist_tab[ct.c_int(i)])
            for i in range(LAT_CELLS + 1)]
    n = sum(cells[0])
    return dict(n=n, total_us=sum(cells[1]),
                min_us=(min(mins) if mins else None),
                max_us=(max(cells[3]) if n else None),
                neg=sum(cells[4]), nostamp=sum(cells[5]), hist=hist)


def zero_latency(acc, hist_tab, lat=None):
    """Resets accumulators and histogram."""
    for i in range(6):
        del acc[ct.c_int(i)]
    idx = (range(LAT_CELLS + 1) if lat is None else
           [i for i, c in enumerate(lat["hist"]) if c])
    for i in idx:
        del hist_tab[ct.c_int(i)]


def pktgen_idle_us(B, names):
    tot = 0
    for n in names:
        with open(B.pg_dev_path(n)) as f:
            v = parse_idle_us(f.read())
        if v is None:
            return None
        tot += v
    return tot


def calibrate_scale(B, window, use, alive, frame):
    """The calibrated scale, before the sweep."""
    ref = REFERENCE if REFERENCE in alive else alive[0]
    print(f"\n{YELLOW} Scale calibration: {ref} at full load, "
          f"{AUTO_CALIB_WINDOWS} windows{NC}")
    use(ref)
    rx_best = sent_best = 0.0
    for _ in range(AUTO_CALIB_WINDOWS):
        try:
            run, _, _, _ = window(ref, frame, 0, 0, timed=False)
        except B.PktgenEmptyRun as e:
            B.warn(f"calibration window discarded ({e})")
            continue
        if not run.window or run.window <= 0:
            continue
        rx_best = max(rx_best, run.dut["rx_xdp"] / run.window)
        sent_best = max(sent_best, (run.tx + getattr(run, "errors", 0))
                        / run.window)
    rates = auto_rates(rx_best, sent_best)
    if not rates:
        return [], "calibrazione fallita"
    B.info(f"reception ceiling ({ref}): {rx_best / 1e6:.3f} Mpps = "
           f"{gbps_of(rx_best, frame):.3f} Gbit/s at {frame} B; the generator "
           f"offers up to {sent_best / 1e6:.3f} Mpps")
    if sent_best < 1.1 * rx_best:
        B.warn("the generator barely exceeds the reception ceiling: the "
               "saturated part of the curve will be short (--threads for more)")
    B.info("scala: " + ", ".join(f"{gbps_of(r, frame):.3f}" for r in rates)
           + f" Gbit/s a {frame} B")
    desc = (f"calibrated: {len(rates)} points, from {AUTO_FRACTIONS[0]} to "
            f"{AUTO_FRACTIONS[-1]} times the reception ceiling of {ref} "
            f"({rx_best / 1e6:.3f} Mpps = {gbps_of(rx_best, frame):.3f} "
            f"Gbit/s at {frame} B), generator {sent_best / 1e6:.3f} Mpps; "
            f"pps " + ",".join(str(r) for r in rates))
    return rates, desc


# --- IL RUN ---
def run_bitrate(B, methods, model_path, frames, rates_of, plan, rounds,
                window_s, lat_target=LAT_TARGET_SAMPLES, egress_cpu=None,
                overhead_reps=OVERHEAD_REPS, save=None, hostmon=None,
                generator="pktgen", xdp_batch=None):
    """Every pipeline, same fabric and same generator, at growing rate."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    sem, n_out = B.class_semantics()
    raw, over, notes = [], [], {}
    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        eg_b, peers = attach_egress(B, fab)
        if not peers:
            raise RuntimeError("no egress counter attached: without it, "
                               "forwarded packets are not counted")
        ctl, acc, hist_tab = eg_b["lat_ctl"], eg_b["lat_acc"], eg_b["lat_hist"]
        rx_tab = eg_b["rx_count"]
        B.info(f"egress program (count + latency) on {len(peers)} peers")

        print(f"\n{YELLOW} Phase 1: loading pipelines and ingress counters "
              f"(no measurement running){NC}")
        loaded = {}
        for m in methods:
            try:
                loaded[m] = load_method(B, m, model_path, fab, sem)
                kind = loaded[m][1]["kind"]
                B.info(f"{m}: " + ("counter only (reference)"
                                   if m == REFERENCE else
                                   f"counter -> tail call -> pipeline "
                                   f"({'same AOT object' if kind == 'aot' else 'BCC'})"))
            except Exception as e:
                B.warn(f"{m}: not loaded, skipping it -- "
                       f"{type(e).__name__}: {e}")
        if not loaded:
            return raw, over, notes

        ing = B.build_ingress(fab, plan, "shared", False)
        gen, napi_devs, egress_napi = None, [], []

        def set_ctl(i, v):
            ctl[ct.c_int(i)] = ct.c_ulonglong(int(v))

        def use(m, direct=False):
            setup, cnt = loaded[m]
            with B._quiet():
                for dev in ing.dut_devs:
                    if direct:
                        attach_xdp(setup["b"], setup["disp"], dev)
                    else:
                        attach_xdp(cnt["b"], cnt["fn"], dev)

        idle_ok = [True]
        dut_napi = []

        def reader(m, direct=False):
            setup, cnt = loaded[m]

            def read():
                d = dict(fwd=_percpu_total(rx_tab, 0))
                if generator == "xdp":
                    d.update(gen.diag())
                d.update(napi_sched(dut_napi))
                idle = pktgen_idle_us(B, gen.names) if idle_ok[0] else 0
                d["idle_us"] = idle or 0
                if not direct:
                    d["rx_xdp"] = _percpu_total(cnt["tab"], 0)
                    d["tail_miss"] = _percpu_total(cnt["tab"], 1)
                if setup is not None:
                    ps = setup["pkt_stats"]
                    d.update(hit=B._read_u64(ps, 0), miss=B._read_u64(ps, 1),
                             drop=B._read_u64(ps, 2))
                if B.HW_COUNTERS is not None:
                    d.update(B.HW_COUNTERS.read())
                return d
            return read

        def window(m, frame, rate, mask, seconds=None, direct=False,
                   timed=True):
            """One steady window."""
            off, _ = realtime_minus_monotonic_ns()
            set_ctl(0, 0)
            set_ctl(1, off)
            set_ctl(2, mask)
            gate = (lambda v: set_ctl(0, v)) if timed else (lambda v: None)
            probe = Probe(reader(m, direct), gate)
            h0 = hostmon.mark() if hostmon is not None else None
            t0 = time.monotonic()
            try:
                run = gen.steady(frame, gen.delay_for(rate) if rate else 0,
                                 probe, seconds=seconds)
            except Exception:
                set_ctl(0, 0)
                time.sleep(DRAIN_S)
                zero_latency(acc, hist_tab)
                raise
            finally:
                set_ctl(0, 0)
            wall = time.monotonic() - t0
            time.sleep(DRAIN_S)
            host = (hostmon.delta(h0, hostmon.mark())
                    if hostmon is not None else None)
            lat = read_latency(acc, hist_tab)
            zero_latency(acc, hist_tab, lat)
            return run, lat, wall, host

        try:
            for setup, _ in loaded.values():
                if setup is not None:
                    B._map_extra_ingress(setup, ing.ifindexes)
            if generator == "xdp":
                from xdp_gen import XdpGen
                kw = {"batch_size": xdp_batch} if xdp_batch else {}
                gen = XdpGen(ing.gen_devs[0], plan, window_s=window_s,
                             **kw).attach()
                B.info(f"xdp_gen: batches of {gen.batch_size} frames (the DUT "
                       f"wakes up at the end of a batch)")
                gen.set_stamp(True)
                B._warn_shared_queues(plan)
                idle_ok[0] = False
                notes["idle_correction"] = "not needed"
            else:
                gen = B.Generator(ing.gen_devs[:1], plan, window_s=window_s,
                                  warmup_s=0.0, window_mode="steady").attach()
                if pktgen_idle_us(B, gen.names) is None:
                    idle_ok[0] = False
                    B.warn("pktgen does not expose `idle` in /proc/net/pktgen: "
                           "the latency is NOT corrected for the wait between "
                           "timestamp and transmission, and at low rate it is "
                           "overestimated by about the delay")
                notes["idle_correction"] = idle_ok[0]

            use(next(iter(loaded)))
            napi_devs = list(ing.dut_devs)
            placed = B.enable_threaded_napi(napi_devs, plan)
            for dv in napi_devs:
                dut_napi.extend(int(x) for x in B._napi_threads(dv))
            if placed:
                B.info("threaded ingress NAPI: " + ", ".join(
                    f"{dv}({nt})->cpu{','.join(map(str, cs))}"
                    for dv, nt, cs in placed))
            else:
                napi_devs = []
                B.warn("no NAPI thread pinned: generator and DUT stay "
                       "on the same core")
            if egress_cpu is not None:
                eplan = B.CpuPlan([], [egress_cpu], B.online_cpus(), [])
                placed_e = B.enable_threaded_napi(list(peers), eplan)
                egress_napi = [dv for dv, _, _ in placed_e]
                B.info(f"threaded egress on cpu{egress_cpu}: "
                       f"{len(egress_napi)} veth")

            print(f"\n{YELLOW} Probe at {SANITY_PPS // 1000} kpps{NC}")
            alive = []
            f0 = frames[0]
            for m in loaded:
                use(m)
                try:
                    run, lat, _, _ = window(m, f0, SANITY_PPS,
                                         sample_mask(SANITY_PPS, SANITY_S,
                                                     lat_target),
                                         seconds=SANITY_S)
                except B.PktgenEmptyRun as e:
                    B.warn(f"{m}: probe without traffic ({e}), excluding it")
                    continue
                d = run.dut
                problems = []
                if d["rx_xdp"] <= 0:
                    problems.append("the ingress counter does not count")
                if m != REFERENCE:
                    if d["tail_miss"]:
                        problems.append(f"{d['tail_miss']} tail calls not "
                                        f"taken")
                    if d["hit"] + d["drop"] <= 0:
                        problems.append("the pipeline does not decide (no "
                                        "HIT/DROP)")
                    if d["fwd"] <= 0:
                        problems.append("nothing reaches the next node")
                if problems:
                    B.warn(f"{m}: " + "; ".join(problems) + " -- excluded")
                    continue
                if m != REFERENCE and not lat["n"]:
                    B.warn(f"{m}: no latency sample (timestamps without "
                           f"pktgen header: {lat['nostamp']}, in the "
                           f"future: {lat['neg']}): counts valid, latency "
                           f"missing")
                B.ok(f"{m}: RX {d['rx_xdp']}, forwarded {d['fwd']}, "
                     f"latency samples {lat['n']}")
                alive.append(m)
            if not alive:
                B.warn("no method passed the probe")
                return raw, over, notes

            if rates_of is None:
                rates, calib = calibrate_scale(B, window, use, alive, f0)
                notes["scala"] = calib
                if not rates:
                    rates = [int(pps_for_gbps(g, DEFAULT_FRAME))
                             for g in DEFAULT_BITRATES_GBPS]
                    B.warn("calibration failed: using the fixed fallback "
                           "scale")
                    notes["scala"] = "fixed (calibration failed)"

                def rates_of(frame, _r=tuple(rates)):
                    return list(_r)

            npts = rounds * sum(len(rates_of(f)) for f in frames) * len(alive)
            print(f"\n{YELLOW}{'=' * 78}{NC}")
            print(f"{YELLOW} Phase 2: {rounds} rounds x {len(alive)} methods x "
                  f"growing rate, frame {frames} -- {npts} windows of "
                  f"{window_s}s{NC}")
            print(f"{YELLOW}{'=' * 78}{NC}")
            print(f"  {'round':>5s} {'requested':>9s} {'method':10s} "
                  f"{'sent':>9s} {'RX XDP':>9s} {'fwd':>9s} "
                  f"{'before%':>7s} {'pipe%':>7s} {'p50us':>7s} {'p99us':>7s}")
            t_run = time.monotonic()
            done = 0
            for rnd in range(1, rounds + 1):
                seq = alive if rnd % 2 else list(reversed(alive))
                for frame in frames:
                    for rate in rates_of(frame):
                        mask = sample_mask(rate, window_s, lat_target)
                        for m in seq:
                            use(m)
                            done += 1
                            try:
                                run, lat, wall, host = window(m, frame, rate,
                                                              mask)
                            except B.PktgenEmptyRun as e:
                                B.warn(f"round {rnd} {m} "
                                       f"{gbps_of(rate, frame):.2f} Gbit/s: "
                                       f"window discarded -- {e}")
                                continue
                            row = window_row(
                                m, frame, rnd, rate,
                                gen.delay_for(rate) if rate else 0,
                                gen.n_inst, run.window, wall, run.tx,
                                getattr(run, "errors", 0), run.dut, lat, mask,
                                idle_ok=idle_ok[0], host=host)
                            row.update(hw_row(B, plan, run))
                            raw.append(row)
                            if save:
                                save(raw, over)
                            _print_point(row, done, npts, t_run)
                            if m != REFERENCE and row["tail_call_miss"]:
                                B.warn(f"{m}: {row['tail_call_miss']} tail "
                                       f"calls not taken in this window")

            pipes = [m for m in alive if m != REFERENCE]
            if overhead_reps > 0 and pipes:
                print(f"\n{YELLOW} Phase 3: cost of the counter, maximum rate, "
                      f"{overhead_reps} repetitions, with and without the chain{NC}")
                old_stats = set_bpf_stats(1)
                notes["bpf_stats"] = old_stats is not None
                if old_stats is None:
                    B.warn("kernel.bpf_stats_enabled not writable: the cost "
                           "is estimated only from throughput, much more "
                           "noisy")
                try:
                    for rep in range(overhead_reps):
                        for m in pipes:
                            variants = ((False, True) if rep % 2 == 0
                                        else (True, False))
                            for direct in variants:
                                use(m, direct=direct)
                                setup, cnt = loaded[m]
                                fd = (setup["disp"] if direct
                                      else cnt["fn"]).fd
                                before = prog_stats(fd)
                                try:
                                    run, _, _, host = window(
                                        m, frames[0], 0, 0, direct=direct,
                                        timed=False)
                                except B.PktgenEmptyRun as e:
                                    B.warn(f"{m}: window discarded ({e})")
                                    continue
                                prog = per_run_ns(before, prog_stats(fd))
                                d = run.dut
                                proc = d["hit"] + d["miss"] + d["drop"]
                                pps = (proc / run.window if run.window > 0
                                       else 0)
                                var = "diretta" if direct else "catena"
                                over.append(dict(
                                    method=m, variant=var, rep=rep + 1,
                                    frame=frames[0],
                                    duration_s=round(run.window, 4),
                                    processed=proc, processed_pps=int(pps),
                                    cost_ns=(round(1e9 / pps, 2) if pps
                                             else None),
                                    prog_ns=(round(prog, 2) if prog is not None
                                             else None),
                                    **(host or {})))
                                if save:
                                    save(raw, over)
                                print(f"  {rep + 1:2d} {m:10s} {var:8s} "
                                      f"{pps / 1e6:6.3f} Mpps processed  "
                                      f"{(1e9 / pps if pps else 0):7.1f} ns "
                                      f"from throughput, program "
                                      + (f"{prog:6.1f} ns" if prog is not None
                                         else "n/a"))
                finally:
                    if old_stats is not None:
                        set_bpf_stats(old_stats)
        finally:
            if gen is not None:
                gen.detach()
            try:
                if os.path.isdir(B.PKTGEN_DIR):
                    B.pg_reset()
            except RuntimeError:
                pass
            if napi_devs:
                B.disable_threaded_napi(napi_devs)
            if egress_napi:
                B.disable_threaded_napi(egress_napi)
            for dev in ing.dut_devs:
                B._detach(dev)
            ing.cleanup()
            for peer in peers:
                B._detach(peer)
    return raw, over, notes


def _print_point(r, done, total, t0):
    def f(v, spec):
        return format(v, spec) if v is not None else "n/a"

    el = time.monotonic() - t0
    eta = el / done * (total - done) if done else 0
    print(f"  {r['round']:5d} {r['bitrate_requested_gbps']:6.2f}G "
          f"{r['method']:10s} {r['sent_pps'] / 1e6:8.3f}M "
          f"{r['rx_pps'] / 1e6:8.3f}M "
          f"{(f(r['forwarded_pps'] / 1e6, '8.3f') + 'M') if r['forwarded_pps'] is not None else '     n/a ':>9s} "
          f"{f(r['loss_before_xdp_pct'], '7.2f'):>7s} "
          f"{f(r['loss_in_pipeline_pct'], '7.2f'):>7s} "
          f"{f(r['e2e_latency_p50_us'], '7.1f'):>7s} "
          f"{f(r['e2e_latency_p99_us'], '7.1f'):>7s}"
          + (f" {RED}machine{NC}" if r.get("host_disturbed") else "")
          + f"  {GREY}[{done}/{total}, ~{eta / 60:.0f} min]{NC}")


def summarise_overhead(over):
    """Per pipeline: median with and without the chain, from the program time
    (BPF statistics, the figure to use) and from throughput (how much the node
    slows down, but noisier), and the differences."""
    per = {}
    for r in over:
        per.setdefault(r["method"], {}).setdefault(r["variant"], []).append(r)
    out = []
    for m, v in per.items():
        def med(var, key):
            return _median([r.get(key) for r in v.get(var, [])])

        def spread(var, key):
            vals = [r.get(key) for r in v.get(var, []) if r.get(key) is not None]
            return round(max(vals) - min(vals), 2) if len(vals) > 1 else None

        row = dict(method=m, reps=len(v.get("catena", [])))
        for key, name in (("prog_ns", "prog"), ("cost_ns", "cost")):
            chain, direct = med("catena", key), med("diretta", key)
            row[f"{name}_chain_ns"] = chain
            row[f"{name}_direct_ns"] = direct
            row[f"{name}_overhead_ns"] = (round(chain - direct, 2)
                                          if chain is not None
                                          and direct is not None else None)
            row[f"{name}_spread_chain_ns"] = spread("catena", key)
            row[f"{name}_spread_direct_ns"] = spread("diretta", key)
        out.append(row)
    return out


def print_summary(summary, ons, over_sum, threshold):
    def f(v, spec):
        return format(v, spec) if v is not None else "n/a"

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Median over rounds. Losses in % of sent; bottleneck "
          f"with threshold {threshold}% above rxonly{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    last = None
    for s in summary:
        key = (s["method"], s["frame"])
        if key != last:
            last = key
            print(f"\n  {s['method']} ({s['frame']} B)")
            print(f"    {'Gbit/s sent':>11s} {'sent':>8s} {'RX XDP':>8s} "
                  f"{'fwd':>8s} {'before%':>7s} {'pipe%':>7s} "
                  f"{'p50us':>7s} {'p99us':>7s}  bottleneck")
        gl = ((f" (gen {s['gen_limited_rounds']}/{s['rounds']})"
               if s.get("gen_limited_rounds") else "")
              + (f" (burst {s['gen_burst_rounds']}/{s['rounds']})"
                 if s.get("gen_burst_rounds") else "")
              + (f" (machine disturbed {s['host_disturbed_rounds']}/"
                 f"{s['rounds']})" if s.get("host_disturbed_rounds") else ""))
        print(f"    {f(s['bitrate_sent_gbps'], '11.3f')} "
              f"{f(s['sent_pps'] and s['sent_pps'] / 1e6, '8.3f')} "
              f"{f(s['rx_pps'] and s['rx_pps'] / 1e6, '8.3f')} "
              f"{f(s['forwarded_pps'] and s['forwarded_pps'] / 1e6, '8.3f'):>8s} "
              f"{f(s['loss_before_xdp_pct'], '7.2f'):>7s} "
              f"{f(s['loss_in_pipeline_pct'], '7.2f'):>7s} "
              f"{f(s['e2e_latency_p50_us'], '7.1f'):>7s} "
              f"{f(s['e2e_latency_p99_us'], '7.1f'):>7s}  "
              f"{s['bottleneck']}{gl}")
    if ons:
        print(f"\n{YELLOW} Where the loss starts{NC}")
        for o in ons:
            lc, fl, lo = o["last_clean"], o["first_loss"], o["lowest"]
            hi = o["highest"]
            cap = o["max_forwarded_pps"]
            head = f"  {o['method']:10s} ({o['frame']} B): "
            if fl is None:
                print(head + f"no attributable loss up to "
                      f"{f(hi['bitrate_sent_gbps'] if hi else None, '.3f')}"
                      f" Gbit/s sent, the highest rate measured; "
                      f"forwarded at most {f(cap and cap / 1e6, '.3f')} "
                      f"Mpps")
                if o.get("max_abs_pipeline_loss_pct") is not None:
                    print(" " * len(head) + "loss after XDP: at most "
                          f"{o['max_abs_pipeline_loss_pct']:.2f}% of "
                          f"sent")
                continue
            print(head + f"clean up to "
                  f"{f(lc['bitrate_sent_gbps'] if lc else None, '.3f')} "
                  f"Gbit/s, loses from {f(fl['bitrate_sent_gbps'], '.3f')} "
                  f"Gbit/s up ({f(fl['sent_pps'] / 1e6, '.3f')} Mpps "
                  f"sent) -> {fl['bottleneck']}. Latency p50 "
                  f"{f(lo['e2e_latency_p50_us'], '.1f')} us at the lowest "
                  f"rate, {f(lc['e2e_latency_p50_us'] if lc else None, '.1f')}"
                  f" us at the last clean one, "
                  f"{f(fl['e2e_latency_p50_us'], '.1f')} us at the first with "
                  f"loss. Forwarded at most "
                  f"{f(cap and cap / 1e6, '.3f')} Mpps")
            if o.get("sporadic"):
                print(" " * len(head) + "sporadic losses below the onset "
                      "(disturbed windows, not capacity): " + ", ".join(
                          f"{f(s['bitrate_sent_gbps'], '.2f')} Gbit/s"
                          for s in o["sporadic"]))
            if o.get("max_abs_pipeline_loss_pct") is not None:
                print(" " * len(head) + "loss after XDP: at most "
                      f"{o['max_abs_pipeline_loss_pct']:.2f}% of sent")
    if over_sum:
        print(f"\n{YELLOW} Cost of the counter (median, maximum rate){NC}")
        for o in over_sum:
            print(f"  {o['method']:10s} program: chain "
                  f"{f(o['prog_chain_ns'], '.1f')} ns, direct "
                  f"{f(o['prog_direct_ns'], '.1f')} ns, counter "
                  f"{f(o['prog_overhead_ns'], '+.1f')} ns  |  throughput: "
                  f"{f(o['cost_overhead_ns'], '+.1f')} ns (spread between "
                  f"windows {f(o['cost_spread_chain_ns'], '.0f')} / "
                  f"{f(o['cost_spread_direct_ns'], '.0f')} ns)")


def save_csv(path, rows):
    """Like bench_capacity._write_csv (union of the keys), but without printing
    and writing to a temporary file then renamed."""
    cols = []
    for r in rows:
        for k in r:
            if not k.startswith("_") and k not in cols:
                cols.append(k)
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, restval="",
                           extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)


def report_from_csv(out_dir, threshold=DEFAULT_LOSS_THRESHOLD):
    """The summary of a run already done, from its raw CSVs."""
    from plot_load_curve import read_summary
    path = os.path.join(out_dir, "bitrate_raw.csv")
    if not os.path.exists(path):
        sys.exit(f"{out_dir}: bitrate_raw.csv missing")
    raw = read_summary(path)
    opath = os.path.join(out_dir, "bitrate_overhead_raw.csv")
    over = read_summary(opath) if os.path.exists(opath) else []
    summary = summarise(raw, threshold)
    print(f"  {len(raw)} windows from {path}; rounds per point: "
          f"{sorted({s['rounds'] for s in summary})}")
    burst = sum(bool(r.get("gen_burst")) for r in raw)
    limited = sum(bool(r.get("gen_limited")) for r in raw)
    print(f"  windows with a generator burst: {burst}, with the generator "
          f"below the requested rate: {limited}")
    print_summary(summary, onsets(summary), summarise_overhead(over),
                  threshold)
    return 0


def _parse_list(spec, what):
    try:
        vals = [float(x) for x in spec.split(",") if x.strip()]
    except ValueError:
        sys.exit(f"{what}: comma-separated numbers expected, got "
                 f"{spec!r}")
    if not vals or min(vals) <= 0:
        sys.exit(f"{what}: positive values needed")
    return sorted(vals)


def _env_value(out_dir, key):
    """A value from the env.csv of a run already done, or None."""
    path = os.path.join(out_dir, "env.csv")
    try:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if len(row) >= 2 and row[0] == key:
                    return row[1]
    except OSError:
        pass
    return None


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
    import host_conditions as HC
    p = argparse.ArgumentParser(
        description=__doc__.strip().split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--method", default="all",
                   help="all (default: rxonly and the five pipelines) or "
                        "a list, e.g. rxonly,baseline,p1_static")
    r = p.add_mutually_exclusive_group()
    r.add_argument("--bitrates", default=None, metavar="LIST|auto",
                   help="bit rates to offer in Gbit/s (L2, frame bytes), "
                        "comma-separated. Default auto: the scale "
                        "calibrated on the reception ceiling measured at the "
                        "start (fractions " + ",".join(str(x) for x in AUTO_FRACTIONS)
                        + ")")
    r.add_argument("--rates", default=None, metavar="LIST",
                   help="alternatively, rates in Mpps")
    p.add_argument("--frames", default=str(DEFAULT_FRAME),
                   help="frame sizes in bytes (pktgen pkt_size, without "
                        "FCS), default 64")
    p.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS,
                   help="full rounds: every round measures every method at "
                        "every rate; the median is reported")
    p.add_argument("--duration", type=float, default=None, metavar="S",
                   help="length of the steady window (default the one "
                        "of bench_capacity, 0.3 s)")
    p.add_argument("--lat-samples", type=int, default=LAT_TARGET_SAMPLES,
                   help="latency samples per window, roughly (0 = every "
                        "packet)")
    p.add_argument("--loss-threshold", type=float, default=None,
                   metavar="PCT",
                   help="loss in %% points of sent, above that of "
                        "rxonly at the same rate, from which a row is called "
                        f"'lossy'. Default {DEFAULT_LOSS_THRESHOLD}; with "
                        f"--report the one written in the run's env.csv")
    p.add_argument("--overhead-reps", type=int, default=OVERHEAD_REPS,
                   help="repetitions of the counter cost measurement "
                        "(0 skips it)")
    p.add_argument("--gen-cpus", default=None, metavar="LIST")
    p.add_argument("--dut-cpus", default=None, metavar="LIST")
    p.add_argument("--threads", type=int, default=None, metavar="N")
    p.add_argument("--allow-cpu0", action="store_true")
    p.add_argument("--egress-cpu", default="auto", metavar="N|auto|none",
                   help="NAPI of the egress veths (the next node) threaded "
                        "on CPU N. auto (default): a physical core of its "
                        "own chosen by the plan, if one is left; none: the "
                        "next node's reception runs on the DUT CPU")
    p.add_argument("--dut-queues", default="auto", metavar="N|auto|gen",
                   help="DUT ingress queues: auto (default) one per DUT "
                        "CPU; gen one per generator thread. "
                        "See bench_capacity.DUT_QUEUES")
    p.add_argument("--generator", choices=("pktgen", "xdp"), default="xdp",
                   help="xdp (default): xdp_gen, raw XDP frames as from a "
                        "NIC with native XDP, pacing and timestamp in the "
                        "generator program. One thread per ingress queue: "
                        "without --gen-cpus or --threads, one per DUT CPU; "
                        "without a scale, the rates of XDP_RATES_MPPS (pacing "
                        "holds up to ~11-12 Mpps per thread). pktgen: skb, with "
                        "the headroom copy on the DUT")
    p.add_argument("--xdp-batch", type=int, default=None, metavar="N",
                   help="with --generator xdp: frames per test_run batch "
                        "(1-256, default 256). At the end of a batch the redirect "
                        "wakes the DUT; a smaller batch wakes it more "
                        "often but shrinks the page_pool")
    p.add_argument("--out", default=None, help="results folder")
    p.add_argument("--no-plot", action="store_true",
                   help="do not draw the charts at the end of the run")
    p.add_argument("--cleanup", action="store_true",
                   help="remove a fabric left over by an interrupted run")
    p.add_argument("--report", default=None, metavar="DIR",
                   help="no measurement: re-read bitrate_raw.csv (and "
                        "bitrate_overhead_raw.csv) from DIR and print again "
                        "summary, loss onset and counter cost with the "
                        "current rules. No root needed.")
    HC.add_args(p)
    import model_under_test as MUT
    MUT.add_args(p)
    a = p.parse_args(argv)
    out_dir = os.path.abspath(a.out) if a.out else None

    if a.report:
        rdir = os.path.abspath(a.report)
        thr = a.loss_threshold
        if thr is None:
            try:
                thr = float(_env_value(rdir, "soglia_perdita_pct"))
            except (TypeError, ValueError):
                thr = DEFAULT_LOSS_THRESHOLD
        return report_from_csv(rdir, thr)
    if sys.platform != "linux":
        sys.exit(f"Linux needed, not {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("root needed: sudo python3 ipa/test/bench_load_curve.py")
    HC.check_args(a)
    MUT.select(a.model, a.topology)
    a.egress_cpu = HC.parse_egress(a.egress_cpu)
    if a.loss_threshold is None:
        a.loss_threshold = DEFAULT_LOSS_THRESHOLD
        threshold_why = "default"
    else:
        threshold_why = "set by hand"
    import bench_capacity as B
    os.chdir(B.SHARED_DIR)
    if a.cleanup:
        from netns_fabric import cleanup
        cleanup()
        B.del_tg_links(16)
        if B.pg_available():
            B.pg_stop()
            B.pg_reset()
        return 0
    if a.generator == "pktgen" and not B.pg_available():
        sys.exit(f"{B.PKTGEN_DIR} does not exist and `modprobe pktgen` did "
                 f"not create it: this kernel lacks the module.")
    if B.pg_available():
        B.pg_reset()

    methods = ([REFERENCE] + list(PIPELINES) if a.method == "all"
               else [m.strip() for m in a.method.split(",") if m.strip()])
    bad = [m for m in methods if m not in (REFERENCE,) + PIPELINES]
    if bad:
        sys.exit(f"--method: unknown {bad}; valid: all, {REFERENCE}, "
                 f"{', '.join(PIPELINES)}")
    frames = [int(x) for x in _parse_list(a.frames, "--frames")]
    if a.generator == "xdp" and not a.rates and not a.bitrates:
        a.rates = ",".join(f"{x:g}" for x in XDP_RATES_MPPS)
    if a.generator == "xdp" and a.gen_cpus is None and a.threads is None:
        a.threads = len(B.parse_cpu_list(a.dut_cpus) or [None])
    scale_spec = (a.bitrates or "auto").strip().lower() if not a.rates \
        else "rates"
    if scale_spec == "auto":
        rates_of = None
        scale_desc = "auto (calibrated on the reception ceiling at the start)"
    elif scale_spec == "rates":
        mpps = _parse_list(a.rates, "--rates")

        def rates_of(frame):
            return [int(x * 1e6) for x in mpps]
        scale_desc = "Mpps: " + a.rates
    else:
        gbps = _parse_list(a.bitrates, "--bitrates")

        def rates_of(frame):
            return [int(pps_for_gbps(g, frame)) for g in gbps]
        scale_desc = "Gbit/s: " + a.bitrates
    window_s = a.duration or B.WINDOW_S

    plan = B.plan_cpus(a.gen_cpus, a.dut_cpus, a.threads, a.allow_cpu0,
                       egress_spec=a.egress_cpu)
    plan.describe()
    if isinstance(a.egress_cpu, int):
        if a.egress_cpu in plan.dut or a.egress_cpu in plan.gen:
            sys.exit(f"--egress-cpu {a.egress_cpu} already belongs to the "
                     f"generator or the DUT")
        if a.egress_cpu not in B.online_cpus():
            sys.exit(f"--egress-cpu {a.egress_cpu}: CPU not online")
    B.DUT_QUEUES = B.parse_dut_queues(a.dut_queues, plan)

    import model_meta as mm
    model_path = mm.default_checkpoint()
    envargs = argparse.Namespace(
        mode="bitrate", no_threaded_napi=False, gen_topology="shared",
        xmit_mode="start_xmit", duration=window_s, window="steady",
        generator=a.generator, ttl_mix=None, egress_cpu=plan.egress,
        warmup=0.0, repeat=1, rounds=a.rounds,
        loss_threshold=a.loss_threshold, clone_skb=0, burst=0)

    def env_now(extra=()):
        env = B.capture_env(envargs, plan, methods, frames)
        env += [("scala", scale_desc),
                ("soglia_perdita_origine", threshold_why),
                ("latenza", "pktgen timestamp -> next node's counter, "
                            "1 us cells, corrected for pktgen's wait"
                 if a.generator == "pktgen" else
                 "xdp_gen timestamp at send (pktgen format) -> next "
                 "node's counter, 1 us cells, no correction"),

                ("latenza_campioni_per_finestra", a.lat_samples),
                ("contatore_ingresso", "program 1 (per-CPU) -> tail call -> "
                                       "production pipeline")]
        if a.generator == "xdp":
            env.append(("xdp_lotto", a.xdp_batch or "256 (default)"))
        env += list(extra)
        return env

    def save(raw_rows, over_rows):
        if not out_dir:
            return
        os.makedirs(out_dir, exist_ok=True)
        save_csv(os.path.join(out_dir, "bitrate_raw.csv"), raw_rows)
        if over_rows:
            save_csv(os.path.join(out_dir, "bitrate_overhead_raw.csv"),
                     over_rows)

    def body(hostmon):
        B.print_env(env_now())
        if out_dir:
            B.info(f"results in {out_dir} (bitrate_raw.csv updated after "
                   f"every window; host_monitor.csv: the machine per second)")
        t0 = time.monotonic()
        try:
            raw, over, notes = run_bitrate(
                B, methods, model_path, frames, rates_of, plan, a.rounds,
                window_s, lat_target=a.lat_samples, egress_cpu=plan.egress,
                overhead_reps=a.overhead_reps, save=save, hostmon=hostmon,
                generator=a.generator, xdp_batch=a.xdp_batch)
        finally:
            if out_dir and os.path.isdir(out_dir):
                B._give_back(out_dir)
        summary = summarise(raw, a.loss_threshold)
        ons = onsets(summary)
        over_sum = summarise_overhead(over)
        print_summary(summary, ons, over_sum, a.loss_threshold)
        print(f"\n  run length: {(time.monotonic() - t0) / 60:.1f} min")
        rc = 0 if raw else 1
        if any(r["tail_call_miss"] for r in raw if not r["reference"]):
            B.warn("tail calls not taken in some window: those packets "
                   "entered the counter and not the pipeline")
            rc = 1
        disturbed = sum(bool(r.get("host_disturbed")) for r in raw)
        if disturbed:
            B.warn(f"{disturbed} windows out of {len(raw)} with the machine "
                   f"outside the declared conditions (host_disturbed column: "
                   f"throttling, DUT frequency off target, powerclamp, "
                   f"battery)")
        if out_dir and raw:
            os.makedirs(out_dir, exist_ok=True)
            B._write_csv(os.path.join(out_dir, "bitrate_raw.csv"), raw)
            B._write_csv(os.path.join(out_dir, "bitrate.csv"), summary)
            if over:
                B._write_csv(os.path.join(out_dir,
                                          "bitrate_overhead_raw.csv"), over)
                B._write_csv(os.path.join(out_dir, "bitrate_overhead.csv"),
                             over_sum)
            B.write_env(out_dir, env_now([
                ("scala_usata", notes.get("scala", scale_desc)),
                ("finestre_macchina_disturbata", f"{disturbed}/{len(raw)}"),
                ("correzione_attesa_pktgen",
                 "not needed (xdp_gen timestamps at send)"
                 if notes.get("idle_correction") == "not needed" else
                 "yes" if notes.get("idle_correction") else "NO: idle missing"),
                ("costo_contatore_da",
                 "kernel BPF statistics + throughput"
                 if notes.get("bpf_stats") else "throughput only"),
                ("durata_run_min", round((time.monotonic() - t0) / 60, 1))]))
            if not a.no_plot:
                try:
                    import plot_load_curve
                    plot_load_curve.plot_all(out_dir)
                except ImportError as e:
                    B.warn(f"charts not drawn ({e}): "
                           f"python3 ipa/test/plot_load_curve.py {out_dir}")
            B._give_back(out_dir)
        return rc

    return B.conditioned(a, plan, body, out_dir)

if __name__ == "__main__":
    sys.exit(main())
