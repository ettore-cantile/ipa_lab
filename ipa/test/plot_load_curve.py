#!/usr/bin/env python3
"""plot_load_curve.py -- charts of bench_load_curve from its CSV: latency,
packets sent / received / forwarded, loss, against the offered rate.

    python3 ipa/test/plot_load_curve.py <results dir>
"""
import csv
import os
import sys

PIPE = {
    "baseline":  dict(color="#7f8c8d", marker="x", label="baseline (no network)"),
    "p1_static": dict(color="#8e44ad", marker="D", label="P1 static"),
    "hardcoded": dict(color="#c0392b", marker="o", label="P1.5 hardcoded"),
    "template":  dict(color="#2980b9", marker="s", label="P2 template"),
    "modular":   dict(color="#27ae60", marker="^", label="P3 modular"),
}
TITLE = {"rxonly": "rxonly (counter only)", **{k: v["label"]
                                               for k, v in PIPE.items()}}
ORDER = ("rxonly", "baseline", "p1_static", "hardcoded", "template", "modular")
C_RX = "#2a78d6"
C_FWD = "#eb6834"
C_REF = "#8b8a85"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e6e5e1"
NUMERIC_SKIP = {"method", "bottleneck"}


def _num(v):
    if v in (None, ""):
        return None
    if v in ("True", "False"):
        return v == "True"
    try:
        f = float(v)
    except ValueError:
        return v
    return int(f) if f.is_integer() and "." not in v else f


def read_summary(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = [{k: (v if k in NUMERIC_SKIP else _num(v)) for k, v in r.items()}
                for r in csv.DictReader(f)]
    return rows


def _style(ax):
    ax.set_facecolor("white")
    ax.grid(True, color=GRID, linewidth=0.8, linestyle="-")
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=8)
    ax.xaxis.label.set_color(INK2)
    ax.yaxis.label.set_color(INK2)


def _series(rows, method, ykey):
    pts = [(r["bitrate_sent_gbps"], r.get(ykey), r) for r in rows
           if r["method"] == method and r.get("bitrate_sent_gbps") is not None
           and r.get(ykey) is not None]
    return sorted(pts, key=lambda p: p[0])


def _bench(r):
    """Loss with the node not saturated."""
    return str(r.get("bottleneck") or "").startswith("banco")


def _lossy(r):
    return r.get("bottleneck") not in (None, "", "nessuna", "riferimento") \
        and not _bench(r)


def _onset(rows, method):
    """The rate from which ALL higher rates lose (as
    bench_load_curve.onsets)."""
    pts = sorted((r for r in rows if r["method"] == method),
                 key=lambda r: r["rate_requested_pps"])
    lossy = [_lossy(r) or _bench(r) for r in pts]
    return next((pts[i] for i in range(len(pts)) if all(lossy[i:])), None)


def _save(fig, out_dir, name):
    paths = []
    for ext in ("png", "pdf"):
        p = os.path.join(out_dir, f"{name}.{ext}")
        fig.savefig(p, dpi=160, bbox_inches="tight", facecolor="white")
        paths.append(p)
    return paths


def fig_latency(plt, rows, frame, out_dir, suffix):
    from matplotlib.lines import Line2D
    from matplotlib.ticker import FixedLocator, NullFormatter, FuncFormatter
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2), sharey=True)
    ymin, ymax = None, None
    drawn = []
    for ax, key, title in ((axes[0], "e2e_latency_p50_us", "median (p50)"),
                           (axes[1], "e2e_latency_p99_us",
                            "99th percentile (p99)")):
        _style(ax)
        for m in ORDER:
            if m not in PIPE:
                continue
            pts = _series(rows, m, key)
            if not pts:
                continue
            st = PIPE[m]
            xs, ys = [p[0] for p in pts], [max(p[1], 0.5) for p in pts]
            ax.plot(xs, ys, color=st["color"], linewidth=2, zorder=2,
                    solid_capstyle="round", solid_joinstyle="round")
            for x, y, (_, _, r) in zip(xs, ys, pts):
                ax.plot([x], [y], marker=st["marker"], markersize=6,
                        color=st["color"], zorder=3, linestyle="none",
                        markerfacecolor=("white" if _lossy(r) else st["color"]),
                        markeredgewidth=1.4)
            ymin = min(ys) if ymin is None else min(ymin, min(ys))
            ymax = max(ys) if ymax is None else max(ymax, max(ys))
            if m not in drawn:
                drawn.append(m)
        ax.set_title(title, fontsize=10, color=INK, loc="left")
        ax.set_xlabel("offered bit rate (Gbit/s)")
    if not drawn:
        plt.close(fig)
        return []
    axes[0].set_yscale("log")
    nice = [v for v in (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000)
            if (ymin or 1) / 2 <= v <= (ymax or 1) * 2]
    axes[0].yaxis.set_major_locator(FixedLocator(nice))
    axes[0].yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    axes[0].yaxis.set_minor_formatter(NullFormatter())
    axes[0].set_ylabel("latenza end-to-end (µs)")
    handles = [Line2D([0], [0], color=PIPE[m]["color"], marker=PIPE[m]["marker"],
                      linewidth=2, markersize=6, label=PIPE[m]["label"])
               for m in drawn]
    handles.append(Line2D([0], [0], color=INK2, marker="o", linestyle="none",
                          markerfacecolor="white", markersize=6,
                          label="empty marker: loss at that rate"))
    fig.legend(handles=handles, loc="upper center", ncol=3, frameon=False,
               fontsize=8, bbox_to_anchor=(0.5, 1.08), labelcolor=INK)
    fig.suptitle(f"End-to-end latency against offered bit rate — frame {frame} B",
                 fontsize=11, color=INK, x=0.01, ha="left", y=1.14)
    stamp = ("xdp_gen timestamp at send -> next node, no "
             "correction" if GENERATOR == "xdp" else
             "pktgen timestamp -> next node, corrected for pktgen's "
             "wait")
    fig.text(0.01, -0.04, f"{stamp}; median over rounds. Log scale.",
             fontsize=7.5, color=INK2, ha="left")
    paths = _save(fig, out_dir, f"bitrate_latency{suffix}")
    plt.close(fig)
    return paths


def _panels(plt, n, sharey=True):
    cols = 3 if n > 4 else min(n, 2) or 1
    nrows = (n + cols - 1) // cols
    fig, axes = plt.subplots(nrows, cols, figsize=(3.6 * cols, 2.9 * nrows),
                             sharex=True, sharey=sharey, squeeze=False)
    flat = [a for row in axes for a in row]
    for a in flat[n:]:
        a.set_visible(False)
    return fig, flat[:n]


def fig_pps(plt, rows, frame, out_dir, suffix):
    from matplotlib.lines import Line2D
    methods = [m for m in ORDER if any(r["method"] == m for r in rows)]
    if not methods:
        return []
    fig, axes = _panels(plt, len(methods))
    xmax = max((r["bitrate_sent_gbps"] for r in rows
                if r.get("bitrate_sent_gbps") is not None), default=1.0)
    for ax, m in zip(axes, methods):
        _style(ax)
        for key, color, z, lw, mk in (("sent_pps", C_REF, 1, 1.2, None),
                                      ("rx_pps", C_RX, 2, 3.4, "o"),
                                      ("forwarded_pps", C_FWD, 3, 1.6, "o")):
            pts = _series(rows, m, key)
            if not pts:
                continue
            xs = [p[0] for p in pts]
            ys = [p[1] / 1e6 for p in pts]
            ax.plot(xs, ys, color=color, linewidth=lw, zorder=z, marker=mk,
                    markersize=(6 if key == "rx_pps" else 3.5),
                    solid_capstyle="round", solid_joinstyle="round")
            lo = [p[2].get(f"{key}_min") for p in pts]
            hi = [p[2].get(f"{key}_max") for p in pts]
            if key != "sent_pps" and all(v is not None for v in lo + hi):
                ax.vlines(xs, [v / 1e6 for v in lo], [v / 1e6 for v in hi],
                          color=color, linewidth=1, alpha=0.5, zorder=z)
        on = _onset(rows, m)
        if on is not None and on.get("bitrate_sent_gbps") is not None:
            x = on["bitrate_sent_gbps"]
            ax.axvline(x, color=INK2, linewidth=0.8, zorder=0)
            right = x > 0.75 * xmax
            what = "bench limit" if _bench(on) else "loses from here"
            ax.text(x, 0.98, (f"{what} " if right else f" {what}"),
                    transform=ax.get_xaxis_transform(), fontsize=7,
                    color=INK2, va="top", ha=("right" if right else "left"))
        ax.set_title(TITLE.get(m, m), fontsize=9, color=INK, loc="left")
    for ax in axes:
        if ax.get_subplotspec().is_last_row():
            ax.set_xlabel("offered bit rate (Gbit/s)")
        if ax.get_subplotspec().is_first_col():
            ax.set_ylabel("Mpps")
    handles = [Line2D([0], [0], color=C_REF, linewidth=1.2,
                      label="sent by the generator"),
               Line2D([0], [0], color=C_RX, linewidth=3.4, marker="o",
                      markersize=6, label="received by XDP (program 1)"),
               Line2D([0], [0], color=C_FWD, linewidth=1.6, marker="o",
                      markersize=3.5, label="forwarded (reached the next "
                                            "node)")]
    fig.legend(handles=handles, loc="upper center", ncol=3, frameon=False,
               fontsize=8, bbox_to_anchor=(0.5, 1.02), labelcolor=INK)
    fig.suptitle(f"Packets per second against offered bit rate — frame "
                 f"{frame} B", fontsize=11, color=INK, x=0.01, ha="left",
                 y=1.07)
    fig.text(0.01, -0.02, "Sent above received: loss before XDP "
             "(ingress queue full, bottleneck the program or reception). "
             "Received above forwarded: loss after XDP (egress, "
             "transmission bottleneck) or the model drops. Bars: min-max over rounds.",
             fontsize=7.5, color=INK2, ha="left", wrap=True)
    fig.tight_layout()
    paths = _save(fig, out_dir, f"bitrate_pps{suffix}")
    plt.close(fig)
    return paths


def fig_loss(plt, rows, frame, out_dir, suffix):
    from matplotlib.lines import Line2D
    methods = [m for m in ORDER if m != "rxonly"
               and any(r["method"] == m for r in rows)]
    if not methods:
        return []
    fig, axes = _panels(plt, len(methods))
    floor = _series(rows, "rxonly", "loss_before_xdp_pct")
    for ax, m in zip(axes, methods):
        _style(ax)
        if floor:
            ax.plot([p[0] for p in floor], [p[1] for p in floor], color=C_REF,
                    linewidth=1.2, zorder=1)
        for key, color, z in (("loss_before_xdp_pct", C_RX, 3),
                              ("loss_in_pipeline_pct", C_FWD, 2)):
            pts = _series(rows, m, key)
            if pts:
                ax.plot([p[0] for p in pts], [p[1] for p in pts], color=color,
                        linewidth=2, marker="o", markersize=4, zorder=z)
        ax.axhline(0, color=GRID, linewidth=0.8, zorder=0)
        ax.set_title(TITLE.get(m, m), fontsize=9, color=INK, loc="left")
    for ax in axes:
        if ax.get_subplotspec().is_last_row():
            ax.set_xlabel("offered bit rate (Gbit/s)")
        if ax.get_subplotspec().is_first_col():
            ax.set_ylabel("% of sent")
    handles = [Line2D([0], [0], color=C_RX, linewidth=2, marker="o",
                      markersize=4, label="lost before XDP"),
               Line2D([0], [0], color=C_FWD, linewidth=2, marker="o",
                      markersize=4, label="lost in the pipeline (egress + "
                                          "decisions)"),
               Line2D([0], [0], color=C_REF, linewidth=1.2,
                      label="counter only (rxonly), before XDP")]
    fig.legend(handles=handles, loc="upper center", ncol=3, frameon=False,
               fontsize=8, bbox_to_anchor=(0.5, 1.02), labelcolor=INK)
    fig.suptitle(f"Loss against offered bit rate — frame {frame} B",
                 fontsize=11, color=INK, x=0.01, ha="left", y=1.07)
    fig.text(0.01, -0.02, "Loss before XDP beyond the counter-only one "
             "is the program's; loss after XDP is the transmission's. "
             "Median over rounds.", fontsize=7.5, color=INK2, ha="left")
    fig.tight_layout()
    paths = _save(fig, out_dir, f"bitrate_loss{suffix}")
    plt.close(fig)
    return paths


GENERATOR = "pktgen"


def _generator_of(out_dir):
    try:
        with open(os.path.join(out_dir, "env.csv"), newline="") as f:
            for row in csv.reader(f):
                if len(row) >= 2 and row[0] == "generatore":
                    return row[1]
    except OSError:
        pass
    return "pktgen"


def plot_all(out_dir):
    """Every figure for every frame size."""
    global GENERATOR
    GENERATOR = _generator_of(out_dir)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    rows = read_summary(os.path.join(out_dir, "bitrate.csv"))
    frames = sorted({r["frame"] for r in rows})
    written = []
    for frame in frames:
        fr = [r for r in rows if r["frame"] == frame]
        suffix = f"_{frame}B" if len(frames) > 1 else ""
        for fn in (fig_latency, fig_pps, fig_loss):
            written += fn(plt, fr, frame, out_dir, suffix)
    for p in written:
        print(f"  written {p}")
    return written


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.exit("usage: plot_load_curve.py <directory with bitrate.csv>")
    if not os.path.exists(os.path.join(argv[0], "bitrate.csv")):
        sys.exit(f"{argv[0]}: bitrate.csv missing (written by bench_load_curve.py)")
    plot_all(argv[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
