#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "matplotlib>=3.9",
#     "pandas>=2.2",
#     "seaborn>=0.13",
# ]
# ///

import argparse
import os
import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from matplotlib.ticker import FuncFormatter

sns.set_theme(style="whitegrid")

RES_DIR = Path(__file__).parent.parent / "res"

TESTS = {"bl": "Baseline", "fp": "Fast Path", "sp": "Slow Path"}
ORDER = ["Baseline", "Fast Path", "Slow Path"]
PALETTE = {"Baseline": "#0965ef", "Fast Path": "#3fcf4e", "Slow Path": "#e50e3f"}
MARKERS = {"Baseline": "o", "Fast Path": "s", "Slow Path": "^"}
X_AXES = {"rps": ("rate", "Incoming Rate [rps]"), "size": ("size", "Asset Size [KB]")}
X_STEP = 2000
Y_TICKS = [1, 2, 3, 4]

_PATH_PATTERN = re.compile(rf"^({'|'.join(TESTS)})(-http2)?-(.+)-(\d+)$")
_SIZE_PATTERN = re.compile(r"^(\d+)KB$")
# oha humanizes durations and may prefix the unit with a multiplier, e.g.
# "0.9465 10 sec" for 9.465 seconds
_AVERAGE_PATTERN = re.compile(r"Average:\s+([\d.]+)\s+(?:([\d.]+)\s+)?(\w+)")
_UNIT_TO_MS = {"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "ms": 1.0, "sec": 1e3}


def _parse_path(path, http2):
    match = _PATH_PATTERN.match(path.stem)
    if match is None:
        return None

    test, proto, size, rate = match.groups()
    if (proto is not None) != http2:
        return None

    size_match = _SIZE_PATTERN.match(size)
    size = int(size_match.group(1)) if size_match else None

    return TESTS[test], int(rate), size


def _parse_log(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            match = _AVERAGE_PATTERN.search(line)
            if match:
                value, mult, unit = match.groups()
                return float(value) * float(mult or 1) * _UNIT_TO_MS[unit]

    return None


def _load_data(exp, http2):
    rows = []

    for path in sorted((RES_DIR / exp).glob("*.log")):
        path_res = _parse_path(path, http2)
        if path_res is None:
            continue

        latency = _parse_log(path)
        if latency is None:
            print(f"No average in {path}")
            continue

        test, rate, size = path_res
        rows.append({"test": test, "rate": rate, "size": size, "latency": latency})

    return pd.DataFrame(rows, columns=["test", "rate", "size", "latency"])


def _x_ticks(left, right):
    left, right = int(left), int(right)

    ticks = [x for x in range(0, min(right, 30000) + 1, X_STEP) if x >= left]

    return ticks


def export_plot(exp, http2, x_axis, max_x, disabled):
    column, xlabel = X_AXES[x_axis]

    df = _load_data(exp, http2)
    df = df[df[column].notna()]
    if df.empty:
        raise ValueError(f"No results for experiment {exp}")

    if x_axis == "size":
        rates = sorted(int(rate) for rate in df["rate"].unique())
        if len(rates) > 1:
            raise ValueError(f"Experiment {exp} holds several rates: {rates}")

    if max_x is not None:
        df = df[df[column] <= max_x]

    df = df[~df["test"].isin(TESTS[test] for test in disabled)]

    order = [test for test in ORDER if test in df["test"].unique()]

    fig, ax = plt.subplots(figsize=(6, 3.5))
    sns.lineplot(
        data=df,
        x=column,
        y="latency",
        hue="test",
        hue_order=order,
        style="test",
        style_order=order,
        palette=PALETTE,
        markers=[MARKERS[test] for test in order],
        dashes=False,
        markersize=7,
        linewidth=2,
        ax=ax,
    )

    ax.set_xlabel(xlabel)
    ax.set_ylabel("Request Latency [ms]")

    if x_axis == "rps":
        min_x = df[column].min()
        ax.set_xlim(left=min_x, right=max_x)
        ax.set_xticks(_x_ticks(*ax.get_xlim()))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{x / 1000:g}k"))
    else:
        ax.set_xlim(right=max_x)
        ax.set_xticks(sorted(df[column].unique()))

    ax.set_ylim(bottom=0, top=Y_TICKS[-1])
    ax.set_yticks(Y_TICKS)
    ax.minorticks_off()
    ax.legend(
        title=None,
        frameon=False,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.0),
        ncols=len(order),
    )
    fig.tight_layout()

    os.makedirs(RES_DIR / "vis", exist_ok=True)
    fig.savefig(RES_DIR / "vis" / f"{exp}.png", dpi=300, bbox_inches="tight")


def parse_args():
    parser = argparse.ArgumentParser(description="Visualize load tests.")
    parser.add_argument("name", type=str, help="Name of the experiment, e.g. 8KB.")
    parser.add_argument(
        "--http2",
        action="store_true",
        help="Plot the HTTP/2 measurements instead of HTTP/1.",
    )
    for test, name in TESTS.items():
        parser.add_argument(
            f"--disable-{test}",
            action="store_true",
            help=f"Remove the {name.lower()} from the plot.",
        )

    parser.add_argument(
        "--x-axis",
        choices=list(X_AXES),
        default="rps",
        help="Plot the latency over the incoming rate or over the asset size.",
    )

    parser.add_argument(
        "-x",
        "--max-x",
        type=float,
        default=None,
        help="Maximum x value to plot.",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    disabled = [test for test in TESTS if getattr(args, f"disable_{test}")]
    export_plot(args.name, args.http2, args.x_axis, args.max_x, disabled)
