
import csv
import statistics
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]

INPUT = ROOT / "results" / "certificate_overhead.csv"
OUTPUT = ROOT / "results" / "certificate_overhead_summary.csv"
FIGURE = ROOT / "figures" / "certificate_overhead_comparison.png"

COMPONENTS = [
    "ledger_overhead_ms",
    "response_overhead_ms",
    "total_overhead_ms",
]


def percentile(values, percentage):
    ordered = sorted(values)

    position = (len(ordered) - 1) * percentage / 100

    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower

    return (
        ordered[lower] * (1 - fraction)
        + ordered[upper] * fraction
    )


def summarize(values):
    return {
        "mean_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "std_ms": (
            statistics.stdev(values)
            if len(values) > 1 else 0
        ),
        "p95_ms": percentile(values, 95),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def main():
    with INPUT.open(
        newline="",
        encoding="utf-8-sig",
    ) as file:
        rows = list(csv.DictReader(file))

    if not rows:
        raise ValueError("No benchmark results")

    groups = {}

    for row in rows:
        if row["status"] != "SUCCESS":
            continue

        blocks = int(row["ledger_history_blocks"])

        groups.setdefault(blocks, []).append(row)

    summary_rows = []

    for blocks in sorted(groups):
        records = groups[blocks]

        for component in COMPONENTS:
            values = [
                float(record[component])
                for record in records
            ]

            stats = summarize(values)

            summary_rows.append({
                "existing_alert_blocks": blocks,
                "component": component,
                "trials": len(values),
                **{
                    key: round(value, 4)
                    for key, value in stats.items()
                },
            })

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(summary_rows[0].keys()),
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    sizes = sorted(groups)

    ledger_means = []
    response_means = []

    for blocks in sizes:
        ledger_means.append(
            statistics.mean(
                float(row["ledger_overhead_ms"])
                for row in groups[blocks]
            )
        )

        response_means.append(
            statistics.mean(
                float(row["response_overhead_ms"])
                for row in groups[blocks]
            )
        )

    positions = range(len(sizes))
    width = 0.35

    plt.figure(figsize=(9, 5))

    plt.bar(
        [position - width / 2 for position in positions],
        ledger_means,
        width=width,
        label="Ledger persistence overhead",
    )

    plt.bar(
        [position + width / 2 for position in positions],
        response_means,
        width=width,
        label="Response verification overhead",
    )

    plt.xticks(
        list(positions),
        [str(size) for size in sizes],
    )

    plt.xlabel("Existing alert blocks")
    plt.ylabel("Mean additional latency (ms)")
    plt.title(
        "PBFT Certificate Processing Overhead"
    )
    plt.legend()
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()

    FIGURE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    plt.savefig(FIGURE, dpi=300)
    plt.close()

    print("=" * 60)
    print("CERTIFICATE OVERHEAD ANALYSIS")
    print("=" * 60)

    for row in summary_rows:
        print(
            f"Blocks={row['existing_alert_blocks']:>2} | "
            f"{row['component']:<22} | "
            f"mean={row['mean_ms']:.4f} ms | "
            f"p95={row['p95_ms']:.4f} ms"
        )

    print(f"\nSummary: {OUTPUT}")
    print(f"Figure: {FIGURE}")


if __name__ == "__main__":
    main()
