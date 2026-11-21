
import csv
import math
import statistics
import argparse
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]

INPUT = ROOT / "results" / "end_to_end_latency.csv"
OUTPUT = ROOT / "results" / "end_to_end_summary.csv"
FIGURES = ROOT / "figures"

FIGURES.mkdir(parents=True, exist_ok=True)


STAGES = {
    "AI inference": "ai_inference_ms",
    "Authentication": "authentication_ms",
    "PBFT consensus": "consensus_stage_ms",
    "Ledger persistence": "ledger_ms",
    "Simulated response": "response_ms",
}


def percentile(values, percentage):
    ordered = sorted(values)

    if not ordered:
        return None

    position = (
        (len(ordered) - 1) * percentage / 100
    )

    lower = math.floor(position)
    upper = math.ceil(position)

    return (
        ordered[lower]
        + (ordered[upper] - ordered[lower])
        * (position - lower)
    )


def summarize(values):
    if not values:
        return None

    return {
        "count": len(values),
        "mean_ms": round(
            statistics.mean(values), 4
        ),
        "median_ms": round(
            statistics.median(values), 4
        ),
        "std_ms": round(
            statistics.stdev(values)
            if len(values) > 1 else 0.0,
            4,
        ),
        "p95_ms": round(
            percentile(values, 95), 4
        ),
        "min_ms": round(min(values), 4),
        "max_ms": round(max(values), 4),
    }


def numeric_values(rows, column):
    values = []

    for row in rows:
        raw = row.get(column, "")

        if raw is None or not raw.strip():
            continue

        value = float(raw)

        if not math.isfinite(value):
            raise ValueError(
                f"Invalid numeric value in {column}"
            )

        values.append(value)

    return values


def main():
    
    parser = argparse.ArgumentParser(
        description="Analyze UAV cybersecurity end-to-end latency"
    )

    parser.add_argument(
        "--input",
        default=str(INPUT),
        help="Path to the benchmark CSV file",
    )

    args = parser.parse_args()

    input_path = Path(args.input)

    if not input_path.exists():
        raise FileNotFoundError(input_path)

    with input_path.open(
        newline="",
        encoding="utf-8-sig",
    ) as file:
        rows = list(csv.DictReader(file))

    if not rows:
        raise ValueError("Benchmark CSV is empty")

    successful = [
        row for row in rows
        if row["status"] == "SUCCESS"
    ]

    print("=" * 60)
    print("END-TO-END UAV CYBERSECURITY ANALYSIS")
    print("=" * 60)

    print(f"Total trials: {len(rows)}")
    print(f"Successful trials: {len(successful)}")
    print(
        f"Success rate: "
        f"{100 * len(successful) / len(rows):.2f}%"
    )

    if not successful:
        raise ValueError(
            "No successful trials available"
        )

    measurements = {
        "Total pipeline": "total_pipeline_ms",
        **STAGES,
    }

    summaries = []

    for name, column in measurements.items():
        values = numeric_values(
            successful, column
        )

        if len(values) != len(successful):
            raise ValueError(
                f"Missing measurements in {column}"
            )

        stats = summarize(values)

        summary = {
            "component": name,
            **stats,
        }

        summaries.append(summary)

        print(f"\n{name}")
        for metric, value in stats.items():
            print(f"  {metric}: {value}")

    # --------------------------------------------------
    # SAVE STATISTICAL SUMMARY
    # --------------------------------------------------

    with OUTPUT.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(summaries[0].keys()),
        )

        writer.writeheader()
        writer.writerows(summaries)

    # --------------------------------------------------
    # FIGURE 1: TOTAL LATENCY DISTRIBUTION
    # --------------------------------------------------

    total = numeric_values(
        successful,
        "total_pipeline_ms",
    )

    plt.figure(figsize=(8, 5))

    plt.boxplot(
        [total],
        tick_labels=["Full pipeline"],
        showmeans=True,
    )

    plt.ylabel("Elapsed time (ms)")
    plt.title(
        "UAV Cybersecurity End-to-End Latency"
    )
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()

    plt.savefig(
        FIGURES / "end_to_end_latency_boxplot.png",
        dpi=300,
    )
    plt.close()

    # --------------------------------------------------
    # FIGURE 2: MEAN LATENCY BY STAGE
    # --------------------------------------------------

    labels = list(STAGES.keys())

    means = [
        statistics.mean(
            numeric_values(successful, column)
        )
        for column in STAGES.values()
    ]

    plt.figure(figsize=(10, 5))

    plt.bar(labels, means)

    plt.ylabel("Mean duration (ms)")
    plt.title(
        "UAV Cybersecurity Pipeline: "
        "Stage Latency"
    )

    plt.xticks(rotation=20, ha="right")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()

    plt.savefig(
        FIGURES / "end_to_end_stage_breakdown.png",
        dpi=300,
    )
    plt.close()

    # --------------------------------------------------
    # FIGURE 3: LEDGER GROWTH VS PERSISTENCE TIME
    # --------------------------------------------------

    block_indices = numeric_values(
        successful,
        "block_index",
    )

    ledger_durations = numeric_values(
        successful,
        "ledger_ms",
    )

    plt.figure(figsize=(8, 5))

    plt.scatter(
        block_indices,
        ledger_durations,
        alpha=0.7,
    )

    plt.xlabel("Appended ledger block index")
    plt.ylabel("Ledger persistence duration (ms)")
    plt.title(
        "Ledger Size Proxy vs Persistence Latency"
    )

    plt.grid(alpha=0.25)
    plt.tight_layout()

    plt.savefig(
        FIGURES / "ledger_growth_latency.png",
        dpi=300,
    )
    plt.close()

    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETED")
    print(f"Summary: {OUTPUT}")
    print(f"Figures: {FIGURES}")
    print("=" * 60)


if __name__ == "__main__":
    main()
