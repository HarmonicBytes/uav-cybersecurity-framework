
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "results" / "pbft_benchmark_timing.csv"
OUTPUT = ROOT / "results" / "pbft_summary.csv"
FIGURES = ROOT / "figures"

FIGURES.mkdir(parents=True, exist_ok=True)


def percentile(values, percent):
    values = sorted(values)
    if not values:
        return None

    position = (len(values) - 1) * percent / 100
    lower = math.floor(position)
    upper = math.ceil(position)

    return values[lower] + (
        values[upper] - values[lower]
    ) * (position - lower)


def summarize(values):
    if not values:
        return {
            "mean_ms": "",
            "median_ms": "",
            "std_ms": "",
            "p95_ms": "",
            "min_ms": "",
            "max_ms": "",
        }

    return {
        "mean_ms": round(statistics.mean(values), 4),
        "median_ms": round(statistics.median(values), 4),
        "std_ms": round(
            statistics.stdev(values)
            if len(values) > 1 else 0,
            4,
        ),
        "p95_ms": round(percentile(values, 95), 4),
        "min_ms": round(min(values), 4),
        "max_ms": round(max(values), 4),
    }


def main():
    with INPUT.open(
        newline="",
        encoding="utf-8-sig",
    ) as file:
        rows = list(csv.DictReader(file))

    scenarios = defaultdict(list)

    for row in rows:
        scenarios[row["scenario"]].append(row)

    summary_rows = []
    local_latency_data = []
    labels = []

    for scenario in ["4online", "3online", "2online"]:
        group = scenarios.get(scenario, [])

        if not group:
            continue

        successful = [
            row for row in group
            if row["consensus_success"] == "True"
        ]

        observed = [
            float(row["observed_duration_ms"])
            for row in successful
        ]

        # Each successful trial contributes one mean
        # across its committed replicas.
        local = [
            float(row["mean_replica_consensus_ms"])
            for row in successful
            if row["mean_replica_consensus_ms"]
        ]

        # Do not include timeout durations in
        # successful-consensus latency statistics.
        stats = summarize(local)

        summary = {
            "scenario": scenario,
            "trials": len(group),
            "successful": len(successful),
            "success_rate_pct": round(
                100 * len(successful) / len(group), 2
            ),
            "mean_observed_ms": (
                round(statistics.mean(observed), 4)
                if observed else ""
            ),
            **stats,
        }

        summary_rows.append(summary)

        print(f"\nScenario: {scenario}")
        for key, value in summary.items():
            print(f"  {key}: {value}")

        if local:
            labels.append(scenario)
            local_latency_data.append(local)

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

    if local_latency_data:
        plt.figure(figsize=(8, 5))
        plt.boxplot(
            local_latency_data,
            tick_labels=labels,
            showmeans=True,
        )
        plt.ylabel("Replica-local consensus latency (ms)")
        plt.xlabel("Active-validator scenario")
        plt.title("PBFT Local Consensus Latency")
        plt.grid(axis="y", alpha=0.25)
        plt.tight_layout()
        plt.savefig(
            FIGURES / "pbft_latency_boxplot.png",
            dpi=300,
        )
        plt.close()

    plt.figure(figsize=(8, 5))
    plt.bar(
        [row["scenario"] for row in summary_rows],
        [row["success_rate_pct"] for row in summary_rows],
    )
    plt.ylim(0, 110)
    plt.ylabel("Consensus success rate (%)")
    plt.xlabel("Active-validator scenario")
    plt.title("PBFT Consensus Success by Scenario")
    plt.tight_layout()
    plt.savefig(
        FIGURES / "pbft_success_rate.png",
        dpi=300,
    )
    plt.close()

    print("\nAnalysis completed.")
    print(f"Summary: {OUTPUT}")
    print(f"Figures: {FIGURES}")


if __name__ == "__main__":
    main()
