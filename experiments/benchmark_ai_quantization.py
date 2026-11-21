
import argparse
import csv
import json
import random
import statistics
import sys
import time
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
from torch import nn


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "ai"))

from autoencoder import TelemetryAutoencoder


FEATURES = [
    "gps_drift_m",
    "snr_db",
    "packet_rate_hz",
    "packet_loss_ratio",
]

MODEL_DIR = ROOT / "results" / "models"
RESULTS_DIR = ROOT / "results"
FIGURES_DIR = ROOT / "figures"

MODEL_PATH = MODEL_DIR / "autoencoder.pt"
SCALER_PATH = MODEL_DIR / "scaler.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"
DATA_PATH = RESULTS_DIR / "ai_test_predictions.csv"

QUANTIZED_PATH = MODEL_DIR / "autoencoder_int8.pt"
SUMMARY_PATH = RESULTS_DIR / "ai_quantization_summary.json"
DETAIL_PATH = RESULTS_DIR / "ai_quantization_latency.csv"
FIGURE_PATH = FIGURES_DIR / "ai_quantization_comparison.png"

SEED = 42


def evaluate(model, inputs, threshold, actual):
    model.eval()

    with torch.no_grad():
        reconstructed = model(inputs)

        scores = torch.mean(
            (inputs - reconstructed) ** 2,
            dim=1,
        ).cpu().numpy()

    predictions = (scores > threshold).astype(int)

    result = {
        "accuracy": float(
            np.mean(predictions == actual)
        ),
        "predicted_anomalies": int(
            np.sum(predictions)
        ),
    }

    if len(np.unique(actual)) == 2:
        from sklearn.metrics import (
            precision_score,
            recall_score,
            f1_score,
        )

        result["precision"] = float(
            precision_score(
                actual,
                predictions,
                zero_division=0,
            )
        )

        result["recall"] = float(
            recall_score(
                actual,
                predictions,
                zero_division=0,
            )
        )

        result["f1_score"] = float(
            f1_score(
                actual,
                predictions,
                zero_division=0,
            )
        )

    return result, scores, predictions


def percentile(values, value):
    return float(np.percentile(values, value))


def latency_stats(values):
    return {
        "mean_ms": round(
            statistics.mean(values), 6
        ),
        "median_ms": round(
            statistics.median(values), 6
        ),
        "p95_ms": round(
            percentile(values, 95), 6
        ),
        "std_ms": round(
            statistics.stdev(values)
            if len(values) > 1 else 0.0,
            6,
        ),
        "min_ms": round(min(values), 6),
        "max_ms": round(max(values), 6),
    }


def benchmark(
    fp32_model,
    int8_model,
    inputs,
    iterations,
    warmup,
):
    rng = random.Random(SEED)

    models = {
        "FP32": fp32_model,
        "INT8": int8_model,
    }

    for model in models.values():
        model.eval()

    # Warm up both implementations.
    with torch.inference_mode():
        for _ in range(warmup):
            sample = inputs[
                rng.randrange(len(inputs))
            ].unsqueeze(0)

            for model in models.values():
                model(sample)

    observations = []

    # Paired measurements on identical inputs.
    # Randomize execution order for each pair.
    with torch.inference_mode():
        for trial in range(1, iterations + 1):
            row_index = rng.randrange(len(inputs))

            sample = inputs[
                row_index
            ].unsqueeze(0)

            order = ["FP32", "INT8"]
            rng.shuffle(order)

            for implementation in order:
                started = time.perf_counter_ns()

                models[implementation](sample)

                duration_ms = (
                    time.perf_counter_ns() - started
                ) / 1_000_000

                observations.append({
                    "trial": trial,
                    "row_index": row_index,
                    "implementation": implementation,
                    "duration_ms": round(
                        duration_ms, 6
                    ),
                })

    return observations


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--iterations",
        type=int,
        default=200,
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=30,
    )

    args = parser.parse_args()

    if args.iterations < 1 or args.warmup < 0:
        parser.error(
            "Invalid iterations or warmup"
        )

    print("=" * 65)
    print("UAV EDGE AI: FP32 VS DYNAMIC INT8")
    print("=" * 65)

    torch.manual_seed(SEED)
    np.random.seed(SEED)
    torch.set_num_threads(1)

    with METRICS_PATH.open(
        encoding="utf-8"
    ) as file:
        training_metrics = json.load(file)

    threshold = float(
        training_metrics["threshold"]
    )

    scaler = joblib.load(SCALER_PATH)

    df = pd.read_csv(DATA_PATH)

    missing = [
        feature
        for feature in FEATURES
        if feature not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing features: {missing}"
        )

    if "is_attack" not in df.columns:
        raise ValueError(
            "Missing is_attack labels"
        )

    scaled = scaler.transform(
        df[FEATURES]
    )

    inputs = torch.tensor(
        scaled,
        dtype=torch.float32,
    )

    actual = df["is_attack"].to_numpy(
        dtype=int
    )

    # Load the original trained network.
    fp32 = TelemetryAutoencoder(
        input_dim=4
    )

    state = torch.load(
        MODEL_PATH,
        map_location="cpu",
        weights_only=True,
    )

    fp32.load_state_dict(state)
    fp32.eval()

    # Quantize Linear layers dynamically.
    int8 = torch.ao.quantization.quantize_dynamic(
        fp32,
        {nn.Linear},
        dtype=torch.qint8,
        inplace=False,
    )

    int8.eval()

    # Store quantized parameters.
    # Loading requires recreating the same
    # quantized model architecture first.
    torch.save(
        int8.state_dict(),
        QUANTIZED_PATH,
    )

    fp32_bytes = MODEL_PATH.stat().st_size
    int8_bytes = QUANTIZED_PATH.stat().st_size

    size_change_pct = (
        (int8_bytes - fp32_bytes)
        / fp32_bytes
        * 100
    )

    print(f"Evaluation samples: {len(df)}")
    print(f"Anomaly threshold: {threshold:.8f}")

    print("\n[1] Serialized model size")
    print(f"FP32: {fp32_bytes} bytes")
    print(f"INT8: {int8_bytes} bytes")
    print(
        f"Size change: {size_change_pct:+.2f}%"
    )

    # Evaluate prediction quality on the
    # same observations and fixed threshold.
    fp32_metrics, fp32_scores, fp32_pred = evaluate(
        fp32,
        inputs,
        threshold,
        actual,
    )

    int8_metrics, int8_scores, int8_pred = evaluate(
        int8,
        inputs,
        threshold,
        actual,
    )

    agreement = float(
        np.mean(fp32_pred == int8_pred)
    )

    changed_predictions = int(
        np.sum(fp32_pred != int8_pred)
    )

    max_score_difference = float(
        np.max(
            np.abs(fp32_scores - int8_scores)
        )
    )

    print("\n[2] Detection performance")
    print(
        f"FP32 accuracy: "
        f"{fp32_metrics['accuracy']:.6f}"
    )
    print(
        f"INT8 accuracy: "
        f"{int8_metrics['accuracy']:.6f}"
    )
    print(
        f"Classification agreement: "
        f"{agreement:.2%}"
    )
    print(
        f"Changed predictions: "
        f"{changed_predictions}"
    )

    print("\n[3] CPU inference benchmark")

    observations = benchmark(
        fp32,
        int8,
        inputs,
        args.iterations,
        args.warmup,
    )

    measurements = {}

    for name in ("FP32", "INT8"):
        values = [
            record["duration_ms"]
            for record in observations
            if record["implementation"] == name
        ]

        measurements[name] = latency_stats(
            values
        )

        print(
            f"{name}: "
            f"mean="
            f"{measurements[name]['mean_ms']:.6f} ms | "
            f"median="
            f"{measurements[name]['median_ms']:.6f} ms | "
            f"p95="
            f"{measurements[name]['p95_ms']:.6f} ms"
        )

    speedup = (
        measurements["FP32"]["mean_ms"]
        / measurements["INT8"]["mean_ms"]
    )

    print(
        f"Mean latency ratio (FP32/INT8): "
        f"{speedup:.3f}x"
    )

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    FIGURES_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary = {
        "experiment": "dynamic_int8_quantization",
        "seed": SEED,
        "evaluation_samples": len(df),
        "iterations_per_model": args.iterations,
        "warmup_iterations": args.warmup,
        "batch_size": 1,
        "cpu_threads": 1,
        "threshold": threshold,
        "fp32_size_bytes": fp32_bytes,
        "int8_size_bytes": int8_bytes,
        "size_change_pct": size_change_pct,
        "fp32_detection": fp32_metrics,
        "int8_detection": int8_metrics,
        "prediction_agreement": agreement,
        "changed_predictions": changed_predictions,
        "maximum_score_difference": (
            max_score_difference
        ),
        "fp32_latency": measurements["FP32"],
        "int8_latency": measurements["INT8"],
        "mean_latency_ratio": speedup,
    }

    with SUMMARY_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            summary,
            file,
            indent=2,
        )

    with DETAIL_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "trial",
                "row_index",
                "implementation",
                "duration_ms",
            ],
        )

        writer.writeheader()
        writer.writerows(observations)

    # Publication-oriented comparison figure.
    plt.figure(figsize=(8, 5))

    labels = ["FP32", "Dynamic INT8"]

    medians = [
        measurements["FP32"]["median_ms"],
        measurements["INT8"]["median_ms"],
    ]

    plt.bar(labels, medians)

    plt.ylabel(
        "Median CPU forward-pass latency (ms)"
    )
    plt.title(
        "UAV Autoencoder Inference Comparison"
    )
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()

    plt.savefig(
        FIGURE_PATH,
        dpi=300,
    )
    plt.close()

    print("\n" + "=" * 65)
    print("QUANTIZATION EXPERIMENT COMPLETED")
    print(f"Summary: {SUMMARY_PATH}")
    print(f"Measurements: {DETAIL_PATH}")
    print(f"Figure: {FIGURE_PATH}")
    print(f"Quantized weights: {QUANTIZED_PATH}")
    print("=" * 65)


if __name__ == "__main__":
    main()
