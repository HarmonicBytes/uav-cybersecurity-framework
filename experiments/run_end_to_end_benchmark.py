
import argparse
import asyncio
import csv
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "src" / "ai"))
sys.path.insert(0, str(ROOT / "experiments"))

from inference import (
    UAVAnomalyDetector,
    generate_alert,
    FEATURES,
)

from run_alert_consensus import run as run_consensus


DEFAULT_INPUT = (
    ROOT / "results" / "ai_test_predictions.csv"
)

DEFAULT_OUTPUT = (
    ROOT / "results" / "end_to_end_latency.csv"
)


# ============================================================
# CSV COLUMNS
# ============================================================

FIELDS = [
    "timestamp_utc",
    "trial",
    "input_row",
    "status",
    "anomaly_score",
    "threshold",
    "ai_inference_ms",
    "authentication_ms",
    "consensus_stage_ms",
    "ledger_ms",
    "replication_ms",
    "replicated_validators",
    "replicated_block_index",
    "replicated_block_hash",
    "response_ms",
    "total_pipeline_ms",
    "GCS_01_consensus_ms",
    "GCS_02_consensus_ms",
    "GCS_03_consensus_ms",
    "GCS_04_consensus_ms",
    "committed_validators",
    "block_index",
    "response_severity",
    "response_actions",
    "error",
]


# ============================================================
# SELECT TELEMETRY OBSERVATION
# ============================================================

def choose_telemetry(input_path, row_index=None):
    df = pd.read_csv(input_path)

    missing = [
        feature
        for feature in FEATURES
        if feature not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing telemetry features: {missing}"
        )

    if row_index is None:
        if "predicted_attack" not in df.columns:
            raise ValueError(
                "Input CSV has no predicted_attack column"
            )

        matching = df.index[
            df["predicted_attack"] == 1
        ]

        if len(matching) == 0:
            raise ValueError(
                "No previously detected anomaly found"
            )

        selected_index = int(matching[0])

    else:
        selected_index = row_index

    if not 0 <= selected_index < len(df):
        raise ValueError(
            "Selected telemetry row is out of range"
        )

    source = df.iloc[selected_index]

    telemetry = {
        feature: float(source[feature])
        for feature in FEATURES
    }

    if any(
        not math.isfinite(value)
        for value in telemetry.values()
    ):
        raise ValueError(
            "Telemetry contains non-finite values"
        )

    return selected_index, telemetry


# ============================================================
# EXECUTE ONE END-TO-END TRIAL
# ============================================================

async def execute_trial(
    detector,
    telemetry,
    trial,
    row_index,
    timeout,
):
    started = time.perf_counter()

    result_row = {
        field: ""
        for field in FIELDS
    }

    result_row.update({
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "trial": trial,
        "input_row": row_index,
        "status": "ERROR",
    })

    try:
        # --------------------------------------------------
        # STAGE 1: REAL AI INFERENCE
        # --------------------------------------------------

        alert, prediction = generate_alert(
            detector,
            telemetry,
            uav_id="UAV_BENCHMARK",
        )

        inference_finished = time.perf_counter()

        result_row["anomaly_score"] = (
            prediction["anomaly_score"]
        )

        result_row["threshold"] = (
            prediction["threshold"]
        )

        result_row["ai_inference_ms"] = round(
            (inference_finished - started) * 1000,
            6,
        )

        if alert is None:
            raise RuntimeError(
                "Selected telemetry did not trigger an anomaly"
            )

        # --------------------------------------------------
        # STAGES 2-5:
        # AUTHENTICATION, PBFT, LEDGER, RESPONSE
        # --------------------------------------------------

        workflow = await run_consensus(
            alert,
            timeout,
        )

        completed = time.perf_counter()

        if workflow["status"] != "SUCCESS":
            raise RuntimeError(
                "Consensus workflow was unsuccessful"
            )

        if workflow["response_status"] != "RECORDED":
            raise RuntimeError(
                "Simulated response was not newly recorded"
            )

        if workflow["committed_validators"] != 4:
            raise RuntimeError(
                "Not all four GCS validators committed"
            )

        # --------------------------------------------------
        # COLLECT MEASUREMENTS
        # --------------------------------------------------

        result_row.update({
            "status": "SUCCESS",

            "authentication_ms": (
                workflow["authentication_ms"]
            ),

            "consensus_stage_ms": (
                workflow["consensus_stage_ms"]
            ),

            "ledger_ms": (
                workflow["ledger_ms"]
            ),
            "replication_ms": (
                workflow["replication_ms"]
            ),

            "replicated_validators": (
                workflow["replicated_validators"]
            ),

            "replicated_block_index": (
                workflow["replicated_block_index"]
            ),

            "replicated_block_hash": (
                workflow["replicated_block_hash"]
            ),
            "response_ms": (
                workflow["response_ms"]
            ),

            "total_pipeline_ms": round(
                (completed - started) * 1000,
                6,
            ),

            "committed_validators": (
                workflow["committed_validators"]
            ),

            "block_index": (
                workflow["block_index"]
            ),

            "response_severity": (
                workflow["response_severity"]
            ),

            "response_actions": (
                workflow["response_actions"]
            ),
        })

        # Individual replica-local consensus times.
        for node_id, latency in (
            workflow["replica_consensus_ms"].items()
        ):
            column = f"{node_id}_consensus_ms"

            if column in result_row:
                result_row[column] = latency

    except Exception as error:
        result_row["status"] = "ERROR"

        result_row["error"] = (
            f"{type(error).__name__}: {error}"
        )

        result_row["total_pipeline_ms"] = round(
            (time.perf_counter() - started) * 1000,
            6,
        )

    return result_row


# ============================================================
# BENCHMARK EXECUTION
# ============================================================

async def main():
    parser = argparse.ArgumentParser(
        description=(
            "Measure end-to-end UAV AI, PBFT, "
            "ledger and simulated response latency"
        )
    )

    parser.add_argument(
        "--trials",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
    )

    parser.add_argument(
        "--row-index",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT),
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
    )

    args = parser.parse_args()

    if args.trials < 1:
        parser.error(
            "--trials must be at least 1"
        )

    if args.timeout <= 0:
        parser.error(
            "--timeout must be positive"
        )

    print("=" * 60)
    print("UAV CYBERSECURITY END-TO-END BENCHMARK")
    print("=" * 60)

    # --------------------------------------------------
    # LOAD INPUT TELEMETRY
    # --------------------------------------------------

    selected_index, telemetry = choose_telemetry(
        Path(args.input),
        args.row_index,
    )

    print(f"Telemetry observation: {selected_index}")

    for feature, value in telemetry.items():
        print(f"{feature}: {value}")

    # --------------------------------------------------
    # LOAD TRAINED AI MODEL
    # --------------------------------------------------

    print("\nLoading trained PyTorch autoencoder...")

    loading_started = time.perf_counter()

    detector = UAVAnomalyDetector()

    model_load_ms = (
        time.perf_counter() - loading_started
    ) * 1000

    print(
        f"Model initialization: {model_load_ms:.3f} ms"
    )

    # Warm up the model before measuring trials.
    # The warm-up is excluded from recorded latency.
    detector.predict(telemetry)

    # --------------------------------------------------
    # PREPARE CSV OUTPUT
    # --------------------------------------------------

    output = Path(args.output)

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if output.exists() and output.stat().st_size > 0:
        with output.open(
            newline="",
            encoding="utf-8-sig",
        ) as file:
            existing_fields = (
                csv.DictReader(file).fieldnames
            )

        if existing_fields != FIELDS:
            raise ValueError(
                "Existing CSV has a different schema. "
                "Choose another output filename."
            )

    write_header = (
        not output.exists()
        or output.stat().st_size == 0
    )

    successes = 0
    durations = []

    # --------------------------------------------------
    # RUN EXPERIMENTAL TRIALS
    # --------------------------------------------------

    with output.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS,
        )

        if write_header:
            writer.writeheader()

        for trial in range(1, args.trials + 1):
            print("\n" + "=" * 60)
            print(
                f"TRIAL {trial}/{args.trials}"
            )
            print("=" * 60)

            result = await execute_trial(
                detector=detector,
                telemetry=telemetry,
                trial=trial,
                row_index=selected_index,
                timeout=args.timeout,
            )

            writer.writerow(result)
            file.flush()

            if result["status"] == "SUCCESS":
                successes += 1

                duration = result[
                    "total_pipeline_ms"
                ]

                durations.append(duration)

                print(
                    f"\nTRIAL {trial}: SUCCESS | "
                    f"Total={duration:.3f} ms"
                )

            else:
                print(
                    f"\nTRIAL {trial}: ERROR | "
                    f"{result['error']}"
                )

    # --------------------------------------------------
    # SUMMARY
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("END-TO-END BENCHMARK SUMMARY")
    print("=" * 60)

    print(f"Trials: {args.trials}")
    print(f"Successful: {successes}")

    print(
        f"Success rate: "
        f"{100 * successes / args.trials:.1f}%"
    )

    print(
        f"Model initialization (excluded): "
        f"{model_load_ms:.3f} ms"
    )

    if durations:
        mean_duration = (
            sum(durations) / len(durations)
        )

        print(
            f"Mean total pipeline latency: "
            f"{mean_duration:.3f} ms"
        )

        print(
            f"Minimum total latency: "
            f"{min(durations):.3f} ms"
        )

        print(
            f"Maximum total latency: "
            f"{max(durations):.3f} ms"
        )

    print(f"Results saved: {output}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
