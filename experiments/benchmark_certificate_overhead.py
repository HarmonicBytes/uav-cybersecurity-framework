
import argparse
import csv
import json
import random
import shutil
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0, str(ROOT / "src" / "blockchain")
)
sys.path.insert(
    0, str(ROOT / "src" / "security")
)

from authentication import sign_message
from protocol import PBFTMessage, calculate_digest
from commit_certificate import verify_commit_certificate
from ledger_store import SecurityLedgerStore
from response_engine import DefensiveResponseEngine


VALIDATORS = [
    "GCS_01",
    "GCS_02",
    "GCS_03",
    "GCS_04",
]

VIEW = 0
SEED = 42

DEFAULT_OUTPUT = (
    ROOT / "results" / "certificate_overhead.csv"
)

FIELDS = [
    "timestamp_utc",
    "ledger_history_blocks",
    "trial",
    "execution_order",
    "uncertified_ledger_ms",
    "certified_ledger_ms",
    "ledger_overhead_ms",
    "uncertified_response_ms",
    "certified_response_ms",
    "response_overhead_ms",
    "uncertified_total_ms",
    "certified_total_ms",
    "total_overhead_ms",
    "standalone_certificate_verify_ms",
    "certificate_votes",
    "status",
]


def make_alert(index):
    return {
        "uav_id": "UAV_BENCHMARK",
        "event_type": "UAV_TELEMETRY_ANOMALY",
        "anomaly_score": 42.5 + index * 0.001,
        "threshold": 1.5,
        "detection_result": "ANOMALY",
        "source": "synthetic_certificate_benchmark",
    }


def make_certificate(alert, sequence):
    digest = calculate_digest(alert)
    certificate = []

    for validator in VALIDATORS:
        message = PBFTMessage(
            phase="COMMIT",
            view=VIEW,
            sequence=sequence,
            digest=digest,
            sender=validator,
        ).to_dict()

        certificate.append(
            sign_message(validator, message)
        )

    return certificate


def create_initial_snapshot(path, history_blocks):
    """
    Construct one common history for both variants.

    history_blocks counts prior alert blocks,
    excluding the genesis block.
    """

    store = SecurityLedgerStore(path=path)

    for index in range(history_blocks):
        alert = make_alert(index)
        sequence = 10000 + index

        store.append_committed_alert(
            alert=alert,
            committed_digest=calculate_digest(alert),
            view=VIEW,
            sequence=sequence,
            committed_validators=VALIDATORS,
        )

    return path if path.exists() else None


def run_variant(
    variant,
    snapshot,
    work_dir,
    alert,
    sequence,
    certificate,
):
    """
    Each variant receives an independent copy of
    the exact same starting ledger history.
    """

    ledger_path = work_dir / f"{variant}_ledger.json"
    response_path = work_dir / f"{variant}_responses.json"

    if snapshot is not None:
        shutil.copyfile(snapshot, ledger_path)

    store = SecurityLedgerStore(path=ledger_path)

    engine = DefensiveResponseEngine(
        ledger_store=store,
        path=response_path,
    )

    certified = variant == "certified"
    digest = calculate_digest(alert)

    # Measure ledger verification, append,
    # serialization and disk persistence.
    started = time.perf_counter_ns()

    ledger_result = store.append_committed_alert(
        alert=alert,
        committed_digest=digest,
        view=VIEW,
        sequence=sequence,
        committed_validators=VALIDATORS,
        commit_certificate=(
            certificate if certified else None
        ),
    )

    ledger_finished = time.perf_counter_ns()

    # Measure the response engine, including
    # reloading and verifying the stored ledger.
    response = engine.process_committed_alert(
        block_index=ledger_result["block_index"],
        expected_digest=digest,
        view=VIEW,
        sequence=sequence,
        require_certificate=certified,
    )

    response_finished = time.perf_counter_ns()

    if response["status"] != "RECORDED":
        raise RuntimeError(
            f"{variant}: response not recorded"
        )

    if response["severity"] != "HIGH":
        raise RuntimeError(
            f"{variant}: unexpected severity"
        )

    if len(response["actions"]) != 3:
        raise RuntimeError(
            f"{variant}: unexpected action count"
        )

    if store.verify()["valid"] is not True:
        raise RuntimeError(
            f"{variant}: invalid stored ledger"
        )

    ledger_ms = (
        ledger_finished - started
    ) / 1_000_000

    response_ms = (
        response_finished - ledger_finished
    ) / 1_000_000

    return {
        "ledger_ms": ledger_ms,
        "response_ms": response_ms,
        "total_ms": ledger_ms + response_ms,
    }


def mean(values):
    return statistics.mean(values)


def run_benchmark(trials, block_sizes, output):
    rng = random.Random(SEED)
    records = []

    print("=" * 65)
    print("PBFT CERTIFICATE PROCESSING OVERHEAD BENCHMARK")
    print("=" * 65)
    print(f"Trials per ledger size: {trials}")
    print(f"Existing alert blocks: {block_sizes}")
    print(f"Random seed: {SEED}")
    print("GCS network: Not required")
    print()

    # TemporaryDirectory keeps benchmark files
    # separate from the production simulation ledger.
    with tempfile.TemporaryDirectory(
        prefix="uav_certificate_benchmark_"
    ) as temporary_root:

        temporary_root = Path(temporary_root)

        for history_blocks in block_sizes:
            print(
                f"\nLEDGER HISTORY: "
                f"{history_blocks} existing alert blocks"
            )
            print("-" * 65)

            group_dir = (
                temporary_root
                / f"history_{history_blocks}"
            )
            group_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            snapshot = create_initial_snapshot(
                group_dir / "initial_snapshot.json",
                history_blocks,
            )

            for trial in range(1, trials + 1):
                # Same event, instance and signed votes
                # are used by both variants in a pair.
                alert = make_alert(100000 + trial)
                sequence = 900000 + trial

                certificate = make_certificate(
                    alert,
                    sequence,
                )

                # Measure certificate verification alone.
                # This is a diagnostic measurement:
                # it is NOT added to end-to-end overhead,
                # because certification is already included
                # in ledger and response timings.
                verify_start = time.perf_counter_ns()

                verification = verify_commit_certificate(
                    alert=alert,
                    certificate=certificate,
                    view=VIEW,
                    sequence=sequence,
                )

                standalone_verify_ms = (
                    time.perf_counter_ns() - verify_start
                ) / 1_000_000

                if verification["verified_votes"] != 4:
                    raise RuntimeError(
                        "Certificate verification failed"
                    )

                order = [
                    "uncertified",
                    "certified",
                ]

                rng.shuffle(order)

                trial_dir = (
                    group_dir / f"trial_{trial:03d}"
                )
                trial_dir.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                results = {}

                for variant in order:
                    results[variant] = run_variant(
                        variant=variant,
                        snapshot=snapshot,
                        work_dir=trial_dir,
                        alert=alert,
                        sequence=sequence,
                        certificate=certificate,
                    )

                baseline = results["uncertified"]
                certified = results["certified"]

                ledger_overhead = (
                    certified["ledger_ms"]
                    - baseline["ledger_ms"]
                )

                response_overhead = (
                    certified["response_ms"]
                    - baseline["response_ms"]
                )

                total_overhead = (
                    certified["total_ms"]
                    - baseline["total_ms"]
                )

                record = {
                    "timestamp_utc": datetime.now(
                        timezone.utc
                    ).isoformat(),
                    "ledger_history_blocks": history_blocks,
                    "trial": trial,
                    "execution_order": "->".join(order),

                    "uncertified_ledger_ms": round(
                        baseline["ledger_ms"], 6
                    ),
                    "certified_ledger_ms": round(
                        certified["ledger_ms"], 6
                    ),
                    "ledger_overhead_ms": round(
                        ledger_overhead, 6
                    ),

                    "uncertified_response_ms": round(
                        baseline["response_ms"], 6
                    ),
                    "certified_response_ms": round(
                        certified["response_ms"], 6
                    ),
                    "response_overhead_ms": round(
                        response_overhead, 6
                    ),

                    "uncertified_total_ms": round(
                        baseline["total_ms"], 6
                    ),
                    "certified_total_ms": round(
                        certified["total_ms"], 6
                    ),
                    "total_overhead_ms": round(
                        total_overhead, 6
                    ),

                    "standalone_certificate_verify_ms": round(
                        standalone_verify_ms, 6
                    ),
                    "certificate_votes": 4,
                    "status": "SUCCESS",
                }

                records.append(record)

                print(
                    f"Trial {trial:02d}: "
                    f"uncertified={baseline['total_ms']:.3f} ms | "
                    f"certified={certified['total_ms']:.3f} ms | "
                    f"delta={total_overhead:+.3f} ms"
                )

            group_records = [
                row for row in records
                if row["ledger_history_blocks"]
                == history_blocks
            ]

            print(
                "\nMean paired overhead: "
                f"{mean([r['total_overhead_ms'] for r in group_records]):+.4f} ms"
            )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Overwrite deliberately to keep each invocation
    # a distinct, non-duplicated experiment dataset.
    with output.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS,
        )
        writer.writeheader()
        writer.writerows(records)

    print("\n" + "=" * 65)
    print("BENCHMARK COMPLETED")
    print(f"Successful paired trials: {len(records)}")
    print(f"Results: {output}")
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--trials",
        type=int,
        default=20,
    )

    parser.add_argument(
        "--blocks",
        type=int,
        nargs="+",
        default=[0, 10, 50],
        help="Number of existing alert blocks",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    if args.trials < 1:
        parser.error("--trials must be positive")

    if any(value < 0 for value in args.blocks):
        parser.error("--blocks cannot be negative")

    if len(set(args.blocks)) != len(args.blocks):
        parser.error("--blocks values must be unique")

    run_benchmark(
        trials=args.trials,
        block_sizes=args.blocks,
        output=args.output,
    )


if __name__ == "__main__":
    main()
