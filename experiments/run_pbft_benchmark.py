
import argparse
import asyncio
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "blockchain"))

from authentication import sign_message
from protocol import PBFTMessage, calculate_digest


ALL_NODES = {
    "GCS_01": 5001,
    "GCS_02": 5002,
    "GCS_03": 5003,
    "GCS_04": 5004,
}

SCENARIOS = {
    "4online": ["GCS_01", "GCS_02", "GCS_03", "GCS_04"],
    "3online": ["GCS_01", "GCS_02", "GCS_03"],
    "2online": ["GCS_01", "GCS_02"],
}

QUORUM = 3

FIELDS = [
    "timestamp_utc",
    "scenario",
    "trial",
    "sequence",
    "active_validators",
    "quorum",
    "committed_validators",
    "consensus_success",
    "expected_outcome_met",
    "observed_duration_ms",
    "result",
    "GCS_01_consensus_ms",
    "GCS_02_consensus_ms",
    "GCS_03_consensus_ms",
    "GCS_04_consensus_ms",
    "mean_replica_consensus_ms",
    "max_replica_consensus_ms",
]


async def send(port, envelope):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port),
        timeout=3.0,
    )

    try:
        writer.write(
            (json.dumps(envelope) + "\n").encode("utf-8")
        )
        await writer.drain()

        data = await asyncio.wait_for(
            reader.readline(),
            timeout=3.0,
        )

        if not data:
            raise ConnectionError("Empty response")

        return json.loads(data.decode("utf-8"))

    finally:
        writer.close()
        await writer.wait_closed()


async def verify_topology(active_ids):
    for node_id, port in ALL_NODES.items():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port),
                timeout=1.0,
            )
        except (OSError, asyncio.TimeoutError):
            online = False
        else:
            online = True
            writer.close()
            await writer.wait_closed()

        expected = node_id in active_ids

        print(
            f"{node_id}: "
            f"{'ONLINE' if online else 'OFFLINE'}"
        )

        if online != expected:
            raise RuntimeError(
                f"Incorrect topology for {node_id}. "
                f"Expected {'ONLINE' if expected else 'OFFLINE'}."
            )


async def run_trial(
    scenario,
    trial,
    sequence,
    timeout,
    poll_interval,
):
    active_ids = SCENARIOS[scenario]
    active_ports = [ALL_NODES[n] for n in active_ids]

    event = {
        "uav_id": "UAV_BENCHMARK",
        "event_type": "GPS_SPOOFING_ALERT",
        "scenario": scenario,
        "trial": trial,
        "sequence": sequence,
    }

    digest = calculate_digest(event)

    proposal = PBFTMessage(
        phase="PRE_PREPARE",
        view=0,
        sequence=sequence,
        digest=digest,
        sender="GCS_01",
    ).to_dict()

    proposal_envelope = sign_message(
        "GCS_01", proposal
    )

    status_envelope = sign_message(
        "GCS_01",
        {
            "type": "PBFT_STATUS",
            "view": 0,
            "sequence": sequence,
        },
    )

    start = time.perf_counter()
    committed_count = 0
    outcome = "TIMEOUT"

    replica_timings = {
        node_id: None
        for node_id in ALL_NODES
    }

    try:
        proposal_results = await asyncio.gather(
            *[
                send(port, proposal_envelope)
                for port in active_ports
            ]
        )

        for response in proposal_results:
            if response.get("status") != "pbft_processed":
                raise RuntimeError(
                    f"Proposal rejected: {response}"
                )

        deadline = start + timeout

        while True:
            responses = await asyncio.gather(
                *[
                    send(port, status_envelope)
                    for port in active_ports
                ]
            )

            committed_count = 0
            prepared_count = 0

            for node_id, response in zip(
                active_ids, responses
            ):
                if (
                    response.get("status") != "ok"
                    or response.get("found") is not True
                ):
                    raise RuntimeError(
                        f"Invalid PBFT status: {response}"
                    )

                state = response["result"]

                if state["digest"] != digest:
                    raise RuntimeError("Digest mismatch")

                if state["prepared"]:
                    prepared_count += 1

                if state["committed"]:
                    if (
                        not state["prepared"]
                        or state["commit_votes"] < QUORUM
                    ):
                        raise RuntimeError(
                            "Invalid committed state"
                        )

                    committed_count += 1
                    latency = state.get(
                        "consensus_latency_ms"
                    )

                    if latency is None or latency < 0:
                        raise RuntimeError(
                            f"Invalid consensus timing: {node_id}"
                        )

                    replica_timings[node_id] = latency

            if committed_count == len(active_ids):
                outcome = "COMMITTED"
                break

            if time.perf_counter() >= deadline:
                if len(active_ids) < QUORUM:
                    if prepared_count or committed_count:
                        outcome = "UNEXPECTED_QUORUM"
                    else:
                        outcome = "NO_QUORUM"
                break

            await asyncio.sleep(poll_interval)

    except Exception as error:
        outcome = f"ERROR: {type(error).__name__}: {error}"

    elapsed_ms = (
        time.perf_counter() - start
    ) * 1000

    consensus_success = outcome == "COMMITTED"

    expected_success = len(active_ids) >= QUORUM

    expected_outcome_met = (
        consensus_success
        if expected_success
        else outcome == "NO_QUORUM"
    )

    measured = [
        value
        for value in replica_timings.values()
        if value is not None
    ]

    timing_columns = {
        f"{node_id}_consensus_ms": latency
        for node_id, latency in replica_timings.items()
    }

    timing_columns["mean_replica_consensus_ms"] = (
        round(sum(measured) / len(measured), 6)
        if measured else None
    )

    timing_columns["max_replica_consensus_ms"] = (
        max(measured) if measured else None
    )

    return {
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "scenario": scenario,
        "trial": trial,
        "sequence": sequence,
        "active_validators": len(active_ids),
        "quorum": QUORUM,
        "committed_validators": committed_count,
        "consensus_success": consensus_success,
        "expected_outcome_met": expected_outcome_met,
        "observed_duration_ms": round(elapsed_ms, 3),
        "result": outcome,
        **timing_columns,
    }


async def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--scenario",
        choices=SCENARIOS,
        required=True,
    )

    parser.add_argument(
        "--trials",
        type=int,
        default=20,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
    )

    parser.add_argument(
        "--poll-ms",
        type=float,
        default=10.0,
    )

    parser.add_argument(
        "--output",
        default=str(
            ROOT / "results" / "pbft_benchmark.csv"
        ),
    )

    args = parser.parse_args()

    if args.trials < 1:
        parser.error("--trials must be at least 1")

    if args.timeout <= 0 or args.poll_ms <= 0:
        parser.error(
            "--timeout and --poll-ms must be positive"
        )

    active_ids = SCENARIOS[args.scenario]

    print("=" * 60)
    print("PBFT REPRODUCIBLE BENCHMARK")
    print(f"Scenario: {args.scenario}")
    print(f"Trials: {args.trials}")
    print("=" * 60)

    await verify_topology(active_ids)

    output = Path(args.output)
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    write_header = (
        not output.exists()
        or output.stat().st_size == 0
    )

    # Millisecond epoch-based sequence block.
    # Keep each trial's request distinct.
    sequence_base = int(time.time_ns() // 1000)

    rows = []

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
            sequence = sequence_base + trial

            result = await run_trial(
                scenario=args.scenario,
                trial=trial,
                sequence=sequence,
                timeout=args.timeout,
                poll_interval=args.poll_ms / 1000,
            )

            writer.writerow(result)
            file.flush()
            rows.append(result)

            print(
                f"Trial {trial:02d}: "
                f"{result['result']} | "
                f"{result['observed_duration_ms']:.3f} ms | "
                f"committed="
                f"{result['committed_validators']}/"
                f"{len(active_ids)}"
            )

    successful = sum(
        row["consensus_success"]
        for row in rows
    )

    expected_met = sum(
        row["expected_outcome_met"]
        for row in rows
    )

    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print(f"Trials: {len(rows)}")
    print(
        f"Consensus success rate: "
        f"{successful / len(rows) * 100:.1f}%"
    )
    print(
        f"Expected outcome rate: "
        f"{expected_met / len(rows) * 100:.1f}%"
    )
    print(f"CSV: {output}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
