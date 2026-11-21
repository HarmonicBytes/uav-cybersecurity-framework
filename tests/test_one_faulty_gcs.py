
import asyncio
import json
import sys
import time
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

ACTIVE_NODES = {
    node_id: port
    for node_id, port in ALL_NODES.items()
    if node_id != "GCS_04"
}

OFFLINE_PORT = 5004
SEQUENCE = 400
VIEW = 0
QUORUM = 3


async def send(port, envelope, timeout=2.0):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port),
        timeout=timeout,
    )

    try:
        writer.write(
            (json.dumps(envelope) + "\n").encode("utf-8")
        )
        await writer.drain()

        data = await asyncio.wait_for(
            reader.readline(),
            timeout=timeout,
        )

        if not data:
            raise ConnectionError("Empty response")

        return json.loads(data.decode("utf-8"))

    finally:
        writer.close()
        await writer.wait_closed()


async def verify_offline_node():
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1", OFFLINE_PORT
            ),
            timeout=1.0,
        )

    except (OSError, asyncio.TimeoutError):
        print("GCS_04: OFFLINE (expected)")
        return

    else:
        writer.close()
        await writer.wait_closed()

        raise AssertionError(
            "GCS_04 is still online. "
            "Stop it before running this experiment."
        )


async def main():
    print("=" * 60)
    print("PBFT FAULT TOLERANCE EXPERIMENT")
    print("Scenario: One validator unavailable (GCS_04)")
    print("=" * 60)

    await verify_offline_node()

    event = {
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING_ALERT",
        "anomaly_score": 4.25,
        "experiment": "one_validator_offline",
    }

    digest = calculate_digest(event)

    proposal = PBFTMessage(
        phase="PRE_PREPARE",
        view=VIEW,
        sequence=SEQUENCE,
        digest=digest,
        sender="GCS_01",
    ).to_dict()

    proposal_envelope = sign_message(
        "GCS_01",
        proposal,
    )

    status_envelope = sign_message(
        "GCS_01",
        {
            "type": "PBFT_STATUS",
            "view": VIEW,
            "sequence": SEQUENCE,
        },
    )

    print("\nSubmitting primary proposal...")

    start = time.perf_counter()

    responses = await asyncio.gather(
        *[
            send(port, proposal_envelope)
            for port in ACTIVE_NODES.values()
        ]
    )

    for node_id, response in zip(
        ACTIVE_NODES, responses
    ):
        assert (
            response["status"] == "pbft_processed"
        ), response

        print(f"{node_id}: PRE-PREPARE accepted")

    print("\nWaiting for consensus...\n")

    deadline = time.perf_counter() + 15.0

    while True:
        responses = await asyncio.gather(
            *[
                send(port, status_envelope)
                for port in ACTIVE_NODES.values()
            ]
        )

        committed_nodes = 0

        for node_id, response in zip(
            ACTIVE_NODES, responses
        ):
            assert response["status"] == "ok", response
            assert response["found"] is True, response

            state = response["result"]

            print(
                f"{node_id}: "
                f"PREPARE={state['prepare_votes']} "
                f"COMMIT={state['commit_votes']} "
                f"prepared={state['prepared']} "
                f"committed={state['committed']}"
            )

            if state["committed"]:
                assert state["prepared"] is True
                assert state["digest"] == digest
                assert state["prepare_votes"] >= QUORUM
                assert state["commit_votes"] >= QUORUM
                committed_nodes += 1

        if committed_nodes == len(ACTIVE_NODES):
            elapsed_ms = (
                time.perf_counter() - start
            ) * 1000

            print("\n" + "=" * 60)
            print("SUCCESS: CONSENSUS WITH ONE OFFLINE GCS")
            print("=" * 60)

            print(
                f"Committed replicas: "
                f"{committed_nodes}/{len(ACTIVE_NODES)}"
            )

            print("Offline replicas: 1")
            print(f"Required quorum: {QUORUM}/4")

            print(
                f"Observed completion upper bound: "
                f"{elapsed_ms:.3f} ms"
            )
            return

        if time.perf_counter() >= deadline:
            raise AssertionError(
                "Consensus incomplete: "
                f"{committed_nodes}/3 replicas committed"
            )

        print("Checking again...\n")
        await asyncio.sleep(0.1)


if __name__ == "__main__":
    asyncio.run(main())
