
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "blockchain"))

from authentication import sign_message
from protocol import PBFTMessage, calculate_digest


NODES = {
    "GCS_01": 5001,
    "GCS_02": 5002,
    "GCS_03": 5003,
    "GCS_04": 5004,
}


async def send(port, envelope):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port),
        timeout=5.0,
    )

    try:
        writer.write(
            (json.dumps(envelope) + "\n").encode("utf-8")
        )
        await writer.drain()

        data = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0,
        )

        if not data:
            raise ConnectionError("Empty response")

        return json.loads(data.decode("utf-8"))

    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    event = {
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING_ALERT",
        "anomaly_score": 4.25,
    }

    digest = calculate_digest(event)
    sequence = 300
    view = 0

    proposal = PBFTMessage(
        phase="PRE_PREPARE",
        view=view,
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
            "view": view,
            "sequence": sequence,
        },
    )

    print("AUTONOMOUS PBFT COMMIT QUORUM TEST")
    print("=" * 55)

    # Submit only the initial PRE-PREPARE proposal.
    responses = await asyncio.gather(
        *[
            send(port, proposal_envelope)
            for port in NODES.values()
        ]
    )

    for node_id, response in zip(NODES, responses):
        assert response["status"] == "pbft_processed", response
        print(f"{node_id}: PRE-PREPARE accepted")

    print("\nWaiting for autonomous consensus...\n")

    loop = asyncio.get_running_loop()
    start = loop.time()
    deadline = start + 10.0

    while True:
        responses = await asyncio.gather(
            *[
                send(port, status_envelope)
                for port in NODES.values()
            ]
        )

        committed_count = 0

        for node_id, response in zip(NODES, responses):
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
                assert state["commit_votes"] >= 3
                committed_count += 1

        if committed_count == len(NODES):
            elapsed_ms = (
                loop.time() - start
            ) * 1000

            print("\n" + "=" * 55)
            print("SUCCESS: ALL FOUR REPLICAS COMMITTED")
            print(
                f"Observed completion upper bound: "
                f"{elapsed_ms:.3f} ms"
            )
            return

        if loop.time() >= deadline:
            raise AssertionError(
                f"Consensus incomplete: "
                f"{committed_count}/4 replicas committed"
            )

        print("Checking again...\n")
        await asyncio.sleep(0.1)


if __name__ == "__main__":
    asyncio.run(main())
