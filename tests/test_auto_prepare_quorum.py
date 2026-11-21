
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
            reader.readline(), timeout=5.0
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
    sequence = 200

    proposal = PBFTMessage(
        phase="PRE_PREPARE",
        view=0,
        sequence=sequence,
        digest=digest,
        sender="GCS_01",
    ).to_dict()

    envelope = sign_message("GCS_01", proposal)

    print("AUTONOMOUS PREPARE QUORUM TEST")
    print("=" * 55)

    # Initiate a proposal on all four replicas.
    results = await asyncio.gather(
        *[
            send(port, envelope)
            for port in NODES.values()
        ]
    )

    for node_id, result in zip(NODES, results):
        assert result["status"] == "pbft_processed", result
        print(f"{node_id}: Proposal accepted")

    print("\nWaiting for validator-generated PREPARE votes...")

    # Repeat the same proposal to inspect existing state.
    # This does not inject additional PREPARE votes.
    deadline = asyncio.get_running_loop().time() + 5.0

    while True:
        responses = await asyncio.gather(
            *[
                send(port, envelope)
                for port in NODES.values()
            ]
        )

        prepared_count = 0

        for node_id, response in zip(NODES, responses):
            assert response["status"] == "pbft_processed", response

            state = response["result"]

            print(
                f"{node_id}: "
                f"PREPARE={state['prepare_votes']} "
                f"prepared={state['prepared']}"
            )

            if state["prepared"]:
                prepared_count += 1

        if prepared_count == 4:
            print("\nSUCCESS: All four replicas are prepared.")
            return

        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError(
                f"Only {prepared_count}/4 replicas prepared"
            )

        print("Checking again...\n")
        await asyncio.sleep(0.2)


if __name__ == "__main__":
    asyncio.run(main())
