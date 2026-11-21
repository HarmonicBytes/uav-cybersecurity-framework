
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
}

OFFLINE_PORTS = [5003, 5004]
SEQUENCE = 500


async def send(port, envelope):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port),
        timeout=2.0,
    )

    try:
        writer.write(
            (json.dumps(envelope) + "\n").encode("utf-8")
        )
        await writer.drain()

        data = await asyncio.wait_for(
            reader.readline(),
            timeout=2.0,
        )

        if not data:
            raise ConnectionError("Empty response")

        return json.loads(data.decode("utf-8"))

    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    print("PBFT TWO-VALIDATOR FAILURE EXPERIMENT")
    print("=" * 55)

    for port in OFFLINE_PORTS:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port),
                timeout=1.0,
            )
        except (OSError, asyncio.TimeoutError):
            print(f"Port {port}: OFFLINE (expected)")
        else:
            writer.close()
            await writer.wait_closed()
            raise AssertionError(
                f"Port {port} must be offline"
            )

    event = {
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING_ALERT",
        "experiment": "two_validators_offline",
    }

    digest = calculate_digest(event)

    proposal = PBFTMessage(
        phase="PRE_PREPARE",
        view=0,
        sequence=SEQUENCE,
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
            "sequence": SEQUENCE,
        },
    )

    # Only the two active nodes receive the proposal.
    responses = await asyncio.gather(
        *[
            send(port, proposal_envelope)
            for port in NODES.values()
        ]
    )

    for response in responses:
        assert response["status"] == "pbft_processed"

    print("\nWaiting for vote exchange...\n")
    await asyncio.sleep(3.0)

    responses = await asyncio.gather(
        *[
            send(port, status_envelope)
            for port in NODES.values()
        ]
    )

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

        assert state["prepare_votes"] <= 2
        assert state["prepared"] is False
        assert state["committed"] is False

    print("\nSUCCESS: No quorum with two unavailable validators.")


if __name__ == "__main__":
    asyncio.run(main())
