
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

    proposal = PBFTMessage(
        phase="PRE_PREPARE",
        view=0,
        sequence=100,
        digest=digest,
        sender="GCS_01",
    ).to_dict()

    envelope = sign_message("GCS_01", proposal)

    print("AUTOMATIC LOCAL PREPARE TEST")
    print("=" * 50)

    for node_id, port in NODES.items():
        response = await send(port, envelope)

        assert response["status"] == "pbft_processed", response

        result = response["result"]

        assert result["accepted"] is True
        assert result["prepare_votes"] >= 1, result
        assert result["committed"] is False

        print(
            f"{node_id}: "
            f"local PREPARE votes={result['prepare_votes']}"
        )

    print("\nAll four replicas generated a local PREPARE.")


if __name__ == "__main__":
    asyncio.run(main())
