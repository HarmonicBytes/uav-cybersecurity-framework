
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKCHAIN_DIR = ROOT / "src" / "blockchain"

sys.path.insert(0, str(BLOCKCHAIN_DIR))

from protocol import PBFTMessage, calculate_digest
from authentication import sign_message

VALIDATORS = {
    "GCS_01": 5001,
    "GCS_02": 5002,
    "GCS_03": 5003,
    "GCS_04": 5004,
}


async def send_pbft_message(
    port, sender, phase, digest, sequence
):
    message = PBFTMessage(
        phase=phase,
        view=0,
        sequence=sequence,
        digest=digest,
        sender=sender,
    ).to_dict()

    envelope = sign_message(sender, message)

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
    sequence = 1

    print("DISTRIBUTED PBFT NETWORK TEST")
    print("=" * 55)

    # Phase 1: Primary proposes the digest.
    for node_id, port in VALIDATORS.items():
        result = await send_pbft_message(
            port, "GCS_01", "PRE_PREPARE",
            digest, sequence
        )

        assert result["status"] == "pbft_processed"

        print(f"{node_id}: PRE-PREPARE accepted")

    # Phase 2: Three validators send PREPARE votes.
    for sender in list(VALIDATORS)[:3]:
        for node_id, port in VALIDATORS.items():
            result = await send_pbft_message(
                port, sender, "PREPARE",
                digest, sequence
            )

            assert result["status"] == "pbft_processed"

    print("\nPREPARE quorum reached on all replicas")

    # Phase 3: Three validators send COMMIT votes.
    for sender in list(VALIDATORS)[:3]:
        for node_id, port in VALIDATORS.items():
            result = await send_pbft_message(
                port, sender, "COMMIT",
                digest, sequence
            )

            assert result["status"] == "pbft_processed"

            if sender == "GCS_03":
                assert result["result"]["committed"] is True
                print(f"{node_id}: COMMITTED")

    print("\nAll four replicas reached the commit condition.")


if __name__ == "__main__":
    asyncio.run(main())
