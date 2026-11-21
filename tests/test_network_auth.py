
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKCHAIN_DIR = ROOT / "src" / "blockchain"

sys.path.insert(0, str(BLOCKCHAIN_DIR))

from authentication import sign_message

async def send_to_node(port, envelope):
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port
    )

    try:
        writer.write(
            (json.dumps(envelope) + "\n").encode("utf-8")
        )
        await writer.drain()

        data = await asyncio.wait_for(
            reader.readline(), timeout=5.0
        )

        return json.loads(data.decode("utf-8"))

    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    message = {
        "type": "SECURITY_ALERT",
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING",
        "anomaly_score": 4.25,
    }

    valid_envelope = sign_message("GCS_01", message)

    print("NETWORK AUTHENTICATION TEST")
    print("=" * 45)

    for port in range(5001, 5005):
        valid_response = await send_to_node(
            port, valid_envelope
        )

        tampered_envelope = {
            "sender": valid_envelope["sender"],
            "message": dict(valid_envelope["message"]),
            "signature": valid_envelope["signature"],
        }

        # Change content without producing a new signature.
        tampered_envelope["message"]["anomaly_score"] = 0.01

        rejected_response = await send_to_node(
            port, tampered_envelope
        )

        print(
            f"Port {port}: "
            f"valid={valid_response['status']}, "
            f"tampered={rejected_response['status']}"
        )

        assert valid_response["status"] == "authenticated"
        assert rejected_response["status"] == "rejected"

    print("\nAll four GCS authentication checks passed.")


if __name__ == "__main__":
    asyncio.run(main())
