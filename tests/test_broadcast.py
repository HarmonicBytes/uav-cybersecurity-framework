
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKCHAIN_DIR = ROOT / "src" / "blockchain"

sys.path.insert(0, str(BLOCKCHAIN_DIR))

from transport import PBFTTransport


async def main():
    transport = PBFTTransport("GCS_01")

    message = {
        "type": "SECURITY_ALERT",
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING_ALERT",
        "anomaly_score": 4.25,
    }

    print("GCS AUTHENTICATED BROADCAST TEST")
    print("=" * 45)

    results = await transport.broadcast(message)

    authenticated = 0

    for node_id, response in results.items():
        status = response.get("status")

        print(f"{node_id}: {status}")

        if status == "authenticated":
            authenticated += 1

    print("=" * 45)
    print(
        f"Authenticated destinations: "
        f"{authenticated}/{len(results)}"
    )

    assert authenticated == 3

    print("Broadcast test passed.")


if __name__ == "__main__":
    asyncio.run(main())
