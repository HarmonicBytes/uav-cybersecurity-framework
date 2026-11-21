
import asyncio
import json
import time
from authentication import sign_message

GCS_NODES = {
    "GCS_01": 5001,
    "GCS_02": 5002,
    "GCS_03": 5003,
    "GCS_04": 5004,
}


async def send_message(node_id, port, message):
    """
    Send a JSON security event to an independent
    Ground Control Station process over TCP.
    """

    start = time.perf_counter()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port),
            timeout=5.0,
        )

        writer.write(
            (json.dumps(message) + "\n").encode("utf-8")
        )
        await writer.drain()

        response_data = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0,
        )

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        if not response_data:
            raise ConnectionError("Empty response")

        response = json.loads(
            response_data.decode("utf-8")
        )

        print(
            f"{node_id}: "
            f"{response['status']} | "
            f"Latency: {latency_ms:.3f} ms"
        )

        return {
            "node": node_id,
            "success": response.get("status") == "authenticated",
            "latency_ms": latency_ms,
            "response": response,
        }

    except (
        OSError,
        asyncio.TimeoutError,
        json.JSONDecodeError,
        KeyError,
    ) as error:

        print(f"{node_id}: FAILED - {error}")

        return {
            "node": node_id,
            "success": False,
            "error": str(error),
        }

    finally:
        if "writer" in locals():
            writer.close()
            await writer.wait_closed()


async def main():

    message = {
        "type": "SECURITY_ALERT",
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING",
        "anomaly_score": 4.25,
        "source": "EDGE_AI",
    }

    signed_message = sign_message("GCS_01", message)

    print("=" * 55)
    print("UAV SECURITY - GCS NETWORK COMMUNICATION TEST")
    print("=" * 55)

    tasks = [
        send_message(node_id, port, signed_message)
        for node_id, port in GCS_NODES.items()
    ]

    results = await asyncio.gather(*tasks)

    successes = sum(
        result["success"] for result in results
    )

    print("\n" + "=" * 55)
    print(f"Nodes responding: {successes}/{len(GCS_NODES)}")

    valid_latencies = [
        result["latency_ms"]
        for result in results
        if result["success"]
    ]

    if valid_latencies:
        average_latency = (
            sum(valid_latencies) / len(valid_latencies)
        )

        print(
            f"Average round-trip latency: "
            f"{average_latency:.3f} ms"
        )


if __name__ == "__main__":
    asyncio.run(main())
