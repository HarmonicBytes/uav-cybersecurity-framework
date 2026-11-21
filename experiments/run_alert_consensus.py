
import argparse
import asyncio
import json
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "blockchain"))
sys.path.insert(0, str(ROOT / "src" / "security"))

from authentication import sign_message
from protocol import PBFTMessage, calculate_digest
from ledger_store import SecurityLedgerStore
from response_engine import DefensiveResponseEngine

NODES = {
    "GCS_01": 5001,
    "GCS_02": 5002,
    "GCS_03": 5003,
    "GCS_04": 5004,
}

QUORUM = 3


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


async def run(event, timeout):
    if not isinstance(event, dict):
        raise ValueError("Alert must be a JSON object")

    for required in ("uav_id", "event_type", "anomaly_score"):
        if required not in event:
            raise ValueError(
                f"Missing alert field: {required}"
            )

    # A new consensus instance for each execution.
    sequence = time.time_ns() // 1000
    view = 0
    digest = calculate_digest(event)

    print("=" * 60)
    print("UAV SECURITY ALERT -> AUTHENTICATION -> PBFT")
    print("=" * 60)
    print(f"UAV: {event['uav_id']}")
    print(f"Threat: {event['event_type']}")
    print(f"Anomaly score: {event['anomaly_score']}")
    print(f"Event digest: {digest}")
    print(f"Sequence: {sequence}")

    start = time.perf_counter()

    # Phase 1: distribute an authenticated security alert.
    security_message = {
        "type": "SECURITY_ALERT",
        "sequence": sequence,
        "event": event,
        "digest": digest,
    }

    security_envelope = sign_message(
        "GCS_01",
        security_message,
    )

    print("\n[1] Sending authenticated security alert")

    results = await asyncio.gather(
        *[
            send(port, security_envelope)
            for port in NODES.values()
        ]
    )

    for node_id, response in zip(NODES, results):
        if (
            response.get("status") != "authenticated"
            or response.get("node_id") != node_id
        ):
            raise RuntimeError(
                f"{node_id} did not authenticate alert: "
                f"{response}"
            )

        print(f"{node_id}: authenticated")

    # Phase 2: submit the digest for PBFT consensus.
    proposal = PBFTMessage(
        phase="PRE_PREPARE",
        view=view,
        sequence=sequence,
        digest=digest,
        sender="GCS_01",
    ).to_dict()

    proposal_envelope = sign_message(
        "GCS_01",
        proposal,
    )

    print("\n[2] Starting autonomous PBFT consensus")

    results = await asyncio.gather(
        *[
            send(port, proposal_envelope)
            for port in NODES.values()
        ]
    )

    for node_id, response in zip(NODES, results):
        if response.get("status") != "pbft_processed":
            raise RuntimeError(
                f"{node_id} rejected the proposal: "
                f"{response}"
            )

        print(f"{node_id}: proposal accepted")

    # Phase 3: query independent GCS replica states.
    status_envelope = sign_message(
        "GCS_01",
        {
            "type": "PBFT_STATUS",
            "view": view,
            "sequence": sequence,
        },
    )

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    while True:
        results = await asyncio.gather(
            *[
                send(port, status_envelope)
                for port in NODES.values()
            ]
        )

        committed = 0
        timings = {}

        for node_id, response in zip(NODES, results):
            if (
                response.get("status") != "ok"
                or response.get("found") is not True
            ):
                raise RuntimeError(
                    f"Invalid status from {node_id}: "
                    f"{response}"
                )

            state = response["result"]

            if state["digest"] != digest:
                raise RuntimeError(
                    f"Digest mismatch at {node_id}"
                )

            if state["committed"]:
                if (
                    not state["prepared"]
                    or state["commit_votes"] < QUORUM
                ):
                    raise RuntimeError(
                        f"Invalid commit at {node_id}"
                    )

                committed += 1

                latency = state.get("consensus_latency_ms")
                if latency is not None:
                    timings[node_id] = latency

        if committed == len(NODES):
            observed_ms = (
                time.perf_counter() - start
            ) * 1000

            print("\n[3] Consensus completed")

        if committed == len(NODES):
            observed_ms = (
                time.perf_counter() - start
            ) * 1000

            # Step 4: Persist the security alert
            # after all four GCS nodes have committed.
            store = SecurityLedgerStore()

            ledger_result = store.append_committed_alert(
                alert=event,
                committed_digest=digest,
                view=view,
                sequence=sequence,
                committed_validators=list(NODES.keys()),
            )

            # Step 5: Evaluate simulated defensive actions
            # only after consensus and ledger persistence.
            response_engine = DefensiveResponseEngine(
                ledger_store=store
            )

            response_result = (
                response_engine.process_committed_alert(
                    block_index=ledger_result["block_index"],
                    expected_digest=digest,
                    view=view,
                    sequence=sequence,
                )
            )

            print("\n[5] Simulated defensive response")
            print(
                f"Status: {response_result['status']}"
            )
            print(
                f"Severity: {response_result['severity']}"
            )

            for action in response_result["actions"]:
                print(
                    f"Action: {action['action']} "
                    f"({action['mode']})"
                )

            print(
                "Response processing duration: "
                f"{response_result['response_latency_ms']:.4f} ms"
            )

            print("\n[4] Security alert persisted")
            print(
                f"Block index: {ledger_result['block_index']}"
            )
            print(
                f"Block hash: {ledger_result['block_hash']}"
            )
            print(
                f"Chain valid: {ledger_result['chain_valid']}"
            )

            print("\n[3] Consensus completed")

            for node_id in NODES:
                latency = timings.get(node_id)

                if latency is not None:
                    print(
                        f"{node_id}: COMMITTED | "
                        f"{latency:.4f} ms local consensus"
                    )
                else:
                    print(f"{node_id}: COMMITTED")

            print("\n" + "=" * 60)
            print("SUCCESS: SECURITY ALERT CONSENSUS")
            print(f"Committed replicas: {committed}/4")
            print(f"Committed digest: {digest}")
            print(
                "Client-observed workflow duration: "
                f"{observed_ms:.3f} ms"
            )
            print("=" * 60)
            return

        if loop.time() >= deadline:
            raise TimeoutError(
                f"PBFT consensus incomplete: "
                f"{committed}/4 committed"
            )

        await asyncio.sleep(0.02)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--event-json",
        required=True,
        help="Path to an AI-generated alert JSON file",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    with open(
        args.event_json,
        "r",
        encoding="utf-8",
    ) as file:
        event = json.load(file)

    asyncio.run(run(event, args.timeout))


if __name__ == "__main__":
    main()
