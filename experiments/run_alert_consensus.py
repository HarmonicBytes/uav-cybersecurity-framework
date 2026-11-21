
import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "blockchain"))
sys.path.insert(0, str(ROOT / "src" / "security"))

from block import Block
from commit_certificate import verify_commit_certificate
from response_engine import DefensiveResponseEngine
from ledger_store import SecurityLedgerStore
from protocol import PBFTMessage, calculate_digest
from authentication import sign_message

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


async def replicate_certified_alert(
    event,
    digest,
    view,
    sequence,
    certificate,
):
    """
    Extend the shared GCS ledger with one canonical
    block containing real PBFT COMMIT evidence.

    All four GCS nodes must already share the
    same nonempty, certified ledger history.
    """

    print("\n[4A] Checking distributed GCS ledger state")

    status_envelope = sign_message(
        "GCS_01",
        {"type": "LEDGER_STATUS"},
    )

    responses = await asyncio.gather(
        *[
            send(port, status_envelope)
            for port in NODES.values()
        ]
    )

    states = []

    for node_id, response in zip(NODES, responses):
        if (
            response.get("status") != "ok"
            or response.get("node_id") != node_id
        ):
            raise RuntimeError(
                f"{node_id}: invalid ledger status: {response}"
            )

        state = response["result"]

        if (
            state.get("valid") is not True
            or type(state.get("blocks")) is not int
            or state["blocks"] < 1
            or state.get("latest_index") != state["blocks"] - 1
            or not isinstance(state.get("latest_hash"), str)
        ):
            raise RuntimeError(
                f"{node_id}: invalid ledger state: {state}"
            )

        states.append(state)

        print(
            f"{node_id}: blocks={state['blocks']} "
            f"hash={state['latest_hash'][:16]}..."
        )

    # Reject inconsistent histories rather than
    # attempting to overwrite or silently repair them.
    histories = {
        (state["blocks"], state["latest_hash"])
        for state in states
    }

    if len(histories) != 1:
        raise RuntimeError(
            "GCS ledgers are not synchronized. "
            "Replication aborted."
        )

    current = states[0]

    # Construct one canonical block extending
    # the existing shared GCS history.
    record = {
        "type": "COMMITTED_SECURITY_ALERT",
        "alert": event,
        "alert_digest": digest,
        "consensus": {
            "protocol": "PBFT_PROTOTYPE",
            "view": view,
            "sequence": sequence,
            "committed_validators": list(NODES.keys()),
            "commitment_source": (
                "integration_client_observation"
            ),
            "commit_certificate": certificate,
            "certificate_verified": True,
        },
    }

    block = Block(
        index=current["blocks"],
        timestamp=time.time(),
        previous_hash=current["latest_hash"],
        event=record,
    )

    block.seal()

    canonical_block = {
        "index": block.index,
        "timestamp": block.timestamp,
        "previous_hash": block.previous_hash,
        "event": block.event,
        "validator_signatures": [],
        "block_hash": block.block_hash,
    }

    print(
        f"\n[4B] Replicating certified block {block.index}"
    )
    print(f"Canonical hash: {block.block_hash}")

    append_envelope = sign_message(
        "GCS_01",
        {
            "type": "LEDGER_APPEND",
            "block": canonical_block,
        },
    )

    responses = await asyncio.gather(
        *[
            send(port, append_envelope)
            for port in NODES.values()
        ]
    )

    for node_id, response in zip(NODES, responses):
        if (
            response.get("status") != "ledger_processed"
            or response.get("node_id") != node_id
        ):
            raise RuntimeError(
                f"{node_id}: replication failed: {response}"
            )

        result = response["result"]

        if (
            result.get("block_index") != block.index
            or result.get("block_hash") != block.block_hash
            or result.get("status")
            not in ("appended", "already_present")
        ):
            raise RuntimeError(
                f"{node_id}: block acknowledgment mismatch"
            )

        print(
            f"{node_id}: {result['status']} "
            f"block={result['block_index']}"
        )

    # Independently query the persisted states
    # after all four acknowledgments.
    responses = await asyncio.gather(
        *[
            send(port, status_envelope)
            for port in NODES.values()
        ]
    )

    for node_id, response in zip(NODES, responses):
        if (
            response.get("status") != "ok"
            or response.get("node_id") != node_id
        ):
            raise RuntimeError(
                f"{node_id}: final status failed"
            )

        state = response["result"]

        if (
            state.get("valid") is not True
            or state.get("blocks") != block.index + 1
            or state.get("latest_index") != block.index
            or state.get("latest_hash") != block.block_hash
        ):
            raise RuntimeError(
                f"{node_id}: replicated ledger mismatch"
            )

    print("\nSUCCESS: FOUR MATCHING CERTIFIED GCS LEDGERS")

    return {
        "replicated_validators": len(NODES),
        "replicated_block_index": block.index,
        "replicated_block_hash": block.block_hash,
    }


async def run(event, timeout):
    if not isinstance(event, dict):
        raise ValueError("Alert must be a JSON object")

    for required in (
        "uav_id",
        "event_type",
        "anomaly_score",
    ):
        if required not in event:
            raise ValueError(
                f"Missing alert field: {required}"
            )

    if timeout <= 0:
        raise ValueError(
            "Timeout must be greater than zero"
        )

    # Create a new consensus instance.
    sequence = time.time_ns() // 1000
    view = 0
    digest = calculate_digest(event)

    print("=" * 60)
    print(
        "UAV SECURITY ALERT -> "
        "AUTHENTICATION -> PBFT"
    )
    print("=" * 60)
    print(f"UAV: {event['uav_id']}")
    print(f"Threat: {event['event_type']}")
    print(f"Anomaly score: {event['anomaly_score']}")
    print(f"Event digest: {digest}")
    print(f"Sequence: {sequence}")

    # Begin client-observed workflow measurement.
    start = time.perf_counter()

    # ===================================================
    # PHASE 1: AUTHENTICATED SECURITY ALERT
    # ===================================================

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

    print(
        "\n[1] Sending authenticated security alert"
    )

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

    # Authentication phase ends here.
    authentication_finished = time.perf_counter()

    # ===================================================
    # PHASE 2: AUTONOMOUS PBFT CONSENSUS
    # ===================================================

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

    print(
        "\n[2] Starting autonomous PBFT consensus"
    )

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

    # ===================================================
    # PHASE 3: VERIFY REPLICA COMMITMENT
    # ===================================================

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

                latency = state.get(
                    "consensus_latency_ms"
                )

                if latency is not None:
                    timings[node_id] = latency

        # ===================================================
        # ALL FOUR VALIDATORS HAVE COMMITTED
        # ===================================================

        if committed == len(NODES):
            consensus_finished = time.perf_counter()

            observed_ms = (
                consensus_finished - start
            ) * 1000

            print("\n[3] Consensus completed")

            # Collect signed COMMIT envelopes actually
            # generated by the four running validators.
            certificate = []

            for node_id, response in zip(NODES, results):
                envelope = response.get(
                    "local_commit_envelope"
                )

                if envelope is None:
                    raise RuntimeError(
                        f"{node_id} has no signed COMMIT evidence"
                    )

                if envelope.get("sender") != node_id:
                    raise RuntimeError(
                        f"Invalid COMMIT sender from {node_id}"
                    )

                certificate.append(envelope)

            # Independently verify the real
            # validator-generated commit certificate.
            verified_certificate = (
                verify_commit_certificate(
                    alert=event,
                    certificate=certificate,
                    view=view,
                    sequence=sequence,
                )
            )

            print("\n[3A] COMMIT certificate verified")
            print(
                f"Verified votes: "
                f"{verified_certificate['verified_votes']}"
            )
            print(
                f"Required quorum: "
                f"{verified_certificate['quorum']}"
            )
            print(
                f"Validators: "
                f"{verified_certificate['validators']}"
            )

            for node_id in NODES:
                latency = timings.get(node_id)

                if latency is not None:
                    print(
                        f"{node_id}: COMMITTED | "
                        f"{latency:.4f} ms local consensus"
                    )
                else:
                    print(
                        f"{node_id}: COMMITTED"
                    )

            # ===================================================
            # PHASE 4: PERSIST COMMITTED SECURITY ALERT
            # ===================================================

            store = SecurityLedgerStore()

            ledger_result = store.append_committed_alert(
                alert=event,
                committed_digest=digest,
                view=view,
                sequence=sequence,
                committed_validators=list(NODES.keys()),
                commit_certificate=certificate,
            )

            ledger_finished = time.perf_counter()

            print("\n[4] Security alert persisted")
            print(
                f"Block index: "
                f"{ledger_result['block_index']}"
            )
            print(
                f"Block hash: "
                f"{ledger_result['block_hash']}"
            )
            print(
                f"Chain valid: "
                f"{ledger_result['chain_valid']}"
            )

            # ===================================================
            # PHASE 4A: DISTRIBUTED CERTIFIED REPLICATION
            # ===================================================

            replication_started = time.perf_counter()

            replication_result = await replicate_certified_alert(
                event=event,
                digest=digest,
                view=view,
                sequence=sequence,
                certificate=certificate,
            )

            replication_finished = time.perf_counter()

            replication_ms = (
                replication_finished - replication_started
            ) * 1000

            print(
                "Distributed replication duration: "
                f"{replication_ms:.4f} ms"
            )

            # Measure defensive response separately,
            # excluding distributed replication.
            response_started = time.perf_counter()

            # ===================================================
            # PHASE 5: SIMULATED DEFENSIVE RESPONSE
            # ===================================================

            response_engine = DefensiveResponseEngine(
                ledger_store=store
            )

            response_result = (
                response_engine.process_committed_alert(
                    block_index=ledger_result["block_index"],
                    expected_digest=digest,
                    view=view,
                    sequence=sequence,
                    require_certificate=True,
                )
            )

            response_finished = time.perf_counter()

            print(
                "\n[5] Simulated defensive response"
            )
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

            # ===================================================
            # WORKFLOW TIMING SUMMARY
            # ===================================================

            authentication_ms = (
                authentication_finished - start
            ) * 1000

            consensus_stage_ms = (
                consensus_finished
                - authentication_finished
            ) * 1000

            ledger_ms = (
                ledger_finished
                - consensus_finished
            ) * 1000

            response_ms = (
                response_finished
                - response_started
            ) * 1000

            alert_to_response_ms = (
                response_finished - start
            ) * 1000

            print("\n[6] Workflow timing breakdown")
            print(
                f"Authentication: "
                f"{authentication_ms:.4f} ms"
            )
            print(
                f"PBFT consensus stage: "
                f"{consensus_stage_ms:.4f} ms"
            )
            print(
                f"Ledger persistence: "
                f"{ledger_ms:.4f} ms"
            )
            print(
                f"Distributed replication: "
                f"{replication_ms:.4f} ms"
            )
            print(
                f"Response processing: "
                f"{response_ms:.4f} ms"
            )
            print(
                f"Alert-to-response: "
                f"{alert_to_response_ms:.4f} ms"
            )

            print("\n" + "=" * 60)
            print(
                "SUCCESS: SECURITY ALERT CONSENSUS"
            )
            print(
                f"Committed replicas: {committed}/4"
            )
            print(
                f"Committed digest: {digest}"
            )
            print(
                "Client-observed alert-to-consensus "
                f"duration: {observed_ms:.3f} ms"
            )
            print("=" * 60)

            # Return measurements to the benchmark.
            return {
                "status": "SUCCESS",
                "sequence": sequence,
                "alert_digest": digest,
                "committed_validators": committed,
                "block_index": (
                    ledger_result["block_index"]
                ),
                "block_hash": (
                    ledger_result["block_hash"]
                ),
                "response_status": (
                    response_result["status"]
                ),
                "response_severity": (
                    response_result["severity"]
                ),
                "response_actions": len(
                    response_result["actions"]
                ),

                "authentication_ms": round(
                    authentication_ms, 6
                ),
                "consensus_stage_ms": round(
                    consensus_stage_ms, 6
                ),
                "ledger_ms": round(
                    ledger_ms, 6
                ),
                "response_ms": round(
                    response_ms, 6
                ),
                "alert_to_response_ms": round(
                    alert_to_response_ms, 6
                ),

                "replication_ms": round(
                    replication_ms, 6
                ),
                "replicated_validators": (
                    replication_result["replicated_validators"]
                ),
                "replicated_block_index": (
                    replication_result["replicated_block_index"]
                ),
                "replicated_block_hash": (
                    replication_result["replicated_block_hash"]
                ),
                "replica_consensus_ms": timings,
            }

        if loop.time() >= deadline:
            raise TimeoutError(
                "PBFT consensus incomplete: "
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
        parser.error(
            "--timeout must be positive"
        )

    with open(
        args.event_json,
        "r",
        encoding="utf-8",
    ) as file:
        event = json.load(file)

    asyncio.run(
        run(event, args.timeout)
    )


if __name__ == "__main__":
    main()
