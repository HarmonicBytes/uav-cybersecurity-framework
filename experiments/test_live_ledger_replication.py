
import asyncio
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0, str(ROOT / "src" / "blockchain")
)

from authentication import sign_message
from ledger_genesis import (
    TRUSTED_GENESIS_HASH,
    create_genesis_block,
)
from block import Blockchain
from ledger_store import SecurityLedgerStore
from protocol import PBFTMessage, calculate_digest


NODES = {
    "GCS_01": 5001,
    "GCS_02": 5002,
    "GCS_03": 5003,
    "GCS_04": 5004,
}


async def send(port, message):
    envelope = sign_message("GCS_01", message)

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
            raise RuntimeError("Empty GCS response")

        return json.loads(data.decode("utf-8"))

    finally:
        writer.close()
        await writer.wait_closed()


async def broadcast(message):
    responses = await asyncio.gather(
        *[
            send(port, message)
            for port in NODES.values()
        ]
    )

    return dict(zip(NODES, responses))


def create_canonical_blocks(path):
    """
    Construct a separate experimental chain.
    This does not touch the real research ledger.

    The COMMIT signatures below are synthetic
    test evidence, not votes from a live PBFT run.
    """

    store = SecurityLedgerStore(path=path)

    genesis = create_genesis_block()

    blockchain = Blockchain()
    assert blockchain.add_block(genesis)

    store._save(blockchain)

    alert = {
        "uav_id": "UAV_REPLICATION_TEST",
        "event_type": "UAV_TELEMETRY_ANOMALY",
        "anomaly_score": 42.5,
        "threshold": 1.5,
        "detection_result": "ANOMALY",
    }

    digest = calculate_digest(alert)

    import time
    sequence = time.time_ns() // 1000

    certificate = []

    for node_id in NODES:
        vote = PBFTMessage(
            phase="COMMIT",
            view=0,
            sequence=sequence,
            digest=digest,
            sender=node_id,
        ).to_dict()

        certificate.append(
            sign_message(node_id, vote)
        )

    store.append_committed_alert(
        alert=alert,
        committed_digest=digest,
        view=0,
        sequence=sequence,
        committed_validators=list(NODES),
        commit_certificate=certificate,
    )

    return json.loads(
        path.read_text(encoding="utf-8")
    )


async def main():
    print("=" * 60)
    print("LIVE GCS CERTIFIED LEDGER REPLICATION TEST")
    print("=" * 60)

    # Fresh replica stores are required for this
    # initial experiment so all GCS nodes start
    # with zero stored blocks.
    statuses = await broadcast({
        "type": "LEDGER_STATUS",
    })

    for node_id, response in statuses.items():
        assert response["status"] == "ok", response

        result = response["result"]

        print(
            f"{node_id}: "
            f"existing blocks={result['blocks']}"
        )

        if result["blocks"] != 0:
            raise RuntimeError(
                f"{node_id} already has a replica ledger. "
                "Use a fresh experimental ledger directory "
                "for a new first-run test."
            )

    with tempfile.TemporaryDirectory() as temp:
        canonical_path = (
            Path(temp) / "canonical.json"
        )

        blocks = create_canonical_blocks(
            canonical_path
        )

        assert len(blocks) == 2
        assert (
            blocks[0]["block_hash"]
            == TRUSTED_GENESIS_HASH
        )

        for block in blocks:
            print(
                f"\nDistributing canonical block "
                f"{block['index']}"
            )

            responses = await broadcast({
                "type": "LEDGER_APPEND",
                "block": block,
            })

            for node_id, response in responses.items():
                if response.get("status") != "ledger_processed":
                    raise RuntimeError(
                        f"{node_id}: {response}"
                    )

                result = response["result"]

                assert (
                    result["block_hash"]
                    == block["block_hash"]
                )

                print(
                    f"{node_id}: "
                    f"{result['status']}"
                )

        statuses = await broadcast({
            "type": "LEDGER_STATUS",
        })

        hashes = set()

        for node_id, response in statuses.items():
            assert response["status"] == "ok", response

            state = response["result"]

            assert state["valid"] is True
            assert state["blocks"] == 2

            hashes.add(state["latest_hash"])

            print(
                f"{node_id}: "
                f"blocks={state['blocks']} "
                f"hash={state['latest_hash'][:16]}..."
            )

        assert len(hashes) == 1

        assert (
            next(iter(hashes))
            == blocks[-1]["block_hash"]
        )

        print("\n" + "=" * 60)
        print("SUCCESS: FOUR IDENTICAL GCS LEDGERS")
        print(f"Trusted genesis: {TRUSTED_GENESIS_HASH}")
        print(f"Latest hash: {blocks[-1]['block_hash']}")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
