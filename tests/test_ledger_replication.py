
import copy
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(ROOT / "src" / "blockchain"),
)

from authentication import sign_message
from block import Block
from ledger_replication import (
    ReplicaLedgerStore,
    LedgerReplicationError,
)
from ledger_store import SecurityLedgerStore
from protocol import PBFTMessage, calculate_digest


VALIDATORS = [
    "GCS_01",
    "GCS_02",
    "GCS_03",
    "GCS_04",
]


def make_certificate(alert, sequence):
    digest = calculate_digest(alert)
    certificate = []

    for sender in VALIDATORS:
        message = PBFTMessage(
            phase="COMMIT",
            view=0,
            sequence=sequence,
            digest=digest,
            sender=sender,
        ).to_dict()

        certificate.append(
            sign_message(sender, message)
        )

    return certificate


@pytest.fixture
def canonical_blocks(tmp_path):
    source = SecurityLedgerStore(
        path=tmp_path / "canonical.json"
    )

    alert = {
        "uav_id": "UAV_001",
        "event_type": "UAV_TELEMETRY_ANOMALY",
        "anomaly_score": 42.5,
        "threshold": 1.5,
        "detection_result": "ANOMALY",
    }

    digest = calculate_digest(alert)

    source.append_committed_alert(
        alert=alert,
        committed_digest=digest,
        view=0,
        sequence=8000,
        committed_validators=VALIDATORS,
        commit_certificate=make_certificate(
            alert, 8000
        ),
    )

    data = json.loads(
        source.path.read_text(encoding="utf-8")
    )

    return data


def make_replica(tmp_path, node_id, genesis_hash):
    return ReplicaLedgerStore(
        node_id=node_id,
        path=tmp_path / node_id / "ledger.json",
        trusted_genesis_hash=genesis_hash,
    )


def test_four_identical_replica_ledgers(
    tmp_path, canonical_blocks
):
    genesis_hash = canonical_blocks[0]["block_hash"]

    replicas = [
        make_replica(
            tmp_path,
            node_id,
            genesis_hash,
        )
        for node_id in VALIDATORS
    ]

    for replica in replicas:
        for block in canonical_blocks:
            result = replica.apply_block(block)
            assert result["status"] == "appended"

    hashes = {
        replica.status()["latest_hash"]
        for replica in replicas
    }

    assert len(hashes) == 1
    assert all(
        replica.status()["blocks"] == 2
        for replica in replicas
    )


def test_duplicate_block_is_idempotent(
    tmp_path, canonical_blocks
):
    replica = make_replica(
        tmp_path,
        "GCS_01",
        canonical_blocks[0]["block_hash"],
    )

    replica.apply_block(canonical_blocks[0])
    replica.apply_block(canonical_blocks[1])

    result = replica.apply_block(
        canonical_blocks[1]
    )

    assert result["status"] == "already_present"
    assert replica.status()["blocks"] == 2


def test_missing_predecessor_rejected(
    tmp_path, canonical_blocks
):
    replica = make_replica(
        tmp_path,
        "GCS_01",
        canonical_blocks[0]["block_hash"],
    )

    with pytest.raises(
        LedgerReplicationError,
        match="Missing preceding blocks",
    ):
        replica.apply_block(canonical_blocks[1])


def test_modified_certificate_rejected(
    tmp_path, canonical_blocks
):
    replica = make_replica(
        tmp_path,
        "GCS_01",
        canonical_blocks[0]["block_hash"],
    )

    replica.apply_block(canonical_blocks[0])

    modified = copy.deepcopy(
        canonical_blocks[1]
    )

    modified["event"]["consensus"][
        "commit_certificate"
    ][0]["message"]["sequence"] += 1

    # Recalculate the hash, simulating an attacker
    # able to replace the JSON block content.
    block = Block(
        index=modified["index"],
        timestamp=modified["timestamp"],
        previous_hash=modified["previous_hash"],
        event=modified["event"],
    )

    modified["block_hash"] = block.calculate_hash()

    with pytest.raises(
        ValueError
    ):
        replica.apply_block(modified)

    assert replica.status()["blocks"] == 1


def test_conflicting_block_rejected(
    tmp_path, canonical_blocks
):
    replica = make_replica(
        tmp_path,
        "GCS_01",
        canonical_blocks[0]["block_hash"],
    )

    for block in canonical_blocks:
        replica.apply_block(block)

    conflicting = copy.deepcopy(
        canonical_blocks[1]
    )

    conflicting["timestamp"] += 1.0

    block = Block(
        index=conflicting["index"],
        timestamp=conflicting["timestamp"],
        previous_hash=conflicting["previous_hash"],
        event=conflicting["event"],
    )

    conflicting["block_hash"] = block.calculate_hash()

    with pytest.raises(
        LedgerReplicationError,
        match="Conflicting block",
    ):
        replica.apply_block(conflicting)


def test_untrusted_genesis_rejected(
    tmp_path, canonical_blocks
):
    replica = make_replica(
        tmp_path,
        "GCS_01",
        "f" * 64,
    )

    with pytest.raises(
        LedgerReplicationError,
        match="Untrusted genesis",
    ):
        replica.apply_block(canonical_blocks[0])


def test_uncertified_block_rejected(
    tmp_path, canonical_blocks
):
    replica = make_replica(
        tmp_path,
        "GCS_01",
        canonical_blocks[0]["block_hash"],
    )

    replica.apply_block(canonical_blocks[0])

    uncertified = copy.deepcopy(
        canonical_blocks[1]
    )

    uncertified["event"]["consensus"].pop(
        "commit_certificate"
    )

    block = Block(
        index=uncertified["index"],
        timestamp=uncertified["timestamp"],
        previous_hash=uncertified["previous_hash"],
        event=uncertified["event"],
    )

    uncertified["block_hash"] = block.calculate_hash()

    with pytest.raises(
        LedgerReplicationError,
        match="Missing COMMIT certificate",
    ):
        replica.apply_block(uncertified)
