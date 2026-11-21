
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "blockchain"))

from authentication import sign_message
from protocol import PBFTMessage, calculate_digest
from replica import PBFTReplica


VALIDATORS = [
    "GCS_01",
    "GCS_02",
    "GCS_03",
    "GCS_04",
]

HONEST = ["GCS_01", "GCS_03", "GCS_04"]
BYZANTINE = "GCS_02"
VIEW = 0

DIGEST_A = calculate_digest({
    "uav_id": "UAV_001",
    "event": "GPS_SPOOFING",
})

DIGEST_B = calculate_digest({
    "uav_id": "UAV_001",
    "event": "TELEMETRY_TAMPERING",
})


def make_replicas():
    return {
        node_id: PBFTReplica(
            node_id=node_id,
            validator_ids=VALIDATORS,
        )
        for node_id in HONEST
    }


def send(replica, sender, phase, digest, sequence):
    message = PBFTMessage(
        phase=phase,
        view=VIEW,
        sequence=sequence,
        digest=digest,
        sender=sender,
    ).to_dict()

    envelope = sign_message(sender, message)
    return replica.process_message(envelope)


def propose_to_honest(replicas, sequence):
    for replica in replicas.values():
        result = send(
            replica,
            "GCS_01",
            "PRE_PREPARE",
            DIGEST_A,
            sequence,
        )
        assert result["accepted"] is True


def prepare_with_honest(replicas, sequence):
    for replica in replicas.values():
        for sender in HONEST:
            result = send(
                replica,
                sender,
                "PREPARE",
                DIGEST_A,
                sequence,
            )
            assert result["accepted"] is True


def commit_with_honest(replicas, sequence):
    for replica in replicas.values():
        for sender in HONEST:
            result = send(
                replica,
                sender,
                "COMMIT",
                DIGEST_A,
                sequence,
            )
            assert result["accepted"] is True


def get_state(replica, sequence):
    return replica.requests[(VIEW, sequence)]


def verify_honest_agreement(replicas, sequence):
    digests = set()

    for node_id, replica in replicas.items():
        state = get_state(replica, sequence)

        print(
            f"{node_id}: "
            f"PREPARE={len(state.prepare_voters)} "
            f"COMMIT={len(state.commit_voters)} "
            f"prepared={state.prepared} "
            f"committed={state.committed}"
        )

        if state.committed:
            digests.add(state.digest)

    assert len(digests) <= 1, (
        "Conflicting honest commitments detected"
    )


# -------------------------------------------------------
# B1: Conflicting PREPARE votes from Byzantine GCS_02
# -------------------------------------------------------

def test_byzantine_conflicting_prepare():
    sequence = 900
    replicas = make_replicas()
    propose_to_honest(replicas, sequence)

    # Malicious GCS_02 signs a correct PREPARE
    # for GCS_01, but a conflicting one for GCS_03.
    accepted = send(
        replicas["GCS_01"],
        BYZANTINE,
        "PREPARE",
        DIGEST_A,
        sequence,
    )

    rejected = send(
        replicas["GCS_03"],
        BYZANTINE,
        "PREPARE",
        DIGEST_B,
        sequence,
    )

    assert accepted["accepted"] is True
    assert rejected["accepted"] is False
    assert rejected["reason"] == "Digest mismatch"

    assert len(
        get_state(replicas["GCS_01"], sequence).prepare_voters
    ) == 1

    assert len(
        get_state(replicas["GCS_03"], sequence).prepare_voters
    ) == 0

    verify_honest_agreement(replicas, sequence)


# -------------------------------------------------------
# B2: Conflicting COMMIT votes from Byzantine GCS_02
# -------------------------------------------------------

def test_byzantine_conflicting_commit():
    sequence = 901
    replicas = make_replicas()

    propose_to_honest(replicas, sequence)
    prepare_with_honest(replicas, sequence)

    accepted = send(
        replicas["GCS_01"],
        BYZANTINE,
        "COMMIT",
        DIGEST_A,
        sequence,
    )

    rejected = send(
        replicas["GCS_03"],
        BYZANTINE,
        "COMMIT",
        DIGEST_B,
        sequence,
    )

    assert accepted["accepted"] is True
    assert rejected["accepted"] is False
    assert rejected["reason"] == "Digest mismatch"

    assert len(
        get_state(replicas["GCS_01"], sequence).commit_voters
    ) == 1

    assert len(
        get_state(replicas["GCS_03"], sequence).commit_voters
    ) == 0

    verify_honest_agreement(replicas, sequence)


# -------------------------------------------------------
# B3: Byzantine GCS_02 remains completely silent
# -------------------------------------------------------

def test_consensus_with_silent_byzantine():
    sequence = 902
    replicas = make_replicas()

    propose_to_honest(replicas, sequence)
    prepare_with_honest(replicas, sequence)
    commit_with_honest(replicas, sequence)

    for replica in replicas.values():
        state = get_state(replica, sequence)

        assert state.prepared is True
        assert state.committed is True

        assert len(state.prepare_voters) == 3
        assert len(state.commit_voters) == 3
        assert state.digest == DIGEST_A

    verify_honest_agreement(replicas, sequence)


# -------------------------------------------------------
# B4: Duplicate votes from Byzantine GCS_02
# -------------------------------------------------------

def test_byzantine_duplicate_votes():
    sequence = 903
    replicas = make_replicas()
    replica = replicas["GCS_01"]

    propose_to_honest(replicas, sequence)

    for _ in range(10):
        result = send(
            replica,
            BYZANTINE,
            "PREPARE",
            DIGEST_A,
            sequence,
        )
        assert result["accepted"] is True

    state = get_state(replica, sequence)

    assert len(state.prepare_voters) == 1
    assert state.prepared is False

    # Reach the three-vote PREPARE quorum.
    for sender in ["GCS_01", "GCS_03"]:
        result = send(
            replica,
            sender,
            "PREPARE",
            DIGEST_A,
            sequence,
        )
        assert result["accepted"] is True

    assert state.prepared is True

    for _ in range(10):
        result = send(
            replica,
            BYZANTINE,
            "COMMIT",
            DIGEST_A,
            sequence,
        )
        assert result["accepted"] is True

    assert len(state.commit_voters) == 1
    assert state.committed is False

    verify_honest_agreement(replicas, sequence)
