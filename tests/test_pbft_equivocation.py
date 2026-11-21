
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

VIEW = 0
QUORUM = 3

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
        for node_id in VALIDATORS
    }


def send_vote(
    replica,
    sender,
    phase,
    digest,
    sequence,
):
    message = PBFTMessage(
        phase=phase,
        view=VIEW,
        sequence=sequence,
        digest=digest,
        sender=sender,
    ).to_dict()

    envelope = sign_message(sender, message)

    return replica.process_message(envelope)


def propose(replica, digest, sequence):
    result = send_vote(
        replica=replica,
        sender="GCS_01",
        phase="PRE_PREPARE",
        digest=digest,
        sequence=sequence,
    )

    assert result["accepted"] is True


def state_of(replica, sequence):
    return replica.requests[(VIEW, sequence)]


def assert_no_conflicting_honest_commits(
    replicas, sequence
):
    honest_nodes = [
        "GCS_02",
        "GCS_03",
        "GCS_04",
    ]

    committed_digests = set()

    for node_id in honest_nodes:
        state = state_of(
            replicas[node_id],
            sequence,
        )

        print(
            f"{node_id}: "
            f"digest={state.digest[:12]} "
            f"PREPARE={len(state.prepare_voters)} "
            f"COMMIT={len(state.commit_voters)} "
            f"prepared={state.prepared} "
            f"committed={state.committed}"
        )

        if state.committed:
            committed_digests.add(state.digest)

    assert len(committed_digests) <= 1, (
        "SAFETY VIOLATION: Honest replicas "
        "committed conflicting digests"
    )


# -------------------------------------------------------
# Scenario 1:
# Malicious primary sends conflicting proposals.
#
# GCS_02 receives proposal A.
# GCS_03 and GCS_04 receive proposal B.
#
# Malicious GCS_01 supplies signed votes for
# both branches, demonstrating equivocation.
# -------------------------------------------------------

def test_equivocation_with_malicious_primary_votes():
    print("\nSCENARIO 1: PRIMARY EQUIVOCATION")

    sequence = 800
    replicas = make_replicas()

    propose(replicas["GCS_02"], DIGEST_A, sequence)
    propose(replicas["GCS_03"], DIGEST_B, sequence)
    propose(replicas["GCS_04"], DIGEST_B, sequence)

    # Honest GCS_02 votes only for A.
    # Malicious primary also votes for A.
    for sender in ["GCS_01", "GCS_02"]:
        result = send_vote(
            replicas["GCS_02"],
            sender,
            "PREPARE",
            DIGEST_A,
            sequence,
        )
        assert result["accepted"] is True

    # GCS_03 and GCS_04 see three matching
    # PREPARE votes on branch B.
    for destination in ["GCS_03", "GCS_04"]:
        for sender in [
            "GCS_01",
            "GCS_03",
            "GCS_04",
        ]:
            result = send_vote(
                replicas[destination],
                sender,
                "PREPARE",
                DIGEST_B,
                sequence,
            )
            assert result["accepted"] is True

    # Branch B has reached its PREPARE quorum.
    for destination in ["GCS_03", "GCS_04"]:
        assert state_of(
            replicas[destination], sequence
        ).prepared is True

    # Authenticated COMMIT votes on branch B.
    for destination in ["GCS_03", "GCS_04"]:
        for sender in [
            "GCS_01",
            "GCS_03",
            "GCS_04",
        ]:
            result = send_vote(
                replicas[destination],
                sender,
                "COMMIT",
                DIGEST_B,
                sequence,
            )
            assert result["accepted"] is True

    state_02 = state_of(
        replicas["GCS_02"], sequence
    )
    state_03 = state_of(
        replicas["GCS_03"], sequence
    )
    state_04 = state_of(
        replicas["GCS_04"], sequence
    )

    assert state_02.digest == DIGEST_A
    assert state_02.committed is False

    assert state_03.digest == DIGEST_B
    assert state_03.committed is True

    assert state_04.digest == DIGEST_B
    assert state_04.committed is True

    # A conflicting B vote cannot advance
    # the state of the replica locked to A.
    rejected = send_vote(
        replicas["GCS_02"],
        "GCS_01",
        "COMMIT",
        DIGEST_B,
        sequence,
    )
    assert rejected["accepted"] is False
    assert rejected["reason"] == "Digest mismatch"

    assert_no_conflicting_honest_commits(
        replicas, sequence
    )

    print("No conflicting honest commits observed.")


# -------------------------------------------------------
# Scenario 2:
# Primary sends conflicting proposals, then stops
# supplying PREPARE and COMMIT votes.
# -------------------------------------------------------

def test_equivocation_with_silent_primary():
    print("\nSCENARIO 2: SILENT MALICIOUS PRIMARY")

    sequence = 801
    replicas = make_replicas()

    propose(replicas["GCS_02"], DIGEST_A, sequence)
    propose(replicas["GCS_03"], DIGEST_B, sequence)
    propose(replicas["GCS_04"], DIGEST_B, sequence)

    # Honest validators vote only for the
    # proposals they locally accepted.
    result = send_vote(
        replicas["GCS_02"],
        "GCS_02",
        "PREPARE",
        DIGEST_A,
        sequence,
    )
    assert result["accepted"] is True

    for destination in ["GCS_03", "GCS_04"]:
        for sender in ["GCS_03", "GCS_04"]:
            result = send_vote(
                replicas[destination],
                sender,
                "PREPARE",
                DIGEST_B,
                sequence,
            )
            assert result["accepted"] is True

    # No branch has the required three votes.
    for node_id in ["GCS_02", "GCS_03", "GCS_04"]:
        state = state_of(
            replicas[node_id], sequence
        )
        assert state.prepared is False
        assert state.committed is False
        assert len(state.commit_voters) == 0

    assert_no_conflicting_honest_commits(
        replicas, sequence
    )

    print("No quorum reached without primary votes.")
