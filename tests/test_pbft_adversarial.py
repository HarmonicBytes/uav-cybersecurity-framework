
import copy
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
SEQUENCE = 700

DIGEST_A = calculate_digest({
    "uav_id": "UAV_001",
    "attack": "GPS_SPOOFING",
})

DIGEST_B = calculate_digest({
    "uav_id": "UAV_001",
    "attack": "TELEMETRY_TAMPERING",
})


@pytest.fixture
def replica():
    return PBFTReplica(
        node_id="GCS_01",
        validator_ids=VALIDATORS,
    )


def signed_pbft(
    sender,
    phase,
    digest=DIGEST_A,
    sequence=SEQUENCE,
    message_sender=None,
):
    message = PBFTMessage(
        phase=phase,
        view=VIEW,
        sequence=sequence,
        digest=digest,
        sender=(
            message_sender
            if message_sender is not None
            else sender
        ),
    ).to_dict()

    return sign_message(sender, message)


def submit_proposal(replica, digest=DIGEST_A):
    result = replica.process_message(
        signed_pbft(
            "GCS_01",
            "PRE_PREPARE",
            digest=digest,
        )
    )

    assert result["accepted"] is True


def reach_prepare_quorum(replica):
    submit_proposal(replica)

    for sender in VALIDATORS[:3]:
        result = replica.process_message(
            signed_pbft(sender, "PREPARE")
        )

        assert result["accepted"] is True

    state = replica.requests[(VIEW, SEQUENCE)]
    assert state.prepared is True


# ----------------------------------------------------
# S1: Tampered signed PREPARE
# ----------------------------------------------------

def test_tampered_signature_rejected(replica):
    submit_proposal(replica)

    envelope = signed_pbft(
        "GCS_02",
        "PREPARE",
    )

    tampered = copy.deepcopy(envelope)

    # Change the signed content without re-signing.
    tampered["message"]["digest"] = DIGEST_B

    result = replica.process_message(tampered)

    assert result["accepted"] is False

    state = replica.requests[(VIEW, SEQUENCE)]

    assert len(state.prepare_voters) == 0
    assert state.prepared is False


# ----------------------------------------------------
# S2: Forged validator identity
# ----------------------------------------------------

def test_forged_sender_identity_rejected(replica):
    submit_proposal(replica)

    # The envelope is authenticated as GCS_02,
    # but the PBFT payload claims GCS_01.
    envelope = signed_pbft(
        sender="GCS_02",
        phase="PREPARE",
        message_sender="GCS_01",
    )

    result = replica.process_message(envelope)

    assert result["accepted"] is False
    assert (
        result["reason"]
        == "Sender identity mismatch"
    )

    state = replica.requests[(VIEW, SEQUENCE)]

    assert len(state.prepare_voters) == 0


# ----------------------------------------------------
# S3: Conflicting primary proposal
# ----------------------------------------------------

def test_conflicting_primary_proposal_rejected(replica):
    submit_proposal(replica, DIGEST_A)

    conflicting = signed_pbft(
        "GCS_01",
        "PRE_PREPARE",
        digest=DIGEST_B,
    )

    result = replica.process_message(conflicting)

    assert result["accepted"] is False
    assert result["reason"] == "Conflicting proposal"

    state = replica.requests[(VIEW, SEQUENCE)]

    assert state.digest == DIGEST_A


# ----------------------------------------------------
# S4: Duplicate COMMIT vote
# ----------------------------------------------------

def test_duplicate_commit_not_double_counted(replica):
    reach_prepare_quorum(replica)

    commit = signed_pbft(
        "GCS_02",
        "COMMIT",
    )

    first = replica.process_message(commit)
    second = replica.process_message(commit)

    assert first["accepted"] is True
    assert second["accepted"] is True

    state = replica.requests[(VIEW, SEQUENCE)]

    assert len(state.commit_voters) == 1
    assert state.committed is False


# ----------------------------------------------------
# S5: Premature COMMIT
# ----------------------------------------------------

def test_commit_before_prepare_quorum_rejected(replica):
    submit_proposal(replica)

    premature_commit = signed_pbft(
        "GCS_02",
        "COMMIT",
    )

    result = replica.process_message(
        premature_commit
    )

    assert result["accepted"] is False
    assert (
        result["reason"]
        == "Prepare quorum not reached"
    )

    state = replica.requests[(VIEW, SEQUENCE)]

    assert state.prepared is False
    assert state.committed is False
    assert len(state.commit_voters) == 0


# ----------------------------------------------------
# S6: Primary equivocation across replicas
# ----------------------------------------------------

def test_primary_equivocation_limitation():
    """
    Evaluate conflicting proposals delivered to
    two independent replicas.

    This test records the current limitation:
    each local replica sees only one proposal.

    It does NOT assert full Byzantine safety.
    """

    replica_02 = PBFTReplica(
        node_id="GCS_02",
        validator_ids=VALIDATORS,
    )

    replica_03 = PBFTReplica(
        node_id="GCS_03",
        validator_ids=VALIDATORS,
    )

    proposal_a = signed_pbft(
        "GCS_01",
        "PRE_PREPARE",
        digest=DIGEST_A,
    )

    proposal_b = signed_pbft(
        "GCS_01",
        "PRE_PREPARE",
        digest=DIGEST_B,
    )

    result_02 = replica_02.process_message(
        proposal_a
    )

    result_03 = replica_03.process_message(
        proposal_b
    )

    assert result_02["accepted"] is True
    assert result_03["accepted"] is True

    state_02 = replica_02.requests[
        (VIEW, SEQUENCE)
    ]

    state_03 = replica_03.requests[
        (VIEW, SEQUENCE)
    ]

    assert state_02.digest == DIGEST_A
    assert state_03.digest == DIGEST_B

    # Both replicas accepted different primary
    # proposals for the same view and sequence.
    # Detecting and recovering from primary
    # equivocation requires further protocol work.
