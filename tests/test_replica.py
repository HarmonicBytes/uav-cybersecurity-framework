
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(ROOT / "src" / "blockchain")
)

from authentication import sign_message
from protocol import PBFTMessage, calculate_digest
from replica import PBFTReplica


VALIDATORS = [
    "GCS_01",
    "GCS_02",
    "GCS_03",
    "GCS_04",
]


def create_signed_vote(sender, phase, digest):
    message = PBFTMessage(
        phase=phase,
        view=0,
        sequence=1,
        digest=digest,
        sender=sender,
    )

    return sign_message(
        sender,
        message.to_dict(),
    )


def test_replica_consensus():

    replica = PBFTReplica(
        node_id="GCS_02",
        validator_ids=VALIDATORS,
    )

    event = {
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING_ALERT",
        "anomaly_score": 4.25,
    }

    digest = calculate_digest(event)

    # Primary sends PRE-PREPARE.
    result = replica.process_message(
        create_signed_vote(
            "GCS_01", "PRE_PREPARE", digest
        )
    )

    assert result["accepted"] is True

    # Three independent validators send PREPARE.
    for sender in VALIDATORS[:3]:
        result = replica.process_message(
            create_signed_vote(
                sender, "PREPARE", digest
            )
        )

    assert result["prepared"] is True
    assert result["prepare_votes"] == 3

    # Three independent validators send COMMIT.
    for sender in VALIDATORS[:3]:
        result = replica.process_message(
            create_signed_vote(
                sender, "COMMIT", digest
            )
        )

    assert result["committed"] is True
    assert result["commit_votes"] == 3


def test_reject_conflicting_digest():

    replica = PBFTReplica(
        node_id="GCS_02",
        validator_ids=VALIDATORS,
    )

    first_digest = calculate_digest({"event": 1})
    second_digest = calculate_digest({"event": 2})

    replica.process_message(
        create_signed_vote(
            "GCS_01", "PRE_PREPARE", first_digest
        )
    )

    result = replica.process_message(
        create_signed_vote(
            "GCS_03", "PREPARE", second_digest
        )
    )

    assert result["accepted"] is False


def test_duplicate_votes_not_counted_twice():

    replica = PBFTReplica(
        node_id="GCS_02",
        validator_ids=VALIDATORS,
    )

    digest = calculate_digest({"event": "test"})

    replica.process_message(
        create_signed_vote(
            "GCS_01", "PRE_PREPARE", digest
        )
    )

    vote = create_signed_vote(
        "GCS_03", "PREPARE", digest
    )

    replica.process_message(vote)
    result = replica.process_message(vote)

    assert result["prepare_votes"] == 1
    assert result["prepared"] is False

def test_prepare_before_preprepare_is_rejected():
    replica = PBFTReplica(
        node_id="GCS_02",
        validator_ids=VALIDATORS,
    )

    digest = calculate_digest({
        "event": "GPS_SPOOFING_ALERT"
    })

    # A PREPARE arrives before the primary proposal.
    early_vote = create_signed_vote(
        "GCS_03",
        "PREPARE",
        digest,
    )

    result = replica.process_message(early_vote)

    assert result["accepted"] is False
    assert result["reason"] == "No accepted primary proposal"

    # The legitimate primary proposal arrives later.
    proposal = create_signed_vote(
        "GCS_01",
        "PRE_PREPARE",
        digest,
    )

    result = replica.process_message(proposal)

    assert result["accepted"] is True
    assert result["prepare_votes"] == 0
