import sys
from pathlib import Path

# Locate the blockchain modules
ROOT = Path(__file__).resolve().parents[1]
BLOCKCHAIN_DIR = ROOT / "src" / "blockchain"

# Add the directory BEFORE importing blockchain modules
sys.path.insert(0, str(BLOCKCHAIN_DIR))

# Import modules only after setting the path
from pbft import PBFTConsensus
from validator import create_validator_network

def create_test_event():
    return {
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING_ALERT",
        "anomaly_score": 4.25,
    }


def test_all_validators_operational():
    validators = create_validator_network(4)
    consensus = PBFTConsensus(validators)

    result = consensus.execute(create_test_event())

    assert result["success"] is True
    assert result["prepare_votes"] == 4
    assert result["commit_votes"] == 4


def test_one_faulty_replica():
    validators = create_validator_network(4)
    validators[3].is_byzantine = True

    consensus = PBFTConsensus(validators)
    result = consensus.execute(create_test_event())

    assert result["success"] is True
    assert result["prepare_votes"] == 3
    assert result["commit_votes"] == 3


def test_two_faulty_replicas():
    validators = create_validator_network(4)
    validators[2].is_byzantine = True
    validators[3].is_byzantine = True

    consensus = PBFTConsensus(validators)
    result = consensus.execute(create_test_event())

    assert result["success"] is False
    assert result["prepare_votes"] == 2


def test_faulty_primary():
    validators = create_validator_network(4)
    validators[0].is_byzantine = True

    consensus = PBFTConsensus(validators)
    result = consensus.execute(create_test_event())

    assert result["success"] is False
    assert "view change" in result["reason"].lower()


def test_reject_modified_signed_vote():
    validators = create_validator_network(4)
    consensus = PBFTConsensus(validators)

    digest = consensus.digest_event(create_test_event())

    vote = consensus.create_vote(
        validators[0],
        "PREPARE",
        1,
        digest,
    )

    # A valid signed vote should pass.
    assert consensus.verify_vote(
        vote, "PREPARE", 1, digest
    ) is True

    # Replaying it under a different sequence must fail.
    assert consensus.verify_vote(
        vote, "PREPARE", 2, digest
    ) is False
