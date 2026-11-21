
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "blockchain"))

from protocol import calculate_digest
from authentication import verify_message
from voting import PBFTVotingService


def test_prepare_vote_is_signed():
    service = PBFTVotingService("GCS_01")
    digest = calculate_digest({"event": 1})

    result = service.create_vote(
        "PREPARE", 0, 1, digest
    )

    assert result["success"] is True
    assert verify_message(result["envelope"]) is True


def test_commit_requires_prepared_state():
    service = PBFTVotingService("GCS_01")
    digest = calculate_digest({"event": 1})

    result = service.create_vote(
        "COMMIT", 0, 1, digest,
        prepared=False,
    )

    assert result["success"] is False


def test_commit_allowed_when_prepared():
    service = PBFTVotingService("GCS_01")
    digest = calculate_digest({"event": 1})

    result = service.create_vote(
        "COMMIT", 0, 1, digest,
        prepared=True,
    )

    assert result["success"] is True
    assert verify_message(result["envelope"]) is True


def test_duplicate_prepare_prevented():
    service = PBFTVotingService("GCS_01")
    digest = calculate_digest({"event": 1})

    service.create_vote("PREPARE", 0, 1, digest)

    result = service.create_vote(
        "PREPARE", 0, 1, digest
    )

    assert result["success"] is False


def test_conflicting_prepare_prevented():
    service = PBFTVotingService("GCS_01")

    first = calculate_digest({"event": 1})
    second = calculate_digest({"event": 2})

    service.create_vote("PREPARE", 0, 1, first)

    result = service.create_vote(
        "PREPARE", 0, 1, second
    )

    assert result["success"] is False
