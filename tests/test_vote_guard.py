
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "blockchain"))

from protocol import calculate_digest
from vote_guard import VoteGuard


def test_first_vote_allowed():
    guard = VoteGuard()
    digest = calculate_digest({"event": 1})

    result = guard.register("PREPARE", 0, 1, digest)

    assert result["allowed"] is True


def test_duplicate_vote_not_generated():
    guard = VoteGuard()
    digest = calculate_digest({"event": 1})

    guard.register("PREPARE", 0, 1, digest)
    result = guard.register("PREPARE", 0, 1, digest)

    assert result["allowed"] is False
    assert result["reason"] == "Vote already registered"


def test_conflicting_vote_rejected():
    guard = VoteGuard()

    first = calculate_digest({"event": 1})
    second = calculate_digest({"event": 2})

    guard.register("PREPARE", 0, 1, first)

    result = guard.register("PREPARE", 0, 1, second)

    assert result["allowed"] is False
    assert result["reason"] == "Conflicting local vote"


def test_prepare_and_commit_are_separate():
    guard = VoteGuard()
    digest = calculate_digest({"event": 1})

    prepare = guard.register("PREPARE", 0, 1, digest)
    commit = guard.register("COMMIT", 0, 1, digest)

    assert prepare["allowed"] is True
    assert commit["allowed"] is True


def test_new_sequence_allowed():
    guard = VoteGuard()
    digest = calculate_digest({"event": 1})

    first = guard.register("PREPARE", 0, 1, digest)
    second = guard.register("PREPARE", 0, 2, digest)

    assert first["allowed"] is True
    assert second["allowed"] is True
