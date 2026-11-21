
import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "blockchain"))
sys.path.insert(0, str(ROOT / "src" / "security"))

from authentication import sign_message
from protocol import PBFTMessage, calculate_digest
from ledger_store import SecurityLedgerStore
from response_engine import DefensiveResponseEngine
from commit_certificate import CommitCertificateError


VALIDATORS = [
    "GCS_01",
    "GCS_02",
    "GCS_03",
    "GCS_04",
]

VIEW = 0
SEQUENCE = 6000

ALERT = {
    "uav_id": "UAV_001",
    "event_type": "UAV_TELEMETRY_ANOMALY",
    "anomaly_score": 42.5,
    "threshold": 1.5,
    "detection_result": "ANOMALY",
}


@pytest.fixture
def environment(tmp_path):
    ledger = SecurityLedgerStore(
        path=tmp_path / "ledger.json"
    )
    engine = DefensiveResponseEngine(
        ledger_store=ledger,
        path=tmp_path / "responses.json",
    )
    return ledger, engine


def make_certificate(alert=ALERT):
    digest = calculate_digest(alert)
    votes = []

    for sender in VALIDATORS:
        message = PBFTMessage(
            phase="COMMIT",
            view=VIEW,
            sequence=SEQUENCE,
            digest=digest,
            sender=sender,
        ).to_dict()

        votes.append(sign_message(sender, message))

    return votes


def append_certified(ledger, certificate=None):
    if certificate is None:
        certificate = make_certificate()

    result = ledger.append_committed_alert(
        alert=ALERT,
        committed_digest=calculate_digest(ALERT),
        view=VIEW,
        sequence=SEQUENCE,
        committed_validators=VALIDATORS,
        commit_certificate=certificate,
    )

    return result


def respond(engine, result):
    return engine.process_committed_alert(
        block_index=result["block_index"],
        expected_digest=calculate_digest(ALERT),
        view=VIEW,
        sequence=SEQUENCE,
        require_certificate=True,
    )


def rewrite_last_block(ledger, modifier):
    """
    Simulate an attacker able to edit the JSON
    and recalculate the latest block hash.
    """

    data = json.loads(
        ledger.path.read_text(encoding="utf-8")
    )

    modifier(data[-1])

    ledger.path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )

    # Recalculate the block hash using the
    # existing Block implementation.
    from block import Block

    last = data[-1]

    block = Block(
        index=last["index"],
        timestamp=last["timestamp"],
        previous_hash=last["previous_hash"],
        event=last["event"],
    )

    last["block_hash"] = block.calculate_hash()

    ledger.path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def test_valid_certified_response(environment):
    ledger, engine = environment
    result = append_certified(ledger)

    response = respond(engine, result)

    assert response["status"] == "RECORDED"
    assert response["severity"] == "HIGH"
    assert len(response["actions"]) == 3


def test_missing_certificate_rejected(environment):
    ledger, engine = environment

    result = ledger.append_committed_alert(
        alert=ALERT,
        committed_digest=calculate_digest(ALERT),
        view=VIEW,
        sequence=SEQUENCE,
        committed_validators=VALIDATORS,
    )

    with pytest.raises(
        ValueError,
        match="Missing signed COMMIT certificate",
    ):
        respond(engine, result)

    assert not engine.path.exists()


def test_tampered_signature_rejected(environment):
    ledger, engine = environment
    result = append_certified(ledger)

    def tamper(block):
        certificate = block["event"]["consensus"][
            "commit_certificate"
        ]

        certificate[0]["message"]["sequence"] += 1

    rewrite_last_block(ledger, tamper)

    # Ordinary hash-chain integrity can still pass.
    assert ledger.verify()["valid"] is True

    # Cryptographic certificate checking must fail.
    with pytest.raises(
        (CommitCertificateError, ValueError)
    ):
        respond(engine, result)

    assert not engine.path.exists()


def test_duplicate_signer_rejected(environment):
    ledger, engine = environment
    result = append_certified(ledger)

    def duplicate(block):
        certificate = block["event"]["consensus"][
            "commit_certificate"
        ]

        certificate[1] = copy.deepcopy(
            certificate[0]
        )

    rewrite_last_block(ledger, duplicate)

    assert ledger.verify()["valid"] is True

    with pytest.raises(
        CommitCertificateError,
        match="Duplicate validator vote",
    ):
        respond(engine, result)

    assert not engine.path.exists()


def test_certificate_removal_rejected(environment):
    ledger, engine = environment
    result = append_certified(ledger)

    def remove(block):
        block["event"]["consensus"].pop(
            "commit_certificate"
        )

    rewrite_last_block(ledger, remove)

    assert ledger.verify()["valid"] is True

    with pytest.raises(
        ValueError,
        match="Missing signed COMMIT certificate",
    ):
        respond(engine, result)

    assert not engine.path.exists()


def test_insufficient_votes_rejected(environment):
    ledger, engine = environment
    result = append_certified(ledger)

    def remove_votes(block):
        certificate = block["event"]["consensus"][
            "commit_certificate"
        ]

        del certificate[2:]

    rewrite_last_block(ledger, remove_votes)

    assert ledger.verify()["valid"] is True

    with pytest.raises(
        CommitCertificateError,
        match="Insufficient signed COMMIT votes",
    ):
        respond(engine, result)

    assert not engine.path.exists()
