
import copy
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0,
    str(ROOT / "src" / "blockchain"),
)

from authentication import sign_message
from commit_certificate import (
    CommitCertificateError,
    verify_commit_certificate,
)
from protocol import PBFTMessage, calculate_digest


ALERT = {
    "uav_id": "UAV_001",
    "event_type": "UAV_TELEMETRY_ANOMALY",
    "anomaly_score": 42.5,
}

VIEW = 0
SEQUENCE = 5000


def make_vote(
    sender,
    alert=ALERT,
    phase="COMMIT",
    sequence=SEQUENCE,
):
    message = PBFTMessage(
        phase=phase,
        view=VIEW,
        sequence=sequence,
        digest=calculate_digest(alert),
        sender=sender,
    ).to_dict()

    return sign_message(sender, message)


def make_certificate():
    return [
        make_vote("GCS_01"),
        make_vote("GCS_02"),
        make_vote("GCS_03"),
    ]


def verify(certificate, alert=ALERT):
    return verify_commit_certificate(
        alert=alert,
        certificate=certificate,
        view=VIEW,
        sequence=SEQUENCE,
    )


def test_valid_three_validator_certificate():
    result = verify(make_certificate())

    assert result["valid"] is True
    assert result["verified_votes"] == 3
    assert result["quorum"] == 3


def test_four_validator_certificate():
    certificate = make_certificate()
    certificate.append(make_vote("GCS_04"))

    result = verify(certificate)

    assert result["verified_votes"] == 4


def test_insufficient_signatures_rejected():
    certificate = [
        make_vote("GCS_01"),
        make_vote("GCS_02"),
    ]

    with pytest.raises(
        CommitCertificateError,
        match="Insufficient signed COMMIT votes",
    ):
        verify(certificate)


def test_duplicate_signer_rejected():
    certificate = make_certificate()

    certificate[2] = copy.deepcopy(
        certificate[0]
    )

    with pytest.raises(
        CommitCertificateError,
        match="Duplicate validator vote",
    ):
        verify(certificate)


def test_modified_signed_vote_rejected():
    certificate = make_certificate()

    certificate[1]["message"]["sequence"] = (
        SEQUENCE + 1
    )

    with pytest.raises(
        CommitCertificateError
    ):
        verify(certificate)


def test_wrong_alert_digest_rejected():
    certificate = make_certificate()

    changed_alert = {
        **ALERT,
        "anomaly_score": 0.01,
    }

    with pytest.raises(
        CommitCertificateError
    ):
        verify(certificate, changed_alert)


def test_prepare_vote_rejected():
    certificate = make_certificate()

    certificate[2] = make_vote(
        "GCS_03",
        phase="PREPARE",
    )

    with pytest.raises(
        CommitCertificateError
    ):
        verify(certificate)


def test_wrong_consensus_sequence_rejected():
    certificate = make_certificate()

    certificate[2] = make_vote(
        "GCS_03",
        sequence=SEQUENCE + 1,
    )

    with pytest.raises(
        CommitCertificateError
    ):
        verify(certificate)
