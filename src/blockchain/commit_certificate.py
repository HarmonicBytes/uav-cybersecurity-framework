
from authentication import verify_message
from protocol import PBFTMessage, calculate_digest


VALIDATOR_IDS = frozenset({
    "GCS_01",
    "GCS_02",
    "GCS_03",
    "GCS_04",
})

QUORUM = 3


class CommitCertificateError(ValueError):
    pass


def verify_commit_certificate(
    alert,
    certificate,
    view,
    sequence,
    validator_ids=VALIDATOR_IDS,
):
    """
    Verify signed PBFT COMMIT votes for one alert.

    This verifies signatures, validator membership,
    distinct senders and consistent consensus fields.

    It does not independently prove that each
    validator reached its local prepared state.
    """

    if not isinstance(alert, dict):
        raise CommitCertificateError(
            "Alert must be a JSON object"
        )

    if type(view) is not int or view < 0:
        raise CommitCertificateError(
            "Invalid view"
        )

    if type(sequence) is not int or sequence < 0:
        raise CommitCertificateError(
            "Invalid sequence"
        )

    if not isinstance(certificate, list):
        raise CommitCertificateError(
            "Certificate must be a list"
        )

    validators = set(validator_ids)

    if len(validators) < 4:
        raise CommitCertificateError(
            "At least four validators required"
        )

    if validators != VALIDATOR_IDS:
        raise CommitCertificateError(
            "Unexpected validator configuration"
        )

    required_quorum = (
        2 * ((len(validators) - 1) // 3) + 1
    )

    digest = calculate_digest(alert)
    verified_senders = set()

    for envelope in certificate:
        if not isinstance(envelope, dict):
            raise CommitCertificateError(
                "Invalid signed vote envelope"
            )

        sender = envelope.get("sender")
        message = envelope.get("message")

        if sender not in validators:
            raise CommitCertificateError(
                "Unknown validator"
            )

        if sender in verified_senders:
            raise CommitCertificateError(
                "Duplicate validator vote"
            )

        if not isinstance(message, dict):
            raise CommitCertificateError(
                "Invalid COMMIT message"
            )

        if message.get("sender") != sender:
            raise CommitCertificateError(
                "Sender identity mismatch"
            )

        if (
            message.get("phase") != "COMMIT"
            or message.get("view") != view
            or message.get("sequence") != sequence
            or message.get("digest") != digest
        ):
            raise CommitCertificateError(
                "COMMIT vote does not match consensus instance"
            )

        # Reject unexpected or unsigned protocol fields.
        expected_message = PBFTMessage(
            phase="COMMIT",
            view=view,
            sequence=sequence,
            digest=digest,
            sender=sender,
        ).to_dict()

        if message != expected_message:
            raise CommitCertificateError(
                "Unexpected COMMIT message fields"
            )

        try:
            valid_signature = verify_message(envelope)
        except (TypeError, ValueError, KeyError) as error:
            raise CommitCertificateError(
                "Invalid validator signature"
            ) from error

        if not valid_signature:
            raise CommitCertificateError(
                "Invalid validator signature"
            )

        verified_senders.add(sender)

    if len(verified_senders) < required_quorum:
        raise CommitCertificateError(
            "Insufficient signed COMMIT votes"
        )

    return {
        "valid": True,
        "digest": digest,
        "view": view,
        "sequence": sequence,
        "quorum": required_quorum,
        "verified_votes": len(verified_senders),
        "validators": sorted(verified_senders),
    }
