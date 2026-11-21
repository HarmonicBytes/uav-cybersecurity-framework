
import base64
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Set

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def serialize_message(message: Dict[str, Any]) -> bytes:
    """
    Produce deterministic bytes for signing PBFT messages.
    """
    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


@dataclass
class GCSValidator:
    validator_id: str
    is_byzantine: bool = False

    private_key: Ed25519PrivateKey = field(
        default_factory=Ed25519PrivateKey.generate,
        repr=False,
    )

    prepared_messages: Set[str] = field(default_factory=set)
    committed_messages: Set[str] = field(default_factory=set)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def sign_message(self, message: Dict[str, Any]) -> str:
        """
        Sign a canonical PBFT message using Ed25519.
        """
        payload = serialize_message(message)
        signature = self.private_key.sign(payload)

        return base64.b64encode(signature).decode("ascii")

    @staticmethod
    def verify_signature(
        message: Dict[str, Any],
        signature: str,
        public_key: Ed25519PublicKey,
    ) -> bool:
        try:
            public_key.verify(
                base64.b64decode(
                    signature,
                    validate=True,
                ),
                serialize_message(message),
            )
            return True

        except (InvalidSignature, ValueError, TypeError):
            return False


def create_validator_network(count: int = 4):
    if count < 4:
        raise ValueError(
            "At least four validators are required "
            "for a one-fault-tolerant PBFT configuration."
        )

    validators = [
        GCSValidator(
            validator_id=f"GCS_{index:02d}"
        )
        for index in range(1, count + 1)
    ]

    return validators


if __name__ == "__main__":
    validators = create_validator_network(4)

    message = {
        "phase": "PREPARE",
        "view": 0,
        "sequence": 1,
        "digest": "example-block-digest",
    }

    sender = validators[0]
    receiver = validators[1]

    signature = sender.sign_message(message)

    valid = receiver.verify_signature(
        message,
        signature,
        sender.public_key,
    )

    print("PBFT Validator Authentication Test")
    print("=" * 45)
    print(f"Validators created: {len(validators)}")
    print(f"Sender: {sender.validator_id}")
    print(f"Receiver: {receiver.validator_id}")
    print(f"Original signature valid: {valid}")

    altered_message = dict(message)
    altered_message["sequence"] = 999

    altered_valid = receiver.verify_signature(
        altered_message,
        signature,
        sender.public_key,
    )

    print(f"Modified message accepted: {altered_valid}")
