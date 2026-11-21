
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict


PBFT_PHASES = {
    "PRE_PREPARE",
    "PREPARE",
    "COMMIT",
}


def calculate_digest(event: Dict[str, Any]) -> str:
    """Create a deterministic SHA-256 digest of an event."""

    payload = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class PBFTMessage:
    phase: str
    view: int
    sequence: int
    digest: str
    sender: str

    def __post_init__(self):
        if self.phase not in PBFT_PHASES:
            raise ValueError("Invalid PBFT phase")

        if self.view < 0 or self.sequence < 1:
            raise ValueError("Invalid view or sequence")

        if len(self.digest) != 64:
            raise ValueError("Invalid digest length")

        if not self.sender:
            raise ValueError("Sender is required")

    def to_dict(self) -> dict:
        return {
            "type": "PBFT",
            "phase": self.phase,
            "view": self.view,
            "sequence": self.sequence,
            "digest": self.digest,
            "sender": self.sender,
        }


if __name__ == "__main__":
    event = {
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING_ALERT",
        "anomaly_score": 4.25,
    }

    digest = calculate_digest(event)

    message = PBFTMessage(
        phase="PREPARE",
        view=0,
        sequence=1,
        digest=digest,
        sender="GCS_02",
    )

    print("Distributed PBFT Message Test")
    print("=" * 45)
    print(json.dumps(message.to_dict(), indent=2))
    print(f"Digest: {digest}")
