
from dataclasses import dataclass, field


@dataclass
class VoteGuard:
    """
    Prevent conflicting local PBFT votes.

    One validator must not sign different digests for
    the same phase, view, and sequence number.
    """

    votes: dict = field(default_factory=dict)

    def register(self, phase, view, sequence, digest):
        if phase not in ("PREPARE", "COMMIT"):
            raise ValueError("Unsupported voting phase")

        if type(view) is not int or view < 0:
            raise ValueError("Invalid view")

        if type(sequence) is not int or sequence < 1:
            raise ValueError("Invalid sequence")

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("Invalid digest")

        key = (phase, view, sequence)

        if key in self.votes:
            if self.votes[key] != digest:
                return {
                    "allowed": False,
                    "reason": "Conflicting local vote",
                }

            return {
                "allowed": False,
                "reason": "Vote already registered",
            }

        self.votes[key] = digest

        return {
            "allowed": True,
            "reason": "Vote registered",
        }
