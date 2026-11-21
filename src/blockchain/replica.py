
import re
from dataclasses import dataclass, field

from authentication import verify_message
from protocol import PBFTMessage


@dataclass
class RequestState:
    digest: str
    prepare_voters: set = field(default_factory=set)
    commit_voters: set = field(default_factory=set)
    prepared: bool = False
    committed: bool = False


class PBFTReplica:
    """
    Local PBFT state for one GCS validator.

    This implementation processes authenticated
    PBFT messages and tracks replica-local quorums.

    Network broadcasting and view changes are
    implemented separately.
    """

    def __init__(self, node_id, validator_ids):
        self.node_id = node_id
        self.validator_ids = set(validator_ids)

        self.n = len(self.validator_ids)
        self.f = (self.n - 1) // 3
        self.quorum = 2 * self.f + 1

        if self.n < 4:
            raise ValueError(
                "At least four validators are required"
            )

        if node_id not in self.validator_ids:
            raise ValueError("Unknown local validator")

        self.requests = {}

    def process_message(self, envelope):
        """
        Process one authenticated PBFT message.

        Returns a result describing the local
        replica's current consensus state.
        """

        if not verify_message(envelope):
            return self._reject("Invalid signature")

        message = envelope.get("message", {})
        sender = envelope.get("sender")

        if not isinstance(message, dict):
            return self._reject("Invalid message")

        if message.get("sender") != sender:
            return self._reject("Sender identity mismatch")

        if sender not in self.validator_ids:
            return self._reject("Unknown validator")

        try:
            pbft = PBFTMessage(
                phase=message["phase"],
                view=message["view"],
                sequence=message["sequence"],
                digest=message["digest"],
                sender=sender,
            )
        except (KeyError, TypeError, ValueError):
            return self._reject("Invalid PBFT fields")

        if message != pbft.to_dict():
            return self._reject("Unexpected message fields")

        if not re.fullmatch(
            r"[0-9a-f]{64}", pbft.digest
        ):
            return self._reject("Invalid digest")

        # Prototype currently supports view 0 only.
        if pbft.view != 0:
            return self._reject("Unsupported view")

        primary = "GCS_01"

        key = (pbft.view, pbft.sequence)

        # PRE-PREPARE: accept primary proposal.
        if pbft.phase == "PRE_PREPARE":
            if sender != primary:
                return self._reject(
                    "Proposal not from primary"
                )

            existing = self.requests.get(key)

            if existing:
                if existing.digest != pbft.digest:
                    return self._reject(
                        "Conflicting proposal"
                    )
            else:
                self.requests[key] = RequestState(
                    digest=pbft.digest
                )

            return self._status(key)

        state = self.requests.get(key)

        if state is None:
            return self._reject(
                "No accepted primary proposal"
            )

        if state.digest != pbft.digest:
            return self._reject("Digest mismatch")

        if pbft.phase == "PREPARE":
            if state.committed:
                return self._reject(
                    "Request already committed"
                )

            state.prepare_voters.add(sender)

            if len(state.prepare_voters) >= self.quorum:
                state.prepared = True

            return self._status(key)

        if pbft.phase == "COMMIT":
            if not state.prepared:
                return self._reject(
                    "Prepare quorum not reached"
                )

            state.commit_voters.add(sender)

            if len(state.commit_voters) >= self.quorum:
                state.committed = True

            return self._status(key)

        return self._reject("Unsupported phase")

    @staticmethod
    def _reject(reason):
        return {
            "accepted": False,
            "reason": reason,
        }

    def _status(self, key):
        state = self.requests[key]

        return {
            "accepted": True,
            "node_id": self.node_id,
            "prepare_votes": len(
                state.prepare_voters
            ),
            "commit_votes": len(
                state.commit_voters
            ),
            "prepared": state.prepared,
            "committed": state.committed,
        }
