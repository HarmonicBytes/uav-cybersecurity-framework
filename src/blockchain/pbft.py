
import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional

from validator import (
    GCSValidator,
    create_validator_network,
)


@dataclass(frozen=True)
class SignedVote:
    sender_id: str
    message: dict
    signature: str


class PBFTConsensus:
    """
    Simplified in-process PBFT protocol prototype.

    Implements:
      - Authenticated PRE-PREPARE
      - Authenticated PREPARE votes
      - Authenticated COMMIT votes
      - Quorum checking
      - Faulty validator omission simulation

    Does not yet implement:
      - Real network transport
      - View changes
      - Persistent replicas
      - Concurrent requests
    """

    def __init__(self, validators: List[GCSValidator]):
        self.validators = validators
        self.validator_map: Dict[str, GCSValidator] = {
            v.validator_id: v for v in validators
        }

        self.n = len(validators)
        self.f = (self.n - 1) // 3
        self.quorum = 2 * self.f + 1

        if self.n < 4 or self.n < 3 * self.f + 1:
            raise ValueError("Invalid PBFT validator configuration")

        self.view = 0
        self.sequence = 0

    @staticmethod
    def digest_event(event: dict) -> str:
        payload = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

        return hashlib.sha256(payload).hexdigest()

    def create_vote(
        self,
        validator: GCSValidator,
        phase: str,
        sequence: int,
        digest: str,
    ) -> SignedVote:

        message = {
            "phase": phase,
            "view": self.view,
            "sequence": sequence,
            "digest": digest,
            "sender": validator.validator_id,
        }

        return SignedVote(
            sender_id=validator.validator_id,
            message=message,
            signature=validator.sign_message(message),
        )

    def verify_vote(
        self,
        vote: SignedVote,
        expected_phase: str,
        sequence: int,
        digest: str,
    ) -> bool:

        validator = self.validator_map.get(vote.sender_id)

        if validator is None:
            return False

        expected_message = {
            "phase": expected_phase,
            "view": self.view,
            "sequence": sequence,
            "digest": digest,
            "sender": vote.sender_id,
        }

        if vote.message != expected_message:
            return False

        return GCSValidator.verify_signature(
            vote.message,
            vote.signature,
            validator.public_key,
        )

    def collect_votes(
        self,
        phase: str,
        sequence: int,
        digest: str,
    ) -> List[SignedVote]:

        valid_votes = []

        for validator in self.validators:
            # Fault model: Byzantine validators omit votes.
            if validator.is_byzantine:
                continue

            vote = self.create_vote(
                validator,
                phase,
                sequence,
                digest,
            )

            if self.verify_vote(
                vote,
                phase,
                sequence,
                digest,
            ):
                valid_votes.append(vote)

        return valid_votes

    def execute(self, event: dict) -> dict:
        self.sequence += 1

        sequence = self.sequence
        digest = self.digest_event(event)

        primary = self.validators[self.view % self.n]

        print(f"\nRequest sequence: {sequence}")
        print(f"Primary validator: {primary.validator_id}")
        print(f"Required quorum: {self.quorum}/{self.n}")

        # Phase 1: PRE-PREPARE
        if primary.is_byzantine:
            return {
                "success": False,
                "reason": "Primary unavailable; view change not implemented",
            }

        proposal = self.create_vote(
            primary,
            "PRE-PREPARE",
            sequence,
            digest,
        )

        if not self.verify_vote(
            proposal,
            "PRE-PREPARE",
            sequence,
            digest,
        ):
            return {
                "success": False,
                "reason": "Invalid primary proposal",
            }

        print("PRE-PREPARE: Primary proposal verified")

        # Phase 2: PREPARE
        prepare_votes = self.collect_votes(
            "PREPARE",
            sequence,
            digest,
        )

        prepare_count = len({
            vote.sender_id for vote in prepare_votes
        })

        print(f"PREPARE: {prepare_count} authenticated votes")

        if prepare_count < self.quorum:
            return {
                "success": False,
                "reason": "Prepare quorum not reached",
                "prepare_votes": prepare_count,
            }

        # Phase 3: COMMIT
        commit_votes = self.collect_votes(
            "COMMIT",
            sequence,
            digest,
        )

        commit_count = len({
            vote.sender_id for vote in commit_votes
        })

        print(f"COMMIT: {commit_count} authenticated votes")

        success = commit_count >= self.quorum

        return {
            "success": success,
            "sequence": sequence,
            "view": self.view,
            "digest": digest,
            "primary": primary.validator_id,
            "prepare_votes": prepare_count,
            "commit_votes": commit_count,
            "quorum": self.quorum,
            "reason": (
                "Quorum reached"
                if success
                else "Commit quorum not reached"
            ),
        }


def run_scenario(name: str, faulty_ids: List[str]):
    validators = create_validator_network(4)

    for validator in validators:
        validator.is_byzantine = (
            validator.validator_id in faulty_ids
        )

    consensus = PBFTConsensus(validators)

    event = {
        "uav_id": "UAV_001",
        "event_type": "GPS_SPOOFING_ALERT",
        "anomaly_score": 4.25,
    }

    print("\n" + "=" * 55)
    print(name)
    print("=" * 55)

    result = consensus.execute(event)

    print(f"Consensus success: {result['success']}")
    print(f"Reason: {result['reason']}")

    return result


if __name__ == "__main__":

    run_scenario(
        "SCENARIO A: All four validators operational",
        faulty_ids=[],
    )

    run_scenario(
        "SCENARIO B: One replica omits votes",
        faulty_ids=["GCS_04"],
    )

    run_scenario(
        "SCENARIO C: Two replicas omit votes",
        faulty_ids=["GCS_03", "GCS_04"],
    )
