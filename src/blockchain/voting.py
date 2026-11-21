
from protocol import PBFTMessage
from vote_guard import VoteGuard
from authentication import sign_message


class PBFTVotingService:
    """
    Generates authenticated PBFT votes for one GCS node.

    Prevents duplicate or conflicting local votes.
    """

    def __init__(self, node_id):
        self.node_id = node_id
        self.guard = VoteGuard()

    def create_vote(
        self,
        phase,
        view,
        sequence,
        digest,
        prepared=False,
    ):
        """
        Generate a signed PREPARE or COMMIT vote.

        A COMMIT vote is permitted only if this
        validator's local replica is prepared.
        """

        if phase == "COMMIT" and not prepared:
            return {
                "success": False,
                "reason": "Local replica not prepared",
            }

        result = self.guard.register(
            phase=phase,
            view=view,
            sequence=sequence,
            digest=digest,
        )

        if not result["allowed"]:
            return {
                "success": False,
                "reason": result["reason"],
            }

        message = PBFTMessage(
            phase=phase,
            view=view,
            sequence=sequence,
            digest=digest,
            sender=self.node_id,
        )

        envelope = sign_message(
            self.node_id,
            message.to_dict(),
        )

        return {
            "success": True,
            "envelope": envelope,
        }
