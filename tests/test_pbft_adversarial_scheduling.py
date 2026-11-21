
import itertools
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "blockchain"))

from authentication import sign_message
from protocol import PBFTMessage, calculate_digest
from replica import PBFTReplica


VALIDATORS = [
    "GCS_01",
    "GCS_02",
    "GCS_03",
    "GCS_04",
]

HONEST = ["GCS_02", "GCS_03", "GCS_04"]
PRIMARY = "GCS_01"
VIEW = 0
QUORUM = 3
SEQUENCE = 1200

DIGEST_A = calculate_digest({
    "uav_id": "UAV_001",
    "event": "GPS_SPOOFING",
})

DIGEST_B = calculate_digest({
    "uav_id": "UAV_001",
    "event": "TELEMETRY_TAMPERING",
})


def signed_message(sender, phase, digest):
    message = PBFTMessage(
        phase=phase,
        view=VIEW,
        sequence=SEQUENCE,
        digest=digest,
        sender=sender,
    ).to_dict()

    return sign_message(sender, message)


def create_replicas():
    return {
        node_id: PBFTReplica(
            node_id=node_id,
            validator_ids=VALIDATORS,
        )
        for node_id in HONEST
    }


def run_schedule(assignments, seed):
    """
    Simulate a malicious primary sending A or B
    independently to each honest validator.

    Randomize authenticated PREPARE/COMMIT
    deliveries and preserve temporarily early
    COMMIT messages for later delivery.

    Honest validators generate a single PREPARE
    and COMMIT vote for their accepted digest.
    """

    rng = random.Random(seed)
    replicas = create_replicas()

    pending = []
    deferred = {node_id: [] for node_id in HONEST}

    prepared_nodes = set()
    committed_digests = set()

    # Every honest replica accepts one signed
    # primary proposal. The primary may equivocate.
    for node_id, digest in assignments.items():
        proposal = signed_message(
            PRIMARY,
            "PRE_PREPARE",
            digest,
        )

        result = replicas[node_id].process_message(
            proposal
        )

        assert result["accepted"] is True

        # Honest validator issues only its own
        # signed PREPARE for its accepted digest.
        prepare = signed_message(
            node_id,
            "PREPARE",
            digest,
        )

        for destination in HONEST:
            pending.append(
                (destination, prepare)
            )

    # Malicious primary equivocates by signing
    # PREPARE and COMMIT for both digests.
    # This deliberately bypasses VoteGuard,
    # modeling a compromised primary.
    for digest in [DIGEST_A, DIGEST_B]:
        for phase in ["PREPARE", "COMMIT"]:
            envelope = signed_message(
                PRIMARY,
                phase,
                digest,
            )

            for destination in HONEST:
                pending.append(
                    (destination, envelope)
                )

    # Include replayed malicious votes.
    for digest in [DIGEST_A, DIGEST_B]:
        duplicate = signed_message(
            PRIMARY,
            "PREPARE",
            digest,
        )

        for destination in HONEST:
            pending.append(
                (destination, duplicate)
            )

    deliveries = 0

    # Randomized asynchronous delivery.
    while pending:
        index = rng.randrange(len(pending))
        destination, envelope = pending.pop(index)

        replica = replicas[destination]
        result = replica.process_message(envelope)

        deliveries += 1

        if deliveries > 500:
            raise AssertionError(
                f"Delivery limit exceeded: "
                f"seed={seed}, assignments={assignments}"
            )

        if not result["accepted"]:
            reason = result.get("reason")

            # Early COMMIT must not bypass the
            # prepared condition. Keep it pending
            # until the destination becomes prepared.
            if reason == "Prepare quorum not reached":
                deferred[destination].append(envelope)
                continue


            # Expected harmless rejections:
            # - a conflicting digest
            # - a late PREPARE after local commitment
            #
            # Neither may change the committed value.
            if reason in (
                "Digest mismatch",
                "Request already committed",
            ):
                continue

            raise AssertionError(
                f"Unexpected rejection: {reason}"
            )


            continue

        state = replica.requests[(VIEW, SEQUENCE)]

        # The first time this replica becomes
        # prepared, generate its own COMMIT.
        if state.prepared and destination not in prepared_nodes:
            prepared_nodes.add(destination)

            commit = signed_message(
                destination,
                "COMMIT",
                state.digest,
            )

            for peer in HONEST:
                pending.append((peer, commit))

            # Retry COMMIT messages that previously
            # arrived too early at this destination.
            for early_commit in deferred[destination]:
                pending.append(
                    (destination, early_commit)
                )

            deferred[destination].clear()

        if state.committed:
            assert len(state.commit_voters) >= QUORUM
            assert state.prepared is True
            committed_digests.add(state.digest)

        # Byzantine agreement safety invariant:
        # honest replicas cannot have committed
        # different digests for this instance.
        assert len(committed_digests) <= 1, (
            "BYZANTINE AGREEMENT VIOLATION! "
            f"seed={seed}, assignments={assignments}, "
            f"digests={committed_digests}"
        )

    # Validate all honest replica states after
    # the message schedule has completed.
    final_committed = set()
    committed_nodes = 0

    for node_id, replica in replicas.items():
        state = replica.requests[(VIEW, SEQUENCE)]

        assert state.digest == assignments[node_id]

        if state.prepared:
            assert len(state.prepare_voters) >= QUORUM

        if state.committed:
            assert state.prepared is True
            assert len(state.commit_voters) >= QUORUM

            final_committed.add(state.digest)
            committed_nodes += 1

        # Any COMMIT left deferred must belong
        # to a replica that is still not prepared.
        if deferred[node_id]:
            assert state.prepared is False

    assert len(final_committed) <= 1, (
        "Conflicting honest commitments detected"
    )

    return {
        "committed_nodes": committed_nodes,
        "deliveries": deliveries,
        "agreement_preserved": True,
    }


# All 2^3 = 8 ways to distribute two
# conflicting proposals to three honest GCS.
PROPOSAL_SPLITS = list(
    itertools.product(
        [DIGEST_A, DIGEST_B],
        repeat=len(HONEST),
    )
)


@pytest.mark.parametrize(
    "proposal_split",
    PROPOSAL_SPLITS,
    ids=[
        "AAA",
        "AAB",
        "ABA",
        "ABB",
        "BAA",
        "BAB",
        "BBA",
        "BBB",
    ],
)
def test_adversarial_message_scheduling(proposal_split):
    assignments = dict(
        zip(HONEST, proposal_split)
    )

    total_schedules = 20
    observed_commits = 0

    for seed in range(total_schedules):
        result = run_schedule(
            assignments=assignments,
            seed=seed,
        )

        assert result["agreement_preserved"]

        if result["committed_nodes"] > 0:
            observed_commits += 1

    print(
        f"\nProposal split: "
        f"{''.join('A' if d == DIGEST_A else 'B' for d in proposal_split)}"
    )

    print(
        f"Schedules tested: {total_schedules}"
    )

    print(
        f"Schedules with honest commitments: "
        f"{observed_commits}"
    )

    print(
        "No conflicting honest commits observed."
    )
