
import argparse
import asyncio
import json

from authentication import load_registry, verify_message
from replica import PBFTReplica
from voting import PBFTVotingService
from transport import PBFTTransport
from pathlib import Path

from ledger_genesis import TRUSTED_GENESIS_HASH
from ledger_replication import (
    ReplicaLedgerStore,
    LedgerReplicationError,
)

class GCSNode:
    """
    Ground Control Station server.

    Each process maintains its own local PBFTReplica.
    """

    def __init__(self, node_id, port):
        self.node_id = node_id
        self.port = port

        self.registry = load_registry()

        if node_id not in self.registry:
            raise ValueError(
                f"Unknown validator: {node_id}"
            )

        expected_port = self.registry[node_id]["port"]

        if port != expected_port:
            raise ValueError(
                f"Expected port {expected_port} for {node_id}"
            )

        self.replica = PBFTReplica(
            node_id=node_id,
            validator_ids=list(self.registry.keys()),
        )
        # Each GCS generates and signs its own PBFT votes.
        self.voting = PBFTVotingService(node_id)

        # Authenticated communication with other validators.
        self.transport = PBFTTransport(node_id)

        # Track ongoing background broadcasts.
        self.background_tasks = set()

        # Preserve this validator's own signed COMMIT votes.
        # Key: (view, sequence)
        self.local_commit_envelopes = {}
        
        # Separate persistent ledger for this GCS.
        # The existing central ledger is not changed.
        root = Path(__file__).resolve().parents[2]

        self.replica_ledger = ReplicaLedgerStore(
            node_id=node_id,
            path=(
                root
                / "results"
                / "replicas"
                / node_id
                / "ledger.json"
            ),
            trusted_genesis_hash=TRUSTED_GENESIS_HASH,
        )
    async def broadcast_local_prepare(self, message):
        """
        Broadcast this GCS node's own PREPARE vote
        to the other three validators.
        """

        try:
            print(
                f"{self.node_id}: Broadcasting PREPARE "
                f"for sequence {message['sequence']}"
            )

            responses = await self.transport.broadcast_prepare(
                message
            )

            for destination, response in responses.items():
                print(
                    f"{self.node_id} -> {destination}: "
                    f"{response.get('status')}"
                )

        except Exception as error:
            print(
                f"{self.node_id}: "
                f"PREPARE broadcast failed: {error}"
            )


    async def broadcast_local_commit(self, message):
        """
        Broadcast this validator's COMMIT vote.

        Retry temporarily rejected COMMIT messages
        when the destination has not yet reached
        its local PREPARE quorum.
        """

        async def send_with_retry(destination_id):
            max_attempts = 20
            retry_delay = 0.05

            for attempt in range(1, max_attempts + 1):
                try:
                    response = await self.transport.send(
                        destination_id,
                        message,
                    )

                    status = response.get("status")
                    result = response.get("result", {})
                    reason = (
                        result.get("reason", "")
                        if isinstance(result, dict)
                        else ""
                    )

                    if status == "pbft_processed":
                        print(
                            f"{self.node_id} -> "
                            f"{destination_id}: "
                            f"COMMIT accepted "
                            f"(attempt {attempt})"
                        )
                        return True

                    if reason not in (
                        "Prepare quorum not reached",
                        "No accepted primary proposal",
                    ):
                        print(
                            f"{self.node_id} -> "
                            f"{destination_id}: "
                            f"COMMIT rejected: {response}"
                        )
                        return False

                except (
                    OSError,
                    asyncio.TimeoutError,
                    ConnectionError,
                ) as error:
                    if attempt == max_attempts:
                        print(
                            f"{self.node_id} -> "
                            f"{destination_id}: "
                            f"COMMIT delivery failed: {error}"
                        )
                        return False

                if attempt < max_attempts:
                    await asyncio.sleep(retry_delay)

            print(
                f"{self.node_id} -> "
                f"{destination_id}: "
                "COMMIT retry limit reached"
            )
            return False

        destinations = [
            node_id
            for node_id in self.registry
            if node_id != self.node_id
        ]

        results = await asyncio.gather(
            *[
                send_with_retry(destination_id)
                for destination_id in destinations
            ]
        )

        accepted = sum(results)

        print(
            f"{self.node_id}: COMMIT broadcast completed "
            f"({accepted}/{len(destinations)} peers accepted)"
        )


    async def handle_connection(self, reader, writer):
        peer = writer.get_extra_info("peername")

        try:
            data = await asyncio.wait_for(
                reader.readline(),
                timeout=5.0,
            )

            if not data:
                return

            envelope = json.loads(
                data.decode("utf-8")
            )

            # Verify cryptographic identity.
            if not verify_message(envelope):
                response = {
                    "status": "rejected",
                    "node_id": self.node_id,
                    "reason": "Invalid signature",
                }

            else:
                message = envelope["message"]
                message_type = message.get("type")

                if message_type == "PBFT":

                    result = self.replica.process_message(
                        envelope
                    )
                    # Generate one local PREPARE vote after accepting
                    # a valid PRE-PREPARE proposal.
                    if (
                        result["accepted"]
                        and message.get("phase") == "PRE_PREPARE"
                    ):
                        vote = self.voting.create_vote(
                            phase="PREPARE",
                            view=message["view"],
                            sequence=message["sequence"],
                            digest=message["digest"],
                        )

                        if vote["success"]:
                            local_result = self.replica.process_message(
                                vote["envelope"]
                            )

                            if not local_result["accepted"]:
                                raise RuntimeError(
                                    "Locally generated PREPARE was rejected"
                                )

                            print(
                                f"{self.node_id}: "
                                "Local signed PREPARE generated"
                            )
                            result = local_result

                            # Broadcast in the background so the node
                            # can respond without blocking on other GCS servers.
                            task = asyncio.create_task(
                                self.broadcast_local_prepare(
                                    vote["envelope"]["message"]
                                )
                            )

                            self.background_tasks.add(task)
                            task.add_done_callback(
                                self.background_tasks.discard
                            )
                    # Check whether this replica has reached
                    # the local PBFT prepared condition.
                    if result["accepted"]:
                        view = message["view"]
                        sequence = message["sequence"]
                        digest = message["digest"]

                        state = self.replica.requests.get(
                            (view, sequence)
                        )

                        if (
                            state is not None
                            and state.prepared
                            and state.digest == digest
                        ):
                            commit_vote = self.voting.create_vote(
                                phase="COMMIT",
                                view=view,
                                sequence=sequence,
                                digest=digest,
                                prepared=state.prepared,
                            )

                            if commit_vote["success"]:

                                local_commit_result = (
                                    self.replica.process_message(
                                        commit_vote["envelope"]
                                    )
                                )


                                if not local_commit_result["accepted"]:
                                    raise RuntimeError(
                                        "Locally generated COMMIT "
                                        "was rejected"
                                    )

                                # Preserve the original signed
                                # envelope generated by this GCS.
                                # Do not sign another vote on request.
                                self.local_commit_envelopes[
                                    (view, sequence)
                                ] = commit_vote["envelope"]

                                result = local_commit_result


                                print(
                                    f"{self.node_id}: "
                                    "Local signed COMMIT generated"
                                )

                                task = asyncio.create_task(
                                    self.broadcast_local_commit(
                                        commit_vote["envelope"]["message"]
                                    )
                                )

                                self.background_tasks.add(task)
                                task.add_done_callback(
                                    self.background_tasks.discard
                                )

                    response = {
                        "status": (
                            "pbft_processed"
                            if result["accepted"]
                            else "rejected"
                        ),
                        "node_id": self.node_id,
                        "result": result,
                    }

                    print(
                        f"{self.node_id}: "
                        f"PBFT {message.get('phase')} "
                        f"from {envelope['sender']} "
                        f"=> {response['status']}"
                    )

                elif message_type == "PBFT_STATUS":
                    view = message.get("view")
                    sequence = message.get("sequence")

                    if (
                        type(view) is not int
                        or type(sequence) is not int
                        or view != 0
                        or sequence < 1
                    ):
                        response = {
                            "status": "rejected",
                            "node_id": self.node_id,
                            "reason": "Invalid status request",
                        }
                    else:
                        state = self.replica.requests.get(
                            (view, sequence)
                        )

                        response = {
                            "status": "ok",
                            "node_id": self.node_id,
                            "view": view,
                            "sequence": sequence,
                            "found": state is not None,
                            "local_commit_envelope": (
                                self.local_commit_envelopes.get(
                                    (view, sequence)
                                )
                                if (
                                    state is not None
                                    and state.committed
                                )
                                else None
                            ),
                            "result": (
                                {
                                    "prepare_votes": len(
                                        state.prepare_voters
                                    ),
                                    "commit_votes": len(
                                        state.commit_voters
                                    ),
                                    "prepared": state.prepared,
                                    "committed": state.committed,
                                    "digest": state.digest,

                                    # Internal PBFT phase timing measurements.
                                    **self.replica.timing_metrics(state),
                                }
                                if state is not None
                                else None
                            ),
                        }
                
                elif message_type == "LEDGER_STATUS":
                    # The request has already passed
                    # Ed25519 authentication.
                    result = self.replica_ledger.status()

                    response = {
                        "status": "ok",
                        "node_id": self.node_id,
                        "result": result,
                    }

                elif message_type == "LEDGER_APPEND":
                    # Only the designated integration
                    # primary can submit canonical blocks.
                    if envelope["sender"] != "GCS_01":
                        response = {
                            "status": "rejected",
                            "node_id": self.node_id,
                            "reason": "Unauthorized ledger writer",
                        }

                    else:
                        block_data = message.get("block")

                        try:
                            result = (
                                self.replica_ledger.apply_block(
                                    block_data
                                )
                            )

                            response = {
                                "status": "ledger_processed",
                                "node_id": self.node_id,
                                "result": result,
                            }

                            print(
                                f"{self.node_id}: "
                                f"Replicated block "
                                f"{result['block_index']} "
                                f"({result['status']})"
                            )

                        except (
                            LedgerReplicationError,
                            ValueError,
                            KeyError,
                            TypeError,
                        ) as error:
                            response = {
                                "status": "rejected",
                                "node_id": self.node_id,
                                "reason": str(error),
                            }


                elif message_type == "SECURITY_ALERT":
                    response = {
                        "status": "authenticated",
                        "node_id": self.node_id,
                        "sender": envelope["sender"],
                        "message_type": message_type,
                    }

                    print(
                        f"{self.node_id}: "
                        f"Authenticated security alert "
                        f"from {envelope['sender']}"
                    )

                else:
                    response = {
                        "status": "rejected",
                        "node_id": self.node_id,
                        "reason": "Unsupported message type",
                    }

            writer.write(
                (json.dumps(response) + "\n").encode(
                    "utf-8"
                )
            )

            await writer.drain()

        except (
            asyncio.TimeoutError,
            json.JSONDecodeError,
            UnicodeDecodeError,
            TypeError,
            ValueError,
        ) as error:

            response = {
                "status": "error",
                "node_id": self.node_id,
                "reason": str(error),
            }

            writer.write(
                (json.dumps(response) + "\n").encode(
                    "utf-8"
                )
            )

            await writer.drain()

            print(
                f"{self.node_id}: Request error from "
                f"{peer}: {error}"
            )

        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):

        server = await asyncio.start_server(
            self.handle_connection,
            host="127.0.0.1",
            port=self.port,
        )

        print("=" * 50)
        print(f"GCS NODE: {self.node_id}")
        print(f"Address: 127.0.0.1:{self.port}")
        print("Signature verification: ENABLED")
        print("PBFT replica state: ENABLED")
        print("=" * 50)

        async with server:
            await server.serve_forever()


async def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--id", required=True)
    parser.add_argument(
        "--port", type=int, required=True
    )

    args = parser.parse_args()

    node = GCSNode(args.id, args.port)

    await node.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nGCS node stopped.")
