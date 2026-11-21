
import argparse
import asyncio
import json

from authentication import load_registry, verify_message
from replica import PBFTReplica


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
