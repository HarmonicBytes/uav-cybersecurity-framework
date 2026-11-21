
import argparse
import asyncio
import json

from authentication import verify_message


async def handle_connection(reader, writer):
    peer = writer.get_extra_info("peername")

    try:
        data = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0,
        )

        if not data:
            return

        envelope = json.loads(data.decode("utf-8"))

        if not verify_message(envelope):
            response = {
                "status": "rejected",
                "node_id": NODE_ID,
                "reason": "Invalid or unauthorized signature",
            }

            print(f"{NODE_ID}: Rejected message from {peer}")

        else:
            message = envelope["message"]

            print(
                f"{NODE_ID}: Authenticated message "
                f"from {envelope['sender']}"
            )

            print(json.dumps(message, indent=2))

            response = {
                "status": "authenticated",
                "node_id": NODE_ID,
                "sender": envelope["sender"],
                "message_type": message.get("type"),
            }

        writer.write(
            (json.dumps(response) + "\n").encode("utf-8")
        )

        await writer.drain()

    except (
        asyncio.TimeoutError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as error:
        print(f"{NODE_ID}: Invalid request: {error}")

    finally:
        writer.close()
        await writer.wait_closed()


async def main(node_id, port):
    global NODE_ID
    NODE_ID = node_id

    server = await asyncio.start_server(
        handle_connection,
        host="127.0.0.1",
        port=port,
    )

    print(f"{NODE_ID} listening on 127.0.0.1:{port}")
    print("Signature verification enabled")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--id", required=True)
    parser.add_argument("--port", type=int, required=True)

    args = parser.parse_args()

    try:
        asyncio.run(main(args.id, args.port))
    except KeyboardInterrupt:
        print("\nNode stopped.")
