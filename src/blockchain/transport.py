
import asyncio
import json

from authentication import load_registry, sign_message


class PBFTTransport:
    """
    Authenticated network transport between GCS validators.

    Each sender signs messages using its own identity.
    """

    def __init__(self, node_id):
        self.node_id = node_id
        self.registry = load_registry()

        if node_id not in self.registry:
            raise ValueError(
                f"Unknown validator: {node_id}"
            )

    async def send(self, destination_id, message):
        if destination_id not in self.registry:
            raise ValueError(
                f"Unknown destination: {destination_id}"
            )

        destination = self.registry[destination_id]

        envelope = sign_message(
            self.node_id,
            message,
        )

        writer = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    destination["host"],
                    destination["port"],
                ),
                timeout=5.0,
            )

            writer.write(
                (json.dumps(envelope) + "\n")
                .encode("utf-8")
            )

            await writer.drain()

            data = await asyncio.wait_for(
                reader.readline(),
                timeout=5.0,
            )

            if not data:
                raise ConnectionError(
                    "Empty response from validator"
                )

            return json.loads(
                data.decode("utf-8")
            )

        except (
            OSError,
            asyncio.TimeoutError,
            json.JSONDecodeError,
        ) as error:
            return {
                "status": "error",
                "node_id": destination_id,
                "reason": str(error),
            }

        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()

    async def broadcast(self, message):
        """
        Send the same signed message to all other
        registered validators concurrently.
        """

        destinations = [
            validator_id
            for validator_id in self.registry
            if validator_id != self.node_id
        ]

        responses = await asyncio.gather(
            *[
                self.send(destination, message)
                for destination in destinations
            ]
        )

        return dict(zip(destinations, responses))

    async def broadcast_prepare(self, message):
        """
        Broadcast a PREPARE message with bounded retries.

        A destination may temporarily reject PREPARE
        if its PRE-PREPARE proposal has not arrived.
        """

        destinations = [
            validator_id
            for validator_id in self.registry
            if validator_id != self.node_id
        ]

        async def send_with_retry(destination_id):
            for attempt in range(5):
                response = await self.send(
                    destination_id,
                    message,
                )

                if response.get("status") == "pbft_processed":
                    return response

                reason = response.get("result", {}).get(
                    "reason",
                    response.get("reason", ""),
                )

                if reason != "No accepted primary proposal":
                    return response

                await asyncio.sleep(0.1 * (attempt + 1))

            return {
                "status": "retry_exhausted",
                "node_id": destination_id,
            }

        responses = await asyncio.gather(
            *[
                send_with_retry(destination)
                for destination in destinations
            ]
        )

        return dict(zip(destinations, responses))
