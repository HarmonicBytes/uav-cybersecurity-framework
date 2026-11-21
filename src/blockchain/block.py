
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Block:
    index: int
    timestamp: float
    previous_hash: str
    event: Dict[str, Any]
    validator_signatures: List[str] = field(
        default_factory=list
    )
    block_hash: str = ""

    def calculate_hash(self) -> str:
        """
        Calculate a deterministic SHA-256 hash
        of the block's immutable event content.
        """

        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "event": self.event,
        }

        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    def seal(self):
        self.block_hash = self.calculate_hash()

    def verify_integrity(self) -> bool:
        return self.block_hash == self.calculate_hash()


class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []

    def add_block(self, block: Block) -> bool:
        """
        Append a block only when its content hash
        and chain linkage are valid.

        Consensus verification will be added
        in a separate module.
        """

        if not block.verify_integrity():
            return False

        if self.chain:
            previous = self.chain[-1]

            if block.index != previous.index + 1:
                return False

            if block.previous_hash != previous.block_hash:
                return False

        else:
            if block.index != 0:
                return False

            if block.previous_hash != "0" * 64:
                return False

        self.chain.append(block)
        return True

    def verify_chain(self) -> bool:
        previous_hash = "0" * 64

        for expected_index, block in enumerate(self.chain):
            if block.index != expected_index:
                return False

            if block.previous_hash != previous_hash:
                return False

            if not block.verify_integrity():
                return False

            previous_hash = block.block_hash

        return True


if __name__ == "__main__":
    import time

    blockchain = Blockchain()

    genesis = Block(
        index=0,
        timestamp=time.time(),
        previous_hash="0" * 64,
        event={"type": "GENESIS"},
    )
    genesis.seal()

    blockchain.add_block(genesis)

    alert = Block(
        index=1,
        timestamp=time.time(),
        previous_hash=genesis.block_hash,
        event={
            "uav_id": "UAV_001",
            "event_type": "GPS_SPOOFING_ALERT",
            "anomaly_score": 4.25,
        },
    )
    alert.seal()

    accepted = blockchain.add_block(alert)

    print("UAV Blockchain Test")
    print("=" * 40)
    print(f"Block accepted: {accepted}")
    print(f"Total blocks: {len(blockchain.chain)}")
    print(f"Chain valid: {blockchain.verify_chain()}")
    print(f"Latest hash: {alert.block_hash}")

    # Demonstrate tamper detection
    alert.event["anomaly_score"] = 0.01

    print("\nAfter unauthorized event modification:")
    print(f"Chain valid: {blockchain.verify_chain()}")
