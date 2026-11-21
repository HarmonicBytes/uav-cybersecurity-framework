
import json
import os
import tempfile
import time
from pathlib import Path

from block import Block, Blockchain
from protocol import calculate_digest
from commit_certificate import verify_commit_certificate

ROOT = Path(__file__).resolve().parents[2]

DEFAULT_LEDGER_PATH = (
    ROOT / "results" / "ledger" / "security_ledger.json"
)


class SecurityLedgerStore:
    """
    Local persistent, hash-linked security-event ledger.

    A caller must establish consensus before appending.
    This class does not independently verify PBFT quorum
    certificates or replicate blocks to GCS processes.
    """

    def __init__(self, path=DEFAULT_LEDGER_PATH):
        self.path = Path(path)

    def load(self):
        blockchain = Blockchain()

        if not self.path.exists():
            return blockchain

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        if not isinstance(data, list):
            raise ValueError(
                "Invalid ledger format: expected list"
            )

        for item in data:
            if not isinstance(item, dict):
                raise ValueError("Invalid block format")

            block = Block(
                index=item["index"],
                timestamp=item["timestamp"],
                previous_hash=item["previous_hash"],
                event=item["event"],
                validator_signatures=item.get(
                    "validator_signatures", []
                ),
                block_hash=item["block_hash"],
            )

            if not blockchain.add_block(block):
                raise ValueError(
                    f"Ledger integrity failure at "
                    f"block {block.index}"
                )

        if not blockchain.verify_chain():
            raise ValueError(
                "Stored blockchain integrity verification failed"
            )

        return blockchain

    def _save(self, blockchain):
        if not blockchain.verify_chain():
            raise ValueError(
                "Refusing to save an invalid blockchain"
            )

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        data = [
            {
                "index": block.index,
                "timestamp": block.timestamp,
                "previous_hash": block.previous_hash,
                "event": block.event,
                "validator_signatures": (
                    block.validator_signatures
                ),
                "block_hash": block.block_hash,
            }
            for block in blockchain.chain
        ]

        # Write a complete replacement file first,
        # then atomically replace the existing file.
        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=".ledger-",
                suffix=".tmp",
                delete=False,
            ) as file:
                temporary_path = Path(file.name)
                json.dump(
                    data,
                    file,
                    indent=2,
                    allow_nan=False,
                )
                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary_path, self.path)

        finally:
            if (
                temporary_path is not None
                and temporary_path.exists()
            ):
                temporary_path.unlink()

    def append_committed_alert(
        self,
        alert,
        committed_digest,
        view,
        sequence,
        committed_validators,
        commit_certificate=None,
    ):
        """
        Persist an alert only after the caller
        confirms the required PBFT commitments.
        """

        if not isinstance(alert, dict):
            raise ValueError("Alert must be an object")

        actual_digest = calculate_digest(alert)

        if actual_digest != committed_digest:
            raise ValueError(
                "Alert digest does not match committed digest"
            )

        if (
            type(view) is not int
            or type(sequence) is not int
            or sequence < 1
        ):
            raise ValueError(
                "Invalid consensus instance"
            )

        if (
            not isinstance(committed_validators, list)
            or len(committed_validators) < 3
            or len(committed_validators)
            != len(set(committed_validators))
            or any(
                not isinstance(node_id, str)
                for node_id in committed_validators
            )
        ):
            raise ValueError(
                "Invalid committed-validator list"
            )

        # Verify the original signed COMMIT envelopes
        # before storing a certificate-backed event.
        if commit_certificate is not None:
            verification = verify_commit_certificate(
                alert=alert,
                certificate=commit_certificate,
                view=view,
                sequence=sequence,
            )

            if verification["digest"] != committed_digest:
                raise ValueError(
                    "Certificate digest mismatch"
                )

            if set(verification["validators"]) != set(
                committed_validators
            ):
                raise ValueError(
                    "Certificate validators do not match "
                    "recorded committed validators"
                )

        blockchain = self.load()

        # Initialize the chain on first use.
        if not blockchain.chain:
            genesis = Block(
                index=0,
                timestamp=time.time(),
                previous_hash="0" * 64,
                event={"type": "GENESIS"},
            )
            genesis.seal()

            if not blockchain.add_block(genesis):
                raise RuntimeError(
                    "Unable to initialize genesis block"
                )

        # Prevent recording the same consensus
        # instance more than once.
        for existing in blockchain.chain[1:]:
            consensus = existing.event.get(
                "consensus", {}
            )

            if (
                consensus.get("view") == view
                and consensus.get("sequence") == sequence
            ):
                raise ValueError(
                    "Consensus instance already recorded"
                )

        previous = blockchain.chain[-1]

        record = {
            "type": "COMMITTED_SECURITY_ALERT",
            "alert": alert,
            "alert_digest": committed_digest,
            "consensus": {
                "protocol": "PBFT_PROTOTYPE",
                "view": view,
                "sequence": sequence,
                "committed_validators": (
                    committed_validators
                ),
                "commitment_source": (
                    "integration_client_observation"
                ),
            },
        }

        # Store cryptographic evidence within the event
        # itself, so it is covered by the block hash.
        if commit_certificate is not None:
            record["consensus"]["commit_certificate"] = (
                commit_certificate
            )
            record["consensus"]["certificate_verified"] = True

        block = Block(
            index=previous.index + 1,
            timestamp=time.time(),
            previous_hash=previous.block_hash,
            event=record,
        )

        block.seal()

        if not blockchain.add_block(block):
            raise RuntimeError(
                "Unable to append security event block"
            )

        self._save(blockchain)

        return {
            "block_index": block.index,
            "block_hash": block.block_hash,
            "alert_digest": committed_digest,
            "chain_length": len(blockchain.chain),
            "chain_valid": blockchain.verify_chain(),
        }

    def verify(self):
        blockchain = self.load()

        return {
            "valid": blockchain.verify_chain(),
            "blocks": len(blockchain.chain),
            "latest_hash": (
                blockchain.chain[-1].block_hash
                if blockchain.chain else None
            ),
        }


if __name__ == "__main__":
    store = SecurityLedgerStore()
    print(json.dumps(store.verify(), indent=2))
