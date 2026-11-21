
import copy
import hashlib
import threading
from authentication import REGISTRY_PATH
from pathlib import Path
from block import Block
from commit_certificate import verify_commit_certificate
from ledger_store import SecurityLedgerStore
from protocol import calculate_digest


class LedgerReplicationError(ValueError):
    """A replicated block failed validation."""


class ReplicaLedgerStore:
    """
    Independent ledger storage for one GCS.

    A trusted genesis hash identifies the intended chain.
    Replicas accept canonical blocks in index order.

    This module does not initiate PBFT consensus.
    """

    def __init__(
        self,
        node_id,
        path=None,
        trusted_genesis_hash=None,
    ):
        if node_id not in {
            "GCS_01",
            "GCS_02",
            "GCS_03",
            "GCS_04",
        }:
            raise ValueError("Unknown GCS validator")

        if (
            not isinstance(trusted_genesis_hash, str)
            or len(trusted_genesis_hash) != 64
        ):
            raise ValueError(
                "A trusted genesis hash is required"
            )

        self.node_id = node_id
        self.trusted_genesis_hash = trusted_genesis_hash

        if path is None:
            root = Path(__file__).resolve().parents[2]
            path = (
                root
                / "results"
                / "replicas"
                / node_id
                / "ledger.json"
            )

        self.store = SecurityLedgerStore(path=path)
        # Trusted only within this running process.
        # Nothing is loaded from an unauthenticated cache file.
        self._lock = threading.RLock()
        self._verified_fingerprint = None
        self._cached_status = None
    @staticmethod
    def _block_from_dict(data):
        if not isinstance(data, dict):
            raise LedgerReplicationError(
                "Block must be an object"
            )

        required = {
            "index",
            "timestamp",
            "previous_hash",
            "event",
            "block_hash",
        }

        if not required.issubset(data):
            raise LedgerReplicationError(
                "Missing block fields"
            )

        if (
            type(data["index"]) is not int
            or data["index"] < 0
            or type(data["timestamp"]) not in (int, float)
            or not isinstance(data["previous_hash"], str)
            or not isinstance(data["block_hash"], str)
            or not isinstance(data["event"], dict)
        ):
            raise LedgerReplicationError(
                "Invalid block fields"
            )

        # The existing Block hash does not cover
        # this auxiliary field. Do not accept it
        # as consensus evidence.
        if data.get("validator_signatures", []):
            raise LedgerReplicationError(
                "Unhashed validator signature field"
            )

        block = Block(
            index=data["index"],
            timestamp=data["timestamp"],
            previous_hash=data["previous_hash"],
            event=copy.deepcopy(data["event"]),
            validator_signatures=[],
            block_hash=data["block_hash"],
        )

        if not block.verify_integrity():
            raise LedgerReplicationError(
                "Invalid block hash"
            )

        return block

    def _verify_genesis(self, block):
        if block.index != 0:
            raise LedgerReplicationError(
                "Expected genesis block"
            )

        if block.previous_hash != "0" * 64:
            raise LedgerReplicationError(
                "Invalid genesis linkage"
            )

        if block.event != {"type": "GENESIS"}:
            raise LedgerReplicationError(
                "Unexpected genesis event"
            )

        if block.block_hash != self.trusted_genesis_hash:
            raise LedgerReplicationError(
                "Untrusted genesis block"
            )

    @staticmethod
    def _verify_certified_event(block):
        record = block.event

        if record.get("type") != "COMMITTED_SECURITY_ALERT":
            raise LedgerReplicationError(
                "Unexpected replicated event type"
            )

        alert = record.get("alert")
        consensus = record.get("consensus")

        if not isinstance(alert, dict):
            raise LedgerReplicationError(
                "Invalid alert"
            )

        if not isinstance(consensus, dict):
            raise LedgerReplicationError(
                "Invalid consensus metadata"
            )

        digest = calculate_digest(alert)

        if record.get("alert_digest") != digest:
            raise LedgerReplicationError(
                "Alert digest mismatch"
            )

        if consensus.get("protocol") != "PBFT_PROTOTYPE":
            raise LedgerReplicationError(
                "Unexpected consensus protocol"
            )

        view = consensus.get("view")
        sequence = consensus.get("sequence")
        certificate = consensus.get("commit_certificate")
        validators = consensus.get("committed_validators")

        if certificate is None:
            raise LedgerReplicationError(
                "Missing COMMIT certificate"
            )

        if (
            type(view) is not int
            or type(sequence) is not int
            or sequence < 1
        ):
            raise LedgerReplicationError(
                "Invalid consensus instance"
            )

        if not isinstance(validators, list):
            raise LedgerReplicationError(
                "Invalid validator list"
            )

        verification = verify_commit_certificate(
            alert=alert,
            certificate=certificate,
            view=view,
            sequence=sequence,
        )

        if (
            len(validators) != len(set(validators))
            or set(validators)
            != set(verification["validators"])
        ):
            raise LedgerReplicationError(
                "Certificate validators mismatch"
            )

        if consensus.get("certificate_verified") is not True:
            raise LedgerReplicationError(
                "Missing certificate metadata"
            )

        return (view, sequence)

    def _content_fingerprint(self):
        """
        Bind previously verified state to the actual
        ledger bytes and current validator registry.

        Hashing the file is cheaper than verifying
        every historical Ed25519 certificate again.
        """
        ledger_path = self.store.path

        ledger_bytes = (
            ledger_path.read_bytes()
            if ledger_path.exists()
            else b""
        )

        registry_bytes = REGISTRY_PATH.read_bytes()

        return (
            hashlib.sha256(ledger_bytes).digest(),
            hashlib.sha256(registry_bytes).digest(),
            ledger_path.exists(),
        )

    def _cache_verified_state(self, blockchain, verified_fingerprint):
        """
        Called only after successful integrity and
        certificate verification.
        """
        self._verified_fingerprint = verified_fingerprint

        self._cached_status = {
            "node_id": self.node_id,
            "valid": True,
            "blocks": len(blockchain.chain),
            "latest_index": (
                blockchain.chain[-1].index
                if blockchain.chain else None
            ),
            "latest_hash": (
                blockchain.chain[-1].block_hash
                if blockchain.chain else None
            ),
        }

    def _apply_block_locked(self, block_data):
        """
        Apply one canonical block after validation.

        Duplicate identical blocks are idempotent.
        Missing predecessors and forks are rejected.
        """

        block = self._block_from_dict(block_data)
        blockchain = self.store.load()

        # Verify this ledger's trust anchor.
        if blockchain.chain:
            self._verify_genesis(blockchain.chain[0])

        # Recheck existing certified blocks before
        # extending the replica's ledger.
        for existing in blockchain.chain[1:]:
            self._verify_certified_event(existing)

        if block.index == 0:
            self._verify_genesis(block)
            instance = None
        else:
            instance = self._verify_certified_event(block)

        # Already received this exact canonical block.
        if block.index < len(blockchain.chain):
            existing = blockchain.chain[block.index]

            if (
                existing.block_hash == block.block_hash
                and existing.timestamp == block.timestamp
                and existing.previous_hash == block.previous_hash
                and existing.event == block.event
            ):
                return {
                    "status": "already_present",
                    "node_id": self.node_id,
                    "block_index": block.index,
                    "block_hash": block.block_hash,
                }

            raise LedgerReplicationError(
                "Conflicting block at existing index"
            )

        if block.index != len(blockchain.chain):
            raise LedgerReplicationError(
                "Missing preceding blocks"
            )

        if instance is not None:
            for existing in blockchain.chain[1:]:
                consensus = existing.event["consensus"]

                if (
                    consensus["view"] == instance[0]
                    and consensus["sequence"] == instance[1]
                ):
                    raise LedgerReplicationError(
                        "Consensus instance already recorded"
                    )

        if not blockchain.add_block(block):
            raise LedgerReplicationError(
                "Block linkage verification failed"
            )

        self.store._save(blockchain)

        return {
            "status": "appended",
            "node_id": self.node_id,
            "block_index": block.index,
            "block_hash": block.block_hash,
        }


    def apply_block(self, block_data):
        """
        Serialize append operations with status checks
        within this ReplicaLedgerStore instance.
        """
        with self._lock:
            try:
                return self._apply_block_locked(block_data)
            finally:
                # Any append attempt can affect the
                # previously verified in-memory state.
                self._verified_fingerprint = None
                self._cached_status = None

    def status(self, full_audit=False):
        """
        Return verified ledger status.

        Reuse verified state only if both the ledger
        content and validator registry are unchanged.

        full_audit=True always verifies the complete
        chain and every historical COMMIT certificate.
        """
        with self._lock:
            before = self._content_fingerprint()

            if (
                not full_audit
                and self._cached_status is not None
                and before == self._verified_fingerprint
            ):
                return dict(self._cached_status)

            blockchain = self.store.load()

            if blockchain.chain:
                self._verify_genesis(
                    blockchain.chain[0]
                )

            for block in blockchain.chain[1:]:
                self._verify_certified_event(block)

            if not blockchain.verify_chain():
                raise LedgerReplicationError(
                    "Ledger integrity verification failed"
                )

            after = self._content_fingerprint()

            if before != after:
                self._verified_fingerprint = None
                self._cached_status = None
                raise LedgerReplicationError(
                    "Ledger or validator registry changed "
                    "during verification"
                )

            self._cache_verified_state(blockchain, verified_fingerprint=after)

            return dict(self._cached_status)

