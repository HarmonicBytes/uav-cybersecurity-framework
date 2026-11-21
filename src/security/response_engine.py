
import json
import math
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

DEFAULT_RESPONSE_PATH = (
    ROOT / "results" / "responses" / "response_log.json"
)


class DefensiveResponseEngine:
    """
    Simulated policy-based defensive response engine.

    Actions are recorded in a JSON file.
    No UAV commands or external notifications are sent.

    This implementation uses a single local writer.
    It is not a distributed response coordinator.
    """

    def __init__(self, ledger_store, path=DEFAULT_RESPONSE_PATH):
        self.ledger_store = ledger_store
        self.path = Path(path)

    def _load_responses(self):
        if not self.path.exists():
            return []

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as file:
            records = json.load(file)

        if not isinstance(records, list):
            raise ValueError(
                "Invalid response-log format"
            )

        if any(
            not isinstance(record, dict)
            for record in records
        ):
            raise ValueError(
                "Invalid response-log record"
            )

        return records

    def _save_responses(self, records):
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=".responses-",
                suffix=".tmp",
                delete=False,
            ) as file:
                temporary_path = Path(file.name)

                json.dump(
                    records,
                    file,
                    indent=2,
                    allow_nan=False,
                )

                file.flush()
                os.fsync(file.fileno())

            os.replace(
                temporary_path,
                self.path,
            )

        finally:
            if (
                temporary_path is not None
                and temporary_path.exists()
            ):
                temporary_path.unlink()

    @staticmethod
    def _evaluate_policy(alert):
        """
        Return simulated actions for a committed anomaly.

        Ratio thresholds are illustrative research settings.
        They are not calibrated attack-severity thresholds.
        """

        if alert.get("detection_result") != "ANOMALY":
            return "NONE", []

        score = float(alert["anomaly_score"])
        threshold = float(alert["threshold"])

        if (
            not math.isfinite(score)
            or not math.isfinite(threshold)
            or threshold <= 0
            or score <= threshold
        ):
            raise ValueError(
                "Invalid confirmed anomaly measurements"
            )

        ratio = score / threshold

        actions = [
            {
                "action": "NOTIFY_SECURITY_OPERATOR",
                "mode": "SIMULATED",
                "reason": "Committed telemetry anomaly",
            },
            {
                "action": "INCREASE_TELEMETRY_MONITORING",
                "mode": "SIMULATED",
                "reason": "Additional observation recommended",
            },
        ]

        severity = "ELEVATED"

        # Demonstration policy only.
        if ratio >= 10.0:
            severity = "HIGH"

            actions.append({
                "action": "REQUEST_MANUAL_UAV_INSPECTION",
                "mode": "SIMULATED",
                "reason": (
                    "Anomaly score exceeds ten times "
                    "the detection threshold"
                ),
            })

        return severity, actions

    def process_committed_alert(
        self,
        block_index,
        expected_digest,
        view,
        sequence,
        require_certificate=False,
    ):
        """
        Verify a persisted alert and record a simulated
        defensive response once per committed block.

        The ledger's validator metadata is an
        integration-client assertion, not a verified
        cryptographic PBFT commit certificate.
        """

        start_ns = time.perf_counter_ns()

        # Load and independently check the stored hash chain.
        blockchain = self.ledger_store.load()

        if not blockchain.verify_chain():
            raise ValueError(
                "Ledger integrity verification failed"
            )

        if (
            type(block_index) is not int
            or block_index < 1
            or block_index >= len(blockchain.chain)
        ):
            raise ValueError(
                "Committed block not found"
            )

        block = blockchain.chain[block_index]

        if block.index != block_index:
            raise ValueError(
                "Ledger block index mismatch"
            )

        record = block.event

        if record.get("type") != "COMMITTED_SECURITY_ALERT":
            raise ValueError(
                "Block is not a committed security alert"
            )

        alert = record.get("alert")
        consensus = record.get("consensus")

        if not isinstance(alert, dict):
            raise ValueError("Invalid stored alert")

        if not isinstance(consensus, dict):
            raise ValueError(
                "Invalid stored consensus metadata"
            )

        # Import locally to reuse the protocol's
        # canonical alert-digest calculation.
        from protocol import calculate_digest

        actual_digest = calculate_digest(alert)

        if (
            record.get("alert_digest") != expected_digest
            or actual_digest != expected_digest
        ):
            raise ValueError(
                "Stored alert digest mismatch"
            )

        if (
            consensus.get("view") != view
            or consensus.get("sequence") != sequence
        ):
            raise ValueError(
                "Consensus instance mismatch"
            )

        validators = consensus.get(
            "committed_validators"
        )

        if (
            not isinstance(validators, list)
            or len(validators) < 3
            or len(validators) != len(set(validators))
        ):
            raise ValueError(
                "Invalid recorded validator metadata"
            )

        # Certified records must carry independently
        # verifiable signed COMMIT evidence.
        certificate = consensus.get("commit_certificate")

        if certificate is None:
            if require_certificate:
                raise ValueError(
                    "Missing signed COMMIT certificate"
                )
        else:
            from commit_certificate import (
                verify_commit_certificate,
            )

            verification = verify_commit_certificate(
                alert=alert,
                certificate=certificate,
                view=view,
                sequence=sequence,
            )

            if verification["digest"] != expected_digest:
                raise ValueError(
                    "Certificate digest mismatch"
                )

            if set(verification["validators"]) != set(
                validators
            ):
                raise ValueError(
                    "Certificate validator mismatch"
                )

        responses = self._load_responses()

        # The block hash identifies the already
        # processed local ledger record.
        for existing in responses:
            if existing.get("block_hash") == block.block_hash:
                return {
                    "status": "ALREADY_PROCESSED",
                    "block_hash": block.block_hash,
                    "actions": existing["actions"],
                    "severity": existing["severity"],
                    "response_latency_ms": 0.0,
                }

        severity, actions = self._evaluate_policy(alert)

        response = {
            "block_index": block.index,
            "block_hash": block.block_hash,
            "alert_digest": expected_digest,
            "view": view,
            "sequence": sequence,
            "severity": severity,
            "actions": actions,
            "executed_at_utc": datetime.now(
                timezone.utc
            ).isoformat(),
        }

        responses.append(response)
        self._save_responses(responses)

        elapsed_ms = (
            time.perf_counter_ns() - start_ns
        ) / 1_000_000

        return {
            "status": "RECORDED",
            "block_hash": block.block_hash,
            "severity": severity,
            "actions": actions,
            "response_latency_ms": round(
                elapsed_ms, 6
            ),
        }
