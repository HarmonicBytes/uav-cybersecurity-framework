
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0, str(ROOT / "src" / "blockchain")
)
sys.path.insert(
    0, str(ROOT / "src" / "security")
)

from ledger_store import SecurityLedgerStore
from protocol import calculate_digest
from response_engine import DefensiveResponseEngine


VALIDATORS = [
    "GCS_01",
    "GCS_02",
    "GCS_03",
    "GCS_04",
]


@pytest.fixture
def environment(tmp_path):
    ledger = SecurityLedgerStore(
        path=tmp_path / "ledger.json"
    )

    engine = DefensiveResponseEngine(
        ledger_store=ledger,
        path=tmp_path / "responses.json",
    )

    return ledger, engine


def make_alert(score=472.71368408, threshold=1.76960075):
    return {
        "uav_id": "UAV_001",
        "event_type": "UAV_TELEMETRY_ANOMALY",
        "anomaly_score": score,
        "threshold": threshold,
        "detection_result": "ANOMALY",
        "source": "pytorch_autoencoder",
    }


def persist_alert(ledger, alert, sequence=2000):
    digest = calculate_digest(alert)

    result = ledger.append_committed_alert(
        alert=alert,
        committed_digest=digest,
        view=0,
        sequence=sequence,
        committed_validators=VALIDATORS,
    )

    return result, digest


def respond(engine, result, digest, sequence=2000):
    return engine.process_committed_alert(
        block_index=result["block_index"],
        expected_digest=digest,
        view=0,
        sequence=sequence,
    )


def test_high_severity_response(environment):
    ledger, engine = environment
    alert = make_alert()

    result, digest = persist_alert(ledger, alert)
    response = respond(engine, result, digest)

    assert response["status"] == "RECORDED"
    assert response["severity"] == "HIGH"

    actions = {
        item["action"]
        for item in response["actions"]
    }

    assert actions == {
        "NOTIFY_SECURITY_OPERATOR",
        "INCREASE_TELEMETRY_MONITORING",
        "REQUEST_MANUAL_UAV_INSPECTION",
    }

    assert all(
        item["mode"] == "SIMULATED"
        for item in response["actions"]
    )


def test_elevated_severity_response(environment):
    ledger, engine = environment

    alert = make_alert(
        score=3.0,
        threshold=1.0,
    )

    result, digest = persist_alert(ledger, alert)
    response = respond(engine, result, digest)

    assert response["severity"] == "ELEVATED"
    assert len(response["actions"]) == 2


def test_response_is_idempotent(environment):
    ledger, engine = environment

    alert = make_alert()
    result, digest = persist_alert(ledger, alert)

    first = respond(engine, result, digest)
    second = respond(engine, result, digest)

    assert first["status"] == "RECORDED"
    assert second["status"] == "ALREADY_PROCESSED"

    records = json.loads(
        engine.path.read_text(encoding="utf-8")
    )

    assert len(records) == 1


def test_reject_incorrect_digest(environment):
    ledger, engine = environment

    result, digest = persist_alert(
        ledger, make_alert()
    )

    with pytest.raises(
        ValueError,
        match="Stored alert digest mismatch",
    ):
        respond(
            engine,
            result,
            "0" * 64,
        )

    assert not engine.path.exists()


def test_reject_wrong_sequence(environment):
    ledger, engine = environment

    result, digest = persist_alert(
        ledger, make_alert()
    )

    with pytest.raises(
        ValueError,
        match="Consensus instance mismatch",
    ):
        respond(
            engine,
            result,
            digest,
            sequence=9999,
        )

    assert not engine.path.exists()


def test_reject_tampered_ledger(environment):
    ledger, engine = environment

    result, digest = persist_alert(
        ledger, make_alert()
    )

    records = json.loads(
        ledger.path.read_text(encoding="utf-8")
    )

    records[1]["event"]["alert"][
        "anomaly_score"
    ] = 0.01

    ledger.path.write_text(
        json.dumps(records),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        respond(engine, result, digest)

    assert not engine.path.exists()


def test_response_persists_after_reopen(environment):
    ledger, engine = environment

    result, digest = persist_alert(
        ledger, make_alert()
    )

    first = respond(engine, result, digest)

    reopened = DefensiveResponseEngine(
        ledger_store=SecurityLedgerStore(
            path=ledger.path
        ),
        path=engine.path,
    )

    second = respond(
        reopened,
        result,
        digest,
    )

    assert first["status"] == "RECORDED"
    assert second["status"] == "ALREADY_PROCESSED"


def test_reject_invalid_anomaly_score(environment):
    ledger, engine = environment

    alert = make_alert(
        score=0.5,
        threshold=1.0,
    )

    result, digest = persist_alert(ledger, alert)

    with pytest.raises(
        ValueError,
        match="Invalid confirmed anomaly measurements",
    ):
        respond(engine, result, digest)

    assert not engine.path.exists()
