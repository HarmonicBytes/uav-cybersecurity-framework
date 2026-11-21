
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0,
    str(ROOT / "src" / "blockchain"),
)

from ledger_store import SecurityLedgerStore
from protocol import calculate_digest


@pytest.fixture
def ledger_store(tmp_path):
    """
    Create an isolated ledger for each test.
    The production ledger is never modified.
    """
    return SecurityLedgerStore(
        path=tmp_path / "security_ledger.json"
    )


@pytest.fixture
def sample_alert():
    return {
        "uav_id": "UAV_001",
        "event_type": "UAV_TELEMETRY_ANOMALY",
        "anomaly_score": 472.71368408,
        "threshold": 1.76960075,
        "detection_result": "ANOMALY",
        "source": "pytorch_autoencoder",
        "data_source": "synthetic_uav_telemetry",
    }


def append_alert(
    store,
    alert,
    sequence=1000,
):
    return store.append_committed_alert(
        alert=alert,
        committed_digest=calculate_digest(alert),
        view=0,
        sequence=sequence,
        committed_validators=[
            "GCS_01",
            "GCS_02",
            "GCS_03",
            "GCS_04",
        ],
    )


# -----------------------------------------------------
# L1: Create genesis and committed event blocks
# -----------------------------------------------------

def test_create_valid_ledger(
    ledger_store,
    sample_alert,
):
    result = append_alert(
        ledger_store,
        sample_alert,
    )

    assert result["block_index"] == 1
    assert result["chain_length"] == 2
    assert result["chain_valid"] is True

    chain = ledger_store.load()

    assert len(chain.chain) == 2
    assert chain.verify_chain() is True

    genesis = chain.chain[0]
    event_block = chain.chain[1]

    assert genesis.index == 0
    assert genesis.event["type"] == "GENESIS"

    assert event_block.index == 1
    assert event_block.previous_hash == genesis.block_hash

    assert (
        event_block.event["alert_digest"]
        == calculate_digest(sample_alert)
    )

    assert event_block.event["alert"] == sample_alert

    print("L1: Valid genesis and event blocks created")


# -----------------------------------------------------
# L2: Verify persistence after reopening
# -----------------------------------------------------

def test_ledger_persists_after_reload(
    ledger_store,
    sample_alert,
):
    append_alert(
        ledger_store,
        sample_alert,
    )

    first_verification = ledger_store.verify()

    # Simulate reopening the ledger from disk.
    reopened = SecurityLedgerStore(
        path=ledger_store.path
    )

    second_verification = reopened.verify()

    assert first_verification["valid"] is True
    assert second_verification["valid"] is True

    assert first_verification["blocks"] == 2
    assert second_verification["blocks"] == 2

    assert (
        first_verification["latest_hash"]
        == second_verification["latest_hash"]
    )

    print("L2: Ledger persistence verified")


# -----------------------------------------------------
# L3: Detect tampering with a stored alert
# -----------------------------------------------------

def test_detect_unauthorized_event_modification(
    ledger_store,
    sample_alert,
):
    append_alert(
        ledger_store,
        sample_alert,
    )

    with ledger_store.path.open(
        "r",
        encoding="utf-8",
    ) as file:
        stored_data = json.load(file)

    # Simulate unauthorized modification.
    stored_data[1]["event"]["alert"][
        "anomaly_score"
    ] = 0.01

    # Deliberately do not update the block hash.
    with ledger_store.path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            stored_data,
            file,
            indent=2,
        )

    with pytest.raises(ValueError):
        ledger_store.load()

    print("L3: Unauthorized modification detected")


# -----------------------------------------------------
# L4: Reject duplicate consensus instances
# -----------------------------------------------------

def test_duplicate_consensus_instance_rejected(
    ledger_store,
    sample_alert,
):
    append_alert(
        ledger_store,
        sample_alert,
        sequence=1000,
    )

    with pytest.raises(
        ValueError,
        match="Consensus instance already recorded",
    ):
        append_alert(
            ledger_store,
            sample_alert,
            sequence=1000,
        )

    verification = ledger_store.verify()

    assert verification["valid"] is True
    assert verification["blocks"] == 2

    print("L4: Duplicate consensus instance rejected")


# -----------------------------------------------------
# L5: Reject mismatched alert and consensus digest
# -----------------------------------------------------

def test_alert_digest_mismatch_rejected(
    ledger_store,
    sample_alert,
):
    incorrect_digest = calculate_digest({
        "uav_id": "DIFFERENT_UAV",
        "event_type": "NORMAL",
    })

    with pytest.raises(
        ValueError,
        match="Alert digest does not match",
    ):
        ledger_store.append_committed_alert(
            alert=sample_alert,
            committed_digest=incorrect_digest,
            view=0,
            sequence=1000,
            committed_validators=[
                "GCS_01",
                "GCS_02",
                "GCS_03",
            ],
        )

    # Rejected data must not create a ledger.
    assert ledger_store.path.exists() is False

    print("L5: Digest mismatch rejected")


# -----------------------------------------------------
# L6: Append multiple valid events
# -----------------------------------------------------

def test_multiple_committed_events(
    ledger_store,
    sample_alert,
):
    first_result = append_alert(
        ledger_store,
        sample_alert,
        sequence=1000,
    )

    second_alert = {
        **sample_alert,
        "uav_id": "UAV_002",
        "anomaly_score": 125.5,
    }

    second_result = append_alert(
        ledger_store,
        second_alert,
        sequence=1001,
    )

    assert first_result["block_index"] == 1
    assert second_result["block_index"] == 2

    chain = ledger_store.load()

    assert len(chain.chain) == 3
    assert chain.verify_chain() is True

    assert (
        chain.chain[2].previous_hash
        == chain.chain[1].block_hash
    )

    print("L6: Multiple event blocks linked correctly")


# -----------------------------------------------------
# L7: Detect corrupted previous-block linkage
# -----------------------------------------------------

def test_detect_invalid_previous_hash(
    ledger_store,
    sample_alert,
):
    append_alert(
        ledger_store,
        sample_alert,
    )

    with ledger_store.path.open(
        "r",
        encoding="utf-8",
    ) as file:
        stored_data = json.load(file)

    # Corrupt the link to the previous block.
    stored_data[1]["previous_hash"] = "f" * 64

    with ledger_store.path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            stored_data,
            file,
            indent=2,
        )

    with pytest.raises(ValueError):
        ledger_store.load()

    print("L7: Invalid previous-block linkage detected")


# -----------------------------------------------------
# L8: Reject malformed ledger JSON
# -----------------------------------------------------

def test_detect_corrupted_ledger_file(
    ledger_store,
):
    ledger_store.path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    ledger_store.path.write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    with pytest.raises(
        json.JSONDecodeError
    ):
        ledger_store.load()

    print("L8: Corrupted ledger JSON rejected")
