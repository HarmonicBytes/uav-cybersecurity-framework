
import base64
import json
from pathlib import Path
from copy import deepcopy
from functools import lru_cache
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "config" / "validators.json"
KEYS_DIR = ROOT / "config" / "keys"



@lru_cache(maxsize=8)
def _load_registry_cached(file_version):
    """
    Cache a registry snapshot for a specific
    filesystem version of validators.json.
    """
    with open(REGISTRY_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def load_registry():
    """
    Reuse the registry while its filesystem metadata
    remains unchanged.

    A modified registry receives a different cache key.
    Return a defensive copy so callers cannot modify
    the cached registry accidentally.
    """
    stat = REGISTRY_PATH.stat()

    file_version = (
        stat.st_mtime_ns,
        stat.st_ctime_ns,
        stat.st_size,
        stat.st_ino,
    )

    return deepcopy(
        _load_registry_cached(file_version)
    )


def load_private_key(validator_id):
    path = KEYS_DIR / f"{validator_id}_private.pem"

    with open(path, "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=None,
        )


def canonical_payload(message):
    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sign_message(validator_id, message):
    private_key = load_private_key(validator_id)

    signature = private_key.sign(
        canonical_payload(message)
    )

    return {
        "sender": validator_id,
        "message": message,
        "signature": base64.b64encode(
            signature
        ).decode("ascii"),
    }


def verify_message(envelope):
    try:
        sender = envelope["sender"]
        message = envelope["message"]
        signature = envelope["signature"]

        registry = load_registry()

        if sender not in registry:
            return False

        public_key_bytes = base64.b64decode(
            registry[sender]["public_key"],
            validate=True,
        )

        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

        public_key.verify(
            base64.b64decode(
                signature,
                validate=True,
            ),
            canonical_payload(message),
        )

        return True

    except (
        KeyError,
        TypeError,
        ValueError,
        InvalidSignature,
    ):
        return False
