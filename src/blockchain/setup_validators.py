
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "config"
KEYS_DIR = CONFIG_DIR / "keys"
REGISTRY_FILE = CONFIG_DIR / "validators.json"

VALIDATORS = {
    "GCS_01": 5001,
    "GCS_02": 5002,
    "GCS_03": 5003,
    "GCS_04": 5004,
}


def setup_validators():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    registry = {}

    for validator_id, port in VALIDATORS.items():
        private_key_path = KEYS_DIR / f"{validator_id}_private.pem"

        if private_key_path.exists():
            private_key = serialization.load_pem_private_key(
                private_key_path.read_bytes(),
                password=None,
            )

            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError(
                    f"Invalid key type for {validator_id}"
                )
        else:
            private_key = Ed25519PrivateKey.generate()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            with open(private_key_path, "xb") as file:
                file.write(private_pem)

        public_key = private_key.public_key()

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        registry[validator_id] = {
            "host": "127.0.0.1",
            "port": port,
            "public_key": base64.b64encode(
                public_bytes
            ).decode("ascii"),
        }

        print(f"{validator_id}: identity configured")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    with open(REGISTRY_FILE, "w", encoding="utf-8") as file:
        json.dump(registry, file, indent=4)

    print("\nValidator setup completed successfully.")
    print(f"Registered validators: {len(registry)}")
    print(f"Public registry: {REGISTRY_FILE}")
    print("Private keys stored locally in config/keys/")


if __name__ == "__main__":
    setup_validators()
