"""Ed25519 signing keys.

Private keys are generated in memory for the duration of a run and are never
written to disk; only the hex-encoded public keys end up in `trust/`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

__all__ = [
    "SigningKey",
    "verify_hex",
    "write_trust_pubkeys",
    "read_trust_pubkeys",
    "TRUST_FILENAME",
]

TRUST_FILENAME = "pubkeys.json"


class SigningKey:
    """An Ed25519 keypair tagged with the key id that appears in signatures."""

    def __init__(self, key_id: str, private_key: ed25519.Ed25519PrivateKey) -> None:
        self.key_id = key_id
        self._private_key = private_key

    @classmethod
    def generate(cls, key_id: str) -> "SigningKey":
        return cls(key_id, ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, key_id: str, seed: bytes) -> "SigningKey":
        """Deterministic key from a 32 byte seed. Tests only."""
        return cls(key_id, ed25519.Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_hex(self) -> str:
        raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign(self, data: bytes) -> str:
        return self._private_key.sign(data).hex()

    def __repr__(self) -> str:  # never leak private material
        return f"SigningKey(key_id={self.key_id!r}, public_hex={self.public_hex[:16]}...)"


def verify_hex(public_hex: str, signature_hex: str, data: bytes) -> bool:
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        public_key.verify(bytes.fromhex(signature_hex), data)
    except (InvalidSignature, ValueError):
        return False
    return True


def write_trust_pubkeys(trust_dir: str | Path, pubkeys: Mapping[str, str]) -> Path:
    """Merge `pubkeys` (key_id -> hex) into `trust_dir/pubkeys.json`."""
    trust_path = Path(trust_dir)
    trust_path.mkdir(parents=True, exist_ok=True)
    target = trust_path / TRUST_FILENAME

    merged = read_trust_pubkeys(trust_path) if target.exists() else {}
    merged.update(pubkeys)
    target.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def read_trust_pubkeys(trust_dir: str | Path) -> dict[str, str]:
    target = Path(trust_dir) / TRUST_FILENAME
    if not target.exists():
        return {}
    return json.loads(target.read_text(encoding="utf-8"))
