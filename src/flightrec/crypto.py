"""ML-DSA-65 signing keys (SPEC §2).

Post-quantum because a bundle is evidence: it has to stay verifiable for years,
and an archived record signed with RSA or ECDSA can be forged retroactively by
an adversary who acquires a quantum computer after the fact.

Private keys are generated in memory for the duration of a run and are never
written to disk; only the hex-encoded public keys end up in `trust/`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Mapping

from dilithium_py.ml_dsa import ML_DSA_65

__all__ = [
    "SigningKey",
    "verify_hex",
    "write_trust_pubkeys",
    "read_trust_pubkeys",
    "demo_seed",
    "PUBKEY_SUFFIX",
]

PUBKEY_SUFFIX = ".pub.hex"


def demo_seed(key_id: str) -> bytes:
    """A fixed 32-byte seed per key id, for reproducible demo bundles only.

    Real evidence must use `SigningKey.generate`; anyone can rederive these.
    """
    return hashlib.sha3_256(f"flightrec-demo/{key_id}".encode("utf-8")).digest()


class SigningKey:
    """An ML-DSA-65 keypair tagged with the key id that appears in `signer`."""

    def __init__(self, key_id: str, public_key: bytes, secret_key: bytes) -> None:
        self.key_id = key_id
        self._public_key = public_key
        self._secret_key = secret_key

    @classmethod
    def generate(cls, key_id: str) -> "SigningKey":
        public_key, secret_key = ML_DSA_65.keygen()
        return cls(key_id, public_key, secret_key)

    @classmethod
    def derive(cls, key_id: str, seed: bytes) -> "SigningKey":
        """Deterministic key from a 32 byte seed (demo bundles, tests)."""
        public_key, secret_key = ML_DSA_65.key_derive(seed)
        return cls(key_id, public_key, secret_key)

    @property
    def public_hex(self) -> str:
        return self._public_key.hex()

    def sign(self, data: bytes) -> str:
        return ML_DSA_65.sign(self._secret_key, data, deterministic=True).hex()

    def __repr__(self) -> str:  # never leak private material
        return f"SigningKey(key_id={self.key_id!r}, public_hex={self.public_hex[:16]}...)"


def verify_hex(public_hex: str, signature_hex: str, data: bytes) -> bool:
    try:
        return bool(
            ML_DSA_65.verify(bytes.fromhex(public_hex), data, bytes.fromhex(signature_hex))
        )
    except (ValueError, TypeError):
        return False


def write_trust_pubkeys(trust_dir: str | Path, pubkeys: Mapping[str, str]) -> list[Path]:
    """Write `key_id -> hex` as one `<key_id>.pub.hex` file each (SPEC §2.1)."""
    directory = Path(trust_dir)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for key_id, public_hex in sorted(pubkeys.items()):
        target = directory / f"{key_id}{PUBKEY_SUFFIX}"
        target.write_text(public_hex + "\n", encoding="utf-8")
        written.append(target)
    return written


def read_trust_pubkeys(trust_dir: str | Path) -> dict[str, str]:
    directory = Path(trust_dir)
    if not directory.is_dir():
        return {}
    return {
        path.name[: -len(PUBKEY_SUFFIX)]: path.read_text(encoding="utf-8").strip()
        for path in sorted(directory.glob(f"*{PUBKEY_SUFFIX}"))
    }
