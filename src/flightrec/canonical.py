"""Canonical serialisation and hashing.

Every hash and signature in a bundle is computed over `canonical_bytes` output,
so that anyone holding the original object can recompute the hash byte for byte.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = ["canonical_bytes", "sha3_256_hex", "H", "hash_obj", "GENESIS_HASH"]

GENESIS_HASH = "0" * 64


def _reject_floats(obj: Any) -> None:
    """SPEC §1: a float has no canonical decimal form across languages."""
    if isinstance(obj, float):
        raise TypeError(f"floats are not canonically serialisable: {obj!r}")
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise TypeError(f"object keys must be strings: {key!r}")
            _reject_floats(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _reject_floats(item)


def canonical_bytes(obj: Any) -> bytes:
    """Serialise `obj` to the one byte string this project ever hashes."""
    _reject_floats(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


#: Shorthand used throughout the codebase: H(canonical_bytes(x)).
H = sha3_256_hex


def hash_obj(obj: Any) -> str:
    return sha3_256_hex(canonical_bytes(obj))
