"""Primitives from SPEC.md sections 1, 2 and 4.

Reimplemented from the spec text. Nothing here may import the producer.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Sequence

from dilithium_py.ml_dsa import ML_DSA_65

__all__ = ["canon_bytes", "h_hex", "verify_sig", "leaf", "merkle_root", "EMPTY_ROOT"]

EMPTY_ROOT = "0" * 64


def _check_no_floats(obj: Any) -> None:
    """SPEC section 1: floats have no canonical decimal form, so they are refused.

    Checked before serialising, and recursively, because a float buried in a
    list is exactly the case where two implementations would silently disagree.
    """
    if isinstance(obj, float):
        raise TypeError(f"floats are not canonically serialisable: {obj!r}")
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise TypeError(f"object keys must be strings: {key!r}")
            _check_no_floats(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_no_floats(item)


def canon_bytes(obj: Any) -> bytes:
    """SPEC section 1: sorted keys, no whitespace, unescaped unicode, UTF-8."""
    _check_no_floats(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def h_hex(data: bytes) -> str:
    """SPEC section 1: SHA3-256, lowercase hex."""
    return hashlib.sha3_256(data).hexdigest()


def verify_sig(pk_hex: str, payload: bytes, sig_hex: str) -> bool:
    """SPEC section 2: ML-DSA-65 verification.

    Malformed keys or signatures are a verification failure, not an exception:
    a verifier reading an attacker-supplied bundle should report RED, not crash.
    """
    try:
        public_key = bytes.fromhex(pk_hex)
        signature = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    if not public_key or not signature:
        return False
    try:
        return bool(ML_DSA_65.verify(public_key, payload, signature))
    except (ValueError, TypeError, IndexError):
        return False


def leaf(seq: int, payload_hash_hex: str) -> str:
    """SPEC section 4.1: h_hex(8-byte big-endian seq || payload_hash)."""
    if seq < 0:
        raise ValueError(f"seq must be non-negative: {seq}")
    return h_hex(seq.to_bytes(8, "big") + bytes.fromhex(payload_hash_hex))


def merkle_root(entries: Iterable[Sequence]) -> str:
    """SPEC section 4.2: root over (seq, payload_hash) pairs, ascending by seq."""
    ordered = sorted((int(seq), str(digest)) for seq, digest in entries)
    if not ordered:
        return EMPTY_ROOT

    level = [leaf(seq, digest) for seq, digest in ordered]
    while len(level) > 1:
        parents = [
            h_hex(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            parents.append(level[-1])  # promote-odd: carried up, never duplicated
        level = parents
    return level[0]
