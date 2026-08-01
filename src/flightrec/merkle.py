"""Merkle leaves and roots (SPEC §4).

The per-record signature cannot say anything about order or count -- that is
the weakness of signing each log line on its own. The root does: every leaf
carries its sequence number, so removing, duplicating or reordering records
changes it.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from .canonical import sha3_256_hex

__all__ = ["EMPTY_ROOT", "leaf", "merkle_root"]

EMPTY_ROOT = "0" * 64


def leaf(seq: int, payload_hash_hex: str) -> str:
    """h_hex(seq as 8 big-endian bytes || payload_hash)."""
    if seq < 0:
        raise ValueError(f"seq must be non-negative: {seq}")
    return sha3_256_hex(seq.to_bytes(8, "big") + bytes.fromhex(payload_hash_hex))


def merkle_root(entries: Iterable[Sequence]) -> str:
    """Root over `(seq, payload_hash_hex)` pairs, sorted by ascending seq."""
    ordered = sorted((int(seq), str(digest)) for seq, digest in entries)
    if not ordered:
        return EMPTY_ROOT

    level = [leaf(seq, digest) for seq, digest in ordered]
    while len(level) > 1:
        parents = [
            sha3_256_hex(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            parents.append(level[-1])  # promote-odd: carried up unchanged
        level = parents
    return level[0]
