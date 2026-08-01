"""Merkle tree over the episode's records, odd node promoted (SPEC.md)."""

from .hashing import hash_raw


def leaf_bytes(seq, payload_hash_hex):
    """Return leaf = H(seq as 8-byte big-endian || bytes.fromhex(payload_hash))."""
    try:
        seq_bytes = int(seq).to_bytes(8, "big")
    except OverflowError as error:
        raise ValueError(f"seq {seq} does not fit in 8 bytes") from error
    return hash_raw(seq_bytes + bytes.fromhex(payload_hash_hex))


def merkle_root(leaves):
    """Reduce raw 32-byte ``leaves`` to the root, as lowercase hex.

    An odd node at any level is promoted unchanged to the next level, never
    duplicated, so a forged sibling cannot be hidden behind a repeated leaf.
    """
    level = list(leaves)
    if not level:
        raise ValueError("cannot build a Merkle root over zero leaves")
    while len(level) > 1:
        parents = [hash_raw(level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            parents.append(level[-1])
        level = parents
    return level[0].hex()


def episode_merkle_root(entries):
    """Root over ``entries``, an iterable of (seq, payload_hash_hex) in seq order."""
    return merkle_root([leaf_bytes(seq, digest) for seq, digest in entries])
