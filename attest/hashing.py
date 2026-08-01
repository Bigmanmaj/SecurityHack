"""H(x) = SHA3-256(x), stored as lowercase hex (SPEC.md)."""

import hashlib

from .canonical import canonical_bytes


def hash_hex(data):
    """Return H(data) as lowercase hex for the raw bytes ``data``."""
    return hashlib.sha3_256(data).hexdigest()


def hash_payload(payload):
    """Return H(canonical_bytes(payload)) as lowercase hex."""
    return hash_hex(canonical_bytes(payload))
