"""SHA3-256 helpers. One hash function everywhere, no negotiation."""

import hashlib

from . import canon

HASH_ALG = "SHA3-256"
HASH_HEX_LEN = 64
ZERO_HASH = "0" * HASH_HEX_LEN


def sha3_bytes(data):
    return hashlib.sha3_256(data).digest()


def sha3_hex(data):
    return hashlib.sha3_256(data).hexdigest()


def body_hash(body):
    """Record hash covers the body only.

    ML-DSA signatures here are deterministic, so ``sig`` is a pure function of
    ``body`` and would add no entropy to the chain.
    """
    return sha3_hex(canon.dumps(body))


def blob_hash(data):
    return sha3_hex(data)
