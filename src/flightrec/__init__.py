"""flightrec — a tamper-evident flight recorder for AI agent episodes.

This package is the *producer* side: it records episodes and investigates them.
Verification lives in the separate `verifier/` package, which implements
SPEC.md independently and imports nothing from here.
"""

from .canonical import H, canonical_bytes, hash_obj, sha3_256_hex
from .crypto import SigningKey, read_trust_pubkeys, verify_hex, write_trust_pubkeys
from .merkle import leaf, merkle_root
from .recorder import NullRecorder, Recorder, build_manifest, signed_message

__all__ = [
    "H",
    "canonical_bytes",
    "hash_obj",
    "sha3_256_hex",
    "SigningKey",
    "read_trust_pubkeys",
    "verify_hex",
    "write_trust_pubkeys",
    "leaf",
    "merkle_root",
    "NullRecorder",
    "Recorder",
    "build_manifest",
    "signed_message",
]
