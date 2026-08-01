"""flightrec — a tamper-evident flight recorder for AI agent episodes."""

from .canonical import H, canonical_bytes, hash_obj, sha3_256_hex
from .crypto import SigningKey, read_trust_pubkeys, verify_hex, write_trust_pubkeys
from .recorder import NullRecorder, Recorder, build_manifest
from .verify import verify_bundle

__all__ = [
    "H",
    "canonical_bytes",
    "hash_obj",
    "sha3_256_hex",
    "SigningKey",
    "read_trust_pubkeys",
    "verify_hex",
    "write_trust_pubkeys",
    "NullRecorder",
    "Recorder",
    "build_manifest",
    "verify_bundle",
]
