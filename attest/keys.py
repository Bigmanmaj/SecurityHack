"""ML-DSA-65 signing and the verifier-side trust directory (SPEC.md).

Secret keys are function arguments only: nothing here writes, logs or prints one.
"""

from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

from .canonical import canonical_bytes

SIGNER_IDS = ("recorder", "anchor-1", "investigator", "anchor-2")

PUBLIC_KEY_BYTES = 1952

_KEY_SUFFIX = ".pub.hex"


def generate_keypair():
    """Return a fresh (public_key, secret_key) pair of raw ML-DSA-65 key bytes."""
    return ML_DSA_65.keygen()


def sign_payload(secret_key, payload):
    """Sign canonical_bytes(payload) with ``secret_key``; return lowercase hex."""
    return ML_DSA_65.sign(secret_key, canonical_bytes(payload)).hex()


def verify_payload(public_key, payload, signature_hex):
    """Return True iff ``signature_hex`` is a valid signature over the payload.

    An unusable signature or public key is a failed verification, not an
    exception: the verifier must be able to report a reason for any input.
    """
    message = canonical_bytes(payload)
    try:
        signature = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    try:
        return ML_DSA_65.verify(public_key, message, signature)
    except ValueError:
        return False


def write_public_key(trust_dir, signer_id, public_key):
    """Publish ``public_key`` as trust_dir/<signer_id>.pub.hex and return its path."""
    if signer_id not in SIGNER_IDS:
        raise ValueError(f"unknown signer_id {signer_id!r}, expected one of {SIGNER_IDS}")
    directory = Path(trust_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{signer_id}{_KEY_SUFFIX}"
    path.write_text(public_key.hex() + "\n", encoding="utf-8")
    return path


def load_trust_dir(trust_dir):
    """Load every <signer_id>.pub.hex in ``trust_dir`` into {signer_id: public_key}."""
    directory = Path(trust_dir)
    if not directory.is_dir():
        raise FileNotFoundError(f"trust dir not found: {directory}")
    trusted = {}
    for path in sorted(directory.glob(f"*{_KEY_SUFFIX}")):
        try:
            public_key = bytes.fromhex(path.read_text(encoding="utf-8").strip())
        except ValueError as error:
            raise ValueError(f"trusted key {path.name} is not valid hex") from error
        if len(public_key) != PUBLIC_KEY_BYTES:
            raise ValueError(f"trusted key {path.name} is not an ML-DSA-65 public key")
        trusted[path.name[: -len(_KEY_SUFFIX)]] = public_key
    return trusted
