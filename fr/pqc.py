"""The only place the project touches a post-quantum signature implementation.

Isolated on purpose: if pure-Python speed ever bites, swapping in a native
backend (quantcrypt ships a prebuilt wheel) is a change to this file alone.

Why post-quantum at all: forensic artifacts have to stay non-repudiable for
years. A signature scheme broken in 2032 retroactively voids every 2026 record
it protected -- the evidence turns back into testimony. This is a durability of
proof argument, not a "harvest now, decrypt later" one.
"""

from dilithium_py.ml_dsa import ML_DSA_65

ALG = "ML-DSA-65"
SEED_LEN = 32
PK_LEN = 1952
SK_LEN = 4032
SIG_LEN = 3309


def key_derive(seed):
    """Deterministically derive ``(pk, sk)`` from a 32-byte seed.

    Determinism is what makes the ratchet implementable: a seed is the whole
    keypair, so erasing the seed erases the ability to sign.
    """
    if len(seed) != SEED_LEN:
        raise ValueError(f"seed must be {SEED_LEN} bytes, got {len(seed)}")
    return ML_DSA_65.key_derive(bytes(seed))


def sign(sk, message):
    """Deterministic signature over ``message`` (ML-DSA takes arbitrary lengths)."""
    return ML_DSA_65.sign(bytes(sk), bytes(message), deterministic=True)


def verify(pk, message, signature):
    try:
        return bool(ML_DSA_65.verify(bytes(pk), bytes(message), bytes(signature)))
    except (ValueError, TypeError):
        return False
