"""Forward-secure key ratchet -- the answer to "but the operator holds the key".

::

    seed_0     <- 32 random bytes, generated inside the recorder at episode start
    pk_i, sk_i  = ML_DSA_65.key_derive(seed_i)          # deterministic from seed
    seed_{i+1}  = SHA3-256(seed_i || b"fr-ratchet-v1")  # one-way

Record ``i`` commits to ``SHA3-256(pk_{i+1})`` in ``body.next_pk``, is signed with
``sk_i``, and then ``seed_i`` and ``sk_i`` are erased.

The consequence, out loud: an operator who seizes the machine at record 40 holds
seed_40. They can forge records 40 onward. They cannot rewrite records 0-39,
because sk_0..sk_39 no longer exist anywhere in the universe. Rewriting the past
requires breaking ML-DSA or SHA3, not stealing a file.
"""

import os

from . import pqc
from .hashes import sha3_bytes, sha3_hex

RATCHET_DOMAIN = b"fr-ratchet-v1"
SEED_LEN = pqc.SEED_LEN
PARAMS = {
    "kdf": "SHA3-256",
    "domain": RATCHET_DOMAIN.decode("ascii"),
    "sig_alg": pqc.ALG,
    "seed_len": SEED_LEN,
}


def next_seed(seed):
    return sha3_bytes(bytes(seed) + RATCHET_DOMAIN)


def _wipe(buf):
    """Best-effort zeroization of a mutable buffer.

    CPython gives no guarantee that no copy lingers, and key_derive necessarily
    sees an immutable copy. We do not pretend otherwise; the security argument
    rests on the seed being unrecoverable from the *files*, and on the process
    having no reason to keep it.
    """
    for i in range(len(buf)):
        buf[i] = 0


class Ratchet:
    """Holds exactly one live seed at a time, plus the next key it has committed to."""

    def __init__(self, seed, index=0):
        if len(seed) != SEED_LEN:
            raise ValueError(f"seed must be {SEED_LEN} bytes, got {len(seed)}")
        self.index = index
        self._seed = bytearray(seed)
        self._pk, self._sk = pqc.key_derive(bytes(self._seed))
        self._next_seed = bytearray(next_seed(self._seed))
        self._next_pk, self._next_sk = pqc.key_derive(bytes(self._next_seed))

    @classmethod
    def new(cls):
        return cls(os.urandom(SEED_LEN))

    @property
    def pk(self):
        """Public key for the record about to be written."""
        return self._pk

    @property
    def next_pk_hash(self):
        """SHA3-256(pk_{i+1}) -- the forward-security commitment for body.next_pk."""
        return sha3_hex(self._next_pk)

    @property
    def anchor(self):
        """SHA3-256(pk_i). Only meaningful at index 0, where it is the trust root."""
        return sha3_hex(self._pk)

    def sign(self, message):
        return pqc.sign(self._sk, message)

    def advance(self):
        """Erase seed_i / sk_i, adopt the committed next key, commit to a new one."""
        _wipe(self._seed)
        self._seed = self._next_seed
        self._pk, self._sk = self._next_pk, self._next_sk
        self._next_seed = bytearray(next_seed(self._seed))
        self._next_pk, self._next_sk = pqc.key_derive(bytes(self._next_seed))
        self.index += 1

    def export_seed(self):
        """The live seed, for persisting recorder state across processes.

        This is the one piece of key material that exists at all. Losing it makes
        the episode permanently unextendable; stealing it never yields the past.
        """
        return bytes(self._seed)


def seed_at(seed0, index):
    """Roll a seed forward ``index`` times. Tests and adversary simulations only."""
    seed = bytes(seed0)
    for _ in range(index):
        seed = next_seed(seed)
    return seed


def anchor_for_seed(seed0):
    pk, _ = pqc.key_derive(bytes(seed0))
    return sha3_hex(pk)
