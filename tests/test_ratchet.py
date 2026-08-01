"""The forward-secure ratchet: what it guarantees, and what it honestly does not."""

import pytest

from fr import pqc
from fr.hashes import sha3_hex
from fr.ratchet import RATCHET_DOMAIN, Ratchet, anchor_for_seed, next_seed, seed_at


def test_key_derivation_is_deterministic():
    """Determinism is what makes a seed equivalent to a keypair."""
    seed = bytes(range(32))
    assert pqc.key_derive(seed) == pqc.key_derive(seed)


def test_signatures_are_deterministic_so_the_body_hash_is_enough():
    _, sk = pqc.key_derive(bytes(range(32)))
    assert pqc.sign(sk, b"evidence") == pqc.sign(sk, b"evidence")


def test_sizes_are_the_ml_dsa_65_sizes():
    pk, sk = pqc.key_derive(bytes(32))
    assert (len(pk), len(sk), len(pqc.sign(sk, b"x"))) == (pqc.PK_LEN, pqc.SK_LEN, pqc.SIG_LEN)


def test_one_byte_change_fails_verification():
    pk, sk = pqc.key_derive(bytes(32))
    sig = pqc.sign(sk, b"http_post")
    assert pqc.verify(pk, b"http_post", sig)
    assert not pqc.verify(pk, b"http_post ", sig)


def test_seed_chain_is_one_way_and_domain_separated():
    seed = bytes(range(32))
    assert next_seed(seed) == bytes.fromhex(sha3_hex(seed + RATCHET_DOMAIN))
    assert next_seed(seed) != next_seed(bytes(32))


def test_advance_commits_to_the_key_it_will_use_next():
    r = Ratchet(bytes(range(32)))
    committed = r.next_pk_hash
    r.advance()
    assert sha3_hex(r.pk) == committed


def test_anchor_is_the_hash_of_the_first_public_key():
    seed = bytes(range(32))
    r = Ratchet(seed)
    assert r.anchor == anchor_for_seed(seed) == sha3_hex(r.pk)


def test_holding_seed_k_does_not_yield_any_earlier_signing_key():
    """The whole claim, as a test.

    An attacker who seizes the machine at record 40 holds seed_40. Every earlier
    secret key is unreachable from it: SHA3 does not run backwards.
    """
    seed0 = bytes(range(32))
    compromised = seed_at(seed0, 40)
    reachable = {compromised}
    seed = compromised
    for _ in range(200):
        seed = next_seed(seed)
        reachable.add(seed)
    earlier = {seed_at(seed0, i) for i in range(40)}
    assert not (reachable & earlier)


def test_the_attacker_can_still_forge_the_future_and_we_say_so():
    """The honest boundary: forward security protects the past, not the future."""
    seed0 = bytes(range(32))
    _, sk40 = pqc.key_derive(seed_at(seed0, 40))
    pk40, _ = pqc.key_derive(seed_at(seed0, 40))
    forged = pqc.sign(sk40, b"a record 40 that never happened")
    assert pqc.verify(pk40, b"a record 40 that never happened", forged)


def test_seed_must_be_32_bytes():
    with pytest.raises(ValueError):
        Ratchet(b"too short")


def test_export_seed_round_trips_the_ratchet_across_processes():
    r = Ratchet(bytes(range(32)))
    r.advance()
    r.advance()
    resumed = Ratchet(r.export_seed(), index=r.index)
    assert sha3_hex(resumed.pk) == sha3_hex(r.pk)
    assert resumed.next_pk_hash == r.next_pk_hash
