import hashlib

import pytest

from attest.canonical import CanonicalizationError
from attest.hashing import hash_hex, hash_payload


def test_hash_hex_is_lowercase_sha3_256():
    digest = hash_hex(b"abc")
    assert digest == hashlib.sha3_256(b"abc").hexdigest()
    assert digest == digest.lower()
    assert len(digest) == 64


def test_hash_payload_hashes_canonical_bytes():
    payload = {"b": 1, "a": [1, 2]}
    expected = hashlib.sha3_256(b'{"a":[1,2],"b":1}').hexdigest()
    assert hash_payload(payload) == expected


def test_hash_payload_is_insensitive_to_key_order():
    assert hash_payload({"a": 1, "b": 2}) == hash_payload({"b": 2, "a": 1})


def test_hash_payload_rejects_floats():
    with pytest.raises(CanonicalizationError):
        hash_payload({"score": 0.5})
