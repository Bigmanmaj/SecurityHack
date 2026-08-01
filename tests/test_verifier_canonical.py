"""C1: the verifier's primitives, checked against SPEC.md and the shared vectors.

This module deliberately imports nothing from `src/flightrec`. The constants it
asserts against come from `tests/vectors.py`, a transcription of the spec that
imports neither implementation, so agreement here means both sides independently
match the spec rather than each other.
"""

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from dilithium_py.ml_dsa import ML_DSA_65

from verifier.canonical import canon_bytes, h_hex, leaf, merkle_root, verify_sig

from .vectors import CANON_VECTORS, MERKLE_ROOTS, payload_hash

ROOT = Path(__file__).resolve().parents[1]


# -- SPEC section 1: canonical bytes -----------------------------------------


def test_canon_bytes_matches_the_shared_vectors():
    for obj, expected in CANON_VECTORS:
        assert canon_bytes(obj) == expected, obj


def test_canon_bytes_is_sorted_compact_and_utf8():
    assert canon_bytes({"b": 1, "a": {"d": 4, "c": 3}}) == b'{"a":{"c":3,"d":4},"b":1}'
    assert b" " not in canon_bytes({"a": 1, "b": [1, 2]})
    assert canon_bytes({"k": "\u00e9"}) == '{"k":"é"}'.encode("utf-8")


def test_floats_are_rejected_recursively():
    for bad in (1.5, [1.5], {"a": 1.5}, {"a": [1, {"b": 2.0}]}, [[[0.0]]]):
        with pytest.raises(TypeError):
            canon_bytes(bad)


def test_nan_and_infinity_are_rejected_too():
    for bad in (float("nan"), float("inf"), {"a": float("-inf")}):
        with pytest.raises(TypeError):
            canon_bytes(bad)


def test_ints_and_bools_still_serialise():
    assert canon_bytes({"a": True, "b": 10**30, "c": None}) == (
        b'{"a":true,"b":1000000000000000000000000000000,"c":null}'
    )


def test_h_hex_is_sha3_256_hex():
    assert h_hex(b"") == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    assert h_hex(b"abc") == hashlib.sha3_256(b"abc").hexdigest()
    assert len(h_hex(b"abc")) == 64 and h_hex(b"abc").islower()


def test_hashing_an_object_means_h_hex_of_canon_bytes():
    assert h_hex(canon_bytes({"i": 0})) == payload_hash(0)


# -- SPEC section 4: merkle --------------------------------------------------


def test_leaf_uses_an_eight_byte_big_endian_seq_prefix():
    digest = payload_hash(0)

    assert leaf(0, digest) == h_hex(bytes(8) + bytes.fromhex(digest))
    assert leaf(1, digest) == h_hex(b"\x00" * 7 + b"\x01" + bytes.fromhex(digest))
    assert leaf(258, digest) == h_hex(b"\x00" * 6 + b"\x01\x02" + bytes.fromhex(digest))
    assert leaf(0, digest) != leaf(1, digest)


def test_merkle_roots_match_the_shared_vectors():
    for count, expected in MERKLE_ROOTS.items():
        entries = [(i, payload_hash(i)) for i in range(count)]
        assert merkle_root(entries) == expected, f"{count} entries"


def test_single_entry_root_is_its_leaf():
    assert merkle_root([(0, payload_hash(0))]) == leaf(0, payload_hash(0))


def test_two_entry_root_is_the_concatenated_hash():
    left, right = leaf(0, payload_hash(0)), leaf(1, payload_hash(1))

    assert merkle_root([(0, payload_hash(0)), (1, payload_hash(1))]) == h_hex(
        bytes.fromhex(left) + bytes.fromhex(right)
    )


def test_three_entries_promote_the_odd_node_unchanged():
    """The promote-odd rule spelled out: the third leaf is carried up, not duplicated."""
    leaves = [leaf(i, payload_hash(i)) for i in range(3)]
    pair = h_hex(bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1]))
    expected = h_hex(bytes.fromhex(pair) + bytes.fromhex(leaves[2]))

    assert merkle_root([(i, payload_hash(i)) for i in range(3)]) == expected
    duplicated_last = h_hex(bytes.fromhex(leaves[2]) + bytes.fromhex(leaves[2]))
    assert expected != h_hex(bytes.fromhex(pair) + bytes.fromhex(duplicated_last))


def test_empty_root_is_all_zeroes():
    assert merkle_root([]) == "0" * 64


def test_root_sorts_by_seq_and_notices_reordering():
    entries = [(i, payload_hash(i)) for i in range(4)]

    assert merkle_root(list(reversed(entries))) == MERKLE_ROOTS[4]

    swapped = [(0, payload_hash(1)), (1, payload_hash(0)), (2, payload_hash(2)), (3, payload_hash(3))]
    assert merkle_root(swapped) != MERKLE_ROOTS[4]


def test_root_notices_a_missing_entry():
    entries = [(i, payload_hash(i)) for i in range(4)]

    assert merkle_root(entries[:3]) != MERKLE_ROOTS[4]


# -- SPEC section 2: signatures ----------------------------------------------


def test_verify_sig_accepts_a_genuine_ml_dsa_65_signature():
    public_key, secret_key = ML_DSA_65.keygen()
    message = canon_bytes({"payload": {"a": 1}})
    signature = ML_DSA_65.sign(secret_key, message, deterministic=True)

    assert verify_sig(public_key.hex(), message, signature.hex()) is True


def test_verify_sig_rejects_a_changed_message_or_key():
    public_key, secret_key = ML_DSA_65.keygen()
    other_public, _ = ML_DSA_65.keygen()
    signature = ML_DSA_65.sign(secret_key, b"message", deterministic=True).hex()

    assert verify_sig(public_key.hex(), b"message ", signature) is False
    assert verify_sig(other_public.hex(), b"message", signature) is False


def test_verify_sig_returns_false_on_malformed_input_rather_than_raising():
    public_key, secret_key = ML_DSA_65.keygen()
    signature = ML_DSA_65.sign(secret_key, b"m", deterministic=True).hex()

    assert verify_sig("not hex", b"m", signature) is False
    assert verify_sig(public_key.hex(), b"m", "zz") is False
    assert verify_sig(public_key.hex(), b"m", "") is False
    assert verify_sig("", b"m", signature) is False


# -- the isolation the whole exercise rests on -------------------------------


def test_the_verifier_package_imports_only_stdlib_and_dilithium():
    allowed = set(sys.stdlib_module_names) | {"dilithium_py", "verifier"}

    for source in sorted((ROOT / "verifier").glob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [(node.module or "").split(".")[0]] if node.level == 0 else []
            else:
                continue
            for root in roots:
                assert root in allowed, f"{source.name} imports {root}"


def test_importing_the_verifier_does_not_load_the_producer():
    code = (
        "import sys, verifier.canonical;"
        "print([m for m in sys.modules if m.startswith('flightrec')])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True
    )

    assert result.stdout.strip() == "[]"
