import hashlib

import pytest

from attest.merkle import episode_merkle_root, leaf_bytes, merkle_root


def sha3(*parts):
    return hashlib.sha3_256(b"".join(parts)).digest()


def digest_of(seq, payload_hash):
    return sha3(seq.to_bytes(8, "big"), bytes.fromhex(payload_hash))


HASHES = [hashlib.sha3_256(bytes([i])).hexdigest() for i in range(6)]


def test_leaf_binds_the_seq_as_eight_byte_big_endian():
    assert leaf_bytes(0, HASHES[0]) == digest_of(0, HASHES[0])
    assert leaf_bytes(258, HASHES[1]) == sha3(
        b"\x00\x00\x00\x00\x00\x00\x01\x02", bytes.fromhex(HASHES[1])
    )


def test_leaf_of_same_hash_at_different_seq_differs():
    assert leaf_bytes(1, HASHES[0]) != leaf_bytes(2, HASHES[0])


@pytest.mark.parametrize("seq", [-1, 2**64])
def test_leaf_rejects_out_of_range_seq(seq):
    with pytest.raises(ValueError):
        leaf_bytes(seq, HASHES[0])


def test_leaf_rejects_non_hex_payload_hash():
    with pytest.raises(ValueError):
        leaf_bytes(0, "not-hex")


def test_root_of_single_leaf_is_that_leaf():
    leaf = leaf_bytes(0, HASHES[0])
    assert merkle_root([leaf]) == leaf.hex()


def test_root_of_two_leaves():
    leaves = [leaf_bytes(i, HASHES[i]) for i in range(2)]
    assert merkle_root(leaves) == sha3(leaves[0], leaves[1]).hex()


def test_odd_node_is_promoted_not_duplicated():
    leaves = [leaf_bytes(i, HASHES[i]) for i in range(3)]
    promoted = sha3(sha3(leaves[0], leaves[1]), leaves[2]).hex()
    duplicated = sha3(sha3(leaves[0], leaves[1]), sha3(leaves[2], leaves[2])).hex()
    assert merkle_root(leaves) == promoted
    assert merkle_root(leaves) != duplicated


def test_root_of_five_leaves_promotes_at_two_levels():
    leaves = [leaf_bytes(i, HASHES[i]) for i in range(5)]
    level_one = [sha3(leaves[0], leaves[1]), sha3(leaves[2], leaves[3]), leaves[4]]
    level_two = [sha3(level_one[0], level_one[1]), level_one[2]]
    assert merkle_root(leaves) == sha3(level_two[0], level_two[1]).hex()


def test_root_is_lowercase_hex_of_32_bytes():
    root = merkle_root([leaf_bytes(i, HASHES[i]) for i in range(4)])
    assert len(root) == 64
    assert root == root.lower()


def test_root_is_order_sensitive():
    leaves = [leaf_bytes(i, HASHES[i]) for i in range(4)]
    assert merkle_root(leaves) != merkle_root(list(reversed(leaves)))


def test_root_of_no_leaves_is_an_error():
    with pytest.raises(ValueError):
        merkle_root([])


def test_episode_merkle_root_builds_leaves_in_seq_order():
    entries = [(i, HASHES[i]) for i in range(3)]
    expected = merkle_root([leaf_bytes(seq, digest) for seq, digest in entries])
    assert episode_merkle_root(entries) == expected


def test_episode_merkle_root_does_not_reorder_its_input():
    entries = [(1, HASHES[1]), (0, HASHES[0])]
    assert episode_merkle_root(entries) != episode_merkle_root(list(reversed(entries)))
