"""Producer-side tests: does `src/flightrec` write what SPEC.md describes?

Whether a bundle *verifies* is the independent verifier's question, and is
tested in tests/test_verify.py against `verifier/`.
"""

import json

import pytest

from flightrec.canonical import canonical_bytes, hash_obj, sha3_256_hex
from flightrec.crypto import (
    PUBKEY_SUFFIX,
    SigningKey,
    demo_seed,
    read_trust_pubkeys,
    verify_hex,
    write_trust_pubkeys,
)
from flightrec.merkle import EMPTY_ROOT, leaf, merkle_root
from flightrec.recorder import NullRecorder, Recorder, build_manifest, signed_message

from .vectors import CANON_VECTORS, MERKLE_ROOTS, payload_hash

FORBIDDEN = ["transfer_funds"]


def make_recorder(tmp_path):
    recorder_key = SigningKey.derive("recorder", demo_seed("test-recorder"))
    anchor_key = SigningKey.derive("anchor-1", demo_seed("test-anchor-1"))
    manifest = build_manifest(
        "test-agent", "fake-model", FORBIDDEN, created_at="2024-01-01T00:00:00+00:00"
    )
    return Recorder(tmp_path / "episode", manifest, recorder_key), anchor_key


# -- SPEC section 1: canonical bytes -----------------------------------------


def test_canonical_bytes_matches_the_shared_vectors():
    for obj, expected in CANON_VECTORS:
        assert canonical_bytes(obj) == expected


def test_floats_are_rejected_recursively():
    with pytest.raises(TypeError):
        canonical_bytes(1.5)
    with pytest.raises(TypeError):
        canonical_bytes({"a": [1, {"b": 0.1}]})
    with pytest.raises(TypeError):
        canonical_bytes({"a": float("nan")})


def test_hash_obj_is_sha3_256_over_canonical_bytes():
    assert hash_obj({"i": 0}) == sha3_256_hex(canonical_bytes({"i": 0})) == payload_hash(0)


# -- SPEC section 4: merkle --------------------------------------------------


def test_merkle_roots_match_the_shared_vectors():
    for count, expected in MERKLE_ROOTS.items():
        entries = [(i, payload_hash(i)) for i in range(count)]
        assert merkle_root(entries) == expected, f"{count} entries"


def test_merkle_root_is_independent_of_input_order_but_not_of_seq():
    entries = [(i, payload_hash(i)) for i in range(3)]

    assert merkle_root(reversed(entries)) == MERKLE_ROOTS[3]
    swapped = [(0, payload_hash(1)), (1, payload_hash(0)), (2, payload_hash(2))]
    assert merkle_root(swapped) != MERKLE_ROOTS[3]


def test_empty_root_and_leaf_prefix():
    assert merkle_root([]) == EMPTY_ROOT
    assert leaf(1, payload_hash(0)) == sha3_256_hex(
        (1).to_bytes(8, "big") + bytes.fromhex(payload_hash(0))
    )


# -- SPEC section 2: keys and signatures -------------------------------------


def test_derived_keys_are_reproducible_and_generated_ones_are_not():
    a = SigningKey.derive("recorder", demo_seed("x"))
    b = SigningKey.derive("recorder", demo_seed("x"))

    assert a.public_hex == b.public_hex
    assert a.sign(b"message") == b.sign(b"message")
    assert SigningKey.generate("recorder").public_hex != a.public_hex


def test_trust_directory_is_one_hex_file_per_key(tmp_path):
    key = SigningKey.derive("anchor-1", demo_seed("y"))

    write_trust_pubkeys(tmp_path, {"anchor-1": key.public_hex})

    written = tmp_path / f"anchor-1{PUBKEY_SUFFIX}"
    assert written.read_text().strip() == key.public_hex
    assert read_trust_pubkeys(tmp_path) == {"anchor-1": key.public_hex}


def test_a_signature_does_not_verify_over_different_bytes():
    key = SigningKey.derive("recorder", demo_seed("z"))
    signature = key.sign(b"a")

    assert verify_hex(key.public_hex, signature, b"a")
    assert not verify_hex(key.public_hex, signature, b"b")


# -- SPEC section 3: records -------------------------------------------------


def test_record_zero_is_the_manifest_and_binds_nothing(tmp_path):
    recorder, _ = make_recorder(tmp_path)

    manifest_record = json.loads((recorder.records_dir / "00000.json").read_text())

    assert manifest_record["seq"] == 0
    assert manifest_record["type"] == "manifest"
    assert manifest_record["binding"] is None
    assert manifest_record["payload_hash"] == hash_obj(recorder.manifest)
    assert manifest_record["payload"]["schema"] == "flightrec/v2"


def test_every_later_record_binds_to_the_manifest_hash(tmp_path):
    recorder, _ = make_recorder(tmp_path)

    first = recorder.emit("retrieval", {"query_hash": "aa", "chunk_hashes": ["bb"]})
    second = recorder.emit("answer", {"answer_hash": "cc"})

    assert [first["seq"], second["seq"]] == [1, 2]
    assert first["binding"] == second["binding"] == recorder.manifest_hash
    assert recorder.record_count == 3


def test_the_signature_covers_the_payload_but_not_the_seq(tmp_path):
    recorder, _ = make_recorder(tmp_path)
    key = SigningKey.derive("recorder", demo_seed("test-recorder"))

    record = recorder.emit("answer", {"answer_hash": "cc"})

    message = signed_message("answer", record["payload"], record["binding"], "recorder")
    assert verify_hex(key.public_hex, record["sig"], message)
    assert b'"seq"' not in message
    edited = signed_message("answer", {"answer_hash": "dd"}, record["binding"], "recorder")
    assert not verify_hex(key.public_hex, record["sig"], edited)


def test_an_attribution_is_signed_by_the_investigator(tmp_path):
    recorder, _ = make_recorder(tmp_path)
    investigator = SigningKey.derive("investigator", demo_seed("test-investigator"))

    record = recorder.append_attribution({"method": "single-chunk-ablation"}, investigator)

    assert record["signer"] == "investigator"
    assert verify_hex(
        investigator.public_hex,
        record["sig"],
        signed_message("attribution", record["payload"], record["binding"], "investigator"),
    )


def test_the_manifest_record_cannot_be_emitted_twice(tmp_path):
    recorder, _ = make_recorder(tmp_path)

    with pytest.raises(ValueError, match="exactly one manifest"):
        recorder.emit("manifest", {"schema": "flightrec/v2"})


def test_reopening_under_a_different_manifest_is_refused(tmp_path):
    recorder, _ = make_recorder(tmp_path)
    other = build_manifest("other", "m", [], created_at="2024-01-01T00:00:00+00:00")

    with pytest.raises(ValueError, match="different manifest"):
        Recorder(recorder.dir, other, SigningKey.generate("recorder"))


def test_reopening_reads_back_the_manifest_and_appends_after_it(tmp_path):
    recorder, _ = make_recorder(tmp_path)
    recorder.emit("answer", {"answer_hash": "cc"})

    reopened = Recorder.open(recorder.dir)

    assert reopened.manifest == recorder.manifest
    assert reopened.record_count == 2


# -- SPEC section 4.3: anchors -----------------------------------------------


def test_the_anchor_commits_to_the_count_and_the_root(tmp_path):
    recorder, anchor_key = make_recorder(tmp_path)
    recorder.emit("answer", {"answer_hash": "cc"})

    anchor = recorder.anchor("anchor-1", anchor_key)

    records = recorder.read_records()
    assert anchor["payload"]["record_count"] == 2
    assert anchor["payload"]["merkle_root"] == merkle_root(
        (r["seq"], r["payload_hash"]) for r in records
    )
    assert anchor["binding"] == recorder.manifest_hash
    assert verify_hex(
        anchor_key.public_hex,
        anchor["sig"],
        signed_message("anchor", anchor["payload"], anchor["binding"], "anchor-1"),
    )


def test_reanchoring_after_an_append_covers_the_longer_bundle(tmp_path):
    recorder, anchor_key = make_recorder(tmp_path)
    recorder.emit("answer", {"answer_hash": "cc"})
    first = recorder.anchor("anchor-1", anchor_key)

    recorder.append_attribution(
        {"method": "single-chunk-ablation"}, SigningKey.derive("investigator", demo_seed("i"))
    )
    second = recorder.reanchor("anchor-2", SigningKey.derive("anchor-2", demo_seed("a2")))

    assert first["payload"]["record_count"] == 2
    assert second["payload"]["record_count"] == 3
    assert first["payload"]["merkle_root"] != second["payload"]["merkle_root"]


def test_an_anchor_id_cannot_be_reused(tmp_path):
    recorder, anchor_key = make_recorder(tmp_path)
    recorder.anchor("anchor-1", anchor_key)

    with pytest.raises(ValueError, match="already exists"):
        recorder.anchor("anchor-1", anchor_key)


def test_null_recorder_writes_nothing(tmp_path):
    recorder = NullRecorder()
    recorder.emit("retrieval", {"query_hash": "aa"})
    recorder.anchor("anchor-1")

    assert list(recorder.types()) == ["retrieval"]
    assert list(tmp_path.iterdir()) == []
