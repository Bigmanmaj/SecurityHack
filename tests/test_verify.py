import json

import pytest

from attest.anchoring import write_anchor
from attest.hashing import hash_payload
from attest.keys import sign_payload, write_public_key
from attest.payloads import answer_payload
from attest.records import make_record, read_record_file, write_record, write_record_file
from attest.verify import verify_episode

MANIFEST = "records/000000.json"
RETRIEVAL = "records/000001.json"
TOOL_CALL = "records/000002.json"
ANSWER = "records/000003.json"
ATTRIBUTION = "records/000004.json"
ANCHOR = "anchor.json"
OTHER_DIGEST = hash_payload("some other object entirely")


def rewrite(episode_dir, relative, mutate):
    """Apply ``mutate`` to a record file in place, exactly as an attacker would."""
    path = episode_dir / relative
    record = read_record_file(path)
    mutate(record)
    write_record_file(path, record)
    return path


def test_an_honest_bundle_verifies_green(episode_dir, trust_dir):
    assert verify_episode(episode_dir, trust_dir) == []


def test_an_episode_without_an_investigation_verifies_green(tmp_path, trust_dir, secret_keys):
    from attest.recorder import record_answer, start_episode

    directory = tmp_path / "clean"
    start_episode(directory, "ep-2", "bot", "model", [], secret_keys["recorder"], ts="t0")
    record_answer(directory, "all good", secret_keys["recorder"], ts="t1")
    write_anchor(directory, "anchor-1", secret_keys["anchor-1"], ts="t2")
    assert verify_episode(directory, trust_dir) == []


def test_stored_payload_hash_is_recomputed(episode_dir, trust_dir):
    rewrite(episode_dir, TOOL_CALL, lambda record: record.update(payload_hash=OTHER_DIGEST))
    assert verify_episode(episode_dir, trust_dir) == [f"HASH_MISMATCH({TOOL_CALL})"]


def test_editing_a_payload_breaks_hash_signature_and_root(episode_dir, trust_dir):
    rewrite(episode_dir, TOOL_CALL, lambda record: record["payload"].update(tool="docs.search"))
    assert verify_episode(episode_dir, trust_dir) == [
        f"HASH_MISMATCH({TOOL_CALL})",
        f"BAD_SIGNATURE({TOOL_CALL})",
        "ROOT_MISMATCH",
    ]


def test_repairing_the_hash_still_leaves_signature_and_root(episode_dir, trust_dir):
    def edit(record):
        record["payload"]["tool"] = "docs.search"
        record["payload_hash"] = hash_payload(record["payload"])

    rewrite(episode_dir, TOOL_CALL, edit)
    assert verify_episode(episode_dir, trust_dir) == [
        f"BAD_SIGNATURE({TOOL_CALL})",
        "ROOT_MISMATCH",
    ]


def test_resigning_with_an_untrusted_key_is_caught(episode_dir, trust_dir, attacker_key):
    def forge(record):
        record["payload"]["tool"] = "docs.search"
        record["payload_hash"] = hash_payload(record["payload"])
        record["signature"] = sign_payload(attacker_key[1], record["payload"])

    rewrite(episode_dir, TOOL_CALL, forge)
    assert verify_episode(episode_dir, trust_dir) == [
        f"BAD_SIGNATURE({TOOL_CALL})",
        "ROOT_MISMATCH",
    ]


def test_keys_shipped_inside_the_bundle_are_never_trusted(episode_dir, trust_dir, attacker_key):
    def forge(record):
        record["payload"]["tool"] = "docs.search"
        record["payload_hash"] = hash_payload(record["payload"])
        record["signature"] = sign_payload(attacker_key[1], record["payload"])

    rewrite(episode_dir, TOOL_CALL, forge)
    write_public_key(episode_dir / "trust", "recorder", attacker_key[0])
    assert f"BAD_SIGNATURE({TOOL_CALL})" in verify_episode(episode_dir, trust_dir)


def test_unknown_signer_is_named(episode_dir, trust_dir):
    rewrite(episode_dir, ANSWER, lambda record: record.update(signer_id="ghost"))
    assert verify_episode(episode_dir, trust_dir) == [f"UNKNOWN_SIGNER({ANSWER})"]


def test_a_trusted_key_in_the_wrong_role_is_rejected(episode_dir, trust_dir, secret_keys):
    def swap_signer(record):
        record["signer_id"] = "investigator"
        record["signature"] = sign_payload(secret_keys["investigator"], record["payload"])

    rewrite(episode_dir, ANSWER, swap_signer)
    assert verify_episode(episode_dir, trust_dir) == [f"WRONG_SIGNER({ANSWER})"]


def test_attribution_signed_by_the_recorder_is_rejected(episode_dir, trust_dir, secret_keys):
    def swap_signer(record):
        record["signer_id"] = "recorder"
        record["signature"] = sign_payload(secret_keys["recorder"], record["payload"])

    rewrite(episode_dir, ATTRIBUTION, swap_signer)
    assert verify_episode(episode_dir, trust_dir) == [f"WRONG_SIGNER({ATTRIBUTION})"]


def test_an_empty_trust_dir_makes_every_signer_unknown(episode_dir, tmp_path):
    empty = tmp_path / "empty-trust"
    empty.mkdir()
    assert verify_episode(episode_dir, empty) == [
        f"UNKNOWN_SIGNER({name})"
        for name in [MANIFEST, RETRIEVAL, TOOL_CALL, ANSWER, ATTRIBUTION]
    ] + ["BAD_ANCHOR(unknown_signer)"]


def test_a_missing_trust_dir_is_never_green(episode_dir, tmp_path):
    reasons = verify_episode(episode_dir, tmp_path / "nope")
    assert reasons == [f"UNREADABLE_TRUST_DIR({tmp_path / 'nope'})"]


def test_a_corrupt_trust_dir_is_reported_not_raised(episode_dir, trust_dir):
    (trust_dir / "recorder.pub.hex").write_text("c0ffee")
    assert verify_episode(episode_dir, trust_dir) == [f"UNREADABLE_TRUST_DIR({trust_dir})"]


def test_a_record_bound_to_the_wrong_manifest_is_caught(tmp_path, trust_dir, secret_keys):
    from attest.recorder import start_episode

    directory = tmp_path / "rebound"
    start_episode(directory, "ep-3", "bot", "model", [], secret_keys["recorder"], ts="t0")
    payload = answer_payload(seq=1, chain_binding=OTHER_DIGEST, answer_hash=OTHER_DIGEST, ts="t1")
    write_record(directory, make_record(payload, "recorder", secret_keys["recorder"]))
    write_anchor(directory, "anchor-1", secret_keys["anchor-1"], ts="t2")
    assert verify_episode(directory, trust_dir) == ["BINDING_BROKEN(records/000001.json)"]


def test_rewriting_the_manifest_breaks_every_binding(episode_dir, trust_dir, secret_keys):
    def rewrite_manifest(record):
        record["payload"]["model"] = "some-cheaper-model"
        record["payload_hash"] = hash_payload(record["payload"])
        record["signature"] = sign_payload(secret_keys["recorder"], record["payload"])

    rewrite(episode_dir, MANIFEST, rewrite_manifest)
    write_anchor(episode_dir, "anchor-2", secret_keys["anchor-2"], ts="2026-08-01T11:00:00.000Z")
    assert verify_episode(episode_dir, trust_dir) == [
        f"BINDING_BROKEN({name})" for name in [RETRIEVAL, TOOL_CALL, ANSWER, ATTRIBUTION]
    ]


def test_a_missing_chain_binding_is_broken(episode_dir, trust_dir, secret_keys):
    def drop_binding(record):
        del record["payload"]["chain_binding"]
        record["payload_hash"] = hash_payload(record["payload"])
        record["signature"] = sign_payload(secret_keys["recorder"], record["payload"])

    rewrite(episode_dir, ANSWER, drop_binding)
    write_anchor(episode_dir, "anchor-2", secret_keys["anchor-2"], ts="2026-08-01T11:00:00.000Z")
    assert verify_episode(episode_dir, trust_dir) == [f"BINDING_BROKEN({ANSWER})"]


def test_deleting_a_record_is_caught(episode_dir, trust_dir):
    (episode_dir / TOOL_CALL).unlink()
    assert verify_episode(episode_dir, trust_dir) == [
        "SEQ_GAP_OR_DUP",
        "COUNT_MISMATCH",
        "ROOT_MISMATCH",
    ]


def test_a_duplicated_seq_is_caught(episode_dir, trust_dir, secret_keys):
    record = read_record_file(episode_dir / ANSWER)
    write_record_file(episode_dir / "records" / "000009.json", record)
    assert verify_episode(episode_dir, trust_dir) == [
        "SEQ_GAP_OR_DUP",
        "COUNT_MISMATCH",
        "ROOT_MISMATCH",
    ]


def test_appending_a_record_without_re_anchoring_is_caught(episode_dir, trust_dir, secret_keys):
    from attest.recorder import record_answer

    record_answer(episode_dir, "and one more thing", secret_keys["recorder"], ts="t9")
    assert verify_episode(episode_dir, trust_dir) == ["COUNT_MISMATCH", "ROOT_MISMATCH"]


def test_dropping_the_investigation_and_re_anchoring_is_still_caught(episode_dir, trust_dir, secret_keys):
    """An anchor cannot un-say what an earlier anchor said, but the count must add up."""
    (episode_dir / ATTRIBUTION).unlink()
    write_anchor(episode_dir, "anchor-2", secret_keys["anchor-2"], ts="t9")
    assert verify_episode(episode_dir, trust_dir) == []


def test_swapping_two_record_filenames_is_not_a_tamper(episode_dir, trust_dir):
    """Order comes from the signed seq inside each payload, not from the filename."""
    retrieval = read_record_file(episode_dir / RETRIEVAL)
    tool_call = read_record_file(episode_dir / TOOL_CALL)
    write_record_file(episode_dir / RETRIEVAL, tool_call)
    write_record_file(episode_dir / TOOL_CALL, retrieval)
    assert verify_episode(episode_dir, trust_dir) == []


def test_reordering_the_signed_seqs_changes_the_root(episode_dir, trust_dir, secret_keys):
    for name, seq in [(RETRIEVAL, 2), (TOOL_CALL, 1)]:
        def renumber(record, seq=seq):
            record["payload"]["seq"] = seq
            record["payload_hash"] = hash_payload(record["payload"])
            record["signature"] = sign_payload(secret_keys["recorder"], record["payload"])

        rewrite(episode_dir, name, renumber)
    assert verify_episode(episode_dir, trust_dir) == ["ROOT_MISMATCH"]


def test_a_missing_anchor_is_named(episode_dir, trust_dir):
    (episode_dir / ANCHOR).unlink()
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(missing)"]


def test_an_unparseable_anchor_is_named(episode_dir, trust_dir):
    (episode_dir / ANCHOR).write_text("{not json")
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(malformed)"]


def test_an_anchor_that_is_not_an_anchor_is_named(episode_dir, trust_dir, secret_keys):
    answer = read_record_file(episode_dir / ANSWER)
    write_record_file(episode_dir / ANCHOR, answer)
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(malformed)"]


def test_anchor_hash_is_recomputed(episode_dir, trust_dir):
    rewrite(episode_dir, ANCHOR, lambda record: record.update(payload_hash=OTHER_DIGEST))
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(hash_mismatch)"]


def test_anchor_signature_is_checked(episode_dir, trust_dir):
    rewrite(episode_dir, ANCHOR, lambda record: record.update(signature="00" * 3309))
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(bad_signature)"]


def test_anchor_signed_by_an_unknown_key_is_named(episode_dir, trust_dir):
    rewrite(episode_dir, ANCHOR, lambda record: record.update(signer_id="ghost"))
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(unknown_signer)"]


def test_anchor_signed_by_the_recorder_is_named(episode_dir, trust_dir, secret_keys):
    def swap_signer(record):
        record["signer_id"] = "recorder"
        record["signature"] = sign_payload(secret_keys["recorder"], record["payload"])

    rewrite(episode_dir, ANCHOR, swap_signer)
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(unexpected_signer)"]


def test_anchor_bound_to_another_manifest_is_named(episode_dir, trust_dir, secret_keys):
    def rebind(record):
        record["payload"]["chain_binding"] = OTHER_DIGEST
        record["payload_hash"] = hash_payload(record["payload"])
        record["signature"] = sign_payload(secret_keys["anchor-2"], record["payload"])

    rewrite(episode_dir, ANCHOR, rebind)
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(binding_broken)"]


def test_a_lying_record_count_is_caught(episode_dir, trust_dir, secret_keys):
    def relabel(record):
        record["payload"]["record_count"] = 4
        record["payload_hash"] = hash_payload(record["payload"])
        record["signature"] = sign_payload(secret_keys["anchor-2"], record["payload"])

    rewrite(episode_dir, ANCHOR, relabel)
    assert verify_episode(episode_dir, trust_dir) == ["COUNT_MISMATCH"]


def test_a_lying_merkle_root_is_caught(episode_dir, trust_dir, secret_keys):
    def relabel(record):
        record["payload"]["merkle_root"] = OTHER_DIGEST
        record["payload_hash"] = hash_payload(record["payload"])
        record["signature"] = sign_payload(secret_keys["anchor-2"], record["payload"])

    rewrite(episode_dir, ANCHOR, relabel)
    assert verify_episode(episode_dir, trust_dir) == ["ROOT_MISMATCH"]


def test_an_anchor_missing_its_fields_is_malformed(episode_dir, trust_dir, secret_keys):
    def strip(record):
        del record["payload"]["merkle_root"]
        record["payload_hash"] = hash_payload(record["payload"])
        record["signature"] = sign_payload(secret_keys["anchor-2"], record["payload"])

    rewrite(episode_dir, ANCHOR, strip)
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(malformed)"]


def test_a_float_in_a_payload_is_malformed(episode_dir, trust_dir):
    rewrite(episode_dir, ATTRIBUTION, lambda record: record["payload"].update(runs=5.0))
    assert verify_episode(episode_dir, trust_dir) == [
        f"MALFORMED_RECORD({ATTRIBUTION})",
        "SEQ_GAP_OR_DUP",
        "ROOT_MISMATCH",
    ]


def test_a_float_in_the_anchor_is_malformed(episode_dir, trust_dir):
    rewrite(episode_dir, ANCHOR, lambda record: record["payload"].update(record_count=5.0))
    assert verify_episode(episode_dir, trust_dir) == ["BAD_ANCHOR(malformed)"]


def test_an_unparseable_record_is_malformed(episode_dir, trust_dir):
    (episode_dir / ANSWER).write_text("}}garbage")
    reasons = verify_episode(episode_dir, trust_dir)
    assert reasons[0] == f"MALFORMED_RECORD({ANSWER})"
    assert set(reasons[1:]) == {"SEQ_GAP_OR_DUP", "ROOT_MISMATCH"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda record: record.pop("signature"),
        lambda record: record.pop("signer_id"),
        lambda record: record.pop("payload_hash"),
        lambda record: record.pop("created_at"),
        lambda record: record.update(payload="not a dict"),
        lambda record: record.update(signature=17),
        lambda record: record["payload"].pop("seq"),
        lambda record: record["payload"].pop("type"),
        lambda record: record["payload"].pop("ts"),
        lambda record: record["payload"].update(seq="3"),
        lambda record: record["payload"].update(type="gossip"),
    ],
)
def test_structurally_unusable_records_are_malformed(episode_dir, trust_dir, mutate):
    rewrite(episode_dir, ANSWER, mutate)
    assert f"MALFORMED_RECORD({ANSWER})" in verify_episode(episode_dir, trust_dir)


def test_a_manifest_that_is_not_at_seq_zero_is_malformed(episode_dir, trust_dir):
    rewrite(episode_dir, MANIFEST, lambda record: record["payload"].update(seq=1))
    assert f"MALFORMED_RECORD({MANIFEST})" in verify_episode(episode_dir, trust_dir)


def test_an_episode_with_no_records_is_never_green(tmp_path, trust_dir):
    empty = tmp_path / "empty"
    (empty / "records").mkdir(parents=True)
    assert verify_episode(empty, trust_dir) == ["BAD_ANCHOR(missing)"]


def test_deleting_every_record_but_keeping_the_anchor_is_caught(episode_dir, trust_dir):
    for path in (episode_dir / "records").iterdir():
        path.unlink()
    assert verify_episode(episode_dir, trust_dir) == [
        "COUNT_MISMATCH",
        "ROOT_MISMATCH",
        "BAD_ANCHOR(binding_broken)",
    ]


def test_a_missing_episode_dir_is_never_green(tmp_path, trust_dir):
    assert verify_episode(tmp_path / "nowhere", trust_dir) != []


def test_reasons_are_deterministic(episode_dir, trust_dir):
    (episode_dir / TOOL_CALL).unlink()
    assert verify_episode(episode_dir, trust_dir) == verify_episode(episode_dir, trust_dir)


def test_verification_does_not_modify_the_bundle(episode_dir, trust_dir):
    before = {
        path.relative_to(episode_dir).as_posix(): path.read_bytes()
        for path in sorted(episode_dir.rglob("*.json"))
    }
    verify_episode(episode_dir, trust_dir)
    after = {
        path.relative_to(episode_dir).as_posix(): path.read_bytes()
        for path in sorted(episode_dir.rglob("*.json"))
    }
    assert before == after


def test_record_files_with_odd_names_are_ignored(episode_dir, trust_dir):
    (episode_dir / "records" / "notes.txt").write_text("hello")
    (episode_dir / "records" / "backup.json.bak").write_text(
        json.dumps(read_record_file(episode_dir / ANSWER))
    )
    assert verify_episode(episode_dir, trust_dir) == []
