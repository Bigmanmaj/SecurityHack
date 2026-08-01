import json

import pytest

from flightrec.canonical import canonical_bytes, hash_obj
from flightrec.crypto import SigningKey, write_trust_pubkeys
from flightrec.recorder import NullRecorder, Recorder, build_manifest
from flightrec.verify import verify_bundle


def make_bundle(tmp_path):
    recorder_key = SigningKey.generate("recorder")
    anchor_key = SigningKey.generate("anchor-1")
    manifest = build_manifest(
        agent_id="test-agent",
        model="fake-model",
        forbidden_tools=["transfer_funds"],
        recorder_pubkey=recorder_key.public_hex,
        created_at="2024-01-01T00:00:00+00:00",
    )
    recorder = Recorder(tmp_path / "episode", manifest, recorder_key)
    write_trust_pubkeys(
        tmp_path / "trust",
        {"recorder": recorder_key.public_hex, "anchor-1": anchor_key.public_hex},
    )
    return recorder, anchor_key


def test_chain_starts_at_the_manifest_and_links_forward(tmp_path):
    recorder, _ = make_bundle(tmp_path)

    first = recorder.emit("retrieval", {"query_hash": "aa", "chunk_hashes": ["bb"]})
    second = recorder.emit("answer", {"answer_hash": "cc"})

    assert first["prev_hash"] == hash_obj(recorder.manifest)
    assert second["prev_hash"] == first["hash"]
    assert recorder.head_hash == second["hash"]
    assert [p.name for p in recorder._record_paths()] == ["00000.json", "00001.json"]


def test_bundle_verifies_end_to_end(tmp_path):
    recorder, anchor_key = make_bundle(tmp_path)
    recorder.emit("retrieval", {"query_hash": "aa", "chunk_hashes": ["bb"]})
    recorder.emit("tool_call", {"tool": "transfer_funds", "args_hash": "dd", "executed": False})
    recorder.emit("answer", {"answer_hash": "cc"})
    recorder.anchor("anchor-1", anchor_key)

    report = verify_bundle(tmp_path / "episode", tmp_path / "trust")

    assert report.ok, report.failures
    assert report.n_records == 3
    assert report.n_anchors == 1
    assert [v["tool"] for v in report.violations] == ["transfer_funds"]


def test_editing_a_record_breaks_verification(tmp_path):
    recorder, anchor_key = make_bundle(tmp_path)
    recorder.emit("tool_call", {"tool": "transfer_funds", "args_hash": "dd", "executed": False})
    recorder.emit("answer", {"answer_hash": "cc"})
    recorder.anchor("anchor-1", anchor_key)

    target = recorder.records_dir / "00000.json"
    tampered = json.loads(target.read_text())
    tampered["payload"]["tool"] = "lookup_account"
    target.write_text(json.dumps(tampered))

    report = verify_bundle(tmp_path / "episode", tmp_path / "trust")

    assert not report.ok
    assert any("does not match its hash" in failure for failure in report.failures)


def test_deleting_the_last_record_breaks_the_anchor(tmp_path):
    recorder, anchor_key = make_bundle(tmp_path)
    recorder.emit("tool_call", {"tool": "transfer_funds", "args_hash": "dd", "executed": False})
    recorder.emit("answer", {"answer_hash": "cc"})
    recorder.anchor("anchor-1", anchor_key)

    (recorder.records_dir / "00001.json").unlink()

    report = verify_bundle(tmp_path / "episode", tmp_path / "trust")

    assert not report.ok
    assert any("not in the bundle" in failure for failure in report.failures)


def test_attribution_is_signed_by_the_investigator_and_reanchored(tmp_path):
    recorder, anchor_key = make_bundle(tmp_path)
    recorder.emit("answer", {"answer_hash": "cc"})
    recorder.anchor("anchor-1", anchor_key)

    investigator_key = SigningKey.generate("investigator")
    anchor_2 = SigningKey.generate("anchor-2")
    record = recorder.append_attribution(
        {"method": "single-chunk-ablation", "culprit_chunk_hash": "ee"}, investigator_key
    )
    recorder.reanchor("anchor-2", anchor_2)
    write_trust_pubkeys(
        tmp_path / "trust",
        {"investigator": investigator_key.public_hex, "anchor-2": anchor_2.public_hex},
    )

    assert record["signature"]["key_id"] == "investigator"

    report = verify_bundle(tmp_path / "episode", tmp_path / "trust")
    assert report.ok, report.failures
    assert report.attributions[0]["culprit_chunk_hash"] == "ee"
    assert report.n_anchors == 2


def test_a_signature_from_an_untrusted_key_is_rejected(tmp_path):
    recorder, anchor_key = make_bundle(tmp_path)
    recorder.emit("answer", {"answer_hash": "cc"})
    recorder.anchor("anchor-1", anchor_key)
    recorder.append_attribution({"method": "x"}, SigningKey.generate("investigator"))

    report = verify_bundle(tmp_path / "episode", tmp_path / "trust")

    assert not report.ok
    assert any("unknown key" in failure for failure in report.failures)


def test_reopening_with_a_different_manifest_is_refused(tmp_path):
    recorder, _ = make_bundle(tmp_path)
    other = build_manifest("other", "m", [], "00", created_at="2024-01-01T00:00:00+00:00")

    with pytest.raises(ValueError):
        Recorder(recorder.dir, other, SigningKey.generate("recorder"))


def test_canonical_bytes_is_order_independent():
    assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})
    assert hash_obj({"a": 1}) != hash_obj({"a": 2})


def test_null_recorder_writes_nothing(tmp_path):
    recorder = NullRecorder()
    recorder.emit("retrieval", {"query_hash": "aa"})
    recorder.anchor("anchor-1")

    assert list(recorder.types()) == ["retrieval"]
    assert list(tmp_path.iterdir()) == []
