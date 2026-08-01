import json
from datetime import datetime

import pytest

from attest.hashing import hash_payload
from attest.keys import verify_payload
from attest.payloads import answer_payload, manifest_payload
from attest.records import (
    make_record,
    read_record_file,
    record_filename,
    record_paths,
    records_dir,
    write_record,
    write_record_file,
)

TS = "2026-08-01T10:00:00.000Z"


def a_payload(seq=1):
    if seq == 0:
        return manifest_payload("ep-1", "agent-a", "model-m", ["shell.exec"], TS)
    return answer_payload(seq=seq, chain_binding=hash_payload({"m": 1}), answer_hash=hash_payload("a"), ts=TS)


def test_make_record_has_exactly_the_spec_fields(secret_keys):
    record = make_record(a_payload(), "recorder", secret_keys["recorder"])
    assert set(record) == {"payload", "payload_hash", "signature", "signer_id", "created_at"}


def test_make_record_hash_and_signature_are_recomputable(keyring, secret_keys):
    payload = a_payload()
    record = make_record(payload, "recorder", secret_keys["recorder"])
    assert record["payload"] == payload
    assert record["payload_hash"] == hash_payload(payload)
    assert record["signer_id"] == "recorder"
    assert verify_payload(keyring["recorder"][0], record["payload"], record["signature"])


def test_make_record_created_at_is_iso8601_utc(secret_keys):
    record = make_record(a_payload(), "recorder", secret_keys["recorder"])
    created_at = record["created_at"]
    assert created_at.endswith("Z")
    assert datetime.fromisoformat(created_at.replace("Z", "+00:00"))


def test_make_record_accepts_an_explicit_created_at(secret_keys):
    record = make_record(a_payload(), "recorder", secret_keys["recorder"], created_at=TS)
    assert record["created_at"] == TS


def test_make_record_refuses_an_unknown_signer(secret_keys):
    with pytest.raises(ValueError):
        make_record(a_payload(), "attacker", secret_keys["recorder"])


def test_record_filename_is_zero_padded_seq():
    assert record_filename(0) == "000000.json"
    assert record_filename(42) == "000042.json"
    assert record_filename(123456) == "123456.json"
    assert record_filename(1234567) == "1234567.json"


def test_records_dir_is_records_under_the_episode(tmp_path):
    assert records_dir(tmp_path) == tmp_path / "records"


def test_write_record_names_the_file_after_the_payload_seq(tmp_path, secret_keys):
    record = make_record(a_payload(seq=7), "recorder", secret_keys["recorder"])
    path = write_record(tmp_path, record)
    assert path == tmp_path / "records" / "000007.json"
    assert read_record_file(path) == record


def test_write_record_output_is_readable_json_with_trailing_newline(tmp_path, secret_keys):
    record = make_record(manifest_payload("ép-1", "a", "m", ["t"], TS), "recorder", secret_keys["recorder"])
    path = write_record(tmp_path, record)
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert "\n  " in text
    assert "ép-1" in text
    assert json.loads(text) == record


def test_written_record_survives_big_ints(tmp_path, secret_keys):
    payload = a_payload()
    payload["runs"] = 2**70
    record = make_record(payload, "recorder", secret_keys["recorder"])
    path = write_record(tmp_path, record)
    assert read_record_file(path)["payload"]["runs"] == 2**70


def test_write_record_refuses_a_payload_without_an_int_seq(tmp_path, secret_keys):
    record = make_record(a_payload(), "recorder", secret_keys["recorder"])
    del record["payload"]["seq"]
    with pytest.raises(ValueError):
        write_record(tmp_path, record)


def test_write_record_file_writes_where_told(tmp_path, secret_keys):
    record = make_record(a_payload(), "recorder", secret_keys["recorder"])
    path = write_record_file(tmp_path / "anchor.json", record)
    assert path.exists()
    assert read_record_file(path) == record


def test_write_record_file_overwrites(tmp_path, secret_keys):
    first = make_record(a_payload(seq=1), "anchor-1", secret_keys["anchor-1"])
    second = make_record(a_payload(seq=2), "anchor-2", secret_keys["anchor-2"])
    path = tmp_path / "anchor.json"
    write_record_file(path, first)
    write_record_file(path, second)
    assert read_record_file(path) == second


def test_record_paths_are_sorted_by_filename(tmp_path, secret_keys):
    for seq in [2, 0, 10, 1]:
        write_record(tmp_path, make_record(a_payload(seq=seq), "recorder", secret_keys["recorder"]))
    assert [path.name for path in record_paths(tmp_path)] == [
        "000000.json",
        "000001.json",
        "000002.json",
        "000010.json",
    ]


def test_record_paths_ignores_non_record_files(tmp_path, secret_keys):
    write_record(tmp_path, make_record(a_payload(seq=0), "recorder", secret_keys["recorder"]))
    (tmp_path / "records" / "notes.txt").write_text("hi")
    (tmp_path / "records" / "000001.json.bak").write_text("{}")
    assert [path.name for path in record_paths(tmp_path)] == ["000000.json"]


def test_record_paths_is_empty_for_a_missing_records_dir(tmp_path):
    assert record_paths(tmp_path) == []


def test_no_secret_key_material_is_written(tmp_path, secret_keys):
    write_record(tmp_path, make_record(a_payload(), "recorder", secret_keys["recorder"]))
    written = (tmp_path / "records" / "000001.json").read_text(encoding="utf-8")
    assert secret_keys["recorder"].hex() not in written
