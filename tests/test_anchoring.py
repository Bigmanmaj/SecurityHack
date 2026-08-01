import pytest

from attest.anchoring import write_anchor
from attest.episode import manifest_binding, record_entries
from attest.hashing import hash_payload
from attest.keys import verify_payload
from attest.merkle import episode_merkle_root
from attest.recorder import record_answer, record_attribution, record_retrieval, start_episode
from attest.records import read_record_file

CHUNKS = ["clean chunk", "poisoned chunk"]


@pytest.fixture
def episode(tmp_path, secret_keys):
    directory = tmp_path / "episode"
    start_episode(
        directory,
        episode_id="ep-1",
        agent_id="support-bot",
        model="claude-sonnet-4-5",
        forbidden_tools=["shell.exec"],
        recorder_secret_key=secret_keys["recorder"],
    )
    record_retrieval(directory, "q", CHUNKS, secret_keys["recorder"])
    record_answer(directory, "a", secret_keys["recorder"])
    return directory


def test_write_anchor_writes_anchor_json_signed_by_anchor_1(episode, keyring, secret_keys):
    path = write_anchor(episode, "anchor-1", secret_keys["anchor-1"])
    assert path == episode / "anchor.json"
    record = read_record_file(path)
    assert record["signer_id"] == "anchor-1"
    assert record["payload_hash"] == hash_payload(record["payload"])
    assert verify_payload(keyring["anchor-1"][0], record["payload"], record["signature"])


def test_anchor_payload_states_the_count_root_and_binding(episode, secret_keys):
    path = write_anchor(episode, "anchor-1", secret_keys["anchor-1"])
    payload = read_record_file(path)["payload"]
    assert payload["type"] == "anchor"
    assert payload["record_count"] == 3
    assert payload["merkle_root"] == episode_merkle_root(record_entries(episode))
    assert payload["chain_binding"] == manifest_binding(episode)
    assert "seq" not in payload


def test_re_anchoring_after_investigation_overwrites_with_anchor_2(episode, secret_keys):
    first = read_record_file(write_anchor(episode, "anchor-1", secret_keys["anchor-1"]))
    record_attribution(episode, hash_payload(CHUNKS[1]), 5, secret_keys["investigator"])
    second = read_record_file(write_anchor(episode, "anchor-2", secret_keys["anchor-2"]))

    assert second["signer_id"] == "anchor-2"
    assert second["payload"]["record_count"] == 4
    assert second["payload"]["merkle_root"] != first["payload"]["merkle_root"]
    assert second["payload"]["merkle_root"] == episode_merkle_root(record_entries(episode))
    assert second["payload"]["chain_binding"] == first["payload"]["chain_binding"]


def test_only_anchor_signers_may_anchor(episode, secret_keys):
    for signer_id in ["recorder", "investigator"]:
        with pytest.raises(ValueError):
            write_anchor(episode, signer_id, secret_keys[signer_id])


def test_anchoring_an_empty_episode_fails(tmp_path, secret_keys):
    with pytest.raises(FileNotFoundError):
        write_anchor(tmp_path / "empty", "anchor-1", secret_keys["anchor-1"])


def test_anchor_timestamp_can_be_pinned(episode, secret_keys):
    path = write_anchor(episode, "anchor-1", secret_keys["anchor-1"], ts="2026-08-01T13:00:00.000Z")
    assert read_record_file(path)["payload"]["ts"] == "2026-08-01T13:00:00.000Z"


def test_no_secret_key_material_lands_in_the_anchor(episode, secret_keys):
    path = write_anchor(episode, "anchor-1", secret_keys["anchor-1"])
    written = path.read_text(encoding="utf-8")
    assert all(secret_key.hex() not in written for secret_key in secret_keys.values())
