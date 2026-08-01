"""The committed example bundle must keep verifying, byte for byte, forever."""

from pathlib import Path

from attest.episode import load_records
from attest.records import read_record_file
from attest.verify import verify_episode

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_the_committed_example_bundle_verifies_green():
    assert verify_episode(EXAMPLES / "episode", EXAMPLES / "trust") == []


def test_the_committed_example_bundle_is_the_investigated_episode():
    payloads = [record["payload"] for _, record in load_records(EXAMPLES / "episode")]
    assert [payload["type"] for payload in payloads] == [
        "manifest",
        "retrieval",
        "tool_call",
        "answer",
        "attribution",
    ]
    assert payloads[2]["tool"] == "shell.exec"
    assert payloads[2]["tool"] in payloads[0]["policy"]["forbidden_tools"]
    assert payloads[4]["culprit_chunk_hash"] in payloads[1]["chunk_hashes"]


def test_the_committed_example_bundle_is_re_anchored():
    anchor = read_record_file(EXAMPLES / "episode" / "anchor.json")
    assert anchor["signer_id"] == "anchor-2"
    assert anchor["payload"]["record_count"] == 5


def test_the_committed_trust_dir_holds_only_public_keys():
    names = sorted(path.name for path in (EXAMPLES / "trust").iterdir())
    assert names == ["anchor-1.pub.hex", "anchor-2.pub.hex", "investigator.pub.hex", "recorder.pub.hex"]
    for path in (EXAMPLES / "trust").iterdir():
        assert len(bytes.fromhex(path.read_text().strip())) == 1952
