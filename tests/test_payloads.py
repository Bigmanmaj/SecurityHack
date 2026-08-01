from datetime import datetime

import pytest

from attest.canonical import canonical_bytes
from attest.clock import utc_now_iso
from attest.hashing import hash_payload
from attest.payloads import (
    anchor_payload,
    answer_payload,
    attribution_payload,
    manifest_payload,
    retrieval_payload,
    tool_call_payload,
)

BINDING = hash_payload({"type": "manifest"})
CHUNK = hash_payload("a retrieved chunk")
TS = "2026-08-01T10:00:00.000Z"


def test_utc_now_iso_is_an_iso8601_utc_string():
    now = utc_now_iso()
    assert now.endswith("Z")
    assert datetime.fromisoformat(now.replace("Z", "+00:00")).utcoffset().total_seconds() == 0


def test_manifest_payload_has_seq_zero_and_no_binding():
    payload = manifest_payload(
        episode_id="ep-1",
        agent_id="agent-a",
        model="claude-sonnet-4",
        forbidden_tools=["shell.exec"],
        ts=TS,
    )
    assert payload == {
        "type": "manifest",
        "seq": 0,
        "ts": TS,
        "episode_id": "ep-1",
        "agent_id": "agent-a",
        "model": "claude-sonnet-4",
        "policy": {"forbidden_tools": ["shell.exec"]},
    }


def test_retrieval_payload_carries_hashes_only():
    payload = retrieval_payload(
        seq=1, chain_binding=BINDING, query_hash=CHUNK, chunk_hashes=[CHUNK], ts=TS
    )
    assert payload == {
        "type": "retrieval",
        "seq": 1,
        "ts": TS,
        "chain_binding": BINDING,
        "query_hash": CHUNK,
        "chunk_hashes": [CHUNK],
    }


def test_tool_call_payload():
    payload = tool_call_payload(seq=2, chain_binding=BINDING, tool="shell.exec", args_hash=CHUNK, ts=TS)
    assert payload == {
        "type": "tool_call",
        "seq": 2,
        "ts": TS,
        "chain_binding": BINDING,
        "tool": "shell.exec",
        "args_hash": CHUNK,
    }


def test_answer_payload():
    payload = answer_payload(seq=3, chain_binding=BINDING, answer_hash=CHUNK, ts=TS)
    assert payload == {
        "type": "answer",
        "seq": 3,
        "ts": TS,
        "chain_binding": BINDING,
        "answer_hash": CHUNK,
    }


def test_attribution_payload_pins_method_and_findings():
    payload = attribution_payload(
        seq=4, chain_binding=BINDING, culprit_chunk_hash=CHUNK, runs=5, ts=TS
    )
    assert payload == {
        "type": "attribution",
        "seq": 4,
        "ts": TS,
        "chain_binding": BINDING,
        "method": "single-chunk-ablation",
        "culprit_chunk_hash": CHUNK,
        "runs": 5,
        "baseline_misbehaved": True,
        "flipped_on_ablation": True,
    }


def test_anchor_payload_has_no_seq():
    payload = anchor_payload(chain_binding=BINDING, record_count=5, merkle_root=CHUNK, ts=TS)
    assert payload == {
        "type": "anchor",
        "chain_binding": BINDING,
        "record_count": 5,
        "merkle_root": CHUNK,
        "ts": TS,
    }


def test_every_payload_canonicalizes():
    payloads = [
        manifest_payload("ep", "a", "m", ["t"], TS),
        retrieval_payload(1, BINDING, CHUNK, [CHUNK, CHUNK], TS),
        tool_call_payload(2, BINDING, "t", CHUNK, TS),
        answer_payload(3, BINDING, CHUNK, TS),
        attribution_payload(4, BINDING, CHUNK, 3, TS),
        anchor_payload(BINDING, 5, CHUNK, TS),
    ]
    for payload in payloads:
        assert canonical_bytes(payload)


def test_chunk_hashes_are_copied_not_aliased():
    chunks = [CHUNK]
    payload = retrieval_payload(1, BINDING, CHUNK, chunks, TS)
    chunks.append("tampered")
    assert payload["chunk_hashes"] == [CHUNK]


def test_forbidden_tools_are_copied_not_aliased():
    tools = ["shell.exec"]
    payload = manifest_payload("ep", "a", "m", tools, TS)
    tools.append("net.post")
    assert payload["policy"]["forbidden_tools"] == ["shell.exec"]


@pytest.mark.parametrize("bad_seq", [0, -1])
def test_non_manifest_payload_needs_a_positive_seq(bad_seq):
    with pytest.raises(ValueError):
        answer_payload(seq=bad_seq, chain_binding=BINDING, answer_hash=CHUNK, ts=TS)


@pytest.mark.parametrize("bad_hash", ["", "xyz", CHUNK[:-1], CHUNK.upper()])
def test_hash_fields_must_be_lowercase_hex_digests(bad_hash):
    with pytest.raises(ValueError):
        answer_payload(seq=1, chain_binding=BINDING, answer_hash=bad_hash, ts=TS)
    with pytest.raises(ValueError):
        answer_payload(seq=1, chain_binding=bad_hash, answer_hash=CHUNK, ts=TS)


def test_retrieval_rejects_a_bad_chunk_hash():
    with pytest.raises(ValueError):
        retrieval_payload(1, BINDING, CHUNK, [CHUNK, "nope"], TS)


def test_attribution_runs_must_be_a_positive_int():
    with pytest.raises(ValueError):
        attribution_payload(4, BINDING, CHUNK, 0, TS)
    with pytest.raises(ValueError):
        attribution_payload(4, BINDING, CHUNK, True, TS)


def test_record_count_must_be_a_positive_int():
    with pytest.raises(ValueError):
        anchor_payload(BINDING, 0, CHUNK, TS)


def test_timestamps_must_be_strings():
    with pytest.raises(ValueError):
        answer_payload(seq=1, chain_binding=BINDING, answer_hash=CHUNK, ts=17)
