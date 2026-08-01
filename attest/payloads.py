"""Builders for the payload schemas in SPEC.md.

Every payload carries "type", "seq" and "ts"; every payload except the manifest
carries "chain_binding", the manifest's payload_hash. Retrieval and tool-call
payloads carry hashes only — never the retrieved content or the tool arguments.
"""

_HEX_DIGITS = set("0123456789abcdef")


def manifest_payload(episode_id, agent_id, model, forbidden_tools, ts):
    """Build the seq=0 manifest that every later record binds itself to."""
    return {
        "type": "manifest",
        "seq": 0,
        "ts": _require_ts(ts),
        "episode_id": _require_str("episode_id", episode_id),
        "agent_id": _require_str("agent_id", agent_id),
        "model": _require_str("model", model),
        "policy": {"forbidden_tools": [_require_str("forbidden_tool", t) for t in forbidden_tools]},
    }


def retrieval_payload(seq, chain_binding, query_hash, chunk_hashes, ts):
    """Build a retrieval record: which chunks were retrieved, by hash."""
    return {
        "type": "retrieval",
        "seq": _require_seq(seq),
        "ts": _require_ts(ts),
        "chain_binding": _require_digest("chain_binding", chain_binding),
        "query_hash": _require_digest("query_hash", query_hash),
        "chunk_hashes": [_require_digest("chunk_hash", h) for h in chunk_hashes],
    }


def tool_call_payload(seq, chain_binding, tool, args_hash, ts):
    """Build a tool-call record: which tool ran, with arguments bound by hash."""
    return {
        "type": "tool_call",
        "seq": _require_seq(seq),
        "ts": _require_ts(ts),
        "chain_binding": _require_digest("chain_binding", chain_binding),
        "tool": _require_str("tool", tool),
        "args_hash": _require_digest("args_hash", args_hash),
    }


def answer_payload(seq, chain_binding, answer_hash, ts):
    """Build an answer record binding the answer the agent finally gave."""
    return {
        "type": "answer",
        "seq": _require_seq(seq),
        "ts": _require_ts(ts),
        "chain_binding": _require_digest("chain_binding", chain_binding),
        "answer_hash": _require_digest("answer_hash", answer_hash),
    }


def attribution_payload(seq, chain_binding, culprit_chunk_hash, runs, ts):
    """Build the investigator's finding: which chunk caused the misbehaviour.

    The record only exists when the baseline misbehaved and ablating this one
    chunk flipped the behaviour, so both findings are pinned true.
    """
    return {
        "type": "attribution",
        "seq": _require_seq(seq),
        "ts": _require_ts(ts),
        "chain_binding": _require_digest("chain_binding", chain_binding),
        "method": "single-chunk-ablation",
        "culprit_chunk_hash": _require_digest("culprit_chunk_hash", culprit_chunk_hash),
        "runs": _require_positive_int("runs", runs),
        "baseline_misbehaved": True,
        "flipped_on_ablation": True,
    }


def anchor_payload(chain_binding, record_count, merkle_root, ts):
    """Build the anchor payload: how many records there are and their Merkle root."""
    return {
        "type": "anchor",
        "chain_binding": _require_digest("chain_binding", chain_binding),
        "record_count": _require_positive_int("record_count", record_count),
        "merkle_root": _require_digest("merkle_root", merkle_root),
        "ts": _require_ts(ts),
    }


def _require_str(field, value):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string, got {value!r}")
    return value


def _require_ts(value):
    return _require_str("ts", value)


def _require_seq(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"seq must be an int >= 1 (seq 0 is the manifest), got {value!r}")
    return value


def _require_positive_int(field, value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be an int >= 1, got {value!r}")
    return value


def _require_digest(field, value):
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX_DIGITS:
        raise ValueError(f"{field} must be 64 lowercase hex digits, got {value!r}")
    return value
