"""The recorder: append signed records as the agent's episode happens (SPEC.md).

Only hashes of the query, chunks, tool arguments and answer are recorded, so the
bundle can be published without leaking the content it attests to.
"""

from .clock import utc_now_iso
from .episode import manifest_binding, next_seq
from .hashing import hash_payload
from .payloads import (
    answer_payload,
    attribution_payload,
    manifest_payload,
    retrieval_payload,
    tool_call_payload,
)
from .records import make_record, record_paths, write_record


def start_episode(
    episode_dir, episode_id, agent_id, model, forbidden_tools, recorder_secret_key, ts=None
):
    """Write the seq=0 manifest that opens the episode; return its path."""
    if record_paths(episode_dir):
        raise FileExistsError(f"{episode_dir} already holds records")
    payload = manifest_payload(episode_id, agent_id, model, forbidden_tools, ts or utc_now_iso())
    return write_record(episode_dir, make_record(payload, "recorder", recorder_secret_key))


def record_retrieval(episode_dir, query, chunks, recorder_secret_key, ts=None):
    """Record which chunks were retrieved for ``query``, by hash only."""
    payload = retrieval_payload(
        seq=next_seq(episode_dir),
        chain_binding=manifest_binding(episode_dir),
        query_hash=hash_payload(query),
        chunk_hashes=[hash_payload(chunk) for chunk in chunks],
        ts=ts or utc_now_iso(),
    )
    return _append(episode_dir, payload, "recorder", recorder_secret_key)


def record_tool_call(episode_dir, tool, args, recorder_secret_key, ts=None):
    """Record a tool call, binding its arguments by hash only."""
    payload = tool_call_payload(
        seq=next_seq(episode_dir),
        chain_binding=manifest_binding(episode_dir),
        tool=tool,
        args_hash=hash_payload(args),
        ts=ts or utc_now_iso(),
    )
    return _append(episode_dir, payload, "recorder", recorder_secret_key)


def record_answer(episode_dir, answer, recorder_secret_key, ts=None):
    """Record the answer the agent gave, by hash only."""
    payload = answer_payload(
        seq=next_seq(episode_dir),
        chain_binding=manifest_binding(episode_dir),
        answer_hash=hash_payload(answer),
        ts=ts or utc_now_iso(),
    )
    return _append(episode_dir, payload, "recorder", recorder_secret_key)


def record_attribution(episode_dir, culprit_chunk_hash, runs, investigator_secret_key, ts=None):
    """Record the investigator's single-chunk-ablation finding."""
    payload = attribution_payload(
        seq=next_seq(episode_dir),
        chain_binding=manifest_binding(episode_dir),
        culprit_chunk_hash=culprit_chunk_hash,
        runs=runs,
        ts=ts or utc_now_iso(),
    )
    return _append(episode_dir, payload, "investigator", investigator_secret_key)


def _append(episode_dir, payload, signer_id, secret_key):
    return write_record(episode_dir, make_record(payload, signer_id, secret_key))
