"""Tampers an attacker without any signing key could try, and what they cost.

Each function mutates a bundle in place and returns the reason the verifier is
expected to name for it.
"""

from attest.hashing import hash_payload
from attest.records import read_record_file, write_record_file

ANSWER = "records/000003.json"
MANIFEST = "records/000000.json"


def _edit(episode_dir, relative, mutate):
    path = episode_dir / relative
    record = read_record_file(path)
    mutate(record)
    write_record_file(path, record)


def edit_the_answer(episode_dir):
    """Change what the agent answered, leaving the claimed hash in place."""
    _edit(episode_dir, ANSWER, lambda record: record["payload"].update(answer_hash=hash_payload("a nicer answer")))
    return f"HASH_MISMATCH({ANSWER})"


def edit_the_answer_and_repair_the_hash(episode_dir):
    """Change the answer and recompute the hash, hoping nobody checks the signature."""

    def mutate(record):
        record["payload"]["answer_hash"] = hash_payload("a nicer answer")
        record["payload_hash"] = hash_payload(record["payload"])

    _edit(episode_dir, ANSWER, mutate)
    return f"BAD_SIGNATURE({ANSWER})"


def rewrite_the_manifest(episode_dir):
    """Claim a different model ran the episode."""

    def mutate(record):
        record["payload"]["model"] = "a-cheaper-model"
        record["payload_hash"] = hash_payload(record["payload"])

    _edit(episode_dir, MANIFEST, mutate)
    return "BINDING_BROKEN(records/000001.json)"


def claim_a_new_signer(episode_dir):
    """Re-label a record as signed by somebody the trust dir never heard of."""
    _edit(episode_dir, ANSWER, lambda record: record.update(signer_id="recorder-v2"))
    return f"UNKNOWN_SIGNER({ANSWER})"


def delete_the_tool_call(episode_dir):
    """Remove the record of the forbidden tool call."""
    (episode_dir / "records" / "000002.json").unlink()
    return "SEQ_GAP_OR_DUP"


def delete_the_attribution(episode_dir):
    """Remove the investigator's finding without touching anything else."""
    (episode_dir / "records" / "000004.json").unlink()
    return "COUNT_MISMATCH"


def lie_about_the_root(episode_dir):
    """Point the anchor at a Merkle root of the attacker's choosing."""
    _edit(
        episode_dir,
        "anchor.json",
        lambda record: record["payload"].update(merkle_root=hash_payload("a friendlier episode")),
    )
    return "BAD_ANCHOR(hash_mismatch)"


def delete_the_anchor(episode_dir):
    """Throw the anchor away and hope the bundle passes unanchored."""
    (episode_dir / "anchor.json").unlink()
    return "BAD_ANCHOR(missing)"


TAMPERS = {
    "edit_the_answer": edit_the_answer,
    "edit_the_answer_and_repair_the_hash": edit_the_answer_and_repair_the_hash,
    "rewrite_the_manifest": rewrite_the_manifest,
    "claim_a_new_signer": claim_a_new_signer,
    "delete_the_tool_call": delete_the_tool_call,
    "delete_the_attribution": delete_the_attribution,
    "lie_about_the_root": lie_about_the_root,
    "delete_the_anchor": delete_the_anchor,
}
