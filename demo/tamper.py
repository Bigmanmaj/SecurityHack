"""Tampers an attacker without any signing key could try, and what they cost.

Each function mutates a bundle in place and returns the reason the verifier is
expected to name for it. Records are located by payload type, not by filename, so
the same tamper works on a three-record bundle and a five-record one.
"""

from pathlib import Path

from attest.hashing import hash_payload
from attest.records import anchor_path, read_record_file, record_paths, write_record_file


def needs(payload_type):
    """Mark which record type a tamper has to find in the bundle to be applicable."""

    def mark(function):
        function.needs = payload_type
        return function

    return mark


@needs("answer")
def edit_the_answer(episode_dir):
    """Change what the agent answered, leaving the claimed hash in place."""
    path = _record_of_type(episode_dir, "answer")
    _edit(path, lambda record: record["payload"].update(answer_hash=hash_payload("a nicer answer")))
    return f"HASH_MISMATCH({_name(episode_dir, path)})"


@needs("answer")
def edit_the_answer_and_repair_the_hash(episode_dir):
    """Change the answer and recompute the hash, hoping nobody checks the signature."""
    path = _record_of_type(episode_dir, "answer")

    def mutate(record):
        record["payload"]["answer_hash"] = hash_payload("a nicer answer")
        record["payload_hash"] = hash_payload(record["payload"])

    _edit(path, mutate)
    return f"BAD_SIGNATURE({_name(episode_dir, path)})"


@needs("manifest")
def rewrite_the_manifest(episode_dir):
    """Claim a different model ran the episode."""

    def mutate(record):
        record["payload"]["model"] = "a-cheaper-model"
        record["payload_hash"] = hash_payload(record["payload"])

    _edit(_record_of_type(episode_dir, "manifest"), mutate)
    return f"BINDING_BROKEN({_name(episode_dir, record_paths(episode_dir)[1])})"


@needs("answer")
def claim_a_new_signer(episode_dir):
    """Re-label a record as signed by somebody the trust dir never heard of."""
    path = _record_of_type(episode_dir, "answer")
    _edit(path, lambda record: record.update(signer_id="recorder-v2"))
    return f"UNKNOWN_SIGNER({_name(episode_dir, path)})"


@needs("tool_call")
def delete_the_tool_call(episode_dir):
    """Remove the record of the forbidden tool call."""
    _record_of_type(episode_dir, "tool_call").unlink()
    return "SEQ_GAP_OR_DUP"


@needs("attribution")
def delete_the_attribution(episode_dir):
    """Remove the investigator's finding without touching anything else."""
    _record_of_type(episode_dir, "attribution").unlink()
    return "COUNT_MISMATCH"


@needs(None)
def lie_about_the_root(episode_dir):
    """Point the anchor at a Merkle root of the attacker's choosing."""
    _edit(
        _anchor(episode_dir),
        lambda record: record["payload"].update(merkle_root=hash_payload("a friendlier episode")),
    )
    return "BAD_ANCHOR(hash_mismatch)"


@needs(None)
def delete_the_anchor(episode_dir):
    """Throw the anchor away and hope the bundle passes unanchored."""
    _anchor(episode_dir).unlink()
    return "BAD_ANCHOR(missing)"


TAMPERS = {
    function.__name__: function
    for function in (
        edit_the_answer,
        edit_the_answer_and_repair_the_hash,
        rewrite_the_manifest,
        claim_a_new_signer,
        delete_the_tool_call,
        delete_the_attribution,
        lie_about_the_root,
        delete_the_anchor,
    )
}


def applicable_tampers(episode_dir):
    """Return the names of the tampers this particular bundle can be subjected to."""
    present = {read_record_file(path)["payload"]["type"] for path in record_paths(episode_dir)}
    return sorted(
        name for name, function in TAMPERS.items() if function.needs in present | {None}
    )


def _edit(path, mutate):
    record = read_record_file(path)
    mutate(record)
    write_record_file(path, record)


def _record_of_type(episode_dir, payload_type):
    for path in record_paths(episode_dir):
        if read_record_file(path)["payload"]["type"] == payload_type:
            return path
    raise LookupError(f"no {payload_type} record in {episode_dir}")


def _anchor(episode_dir):
    return anchor_path(episode_dir)


def _name(episode_dir, path):
    return path.relative_to(Path(episode_dir)).as_posix()
