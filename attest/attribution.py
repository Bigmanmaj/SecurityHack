"""Single-chunk ablation: which retrieved chunk caused the misbehaviour (SPEC.md).

The method is deliberately blunt. Re-run the episode ``runs`` times with the full
context, then ``runs`` times with each chunk removed in turn. A chunk is only
named as the culprit when the misbehaviour happened on every baseline run and
stopped on every run without that one chunk — one chunk, both directions,
no partial credit.
"""

from .hashing import hash_payload


def chunk_hash(chunk):
    """Return the chunk's hash, the same value the retrieval record carries."""
    return hash_payload(chunk)


def single_chunk_ablation(chunks, run_agent, misbehaved, runs=3):
    """Attribute misbehaviour to at most one chunk.

    ``run_agent(chunks)`` replays the episode with the given context and returns
    an observation; ``misbehaved(observation)`` says whether that replay
    misbehaved. Returns a report dict with the culprit (or None) plus the two
    findings the attribution record needs.
    """
    if isinstance(runs, bool) or not isinstance(runs, int) or runs < 1:
        raise ValueError(f"runs must be an int >= 1, got {runs!r}")
    if not chunks:
        raise ValueError("cannot attribute misbehaviour without any chunks")

    baseline_misbehaved = _always_misbehaves(list(chunks), run_agent, misbehaved, runs)
    flipped_indexes = []
    if baseline_misbehaved:
        for index in range(len(chunks)):
            without = [chunk for position, chunk in enumerate(chunks) if position != index]
            if _never_misbehaves(without, run_agent, misbehaved, runs):
                flipped_indexes.append(index)

    culprit_index = flipped_indexes[0] if len(flipped_indexes) == 1 else None
    return {
        "runs": runs,
        "baseline_misbehaved": baseline_misbehaved,
        "flipped_on_ablation": culprit_index is not None,
        "flipped_indexes": flipped_indexes,
        "culprit_index": culprit_index,
        "culprit_chunk_hash": None if culprit_index is None else chunk_hash(chunks[culprit_index]),
    }


def _replay(chunks, run_agent, misbehaved, runs):
    """Run the agent ``runs`` times, never short-circuiting, so the count is honest."""
    return [bool(misbehaved(run_agent(chunks))) for _ in range(runs)]


def _always_misbehaves(chunks, run_agent, misbehaved, runs):
    return all(_replay(chunks, run_agent, misbehaved, runs))


def _never_misbehaves(chunks, run_agent, misbehaved, runs):
    return not any(_replay(chunks, run_agent, misbehaved, runs))
