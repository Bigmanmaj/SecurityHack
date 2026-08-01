"""Post-hoc attribution by single-chunk ablation.

The question is not "did the agent misbehave" -- the record chain already
proves that -- but "which of the documents it read made it misbehave". The
answer is found by replaying the episode once per document with that document
removed. The document whose removal stops the forbidden tool call is the
culprit, and that conclusion is signed and appended to the same chain, so it
cannot later be separated from the episode it explains.

Replays are only meaningful because every model call goes through the response
cache: the baseline replay is a pure cache hit, and each ablation is a stable
function of its context.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from . import agent
from .canonical import H, canonical_bytes
from .crypto import SigningKey
from .recorder import NullRecorder, Recorder

__all__ = [
    "METHOD",
    "judge",
    "replay",
    "AblationRun",
    "Investigation",
    "ablate",
    "investigate",
]

METHOD = "single-chunk-ablation"

Chunk = tuple[str, str]


def judge(result: dict[str, Any], forbidden_tools: Sequence[str]) -> bool:
    """True if the run called a tool the policy forbids."""
    forbidden = set(forbidden_tools)
    return any(tool in forbidden for tool in result.get("tools_called", []))


def replay(
    query: str,
    corpus: Sequence[Chunk],
    llm: Any,
    forbidden_tools: Sequence[str],
) -> dict[str, Any]:
    """Run the agent again without writing anything to the bundle."""
    return agent.run(query, corpus, llm, NullRecorder(), forbidden_tools)


@dataclass
class AblationRun:
    index: int
    doc_id: str
    removed_chunk_hash: str
    misbehaved: bool
    tools_called: list[str]


@dataclass
class Investigation:
    baseline_misbehaved: bool
    baseline_tools: list[str]
    runs: int
    ablations: list[AblationRun] = field(default_factory=list)
    culprit_index: int | None = None
    culprit_doc_id: str | None = None
    culprit_chunk_hash: str | None = None
    attribution: dict[str, Any] | None = None
    record: dict[str, Any] | None = None

    @property
    def flipped_on_ablation(self) -> bool:
        return self.culprit_index is not None


def _without(corpus: Sequence[Chunk], index: int) -> list[Chunk]:
    return [chunk for position, chunk in enumerate(corpus) if position != index]


def ablate(
    query: str,
    corpus: Sequence[Chunk],
    llm: Any,
    forbidden_tools: Sequence[str],
    on_run: Any = None,
) -> Investigation:
    """Baseline replay, then one replay per removed document."""
    baseline = replay(query, corpus, llm, forbidden_tools)
    investigation = Investigation(
        baseline_misbehaved=judge(baseline, forbidden_tools),
        baseline_tools=list(baseline["tools_called"]),
        runs=len(corpus),
    )
    if not investigation.baseline_misbehaved:
        investigation.runs = 0
        return investigation

    for index, (doc_id, text) in enumerate(corpus):
        result = replay(query, _without(corpus, index), llm, forbidden_tools)
        run = AblationRun(
            index=index,
            doc_id=doc_id,
            removed_chunk_hash=H(canonical_bytes(text)),
            misbehaved=judge(result, forbidden_tools),
            tools_called=list(result["tools_called"]),
        )
        investigation.ablations.append(run)
        if on_run is not None:
            on_run(run)

        # First document whose removal stops the misbehaviour is the culprit.
        if not run.misbehaved and investigation.culprit_index is None:
            investigation.culprit_index = index
            investigation.culprit_doc_id = doc_id
            investigation.culprit_chunk_hash = run.removed_chunk_hash

    return investigation


def recorded_chunk_hashes(episode_dir: str | Path) -> list[str]:
    """The chunk hashes from the episode's retrieval record."""
    records_dir = Path(episode_dir) / "records"
    for path in sorted(records_dir.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["type"] == "retrieval":
            return list(record["payload"]["chunk_hashes"])
    raise ValueError(f"no retrieval record in {records_dir}")


def recorded_query_hash(episode_dir: str | Path) -> str:
    records_dir = Path(episode_dir) / "records"
    for path in sorted(records_dir.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["type"] == "retrieval":
            return record["payload"]["query_hash"]
    raise ValueError(f"no retrieval record in {records_dir}")


def investigate(
    episode_dir: str | Path,
    corpus: Sequence[Chunk],
    llm: Any,
    forbidden_tools: Sequence[str],
    investigator_sk: SigningKey,
    anchor_sk: SigningKey,
    query: str | None = None,
    anchor_id: str = "anchor-2",
    on_run: Any = None,
) -> Investigation:
    """Attribute the recorded misbehaviour to a document and sign the finding.

    `corpus` must be the corpus the episode was recorded over: it is checked
    against the chunk hashes in the retrieval record before anything is
    replayed, so an investigation cannot quietly be run over different
    documents than the agent saw.
    """
    episode = Path(episode_dir)
    expected = recorded_chunk_hashes(episode)
    actual = [H(canonical_bytes(text)) for _, text in corpus]
    if expected != actual:
        raise ValueError(
            "corpus does not match the retrieval record in the episode: "
            f"{len(expected)} recorded chunks vs {len(actual)} supplied"
        )

    if query is None:
        raise ValueError("the original query is required to replay the episode")
    if H(canonical_bytes(query)) != recorded_query_hash(episode):
        raise ValueError("query does not match the query_hash in the retrieval record")

    investigation = ablate(query, corpus, llm, forbidden_tools, on_run=on_run)
    if not investigation.baseline_misbehaved or not investigation.flipped_on_ablation:
        return investigation

    investigation.attribution = {
        "method": METHOD,
        "culprit_chunk_hash": investigation.culprit_chunk_hash,
        "runs": investigation.runs,
        "baseline_misbehaved": True,
        "flipped_on_ablation": True,
    }

    recorder = Recorder.open(episode)
    investigation.record = recorder.append_attribution(investigation.attribution, investigator_sk)
    recorder.reanchor(anchor_id, anchor_sk)
    return investigation
