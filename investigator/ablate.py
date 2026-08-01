"""Ablation replay: re-run the episode with inputs removed and watch the detector.

Linear leave-one-out over the retrieved set times R repeats is honest but slow.
Group bisection finds a single sufficient cause in log2(n) rounds, and the
leave-one-out / leave-one-in confirmations are what turn "the violation went
away" into the two claims worth making: necessary, and sufficient.
"""

from agent.rag import assemble_prompt, detect_violation


class ReplayOutcome:
    __slots__ = ("phase", "repeat", "retained", "removed", "prompt", "text", "violation",
                 "rule", "tool", "meta")

    def __init__(self, phase, repeat, retained, removed, prompt, result, call, decision):
        self.phase = phase
        self.repeat = repeat
        self.retained = retained
        self.removed = removed
        self.prompt = prompt
        self.text = result.text
        self.meta = dict(result.meta)
        self.violation = bool(decision is not None and not decision.authorized)
        self.rule = decision.rule if decision is not None else None
        self.tool = call["name"] if call is not None else None


class Replayer:
    """Runs replays and hands each one to ``on_run`` so the caller can sign it.

    Every replay lands in the chain: the investigation shows its work, so a third
    party can re-derive the verdict from the evidence instead of believing it.
    """

    def __init__(self, task, chunks, backend, policy, repeats=1, on_run=None):
        self.task = task
        self.chunks = list(chunks)
        self.backend = backend
        self.policy = policy
        self.repeats = repeats
        self.on_run = on_run
        self.runs = []
        self.phase = "bisect"

    def _keys(self, chunks):
        return [f"{c.doc_id}#{c.chunk_id}" for c in chunks]

    def replay(self, retained):
        """Run one ablation R times and return (violation_votes, outcomes)."""
        keep = [c for c in self.chunks if c in retained]
        removed = [c for c in self.chunks if c not in retained]
        prompt = assemble_prompt(self.task, keep)
        outcomes = []
        params = self.backend.request_params()
        for repeat in range(self.repeats):
            result = self.backend.complete(prompt, params, repeat=repeat)
            call, decision = detect_violation(result, self.policy)
            outcome = ReplayOutcome(self.phase, repeat, self._keys(keep), self._keys(removed),
                                    prompt, result, call, decision)
            outcomes.append(outcome)
            self.runs.append(outcome)
            if self.on_run:
                self.on_run(outcome)
        return sum(1 for o in outcomes if o.violation), outcomes

    def majority(self, retained):
        votes, outcomes = self.replay(retained)
        return votes * 2 > self.repeats, votes, outcomes


def bisect(replayer, on_round=None):
    """Narrow to a single sufficient cause by halving the retained set.

    Returns ``(candidate, rounds, status)`` where status is one of
    ``single`` (one chunk suffices), ``multiple`` (both halves suffice on their
    own), or ``distributed`` (neither half suffices alone).
    """
    working = list(replayer.chunks)
    rounds = 0
    while len(working) > 1:
        rounds += 1
        mid = len(working) // 2
        left, right = working[:mid], working[mid:]
        left_violates, _, _ = replayer.majority(left)
        right_violates, _, _ = replayer.majority(right)
        if on_round:
            on_round(rounds, left, right, left_violates, right_violates)
        if left_violates and right_violates:
            return None, rounds, "multiple"
        if left_violates:
            working = left
        elif right_violates:
            working = right
        else:
            return None, rounds, "distributed"
    return (working[0] if working else None), rounds, "single"


def exhaustive_sweep(replayer, chunks=None):
    """Per-chunk necessity and sufficiency, in milli-units. Slow, legible, honest."""
    table = []
    replayer.phase = "sweep"
    for chunk in chunks if chunks is not None else replayer.chunks:
        loo_violates, loo_votes, _ = replayer.majority([c for c in replayer.chunks if c is not chunk])
        loi_violates, loi_votes, _ = replayer.majority([chunk])
        table.append(
            {
                "doc_id": chunk.doc_id,
                "chunk_id": chunk.chunk_id,
                "sha3": chunk.sha3,
                # Necessary means: take this one away and the violation stops.
                "necessity_milli": _milli(replayer.repeats - loo_votes, replayer.repeats),
                # Sufficient means: this one alone is enough to cause it.
                "sufficiency_milli": _milli(loi_votes, replayer.repeats),
            }
        )
    table.sort(key=lambda row: (-row["necessity_milli"], -row["sufficiency_milli"],
                                row["doc_id"], row["chunk_id"]))
    return table


def _milli(part, whole):
    return 0 if not whole else (part * 1000) // whole
