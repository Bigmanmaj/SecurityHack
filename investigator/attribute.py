"""Turning replays into a verdict.

Two claims are worth making, and they are different claims:

* **necessary** -- remove only this chunk and the violation stops.
* **sufficient** -- retrieve only this chunk and the violation happens anyway.

A cause that is both is a single source. Anything else gets named as what it is,
because a forensic tool that says "I don't know, here is the evidence" beats one
that always produces a culprit.
"""

CAUSAL_SINGLE_SOURCE = "CAUSAL_SINGLE_SOURCE"
NECESSARY_NOT_SUFFICIENT = "NECESSARY_NOT_SUFFICIENT"
SUFFICIENT_NOT_NECESSARY = "SUFFICIENT_NOT_NECESSARY"
MULTIPLE_OR_DISTRIBUTED_CAUSE = "MULTIPLE_OR_DISTRIBUTED_CAUSE"
NO_CAUSE_FOUND = "NO_CAUSE_FOUND"

# A strict majority of replays, the same rule the bisection votes on: two of
# three is 666 in integer milli-units, so the bar sits just above one half.
THRESHOLD_MILLI = 501

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"


def milli(part, whole):
    return 0 if not whole else (part * 1000) // whole


def classify(necessity_milli, sufficiency_milli):
    necessary = necessity_milli >= THRESHOLD_MILLI
    sufficient = sufficiency_milli >= THRESHOLD_MILLI
    if necessary and sufficient:
        return CAUSAL_SINGLE_SOURCE
    if necessary:
        return NECESSARY_NOT_SUFFICIENT
    if sufficient:
        return SUFFICIENT_NOT_NECESSARY
    return NO_CAUSE_FOUND


def confidence(repeats, deterministic, *vote_pairs):
    """Nondeterminism degrades confidence; it never silently changes the verdict."""
    unanimous = all(votes in (0, repeats) for votes in vote_pairs)
    if not unanimous:
        return MEDIUM if all(votes * 2 != repeats for votes in vote_pairs) else LOW
    if deterministic or repeats >= 3:
        return HIGH
    return MEDIUM


def build_finding(violation_seq, violation, method, replay_seqs, culprit,
                  necessity_milli, sufficiency_milli, runner_up_necessity_milli,
                  verdict, conf, repeats, extras=None):
    payload = {
        "violation_seq": violation_seq,
        "violation": violation,
        "method": method,
        "replay_seqs": list(replay_seqs),
        "culprit": culprit,
        "necessity_milli": necessity_milli,
        "sufficiency_milli": sufficiency_milli,
        "runner_up_necessity_milli": runner_up_necessity_milli,
        "verdict": verdict,
        "confidence": conf,
        "repeats": repeats,
    }
    if extras:
        payload.update(extras)
    return payload
