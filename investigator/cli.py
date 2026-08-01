"""``python -m investigator.cli episode/``

Verifies the episode first and refuses to proceed on RED. An investigation of
unverified logs is exactly the thing this project argues against, so the tool
embodies it rather than documenting it.
"""

import argparse
import os
import sys

import verify_episode
from agent import llm as llm_mod
from agent.corpus import Corpus, load_docs
from agent.rag import POISONED_DOC, prompt_assembly_sha3, strip_injection
from fr import Recorder
from fr import record as R
from fr.hashes import sha3_hex
from fr.policy import PolicyEngine

from . import attribute
from .ablate import bisect, exhaustive_sweep, Replayer

INVESTIGATOR_VERSION = "investigator:ablation@1"
METHOD = "group_bisection+loo+loi"


class InvestigationError(RuntimeError):
    pass


def find(bodies, type_):
    return [b for b in bodies if b["type"] == type_]


def rebuild_corpus(genesis):
    """Rebuild the exact corpus the episode ran against, and prove it is the same one.

    A replay against a drifted corpus would be a counterfactual about a different
    world, so the manifest hashes pinned in GENESIS are checked, not trusted.
    """
    docs = load_docs()
    if genesis["payload"].get("scenario") == "clean":
        docs[POISONED_DOC] = strip_injection(docs[POISONED_DOC])
    for entry in genesis["payload"]["corpus_manifest"]:
        doc_id = entry["doc_id"]
        if doc_id not in docs:
            raise InvestigationError(f"corpus drift: {doc_id} is missing from the corpus")
        actual = sha3_hex(docs[doc_id].encode("utf-8"))
        if actual != entry["sha3"]:
            raise InvestigationError(
                f"corpus drift: {doc_id} hashes {actual[:16]}..., "
                f"GENESIS pinned {entry['sha3'][:16]}..."
            )
    return Corpus(docs)


def resolve_chunks(corpus, retrieval):
    chunks = []
    for entry in retrieval["payload"]["chunks"]:
        chunk = corpus.get(entry["doc_id"], entry["chunk_id"])
        if chunk.sha3 != entry["sha3"]:
            raise InvestigationError(
                f"chunk drift: {entry['doc_id']}#{entry['chunk_id']} no longer hashes to "
                f"{entry['sha3'][:16]}..."
            )
        chunks.append(chunk)
    return chunks


def investigate(root, backend_name="mock", repeats=None, exhaustive=False, model=None,
                echo=print):
    summary = verify_episode.verify(root)  # raises Fail on RED; nothing else runs
    echo(f"  pre-flight: episode GREEN - {summary['count']} records - proceeding")

    bodies = summary["bodies"]
    genesis = find(bodies, R.GENESIS)[0]
    violations = find(bodies, R.POLICY_VIOLATION)
    if not violations:
        raise InvestigationError("no POLICY_VIOLATION in this episode: nothing to attribute")
    violation = violations[0]
    retrieval = find(bodies, R.RETRIEVAL)[0]
    task = find(bodies, R.USER_INPUT)[0]["payload"]["text"]

    if genesis["payload"].get("prompt_assembly_sha3") != prompt_assembly_sha3():
        raise InvestigationError(
            "prompt assembly code has changed since recording: a replay would be "
            "re-running a different agent"
        )

    corpus = rebuild_corpus(genesis)
    chunks = resolve_chunks(corpus, retrieval)

    backend = llm_mod.get_backend(backend_name, model=model)
    deterministic = backend.backend == "mock"
    repeats = repeats if repeats is not None else (1 if deterministic else 3)
    policy = PolicyEngine(
        genesis["payload"]["policy"]["allowlist"],
        internal_hosts=genesis["payload"]["policy"]["internal_hosts"],
        internal_email_domains=genesis["payload"]["policy"]["internal_email_domains"],
    )

    seal = find(bodies, R.SEAL)[-1]
    rec = Recorder.reopen(root, actor=INVESTIGATOR_VERSION)
    rec.reopen_after_seal()
    rec.append(
        R.INVESTIGATION_OPEN,
        {
            "parent_head": seal["payload"]["head_hash"],
            "sealed_count": seal["payload"]["count"],
            "investigator": INVESTIGATOR_VERSION,
            "method": METHOD,
            "backend": backend.backend,
            "model": backend.model_id,
            "repeats": repeats,
            "violation_seq": violation["seq"],
        },
    )

    replay_seqs = []

    def sign_run(outcome):
        body = rec.append(
            R.REPLAY_RUN,
            {
                "phase": outcome.phase,
                "repeat": outcome.repeat,
                "ablated": outcome.removed,
                "retained": outcome.retained,
                "prompt": rec.put_blob(outcome.prompt),
                "response": rec.put_blob(outcome.text),
                "violation": outcome.violation,
                "rule": outcome.rule,
                "tool": outcome.tool,
            },
        )
        replay_seqs.append(body["seq"])

    replayer = Replayer(task, chunks, backend, policy, repeats=repeats, on_run=sign_run)

    def show_round(n, left, right, left_hit, right_hit):
        echo(f"  bisect {n}: retain {len(left)} -> {_yn(left_hit)} | "
             f"retain {len(right)} -> {_yn(right_hit)}")

    replayer.phase = "bisect"
    candidate, rounds, status = bisect(replayer, on_round=show_round)
    echo(f"  bisection  {rounds} rounds / {len(replayer.runs)} replays")

    sweep = None
    if status != "single" or candidate is None:
        echo(f"  bisection inconclusive ({status}) - falling back to the exhaustive sweep")
        sweep = exhaustive_sweep(replayer)
        payload = attribute.build_finding(
            violation_seq=violation["seq"],
            violation={"tool": violation["payload"]["tool"], "rule": violation["payload"]["rule"]},
            method=METHOD + "+exhaustive",
            replay_seqs=replay_seqs,
            culprit=None,
            necessity_milli=sweep[0]["necessity_milli"] if sweep else 0,
            sufficiency_milli=sweep[0]["sufficiency_milli"] if sweep else 0,
            runner_up_necessity_milli=sweep[1]["necessity_milli"] if len(sweep) > 1 else 0,
            verdict=attribute.MULTIPLE_OR_DISTRIBUTED_CAUSE,
            conf=attribute.MEDIUM,
            repeats=repeats,
            extras={"bisection_status": status, "per_chunk": sweep},
        )
    else:
        replayer.phase = "loo"
        _, loo_votes, _ = replayer.majority([c for c in chunks if c is not candidate])
        replayer.phase = "loi"
        _, loi_votes, _ = replayer.majority([candidate])
        necessity = attribute.milli(repeats - loo_votes, repeats)
        sufficiency = attribute.milli(loi_votes, repeats)
        echo(f"  leave-one-out  {candidate.doc_id} chunk {candidate.chunk_id} removed -> "
             f"{'violation' if loo_votes else 'no violation'}"
             f"   ({'necessary' if necessity >= attribute.THRESHOLD_MILLI else 'not necessary'})")
        echo(f"  leave-one-in   {candidate.doc_id} chunk {candidate.chunk_id} alone   -> "
             f"{'violation' if loi_votes else 'no violation'}"
             f"      ({'sufficient' if sufficiency >= attribute.THRESHOLD_MILLI else 'not sufficient'})")

        others = [c for c in chunks if c is not candidate]
        if exhaustive:
            sweep = exhaustive_sweep(replayer)
            runner_up = next((row["necessity_milli"] for row in sweep
                              if (row["doc_id"], row["chunk_id"]) != candidate.key), 0)
        else:
            sweep = exhaustive_sweep(replayer, chunks=others) if others else []
            runner_up = sweep[0]["necessity_milli"] if sweep else 0

        payload = attribute.build_finding(
            violation_seq=violation["seq"],
            violation={"tool": violation["payload"]["tool"], "rule": violation["payload"]["rule"]},
            method=METHOD + ("+exhaustive" if exhaustive else ""),
            replay_seqs=replay_seqs,
            culprit=candidate.citation(),
            necessity_milli=necessity,
            sufficiency_milli=sufficiency,
            runner_up_necessity_milli=runner_up,
            verdict=attribute.classify(necessity, sufficiency),
            conf=attribute.confidence(repeats, deterministic, repeats - loo_votes, loi_votes),
            repeats=repeats,
            extras={"bisection_rounds": rounds, "per_chunk": sweep},
        )

    finding = rec.append(R.ATTRIBUTION_FINDING, payload)
    rec.anchor_record()
    rec.seal("normal")

    echo("")
    echo(f"  VERDICT  {payload['verdict']}   confidence {payload['confidence']}")
    if payload["culprit"]:
        span = payload["culprit"]["char_span"]
        echo(f"  culprit  {payload['culprit']['doc_id']} chunk {payload['culprit']['chunk_id']} "
             f"chars {span[0]}-{span[1]}")
        echo(f"           sha3 {payload['culprit']['sha3'][:32]}...")
    echo(f"  necessity {payload['necessity_milli']}/1000 - sufficiency "
         f"{payload['sufficiency_milli']}/1000 - runner-up necessity "
         f"{payload['runner_up_necessity_milli']}/1000")
    echo(f"  finding signed -> record {finding['seq']:06d} - resealed ({rec.count} records)")
    return payload, rec


def _yn(flag):
    return "violation" if flag else "clean"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Investigate a recorded episode.")
    ap.add_argument("episode")
    ap.add_argument("--llm", dest="backend", choices=("mock", "live"), default="mock")
    ap.add_argument("--model", default=None)
    ap.add_argument("--repeats", type=int, default=None,
                    help="replays per ablation (default 1 for mock, 3 for live)")
    ap.add_argument("--exhaustive", action="store_true",
                    help="run the full linear sweep and report a per-chunk table")
    args = ap.parse_args(argv)

    try:
        investigate(args.episode, backend_name=args.backend, repeats=args.repeats,
                    exhaustive=args.exhaustive, model=args.model)
    except verify_episode.Fail as fail:
        print(f"  refusing to investigate: episode is RED - {fail.code}", file=sys.stderr)
        print(f"    {fail.detail}", file=sys.stderr)
        if fail.seq is not None:
            print(f"    record {fail.seq}  {fail.path or ''}".rstrip(), file=sys.stderr)
        return 1
    except InvestigationError as exc:
        print(f"  cannot investigate: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
