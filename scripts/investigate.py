#!/usr/bin/env python3
"""Attribute a recorded policy violation to a document.

    python scripts/investigate.py [--episode DIR] [--live | --offline] [--demo-keys]

Replays the episode from the LLM cache, then replays it once per document with
that document removed. The document whose removal stops the forbidden tool call
is the culprit; the finding is appended to the bundle as a signed attribution
record and the bundle is re-anchored.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from _corpus import CORPUS_DIR, load_corpus  # noqa: E402
from _offline_llm import build_llm  # noqa: E402
from record_episode import FORBIDDEN_TOOLS, QUERY, make_key  # noqa: E402

from flightrec.crypto import write_trust_pubkeys  # noqa: E402
from flightrec.investigator import investigate  # noqa: E402
from flightrec.llm import DEFAULT_CACHE_DIR, DEFAULT_MODEL  # noqa: E402
from flightrec.recorder import Recorder  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--episode", default=str(ROOT / "episode"))
    parser.add_argument("--trust", default=str(ROOT / "trust"))
    parser.add_argument("--cache", default=str(ROOT / DEFAULT_CACHE_DIR))
    parser.add_argument("--corpus", default=str(CORPUS_DIR),
                        help="corpus directory the agent retrieves from")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--query", default=QUERY)
    parser.add_argument("--anchor-id", default="anchor-2")
    parser.add_argument(
        "--demo-keys",
        action="store_true",
        help="derive keys from fixed seeds so the bundle is byte-reproducible (demo only)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_const", dest="mode", const="live")
    mode.add_argument("--offline", action="store_const", dest="mode", const="offline")
    parser.set_defaults(mode="auto")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    episode_dir = Path(args.episode)

    if not (episode_dir / "records" / "00000.json").exists():
        print(f"no episode in {episode_dir}; run scripts/record_episode.py first", file=sys.stderr)
        return 2
    if (episode_dir / "anchors" / f"{args.anchor_id}.json").exists():
        print(
            f"{args.anchor_id} already exists in this bundle; a second investigation needs a "
            "fresh anchor id (--anchor-id anchor-3)",
            file=sys.stderr,
        )
        return 2

    manifest = Recorder.open(episode_dir).manifest
    corpus = load_corpus(args.corpus)
    # The manifest records the model that produced the episode; replaying under
    # any other model would not be a replay.
    llm, live = build_llm(args.model, args.cache, args.mode)
    if llm.model != manifest["model"]:
        print(
            f"episode was recorded with model {manifest['model']!r} but this run would use "
            f"{llm.model!r}; replays would not be comparable",
            file=sys.stderr,
        )
        return 2

    investigator_key = make_key("investigator", args.demo_keys)
    anchor_key = make_key(args.anchor_id, args.demo_keys)

    print(f"episode    {episode_dir} ({len(corpus)} chunks, model {manifest['model']})")
    print(f"policy     forbidden tools: {', '.join(manifest['policy']['forbidden_tools'])}")
    print(f"mode       {'live' if live else 'offline stand-in'}")
    print()

    def report_run(run):
        verdict = "still misbehaves" if run.misbehaved else "BEHAVES  <- culprit"
        print(f"  without {run.doc_id}: {verdict}")

    investigation = investigate(
        episode_dir,
        corpus,
        llm,
        manifest["policy"]["forbidden_tools"] or FORBIDDEN_TOOLS,
        investigator_key,
        anchor_key,
        query=args.query,
        anchor_id=args.anchor_id,
        on_run=report_run,
    )

    if not investigation.baseline_misbehaved:
        print(
            "baseline replay did not call a forbidden tool: there is nothing to attribute.",
            file=sys.stderr,
        )
        return 1

    print()
    print(f"baseline   misbehaved, called {', '.join(investigation.baseline_tools)}")
    print(f"replays    {investigation.runs} single-chunk ablations "
          f"(cache {llm.hits} hit / {llm.misses} miss)")

    if not investigation.flipped_on_ablation:
        print("no single document explains the behaviour; nothing was signed.", file=sys.stderr)
        return 1

    write_trust_pubkeys(
        args.trust,
        {"investigator": investigator_key.public_hex, args.anchor_id: anchor_key.public_hex},
    )

    print()
    print(f"culprit    {investigation.culprit_doc_id} "
          f"(chunk {investigation.culprit_chunk_hash[:16]}...)")
    print(f"record     seq {investigation.record['seq']}, signed by "
          f"{investigation.record['signer']}")
    print(f"{args.anchor_id}   re-anchored over {investigation.record['seq'] + 1} records")
    print("attribution signed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
