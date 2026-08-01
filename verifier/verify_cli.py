#!/usr/bin/env python3
"""Verify a flightrec bundle against a directory of trusted public keys.

    python verifier/verify_cli.py --episode DIR --trust DIR [--corpus DIR]

Prints a short summary, then one line per failure, then GREEN (exit 0) or RED
(exit 1).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow running the file directly
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verifier.verify import (
    describe,
    load_trust,
    resolve_chunk_hash,
    resolve_context,
    verify_episode,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--episode", required=True, help="episode bundle directory")
    parser.add_argument("--trust", required=True, help="directory of <key_id>.pub.hex files")
    parser.add_argument(
        "--corpus",
        help="optional corpus directory, to resolve an attributed chunk hash to a document",
    )
    parser.add_argument("--quiet", action="store_true", help="only the reasons and the verdict")
    return parser.parse_args(argv)


def print_summary(episode: str, trust: str, corpus: str | None) -> None:
    summary = describe(episode)
    keys = load_trust(trust)

    print(f"episode    {episode}")
    print(f"trust      {trust} ({len(keys)} keys: {', '.join(sorted(keys)) or 'none'})")
    print(f"agent      {summary['agent_id']} on {summary['model']}")
    print(f"records    {summary['records']} records: {', '.join(summary['types'])}")

    if summary["chunk_hashes"]:
        count = len(summary["chunk_hashes"])
        if corpus:
            resolved = resolve_context(corpus, summary["chunk_hashes"])
            named = [name for _, name in resolved if name]
            unknown = count - len(named)
            detail = ", ".join(named) + (f", and {unknown} not in this corpus" if unknown else "")
            print(f"context    {count} chunks: {detail}")
        else:
            print(f"context    {count} chunks, hashes only (pass --corpus to name them)")

    for anchor in summary["anchors"]:
        print(
            f"anchor     {anchor['anchor_id']} over {anchor['record_count']} records, "
            f"root {str(anchor['merkle_root'])[:16]}..., signed by {anchor['signer']}"
        )

    for violation in summary["violations"]:
        print(
            f"violation  seq {violation['seq']}: forbidden tool {violation['tool']} "
            f"(executed: {violation['executed']})"
        )

    attribution = summary["attribution"]
    if attribution is None:
        print("verdict    no attribution in this bundle")
    else:
        culprit = attribution.get("culprit_chunk_hash", "")
        named = resolve_chunk_hash(corpus, culprit) if corpus else None
        location = f" = {named}" if named else ""
        print(
            f"verdict    {attribution.get('method')} by {attribution.get('signer')}: "
            f"culprit chunk {culprit[:16]}...{location}"
        )
    print()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if not args.quiet:
        print_summary(args.episode, args.trust, args.corpus)

    ok, reasons = verify_episode(args.episode, args.trust)
    for reason in reasons:
        print(reason)
    if reasons:
        print()

    print("GREEN" if ok else "RED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
