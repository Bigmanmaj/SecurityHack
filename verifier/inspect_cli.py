#!/usr/bin/env python3
"""Read an episode bundle out loud. Verifies nothing.

    python verifier/inspect_cli.py --episode DIR [--corpus DIR]

A bundle is mostly hashes, which makes it unreadable at a glance and easy to
misread under pressure. This prints the timeline a human wants -- what was
retrieved, what was called, what was concluded -- with hashes cut to eight
characters and, given the corpus, chunk hashes resolved back to file names.

It is deliberately powerless. It does not recompute a payload hash, check a
signature or recompute the Merkle root, and it never reports a verdict:
`verify_cli.py` is the only thing entitled to say whether a bundle holds up.
Keeping the two apart matters, because a pretty summary is exactly the sort of
thing an audience mistakes for a check.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):  # allow running the file directly
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verifier.canonical import canon_bytes, h_hex

FOOTER = "This view is unverified. Run verify_cli.py for the verdict."
SHORT = 8


def short(value: Any) -> str:
    """Hashes are cut down; anything else is printed as it is."""
    text = str(value)
    return f"{text[:SHORT]}..." if len(text) > SHORT else text


def corpus_map(corpus_dir: str | Path) -> dict[str, str]:
    """`chunk hash -> file name` for every document in a corpus directory.

    SPEC section 3.2: a chunk hash is h_hex(canon_bytes(document text)).
    """
    mapping: dict[str, str] = {}
    for path in sorted(Path(corpus_dir).glob("*.md")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        mapping[h_hex(canon_bytes(text))] = path.name
    return mapping


def annotate(digest: Any, names: dict[str, str]) -> str:
    """`abcd1234... (= doc_07.md)` when we can name it, plain otherwise."""
    rendered = short(digest)
    named = names.get(digest) if isinstance(digest, str) else None
    return f"{rendered} (= {named})" if named else rendered


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def signer_of(record: dict[str, Any]) -> str:
    return str(record.get("signer") or record.get("signer_id") or "?")


def describe_record(
    record: dict[str, Any], forbidden: list[str], names: dict[str, str], expand: bool = False
) -> tuple[str, list[str]]:
    """One headline for the record, plus any indented lines under it."""
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return "", []

    kind = record.get("type")

    if kind == "manifest":
        parts = []
        if payload.get("episode_id"):
            parts.append(f"episode {payload['episode_id']}")
        parts.append(f"agent {payload.get('agent_id', '?')}")
        parts.append(f"model {payload.get('model', '?')}")
        policy = payload.get("policy") or {}
        tools = policy.get("forbidden_tools") or []
        parts.append(f"forbidden: {', '.join(tools) if tools else 'nothing'}")
        return "  ".join(parts), []

    if kind == "retrieval":
        chunks = payload.get("chunk_hashes") or []
        headline = f"{len(chunks)} chunks in context, query {short(payload.get('query_hash'))}"
        detail = []
        if expand:
            # Listed whether or not they resolve: a chunk the corpus cannot
            # account for is worth seeing, not hiding.
            detail = [
                f"chunk {position}: {annotate(digest, names)}"
                for position, digest in enumerate(chunks)
            ]
        return headline, detail

    if kind == "tool_call":
        tool = str(payload.get("tool", "?"))
        line = f"{tool}  args {short(payload.get('args_hash'))}"
        if payload.get("executed") is False:
            line += "  (not executed)"
        if tool in forbidden:
            line += "  <-- VIOLATES POLICY"
        return line, []

    if kind == "tool_result":
        return f"{payload.get('tool', '?')}  result {short(payload.get('result_hash'))}", []

    if kind == "answer":
        return f"answer {short(payload.get('answer_hash'))}", []

    if kind == "attribution":
        culprit = annotate(payload.get("culprit_chunk_hash"), names)
        return (
            f"{payload.get('method', '?')} over {payload.get('runs', '?')} runs, "
            f"culprit {culprit}"
        ), []

    return "", []


def anchor_paths(episode: Path) -> list[Path]:
    """Anchors live in anchors/, but a bundle may carry a bare anchor.json."""
    paths = sorted((episode / "anchors").glob("*.json"))
    single = episode / "anchor.json"
    if single.exists():
        paths.append(single)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--episode", required=True, help="episode bundle directory")
    parser.add_argument("--corpus", help="optional corpus, to name the chunks by file")
    args = parser.parse_args(argv)

    episode = Path(args.episode)
    names = corpus_map(args.corpus) if args.corpus else {}

    records = []
    for path in sorted((episode / "records").glob("*.json")):
        record = load_json(path)
        records.append((path.name, record if isinstance(record, dict) else None))

    forbidden: list[str] = []
    for _, record in records:
        if record and record.get("type") == "manifest":
            payload = record.get("payload")
            if isinstance(payload, dict):
                policy = payload.get("policy") or {}
                forbidden = list(policy.get("forbidden_tools") or [])
            break

    print(f"episode    {episode}")
    print(f"records    {len(records)}")
    if args.corpus:
        print(f"corpus     {args.corpus} ({len(names)} documents)")
    print()

    for file_name, record in records:
        if record is None:
            print(f"  {'?':>3}  {'unreadable':<12} {'':<13} {file_name}")
            continue

        seq = record.get("seq", "?")
        kind = str(record.get("type", "?"))
        headline, detail = describe_record(record, forbidden, names, expand=bool(args.corpus))
        print(f"  {str(seq):>3}  {kind:<12} {signer_of(record):<13} {headline}".rstrip())
        for line in detail:
            print(f"       {' ' * 26}{line}")

    anchors = anchor_paths(episode)
    if anchors:
        print()
    for path in anchors:
        anchor = load_json(path)
        if not isinstance(anchor, dict):
            print(f"  anchor  {path.name}  (unreadable)")
            continue
        payload = anchor.get("payload") if isinstance(anchor.get("payload"), dict) else {}
        print(
            f"  anchor  {payload.get('anchor_id', path.stem)}  "
            f"{payload.get('record_count', '?')} records  "
            f"root {short(payload.get('merkle_root'))}  "
            f"signed by {signer_of(anchor)}"
        )

    print()
    print(FOOTER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
