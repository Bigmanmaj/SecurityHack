#!/usr/bin/env python3
"""Tamper with a copy of an episode bundle, to show the verifier catching it.

    python scripts/tamper.py flip   --episode episode --out /tmp/tampered
    python scripts/tamper.py delete --episode episode --out /tmp/tampered
    python scripts/tamper.py swap   --episode episode --out /tmp/tampered

The original bundle is never modified: every subcommand copies `--episode` to
`--out` first and edits the copy, so a demo can be run again from the same
checkout. Each subcommand prints exactly what it changed, then the reasons the
verifier is expected to report (`verifier/verify_cli.py` decides that for real).

No dependencies beyond the standard library: a tamperer does not get to use our
tools.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

HEX_DIGITS = "0123456789abcdef"


def prepare(episode: Path, out: Path, force: bool) -> Path:
    if not (episode / "records").is_dir():
        raise SystemExit(f"{episode} does not look like an episode bundle")
    if out.exists():
        if not force and any(out.iterdir()):
            raise SystemExit(f"{out} already exists; pass --force to replace it")
        shutil.rmtree(out)
    shutil.copytree(episode, out)
    print(f"copied     {episode} -> {out}")
    return out


def record_paths(episode: Path) -> list[Path]:
    return sorted((episode / "records").glob("*.json"))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save(path: Path, record: dict) -> None:
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def pick(paths: list[Path], seq: int | None, what: str) -> Path:
    """A non-manifest record: the manifest is record 0 and is left alone."""
    candidates = [path for path in paths if load(path)["type"] != "manifest"]
    if not candidates:
        raise SystemExit(f"no non-manifest record to {what}")
    if seq is None:
        return candidates[0]
    for path in candidates:
        if load(path)["seq"] == seq:
            return path
    raise SystemExit(f"no non-manifest record with seq {seq}")


def find_hex_field(payload: dict) -> tuple[str, str] | None:
    """The first 64-character hex value in a payload, which is a hash."""
    for key in sorted(payload):
        value = payload[key]
        if isinstance(value, str) and len(value) == 64 and all(c in HEX_DIGITS for c in value):
            return key, value
    return None


def flip(episode: Path, seq: int | None) -> list[str]:
    path = pick(record_paths(episode), seq, "flip")
    record = load(path)
    found = find_hex_field(record["payload"])
    if found is None:
        raise SystemExit(f"{path.name} has no hash field to flip")

    field, value = found
    index = 0
    replacement = HEX_DIGITS[(HEX_DIGITS.index(value[index]) + 1) % 16]
    record["payload"][field] = replacement + value[1:]
    save(path, record)

    print(f"flipped    {path} record seq {record['seq']} ({record['type']})")
    print(f"           payload.{field}[{index}]: {value[index]!r} -> {replacement!r}")
    print(f"           payload_hash left as {record['payload_hash'][:16]}... (not recomputed)")
    return ["HASH_MISMATCH", "BAD_SIGNATURE"]


def delete(episode: Path, seq: int | None) -> list[str]:
    paths = record_paths(episode)
    # A middle record, so the deletion shows up as a gap as well as a short count.
    path = pick(paths, seq if seq is not None else load(paths[len(paths) // 2])["seq"], "delete")
    record = load(path)
    path.unlink()

    print(f"deleted    {path} record seq {record['seq']} ({record['type']})")
    print(f"           {len(paths) - 1} record files remain")
    return ["SEQ_GAP_OR_DUP", "COUNT_MISMATCH", "ROOT_MISMATCH"]


def swap(episode: Path, seq: int | None) -> list[str]:
    paths = record_paths(episode)
    candidates = [path for path in paths if load(path)["type"] != "manifest"]
    if len(candidates) < 2:
        raise SystemExit("need two non-manifest records to swap")

    first_path, second_path = candidates[0], candidates[-1]
    first, second = load(first_path), load(second_path)
    first_seq, second_seq = first["seq"], second["seq"]

    first["seq"], second["seq"] = second_seq, first_seq
    save(first_path, second)  # file names follow seq, so the contents change places
    save(second_path, first)

    print(f"swapped    seq {first_seq} ({first['type']}) <-> seq {second_seq} ({second['type']})")
    print(f"           {first_path.name} now holds the {second['type']} record")
    print(f"           {second_path.name} now holds the {first['type']} record")
    print("           payloads, bindings and signatures are untouched and still valid")
    return ["ROOT_MISMATCH"]


ACTIONS = {"flip": flip, "delete": delete, "swap": swap}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="action", required=True)
    for name, function in ACTIONS.items():
        sub = subparsers.add_parser(name, help=(function.__doc__ or name).strip().splitlines()[0])
        sub.add_argument("--episode", required=True, help="bundle to copy from (never modified)")
        sub.add_argument("--out", required=True, help="where to write the tampered copy")
        sub.add_argument("--seq", type=int, help="which record to touch (default: chosen for you)")
        sub.add_argument("--force", action="store_true", help="replace --out if it exists")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    out = prepare(Path(args.episode), Path(args.out), args.force)

    expected = ACTIONS[args.action](out, args.seq)

    print()
    print(f"expect     {', '.join(expected)} from the verifier")
    print(f"           python verifier/verify_cli.py --episode {out} --trust trust")
    return 0


if __name__ == "__main__":
    sys.exit(main())
