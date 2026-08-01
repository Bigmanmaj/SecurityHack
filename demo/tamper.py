#!/usr/bin/env python3
"""One character. That is the whole demo.

    python demo/tamper.py episode/records/000005.json
    python demo/tamper.py episode/                     # finds the TOOL_CALL record

Deliberately dependency-free and about forty lines: the adversary in the threat
model has root and a text editor, and this is all that takes. The operator can
edit the file. They cannot make the edit survive verification.
"""

import argparse
import json
import os
import sys

DEFAULT_FIND = b'"http_post"'
DEFAULT_REPLACE = b'"http_post "'


def locate(target):
    """Accept a record file, or an episode directory to search for the tool call."""
    if os.path.isfile(target):
        return target
    records = os.path.join(target, "records") if os.path.isdir(os.path.join(target, "records")) else target
    for name in sorted(os.listdir(records)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(records, name)
        with open(path, "r", encoding="utf-8") as fh:
            body = json.load(fh)["body"]
        if body["type"] == "TOOL_CALL":
            return path
    raise SystemExit(f"  no TOOL_CALL record found under {target}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Edit one character inside a signed record.")
    ap.add_argument("target", help="a record file, or an episode directory")
    ap.add_argument("--find", default=DEFAULT_FIND.decode())
    ap.add_argument("--replace", default=DEFAULT_REPLACE.decode())
    args = ap.parse_args(argv)

    path = locate(args.target)
    with open(path, "rb") as fh:
        data = fh.read()
    find, replace = args.find.encode(), args.replace.encode()
    if find not in data:
        raise SystemExit(f"  {args.find} not present in {path}")
    with open(path, "wb") as fh:
        fh.write(data.replace(find, replace, 1))
    print(f"  edited {path}")
    print(f"    {args.find}  ->  {args.replace}")
    print("  the file is still valid JSON, and still says almost the same thing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
