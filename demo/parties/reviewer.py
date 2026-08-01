#!/usr/bin/env python3
"""The reviewer: holds no key at all, and decides whether to investigate.

    python3 demo/parties/reviewer.py --episode DIR

Exits 1 when the episode broke its own manifest policy, so a caller can branch
on it the same way it branches on the verifier.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from attest.episode import load_records
from attest.policy import forbidden_tool_calls, manifest_policy


def main(argv=None):
    args = parse_args(argv)
    payloads = [record["payload"] for _, record in load_records(args.episode)]
    violations = forbidden_tool_calls(payloads, manifest_policy(payloads))
    if not violations:
        print("reviewer: no forbidden tool call, nothing to investigate")
        return 0
    for violation in violations:
        print(f"reviewer: seq {violation['seq']} called {violation['tool']} — investigate")
    return 1


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Review an episode against its own policy.")
    parser.add_argument("--episode", required=True)
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
