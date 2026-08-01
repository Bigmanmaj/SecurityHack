#!/usr/bin/env python3
"""The investigator: replays the episode to find the chunk that caused it.

    python3 demo/parties/investigator.py --episode DIR --trust DIR --runs 3

Generates the "investigator" keypair and signs the attribution record. It cannot
sign anything else in the bundle, and the recorder cannot sign this.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from attest.attribution import single_chunk_ablation
from attest.keys import generate_keypair, write_public_key
from attest.recorder import record_attribution
from demo.corpus import CHUNKS, FORBIDDEN_TOOLS
from demo.scripted_agent import AGENTS, misbehaved


def main(argv=None):
    args = parse_args(argv)
    report = single_chunk_ablation(
        CHUNKS,
        AGENTS[args.agent],
        lambda observation: misbehaved(observation, FORBIDDEN_TOOLS),
        args.runs,
    )
    if not report["culprit_chunk_hash"]:
        print(f"investigator: no single chunk explains it {report['flipped_indexes']}")
        return 1

    public_key, secret_key = generate_keypair()
    write_public_key(args.trust, "investigator", public_key)
    record_attribution(
        args.episode, report["culprit_chunk_hash"], report["runs"], secret_key
    )
    print(
        f"investigator: chunk #{report['culprit_index']} "
        f"({report['culprit_chunk_hash'][:12]}…) caused it in {report['runs']}/{report['runs']} runs"
    )
    return 0


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Attribute misbehaviour to one chunk.")
    parser.add_argument("--episode", required=True)
    parser.add_argument("--trust", required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--agent", choices=sorted(AGENTS), default="injected")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
