#!/usr/bin/env python3
"""An anchor: commits to how many records exist and what their Merkle root is.

    python3 demo/parties/anchor.py --episode DIR --trust DIR --signer anchor-1

Reads only the records, which are public, so an anchor never needs anybody
else's key — and holding an anchor key does not let you write records.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from attest.anchoring import ANCHOR_SIGNERS, write_anchor
from attest.keys import generate_keypair, write_public_key
from attest.records import read_record_file


def main(argv=None):
    args = parse_args(argv)
    public_key, secret_key = generate_keypair()
    write_public_key(args.trust, args.signer, public_key)
    payload = read_record_file(write_anchor(args.episode, args.signer, secret_key))["payload"]
    print(
        f"{args.signer}: anchored {payload['record_count']} records "
        f"at root {payload['merkle_root'][:12]}…"
    )
    return 0


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Anchor an episode as an anchor party.")
    parser.add_argument("--episode", required=True)
    parser.add_argument("--trust", required=True)
    parser.add_argument("--signer", choices=ANCHOR_SIGNERS, required=True)
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
