#!/usr/bin/env python3
"""verify_cli.py --episode DIR --trust DIR (SPEC.md).

Prints GREEN and exits 0 when the bundle verifies, otherwise prints every
failure reason, then RED, and exits 1.
"""

import argparse
import sys

from attest.verify import verify_episode


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify a signed agent episode bundle.")
    parser.add_argument("--episode", required=True, help="episode bundle directory")
    parser.add_argument("--trust", required=True, help="the verifier's own copy of the public keys")
    args = parser.parse_args(argv)

    reasons = verify_episode(args.episode, args.trust)
    if reasons:
        for reason in reasons:
            print(reason)
        print("RED")
        return 1
    print("GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
