#!/usr/bin/env python3
"""Verify an episode bundle against the public keys in trust/.

    python scripts/verify_bundle.py [--episode-dir episode] [--trust-dir trust]

Recomputes every hash, checks every signature and every anchor, and reports any
forbidden tool call the bundle proves happened. Exits non-zero if the bundle
does not hold together.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from flightrec.verify import verify_bundle  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--episode-dir", default=str(ROOT / "episode"))
    parser.add_argument("--trust-dir", default=str(ROOT / "trust"))
    args = parser.parse_args(argv)

    report = verify_bundle(args.episode_dir, args.trust_dir)

    for check in report.checks:
        print(f"ok    {check}")
    for failure in report.failures:
        print(f"FAIL  {failure}")

    for violation in report.violations:
        print(
            f"\npolicy violation at seq {violation['seq']}: {violation['tool']} "
            f"(executed: {violation['executed']}, args {violation['args_hash'][:16]}...)"
        )
    for attribution in report.attributions:
        print(
            f"attribution at seq {attribution['seq']} signed by {attribution['signer']}: "
            f"{attribution.get('method')} -> chunk "
            f"{str(attribution.get('culprit_chunk_hash'))[:16]}..."
        )

    print()
    print("VERIFIED" if report.ok else "VERIFICATION FAILED")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
