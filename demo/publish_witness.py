#!/usr/bin/env python3
"""Print the witness values for an episode, ready to publish.

    python demo/publish_witness.py episode/ > somewhere-the-operator-cannot-edit

A witness is the one piece of state that has to live outside the box. Without it,
`verify_episode.py` proves the chain is internally consistent; with it, the chain
is also provably the right one and a complete one.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import verify_episode  # noqa: E402

HEADER = """\
# Published witness for {root}
#
# These are the values a third party would hold to check the episode is the right
# one and a complete one, not merely an internally consistent one:
#
#   python verify_episode.py {root} \\
#       --anchor {anchor} \\
#       --head   {head} \\
#       --count  {count}
#
# Committing them to git is a stand-in for the real thing. A witness is only worth
# anything when it is published somewhere the operator of the agent cannot rewrite
# it -- a transparency log, a counterparty's system, a signed commit in a repo they
# do not control. Automating that publication is the highest-value extension.

anchor {anchor}
head   {head}
count  {count}"""


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    root = argv[0].rstrip("/") + "/"
    try:
        summary = verify_episode.verify(root)
    except verify_episode.Fail as fail:
        print(f"  refusing to publish a witness for a RED episode: {fail.code}", file=sys.stderr)
        print(f"    {fail.detail}", file=sys.stderr)
        return 1
    print(HEADER.format(root=root, anchor=summary["anchor"], head=summary["head_hash"],
                        count=summary["count"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
