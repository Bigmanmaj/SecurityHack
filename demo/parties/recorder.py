#!/usr/bin/env python3
"""The recorder: records the episode as it happens.

    python3 demo/parties/recorder.py --episode DIR --trust DIR --agent injected

Generates the "recorder" keypair, publishes the public half, and signs the
manifest, retrieval, tool_call and answer records. The private key lives in a
local variable and dies when this process exits, so nothing later in the
pipeline can sign as the recorder.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from attest.keys import generate_keypair, write_public_key
from attest.recorder import record_answer, record_retrieval, record_tool_call, start_episode
from demo.corpus import CHUNKS, FORBIDDEN_TOOLS, QUERY
from demo.scripted_agent import AGENTS


def record_episode(episode_dir, secret_key, agent):
    """Record one episode with ``agent`` in the driving seat; return its observation."""
    start_episode(
        episode_dir,
        episode_id=f"ep-{Path(episode_dir).name}",
        agent_id="support-bot",
        model=f"scripted-stub/{agent}",
        forbidden_tools=FORBIDDEN_TOOLS,
        recorder_secret_key=secret_key,
    )
    record_retrieval(episode_dir, QUERY, CHUNKS, secret_key)
    observation = AGENTS[agent](CHUNKS)
    if observation["tool"]:
        record_tool_call(episode_dir, observation["tool"], observation["args"], secret_key)
    record_answer(episode_dir, observation["answer"], secret_key)
    return observation


def main(argv=None):
    args = parse_args(argv)
    public_key, secret_key = generate_keypair()
    write_public_key(args.trust, "recorder", public_key)
    observation = record_episode(args.episode, secret_key, args.agent)
    called = observation["tool"] or "no tool"
    print(f"recorder: recorded the episode ({called}), published recorder.pub.hex")
    return 0


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Record an episode as the recorder party.")
    parser.add_argument("--episode", required=True)
    parser.add_argument("--trust", required=True)
    parser.add_argument("--agent", choices=sorted(AGENTS), default="injected")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
