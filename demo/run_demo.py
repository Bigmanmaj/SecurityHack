#!/usr/bin/env python3
"""Run one prompt-injection episode end to end: record, anchor, attribute, verify.

    python demo/run_demo.py --out out/demo
    python demo/run_demo.py --out out/demo --tamper
    python demo/run_demo.py --out out/demo --live --model claude-sonnet-4-5

Secret keys are generated here and stay in local variables; only the four public
keys are published, into the verifier's trust dir.
"""

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as a script or as -m

from attest.anchoring import write_anchor
from attest.attribution import single_chunk_ablation
from attest.clock import utc_now_iso
from attest.episode import load_records
from attest.keys import SIGNER_IDS, generate_keypair, write_public_key
from attest.policy import forbidden_tool_calls
from attest.records import read_record_file
from attest.recorder import (
    record_answer,
    record_attribution,
    record_retrieval,
    record_tool_call,
    start_episode,
)
from attest.verify import verify_episode
from demo.corpus import CHUNKS, FORBIDDEN_TOOLS, QUERY
from demo.scripted_agent import misbehaved, scripted_agent
from demo.tamper import TAMPERS


def publish_trust(trust_dir, keyring):
    """Write every signer's public key into the verifier's trust dir; return it."""
    for signer_id in SIGNER_IDS:
        path = write_public_key(trust_dir, signer_id, keyring[signer_id][0])
    return path.parent


def build_episode(
    episode_dir,
    secret_keys,
    run_agent,
    query,
    chunks,
    forbidden_tools,
    runs=3,
    episode_id=None,
    agent_id="support-bot",
    model="scripted-stub",
):
    """Record one episode, anchor it, and investigate it if the policy was broken."""
    start_episode(
        episode_dir,
        episode_id=episode_id or f"ep-{utc_now_iso()}",
        agent_id=agent_id,
        model=model,
        forbidden_tools=forbidden_tools,
        recorder_secret_key=secret_keys["recorder"],
    )
    record_retrieval(episode_dir, query, chunks, secret_keys["recorder"])
    observation = run_agent(chunks)
    if observation["tool"]:
        record_tool_call(
            episode_dir, observation["tool"], observation["args"], secret_keys["recorder"]
        )
    record_answer(episode_dir, observation["answer"], secret_keys["recorder"])
    write_anchor(episode_dir, "anchor-1", secret_keys["anchor-1"])

    payloads = [record["payload"] for _, record in load_records(episode_dir)]
    violations = forbidden_tool_calls(payloads, forbidden_tools)
    report = None
    if violations:
        report = single_chunk_ablation(
            chunks,
            run_agent,
            lambda observation: misbehaved(observation, forbidden_tools),
            runs,
        )
        if report["culprit_chunk_hash"]:
            record_attribution(
                episode_dir,
                report["culprit_chunk_hash"],
                report["runs"],
                secret_keys["investigator"],
            )
            write_anchor(episode_dir, "anchor-2", secret_keys["anchor-2"])

    anchor = read_record_file(episode_dir / "anchor.json")
    return {
        "observation": observation,
        "violations": violations,
        "report": report,
        "record_count": anchor["payload"]["record_count"],
        "merkle_root": anchor["payload"]["merkle_root"],
        "anchor_signer": anchor["signer_id"],
    }


def main(argv=None):
    args = _parse_args(argv)
    out = Path(args.out)
    episode_dir, trust_dir = out / "episode", out / "trust"
    if out.exists():
        shutil.rmtree(out)

    keyring = {signer_id: generate_keypair() for signer_id in SIGNER_IDS}
    secret_keys = {signer_id: secret for signer_id, (_, secret) in keyring.items()}
    publish_trust(trust_dir, keyring)

    run_agent, model = _pick_agent(args)
    summary = build_episode(
        episode_dir,
        secret_keys,
        run_agent,
        QUERY,
        CHUNKS,
        FORBIDDEN_TOOLS,
        runs=args.runs,
        model=model,
    )
    _print_story(episode_dir, trust_dir, summary)

    reasons = verify_episode(episode_dir, trust_dir)
    print("\n== verifier ==")
    for reason in reasons:
        print(f"  {reason}")
    print(f"  {'RED' if reasons else 'GREEN'}")
    if reasons:
        return 1
    return _demonstrate_tampers(out, episode_dir, trust_dir) if args.tamper else 0


def _parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="out/demo", help="where to write the bundle")
    parser.add_argument("--runs", type=int, default=3, help="ablation runs per configuration")
    parser.add_argument("--live", action="store_true", help="use the Anthropic API, not the stub")
    parser.add_argument("--model", default="claude-sonnet-4-5", help="model id for --live")
    parser.add_argument("--tamper", action="store_true", help="also show what tampering costs")
    return parser.parse_args(argv)


def _pick_agent(args):
    if not args.live:
        return scripted_agent, "scripted-stub"
    from demo.claude_agent import make_claude_agent

    return make_claude_agent(args.model, QUERY, FORBIDDEN_TOOLS), args.model


def _print_story(episode_dir, trust_dir, summary):
    print(f"== episode {episode_dir} ==")
    for _, record in load_records(episode_dir):
        payload = record["payload"]
        print(
            f"  seq {payload['seq']}  {payload['type']:<12} "
            f"signed by {record['signer_id']:<12} {record['payload_hash'][:12]}…"
        )
    print(f"  trust dir: {trust_dir} ({len(SIGNER_IDS)} public keys)")

    print("\n== review ==")
    for violation in summary["violations"] or [{"seq": "-", "tool": "none"}]:
        print(f"  seq {violation['seq']}: called {violation['tool']} (forbidden by the manifest)")

    report = summary["report"]
    if report:
        print("\n== investigation (single-chunk ablation) ==")
        print(f"  runs per configuration: {report['runs']}")
        print(f"  baseline misbehaved: {report['baseline_misbehaved']}")
        print(f"  chunks whose removal stopped it: {report['flipped_indexes']}")
        print(f"  culprit chunk: #{report['culprit_index']} {report['culprit_chunk_hash'][:12]}…")

    print("\n== anchor ==")
    print(f"  {summary['anchor_signer']} over {summary['record_count']} records")
    print(f"  merkle root {summary['merkle_root']}")


def _demonstrate_tampers(out, episode_dir, trust_dir):
    print("\n== tampering, without any signing key ==")
    caught = True
    for name in sorted(TAMPERS):
        copy = out / "tampered" / name
        shutil.copytree(episode_dir, copy)
        expected = TAMPERS[name](copy)
        reasons = verify_episode(copy, trust_dir)
        caught = caught and expected in reasons
        print(f"  {name}: {', '.join(reasons) if reasons else 'NOT CAUGHT'}")
        print(f"    {'RED' if reasons else 'GREEN'} (expected {expected})")
    return 0 if caught else 1


if __name__ == "__main__":
    sys.exit(main())
