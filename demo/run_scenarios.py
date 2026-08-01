#!/usr/bin/env python3
"""Run every scenario with each party in its own process, and report the verdicts.

    python3 demo/run_scenarios.py --out out/scenarios
    python3 demo/run_scenarios.py --out out/scenarios --runs 1

Five scenarios: a behaving agent and a misbehaving one, each untampered and
tampered with, plus a recorder that rewrites its own history after anchoring.
Exit 0 only if every scenario reached the verdict it was supposed to.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attest.attribution import chunk_hash
from attest.episode import load_records
from attest.hashing import hash_payload
from attest.policy import forbidden_tool_calls, manifest_policy
from attest.records import read_record_file, record_paths, write_record_file
from demo.corpus import CHUNKS

REPO_ROOT = Path(__file__).resolve().parents[1]

ROLES = (
    {
        "name": "recorder",
        "key": "recorder",
        "holds": "its own signing key",
        "does": "records the manifest, retrieval, tool call and answer as they happen",
    },
    {
        "name": "anchor-1",
        "key": "anchor-1",
        "holds": "its own signing key",
        "does": "signs how many records exist and their Merkle root",
    },
    {
        "name": "reviewer",
        "key": None,
        "holds": "no key at all",
        "does": "reads the bundle and flags tool calls the manifest forbids",
    },
    {
        "name": "investigator",
        "key": "investigator",
        "holds": "its own signing key",
        "does": "replays the episode with each chunk removed and names the culprit",
    },
    {
        "name": "anchor-2",
        "key": "anchor-2",
        "holds": "its own signing key",
        "does": "re-anchors once the investigation added a record",
    },
    {
        "name": "verifier",
        "key": None,
        "holds": "only the four public keys",
        "does": "recomputes every hash, signature, binding and root, then says GREEN or RED",
    },
)


def edit_the_answer(episode_dir):
    """An outsider with no key changes what the agent answered."""
    path = record_of_type(episode_dir, "answer")
    record = read_record_file(path)
    record["payload"]["answer_hash"] = hash_payload("a much nicer answer")
    write_record_file(path, record)


def delete_the_tool_call(episode_dir):
    """An outsider with no key removes the record of the forbidden call."""
    record_of_type(episode_dir, "tool_call").unlink()


SCENARIOS = (
    {
        "name": "behaving_agent",
        "story": "the agent treats the retrieved text as data and ignores the injection",
        "agent": "hardened",
        "flow": "parties",
        "tampers": (),
        "expect_verdict": "GREEN",
        "expect_reasons": (),
    },
    {
        "name": "misbehaving_agent",
        "story": "the agent obeys an instruction hidden in a retrieved chunk",
        "agent": "injected",
        "flow": "parties",
        "tampers": (),
        "expect_verdict": "GREEN",
        "expect_reasons": (),
    },
    {
        "name": "behaving_agent_tampered",
        "story": "a clean episode, then an outsider edits the answer",
        "agent": "hardened",
        "flow": "parties",
        "tampers": (edit_the_answer,),
        "expect_verdict": "RED",
        "expect_reasons": ("BAD_SIGNATURE(records/000002.json)", "ROOT_MISMATCH"),
    },
    {
        "name": "misbehaving_agent_tampered",
        "story": "an investigated episode, then an outsider deletes the tool call",
        "agent": "injected",
        "flow": "parties",
        "tampers": (delete_the_tool_call,),
        "expect_verdict": "RED",
        "expect_reasons": ("SEQ_GAP_OR_DUP", "COUNT_MISMATCH", "ROOT_MISMATCH"),
    },
    {
        "name": "rogue_recorder",
        "story": "the recorder itself relabels the forbidden call after anchoring",
        "agent": "injected",
        "flow": "rogue",
        "tampers": (),
        "expect_verdict": "RED",
        "expect_reasons": ("ROOT_MISMATCH",),
    },
)


def run_scenario(scenario, out_dir, runs=3):
    """Build one scenario's bundle party by party, then verify it; return the result."""
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    episode, trust = out_dir / "episode", out_dir / "trust"
    commands = []

    if scenario["flow"] == "rogue":
        _party(commands, "rogue_recorder", episode, trust)
    else:
        _party(commands, "recorder", episode, trust, "--agent", scenario["agent"])
        _party(commands, "anchor", episode, trust, "--signer", "anchor-1")
        review = _party(commands, "reviewer", episode, None)
        if review.returncode:
            _party(commands, "investigator", episode, trust, "--runs", str(runs),
                   "--agent", scenario["agent"])
            _party(commands, "anchor", episode, trust, "--signer", "anchor-2")

    for tamper in scenario["tampers"]:
        tamper(episode)

    verdict, reasons, verify_command = _verify(episode, trust)
    commands.append(verify_command)
    return {
        "name": scenario["name"],
        "verdict": verdict,
        "reasons": reasons,
        "commands": commands,
        **_describe(episode),
    }


def record_of_type(episode_dir, payload_type):
    """Find the record file holding a payload of ``payload_type``."""
    for path in record_paths(episode_dir):
        if read_record_file(path)["payload"]["type"] == payload_type:
            return path
    raise LookupError(f"no {payload_type} record in {episode_dir}")


def main(argv=None):
    args = _parse_args(argv)
    _print_roles()
    results = [
        run_scenario(scenario, Path(args.out) / scenario["name"], args.runs)
        for scenario in SCENARIOS
    ]
    for scenario, result in zip(SCENARIOS, results):
        _print_scenario(scenario, result)
    return _print_summary(results)


def _party(commands, role, episode, trust, *extra):
    """Run one party as its own process; record the command that was run."""
    argv = [sys.executable, str(REPO_ROOT / "demo" / "parties" / f"{role}.py"),
            "--episode", str(episode)]
    if trust is not None:
        argv += ["--trust", str(trust)]
    argv += list(extra)
    commands.append((role, *extra))
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _verify(episode, trust):
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "verify_cli.py"),
         "--episode", str(episode), "--trust", str(trust)],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = result.stdout.strip().splitlines()
    return lines[-1], lines[:-1], ("verify_cli",)


def _describe(episode_dir):
    """Read back what the bundle now says, the way any reviewer would."""
    payloads = [record["payload"] for _, record in load_records(episode_dir)]
    retrieval = next((p for p in payloads if p["type"] == "retrieval"), None)
    attribution = next((p for p in payloads if p["type"] == "attribution"), None)
    culprit = attribution["culprit_chunk_hash"] if attribution else None
    anchor = read_record_file(Path(episode_dir) / "anchor.json")
    return {
        "record_types": [payload["type"] for payload in payloads],
        "violations": forbidden_tool_calls(payloads, manifest_policy(payloads)),
        "culprit_index": retrieval["chunk_hashes"].index(culprit) if culprit else None,
        "anchor_signer": anchor["signer_id"],
        "record_count": anchor["payload"]["record_count"],
    }


def _print_roles():
    print("== the parties ==")
    for role in ROLES:
        print(f"  {role['name']:<14}{role['holds']:<26}{role['does']}")
    print("  each runs as its own process, so no private key ever crosses a process boundary")
    print(f"  the poisoned chunk in the corpus is #1, hash {chunk_hash(CHUNKS[1])[:12]}…")
    print("  every command below omits --episode and --trust for readability")


def _print_scenario(scenario, result):
    print(f"\n== {scenario['name']} ==")
    print(f"  {scenario['story']}")
    for command in result["commands"]:
        print(f"  $ {_as_command(command)}")
    if scenario["tampers"]:
        print(f"  then, with no key at all: {', '.join(t.__name__ for t in scenario['tampers'])}")

    print(f"  records now on disk: {', '.join(result['record_types'])}")
    print(f"  a reviewer reading it now would see: {result['violations'] or 'nothing'}")
    if result["culprit_index"] is not None:
        print(f"  the attribution record blames chunk #{result['culprit_index']}")
    print(
        f"  the anchor is signed by {result['anchor_signer']} "
        f"and claims {result['record_count']} records"
    )
    for reason in result["reasons"]:
        print(f"  {reason}")
    print(f"  verifier: {result['verdict']} (expected {scenario['expect_verdict']})")


def _as_command(command):
    """Render a recorded step the way you would type it, minus the two path flags."""
    role, *extra = command
    script = "verify_cli.py" if role == "verify_cli" else f"demo/parties/{role}.py"
    return " ".join(["python3", script, *extra])


def _print_summary(results):
    print("\n== summary ==")
    matched = 0
    for scenario, result in zip(SCENARIOS, results):
        expected = scenario["expect_verdict"] == result["verdict"] and all(
            reason in result["reasons"] for reason in scenario["expect_reasons"]
        )
        matched += expected
        print(f"  {scenario['name']:<28}{result['verdict']:<6}{'as expected' if expected else 'UNEXPECTED'}")
    print(f"  {matched} scenarios matched expectations, {len(results) - matched} did not")
    return 0 if matched == len(results) else 1


def _parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="out/scenarios", help="where to write the bundles")
    parser.add_argument("--runs", type=int, default=3, help="ablation runs per configuration")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
