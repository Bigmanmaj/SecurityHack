"""What the web app can do: build a session's bundle, tamper with it, verify it.

Every session gets its own directory, its own four keypairs and its own trust dir.
Secret keys stay in local variables inside build_session and are gone by the time
it returns — the verifier that runs afterwards has only the published public keys.
"""

import json
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from attest.episode import load_records
from attest.keys import SIGNER_IDS, generate_keypair
from attest.policy import forbidden_tool_calls, manifest_policy
from attest.records import read_record_file
from demo.run_demo import build_episode, publish_trust
from demo.run_scenarios import ROLES
from demo.scripted_agent import hardened_agent, make_injectable_agent
from demo.tamper import TAMPERS, applicable_tampers

REPO_ROOT = Path(__file__).resolve().parents[1]

AGENT_KINDS = ("injectable", "hardened")
MAX_CHUNKS = 12
MAX_TEXT = 5000
MAX_RUNS = 10


class InvalidInput(ValueError):
    """Raised when a request cannot be honoured; the message is shown to the user."""


def default_input():
    """The request the page starts with: a poisoned chunk among honest ones."""
    from demo.corpus import CHUNKS, FORBIDDEN_TOOLS, QUERY

    return {
        "query": QUERY,
        "chunks": list(CHUNKS),
        "forbidden_tools": list(FORBIDDEN_TOOLS),
        "agent": "injectable",
        "runs": 3,
    }


def build_session(sessions_dir, request):
    """Run the whole pipeline for ``request`` in a fresh session; return its story."""
    request = _validate(request)
    session = secrets.token_hex(6)
    session_dir = Path(sessions_dir) / session
    session_dir.mkdir(parents=True)
    _write_request(session_dir, request)
    _run_pipeline(session_dir, request)
    return session_story(sessions_dir, session)


def rebuild_session(sessions_dir, session):
    """Throw away every tamper and rebuild the session's bundle from its request."""
    session_dir = _session_dir(sessions_dir, session)
    request = _read_request(session_dir)
    for name in ("episode", "trust"):
        shutil.rmtree(session_dir / name, ignore_errors=True)
    (session_dir / "applied.json").unlink(missing_ok=True)
    _run_pipeline(session_dir, request)
    return session_story(sessions_dir, session)


def apply_tamper(sessions_dir, session, name):
    """Apply one named tamper to the session's bundle and re-verify it."""
    session_dir = _session_dir(sessions_dir, session)
    if name not in TAMPERS:
        raise InvalidInput(f"unknown tamper {name!r}")
    if name not in applicable_tampers(session_dir / "episode"):
        raise InvalidInput(f"this bundle has no record for {name!r} to touch")
    TAMPERS[name](session_dir / "episode")
    applied = _applied(session_dir) + [name]
    (session_dir / "applied.json").write_text(json.dumps(applied), encoding="utf-8")
    return session_story(sessions_dir, session)


def session_story(sessions_dir, session):
    """Describe the session's bundle as it stands right now."""
    session_dir = _session_dir(sessions_dir, session)
    request = _read_request(session_dir)
    episode, trust = session_dir / "episode", session_dir / "trust"
    records = [record for _, record in load_records(episode)]
    payloads = [record["payload"] for record in records]
    return {
        "session": session,
        "input": request,
        "roles": [dict(role) for role in ROLES],
        "records": [_describe_record(record) for record in records],
        "review": {
            "policy": manifest_policy(payloads),
            "violations": forbidden_tool_calls(payloads, manifest_policy(payloads)),
        },
        "investigation": _read_investigation(session_dir, payloads, request),
        "anchor": _describe_anchor(episode),
        "observation": _read_json(session_dir / "observation.json"),
        "verifier": _verify(episode, trust),
        "leak_check": _leak_check(episode, request),
        "tampers": _offered_tampers(episode),
        "applied": _applied(session_dir),
    }


def _run_pipeline(session_dir, request):
    keyring = {signer_id: generate_keypair() for signer_id in SIGNER_IDS}
    secret_keys = {signer_id: secret for signer_id, (_, secret) in keyring.items()}
    publish_trust(session_dir / "trust", keyring)

    calls = []
    summary = build_episode(
        session_dir / "episode",
        secret_keys,
        _logged_agent(request, calls),
        request["query"],
        request["chunks"],
        request["forbidden_tools"],
        runs=request["runs"],
        episode_id=f"ep-{session_dir.name}",
        model=f"scripted-stub/{request['agent']}",
    )
    _write_json(session_dir / "observation.json", summary["observation"])
    _write_json(session_dir / "report.json", summary["report"])
    # The first replay is the episode itself; the rest belong to the investigation.
    _write_json(session_dir / "matrix.json", _matrix(calls[1:], request))


def _logged_agent(request, calls):
    """Wrap the agent so every replay is observable, for the ablation matrix."""
    agent = (
        hardened_agent
        if request["agent"] == "hardened"
        else make_injectable_agent(request["forbidden_tools"])
    )

    def run_agent(chunks):
        observation = agent(chunks)
        calls.append(
            {
                "chunks": list(chunks),
                "misbehaved": observation["tool"] in request["forbidden_tools"],
            }
        )
        return observation

    return run_agent


def _matrix(calls, request):
    """Group the logged replays into one row per configuration that was tried."""
    rows = {}
    for call in calls:
        missing = [
            index for index, chunk in enumerate(request["chunks"]) if chunk not in call["chunks"]
        ]
        config = "baseline" if not missing else f"without #{missing[0]}"
        rows.setdefault(config, []).append(call["misbehaved"])
    return [{"config": config, "outcomes": outcomes} for config, outcomes in rows.items()]


def _read_investigation(session_dir, payloads, request):
    report = _read_json(session_dir / "report.json")
    attribution = next((p for p in payloads if p["type"] == "attribution"), None)
    retrieval = next((p for p in payloads if p["type"] == "retrieval"), None)
    if report is None:
        return {"ran": False, "matrix": [], "culprit_index": None}
    culprit = attribution["culprit_chunk_hash"] if attribution else None
    return {
        "ran": True,
        "runs": report["runs"],
        "baseline_misbehaved": report["baseline_misbehaved"],
        "flipped_indexes": report["flipped_indexes"],
        "culprit_index": retrieval["chunk_hashes"].index(culprit) if culprit else None,
        "culprit_chunk_hash": culprit,
        "matrix": _read_json(session_dir / "matrix.json") or [],
    }


def _describe_record(record):
    payload = record["payload"]
    return {
        "seq": payload["seq"],
        "type": payload["type"],
        "signer_id": record["signer_id"],
        "payload_hash": record["payload_hash"],
        "created_at": record["created_at"],
        "signature_preview": record["signature"][:32] + "…",
        "signature_bytes": len(record["signature"]) // 2,
        "payload": payload,
    }


def _describe_anchor(episode_dir):
    """Describe the anchor, or None when a tamper has removed or broken it."""
    try:
        anchor = read_record_file(episode_dir / "anchor.json")
    except (OSError, ValueError):
        return None
    return {
        "signer_id": anchor["signer_id"],
        "payload_hash": anchor["payload_hash"],
        **anchor["payload"],
    }


def _verify(episode, trust):
    """Run the real CLI as a separate process, and report exactly what it printed."""
    argv = [
        sys.executable,
        str(REPO_ROOT / "verify_cli.py"),
        "--episode",
        str(episode),
        "--trust",
        str(trust),
    ]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    lines = result.stdout.strip().splitlines()
    return {
        "command": f"python3 verify_cli.py --episode {episode.name} --trust {trust.name}",
        "stdout": result.stdout,
        "verdict": lines[-1] if lines else "RED",
        "reasons": lines[:-1],
        "exit_code": result.returncode,
    }


def _leak_check(episode_dir, request):
    """Prove the published bundle contains none of the text it attests to."""
    published = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(episode_dir.rglob("*.json"))
    )
    secrets_to_check = [request["query"], *request["chunks"]]
    return {
        "checked": len(secrets_to_check),
        "found": [text[:40] for text in secrets_to_check if text and text in published],
    }


def _offered_tampers(episode_dir):
    return [
        {"name": name, "expects": TAMPERS[name].__doc__.strip().splitlines()[0]}
        for name in applicable_tampers(episode_dir)
    ]


def _validate(request):
    if not isinstance(request, dict):
        raise InvalidInput("expected a JSON object")
    query = _text("query", request.get("query"))
    chunks = request.get("chunks")
    if not isinstance(chunks, list) or not 1 <= len(chunks) <= MAX_CHUNKS:
        raise InvalidInput(f"chunks must be a list of 1 to {MAX_CHUNKS} strings")
    tools = request.get("forbidden_tools")
    if not isinstance(tools, list) or not tools:
        raise InvalidInput("forbidden_tools must be a non-empty list of tool names")
    agent = request.get("agent")
    if agent not in AGENT_KINDS:
        raise InvalidInput(f"agent must be one of {', '.join(AGENT_KINDS)}")
    runs = request.get("runs")
    if isinstance(runs, bool) or not isinstance(runs, int) or not 1 <= runs <= MAX_RUNS:
        raise InvalidInput(f"runs must be a whole number from 1 to {MAX_RUNS}")
    return {
        "query": query,
        "chunks": [_text(f"chunk {index}", chunk) for index, chunk in enumerate(chunks)],
        "forbidden_tools": [_text("forbidden tool", tool) for tool in tools],
        "agent": agent,
        "runs": runs,
    }


def _text(field, value):
    if not isinstance(value, str) or not value.strip():
        raise InvalidInput(f"{field} must not be empty")
    if len(value) > MAX_TEXT:
        raise InvalidInput(f"{field} must be under {MAX_TEXT} characters")
    return value


def _session_dir(sessions_dir, session):
    if not session or len(session) > 32 or not all(c in "0123456789abcdef" for c in session):
        raise InvalidInput("that is not a session id")
    session_dir = Path(sessions_dir) / session
    if not (session_dir / "request.json").is_file():
        raise InvalidInput("no such session — run an episode first")
    return session_dir


def _write_request(session_dir, request):
    _write_json(session_dir / "request.json", request)


def _read_request(session_dir):
    return _read_json(session_dir / "request.json")


def _applied(session_dir):
    return _read_json(session_dir / "applied.json") or []


def _write_json(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def _read_json(path):
    if not Path(path).is_file():
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))
