"""The web layer.

Two things are worth testing here and they are not the pixels:

1. **The verdict is never computed in the app.** ``/api/verify`` must shell out to
   the real verifier and hand back its stdout and exit code untouched. A demo that
   decided GREEN in Python would be exactly the thing a judge should suspect.
2. **The write endpoint is the threat model, not a vulnerability.** It hands the
   adversary a pen on purpose, so it had better not also hand them the filesystem.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("fastapi", reason="web UI is optional: pip install '.[web]'")
from fastapi.testclient import TestClient  # noqa: E402

import verify_episode  # noqa: E402
from demo import attacks  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A server pointed at a throwaway episode directory."""
    monkeypatch.setenv("FR_EPISODE", "unused")
    from web import app as web_app

    root = str(tmp_path / "episode")
    monkeypatch.setattr(web_app, "EPISODE_ROOT", root)
    web_app.DEMO.reset_soft()
    with TestClient(web_app.app) as client:
        client.episode_root = root
        yield client
    web_app.DEMO.reset_soft()


def record_episode(client):
    with client.stream("GET", "/api/run/events") as response:
        assert response.status_code == 200
        events = [line for line in response.iter_lines()]
    return events


def sse_events(lines):
    out, name = [], None
    for line in lines:
        if line.startswith("event: "):
            name = line[7:]
        elif line.startswith("data: ") and name:
            out.append((name, json.loads(line[6:])))
    return out


# --- the page and the empty state -----------------------------------------

def test_the_page_makes_no_external_requests():
    """Conference wifi is a myth. Nothing may be fetched from anywhere."""
    with open(os.path.join(REPO, "web", "index.html"), encoding="utf-8") as fh:
        html = fh.read()
    for offender in ("http://", "https://", "//cdn", "<script src", "<link rel=\"stylesheet\""):
        assert offender not in html.replace(
            "http://www.w3.org/2000/svg", ""     # the inline favicon's SVG namespace
        ).replace("https://vendor-sync", ""), f"external reference in index.html: {offender}"


def test_state_on_an_empty_directory(client):
    state = client.get("/api/state").json()
    assert state["exists"] is False and state["count"] == 0
    assert state["attacks"], "the attack menu is served from the registry"
    assert {a["key"] for a in state["attacks"]} == set(attacks.BY_KEY)


def test_verify_refuses_when_there_is_nothing_to_verify(client):
    assert client.post("/api/verify").status_code == 409


# --- beat 1 ---------------------------------------------------------------

def test_run_streams_one_event_per_signed_record(client):
    events = sse_events(record_episode(client))
    kinds = [name for name, _ in events]
    assert kinds[0] == "start" and kinds[-1] == "done"

    records = [data for name, data in events if name == "record"]
    assert [r["seq"] for r in records] == list(range(len(records)))
    assert records[0]["type"] == "GENESIS" and records[-1]["type"] == "SEAL"
    assert any(r["type"] == "POLICY_VIOLATION" for r in records)
    # Real measured latency, not a setTimeout.
    assert all(isinstance(r["sign_ms"], int) and r["sign_ms"] >= 0 for r in records)


def test_the_spine_reports_every_key_but_the_newest_as_erased(client):
    record_episode(client)
    rows = client.get("/api/state").json()["records"]
    erased = [r for r in rows if r["key"]["erased"]]
    live = [r for r in rows if not r["key"]["erased"]]
    assert len(live) == 1 and live[0]["seq"] == rows[-1]["seq"]
    assert len(erased) == len(rows) - 1
    assert all(r["key"]["erased_at"] > r["key"]["signed_at"] for r in erased)


def test_run_refuses_to_overwrite_an_existing_episode(client):
    record_episode(client)
    assert client.get("/api/run/events").status_code == 409


# --- the verdict comes from a subprocess ----------------------------------

def test_verify_shells_out_and_returns_the_real_output(client):
    record_episode(client)
    verdict = client.post("/api/verify").json()
    assert verdict["returncode"] == 0 and verdict["green"] is True
    assert "GREEN - chain intact" in verdict["stdout"]

    # The same command, run by hand, must produce the same text. This is the
    # offer we make to a sceptical judge, so it is a test.
    proc = subprocess.run(
        [sys.executable, "verify_episode.py", client.episode_root, "--no-color"],
        cwd=REPO, capture_output=True, text=True)
    assert proc.stdout == verdict["stdout"]
    assert proc.returncode == verdict["returncode"]


def test_a_red_verdict_carries_the_reason_and_the_location(client):
    record_episode(client)
    client.post("/api/tamper/edit_byte")
    verdict = client.post("/api/verify").json()
    assert verdict["returncode"] == 1 and verdict["green"] is False
    assert verdict["reason"] == "SIGNATURE_INVALID"
    assert isinstance(verdict["seq"], int)
    assert verdict["path"].endswith(".json")


# --- beat 2 ---------------------------------------------------------------

def test_investigate_streams_bisection_and_a_signed_verdict(client):
    record_episode(client)
    with client.stream("GET", "/api/investigate/events") as response:
        events = sse_events(list(response.iter_lines()))
    kinds = [name for name, _ in events]
    assert "preflight" in kinds and "bisect_round" in kinds and "verdict" in kinds

    rounds = [d for n, d in events if n == "bisect_round"]
    assert rounds and all("left_violation" in r for r in rounds)
    verdict = next(d for n, d in events if n == "verdict")["finding"]
    assert verdict["verdict"] == "CAUSAL_SINGLE_SOURCE"
    assert verdict["culprit"]["doc_id"] == "doc-07-vendor-faq.md"

    assert client.post("/api/verify").json()["green"] is True


def test_investigate_refuses_a_tampered_episode(client):
    record_episode(client)
    client.post("/api/tamper/edit_byte")
    with client.stream("GET", "/api/investigate/events") as response:
        events = sse_events(list(response.iter_lines()))
    failures = [d for n, d in events if n == "failed"]
    assert failures and "SIGNATURE_INVALID" in failures[0]["message"]


# --- the write endpoint: deliberate, and deliberately narrow --------------

def test_editing_a_record_marks_it_and_drops_the_stale_verdict(client):
    record_episode(client)
    assert client.post("/api/verify").json()["green"] is True

    original = client.get("/api/records/5").json()
    edited = original["text"].replace('"http_post"', '"http_post "', 1)
    assert edited != original["text"]
    state = client.put("/api/records/5", json={"text": edited}).json()["state"]

    # The UI knows the bytes changed. It does not pretend to know the verdict.
    assert state["verdict"] is None
    assert [r["seq"] for r in state["records"] if r["edited"]] == [5]
    assert client.post("/api/verify").json()["reason"] == "SIGNATURE_INVALID"


@pytest.mark.parametrize("seq", ["../../../etc/passwd", "..%2f..%2fetc%2fpasswd", "1;rm", "1.5"])
def test_a_non_integer_seq_never_reaches_the_filesystem(client, seq):
    record_episode(client)
    assert client.get(f"/api/records/{seq}").status_code in (404, 422)
    assert client.put(f"/api/records/{seq}", json={"text": "x"}).status_code in (404, 422)


@pytest.mark.parametrize("seq", [-1, 10**9])
def test_out_of_range_seqs_are_refused(client, seq):
    record_episode(client)
    assert client.get(f"/api/records/{seq}").status_code == 400


def test_writing_outside_the_episode_leaves_the_repo_alone(client):
    record_episode(client)
    before = os.path.getmtime(os.path.join(REPO, "verify_episode.py"))
    for seq in ("../../verify_episode", "..", "0/../../../x"):
        client.put(f"/api/records/{seq}", json={"text": "compromised"})
    assert os.path.getmtime(os.path.join(REPO, "verify_episode.py")) == before


# --- the attack menu ------------------------------------------------------

@pytest.mark.parametrize("attack", attacks.ATTACKS, ids=lambda a: a.key)
def test_each_menu_button_produces_the_reason_it_advertises(client, attack, tmp_path):
    """The same promise as the tamper matrix, made over HTTP this time."""
    from web import app as web_app

    record_episode(client)
    if attack.requires == attacks.NEEDS_FOREIGN:
        foreign = str(tmp_path / "foreign")
        shutil.copytree(os.path.join(REPO, "episodes", "golden"), foreign)
        web_app.GOLDEN_ROOT = foreign

    response = client.post(f"/api/tamper/{attack.key}")
    assert response.status_code == 200, response.json()
    assert response.json()["expected_reason"] == attack.reason
    assert client.post("/api/verify").json()["reason"] == attack.reason
    web_app.GOLDEN_ROOT = os.path.join(REPO, "episodes", "golden")


def test_an_unknown_attack_is_refused(client):
    record_episode(client)
    assert client.post("/api/tamper/drop_the_database").status_code == 409


# --- reset ----------------------------------------------------------------

def test_reset_always_returns_to_a_blank_slate(client):
    for _ in range(3):
        record_episode(client)
        client.post("/api/tamper/delete_record")
        state = client.post("/api/reset").json()
        assert state["exists"] is False and state["count"] == 0
        assert state["verdict"] is None


def test_loading_the_golden_episode_says_it_is_not_a_live_run(client):
    state = client.post("/api/load-golden").json()
    assert state["source"] == "golden"
    assert state["appendable"] is False, "the golden episode ships without its seed"
    assert client.post("/api/verify").json()["green"] is True
    verify_episode.verify(client.episode_root)
