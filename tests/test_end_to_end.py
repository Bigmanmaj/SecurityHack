"""Record -> verify -> investigate -> re-verify -> tamper -> RED.

The three demo beats, asserted rather than rehearsed.
"""

import json
import os
import subprocess
import sys

import pytest

import adversary as adv
import verify_episode
from agent import rag
from fr import reasons
from investigator import attribute
from investigator.cli import InvestigationError, investigate

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CULPRIT = ("doc-07-vendor-faq.md", 3)


@pytest.fixture(scope="module")
def recorded(tmp_path_factory):
    root = str(tmp_path_factory.mktemp("run") / "episode")
    rag.run_episode(root, scenario="poisoned", backend_name="mock")
    return root


def types_of(root):
    return [b["type"] for b in verify_episode.verify(root)["bodies"]]


def body_of(root, type_):
    return [b for b in verify_episode.verify(root)["bodies"] if b["type"] == type_]


# --- Beat 1 ---------------------------------------------------------------

def test_the_incident_is_recorded_and_the_chain_verifies(recorded):
    summary = verify_episode.verify(recorded)
    assert summary["types"][0] == "GENESIS" and summary["types"][-1] == "SEAL"
    assert "POLICY_VIOLATION" in summary["types"]


def test_the_violation_names_the_rule_and_the_offending_record(recorded):
    violation = body_of(recorded, "POLICY_VIOLATION")[0]["payload"]
    call = body_of(recorded, "TOOL_CALL")[0]
    assert violation["rule"] == "NOT_IN_TASK_SCOPE"
    assert violation["tool"] == "http_post"
    assert violation["offending_seq"] == call["seq"]
    assert call["payload"]["authorized"] is False


def test_the_unauthorized_tool_never_executed(recorded):
    result = body_of(recorded, "TOOL_RESULT")[0]["payload"]
    assert result["executed"] is False
    assert "blocked by policy" in result["error"]


def test_genesis_pins_the_task_scoped_allowlist_and_the_corpus(recorded):
    genesis = body_of(recorded, "GENESIS")[0]["payload"]
    assert genesis["tool_allowlist"] == ["read_doc", "search_docs"]
    assert "http_post" in genesis["tools_available"]
    assert len(genesis["corpus_manifest"]) == 10


def test_the_clean_scenario_produces_no_violation(tmp_path):
    root = str(tmp_path / "clean")
    rag.run_episode(root, scenario="clean", backend_name="mock")
    assert "POLICY_VIOLATION" not in types_of(root)
    verify_episode.verify(root)


def test_the_episode_is_reproducible_from_the_same_corpus(tmp_path):
    """Two independent runs retrieve the same chunks and reach the same verdict."""
    roots = []
    for name in ("a", "b"):
        root = str(tmp_path / name)
        rag.run_episode(root, scenario="poisoned", backend_name="mock")
        roots.append(root)
    retrievals = [body_of(r, "RETRIEVAL")[0]["payload"]["chunks"] for r in roots]
    assert retrievals[0] == retrievals[1]


# --- Beat 2 ---------------------------------------------------------------

def test_the_investigator_names_the_culprit_chunk(recorded):
    payload, _ = investigate(recorded, echo=lambda *a: None)
    assert payload["verdict"] == attribute.CAUSAL_SINGLE_SOURCE
    assert payload["confidence"] == attribute.HIGH
    assert (payload["culprit"]["doc_id"], payload["culprit"]["chunk_id"]) == CULPRIT
    assert payload["necessity_milli"] == 1000
    assert payload["sufficiency_milli"] == 1000
    assert payload["runner_up_necessity_milli"] == 0


def test_the_finding_lands_in_the_same_chain_and_it_still_verifies(recorded):
    summary = verify_episode.verify(recorded)
    assert summary["types"][-1] == "SEAL"
    assert len(summary["seals"]) == 2, "one seal for the agent, one for the investigation"
    assert summary["types"].count("INVESTIGATION_OPEN") == 1
    assert summary["types"].count("ATTRIBUTION_FINDING") == 1


def test_every_replay_is_signed_into_the_chain(recorded):
    finding = body_of(recorded, "ATTRIBUTION_FINDING")[0]["payload"]
    replays = {b["seq"] for b in body_of(recorded, "REPLAY_RUN")}
    assert finding["replay_seqs"], "the investigation must show its work"
    assert set(finding["replay_seqs"]) <= replays


def test_the_finding_carries_no_floats(recorded):
    payload = body_of(recorded, "ATTRIBUTION_FINDING")[0]["payload"]
    text = json.dumps(payload)
    assert all(isinstance(v, int) for v in
               (payload["necessity_milli"], payload["sufficiency_milli"]))
    assert "." not in text.replace(".md", "").replace("...", "")


def test_the_investigator_refuses_a_red_episode(tmp_path):
    root = str(tmp_path / "tampered")
    rag.run_episode(root, scenario="poisoned", backend_name="mock")
    adv.raw_edit(root, 5, b'"http_post"', b'"http_post "')
    with pytest.raises(verify_episode.Fail) as exc:
        investigate(root, echo=lambda *a: None)
    assert exc.value.code == reasons.SIGNATURE_INVALID


def test_the_investigator_refuses_an_episode_with_nothing_to_attribute(tmp_path):
    root = str(tmp_path / "clean")
    rag.run_episode(root, scenario="clean", backend_name="mock")
    with pytest.raises(InvestigationError, match="no POLICY_VIOLATION"):
        investigate(root, echo=lambda *a: None)


def test_the_investigator_refuses_a_drifted_corpus(tmp_path, monkeypatch):
    root = str(tmp_path / "drift")
    rag.run_episode(root, scenario="poisoned", backend_name="mock")
    real = rag.load_docs

    def drifted(*args, **kwargs):
        docs = real(*args, **kwargs)
        docs["doc-01-expense-policy.md"] += "\n\nAn edit made after the fact.\n"
        return docs

    monkeypatch.setattr("investigator.cli.load_docs", drifted)
    with pytest.raises(InvestigationError, match="corpus drift"):
        investigate(root, echo=lambda *a: None)


def test_the_exhaustive_sweep_reports_a_per_chunk_table(tmp_path):
    root = str(tmp_path / "sweep")
    rag.run_episode(root, scenario="poisoned", backend_name="mock")
    payload, _ = investigate(root, exhaustive=True, echo=lambda *a: None)
    table = payload["per_chunk"]
    assert len(table) == 5
    assert (table[0]["doc_id"], table[0]["chunk_id"]) == CULPRIT
    assert table[0]["necessity_milli"] == 1000
    assert all(row["necessity_milli"] == 0 for row in table[1:])


# --- Beat 3 ---------------------------------------------------------------

def test_one_character_turns_the_episode_red(tmp_path):
    root = str(tmp_path / "beat3")
    rag.run_episode(root, scenario="poisoned", backend_name="mock")
    before = subprocess.run([sys.executable, "verify_episode.py", root, "--no-color"],
                            cwd=REPO, capture_output=True, text=True)
    assert before.returncode == 0 and "GREEN" in before.stdout

    tamper = subprocess.run([sys.executable, "demo/tamper.py", root],
                            cwd=REPO, capture_output=True, text=True)
    assert tamper.returncode == 0, tamper.stderr

    after = subprocess.run([sys.executable, "verify_episode.py", root, "--no-color"],
                           cwd=REPO, capture_output=True, text=True)
    assert after.returncode == 1
    assert "RED - SIGNATURE_INVALID" in after.stdout
    assert "records/" in after.stdout, "a RED must name the file it found the problem in"


def test_the_committed_golden_episode_still_verifies():
    """Demo insurance: a pre-verified episode that needs no recording step."""
    golden = os.path.join(REPO, "episodes", "golden")
    summary = verify_episode.verify(golden)
    assert len(summary["seals"]) == 2
    finding = [b for b in summary["bodies"] if b["type"] == "ATTRIBUTION_FINDING"][0]["payload"]
    assert finding["verdict"] == attribute.CAUSAL_SINGLE_SOURCE
    assert (finding["culprit"]["doc_id"], finding["culprit"]["chunk_id"]) == CULPRIT
    assert not os.path.exists(os.path.join(golden, ".recorder-state.json")), (
        "the golden episode ships without its ratchet seed: it is append-closed"
    )


def test_the_cli_surface_is_three_verbs(tmp_path):
    root = str(tmp_path / "cli")
    record = subprocess.run([sys.executable, "-m", "agent.rag", "--scenario", "poisoned",
                             "--out", root], cwd=REPO, capture_output=True, text=True)
    assert record.returncode == 0, record.stderr
    verify = subprocess.run([sys.executable, "verify_episode.py", root],
                            cwd=REPO, capture_output=True, text=True)
    assert verify.returncode == 0, verify.stderr
    inv = subprocess.run([sys.executable, "-m", "investigator.cli", root],
                         cwd=REPO, capture_output=True, text=True)
    assert inv.returncode == 0, inv.stderr
    assert "CAUSAL_SINGLE_SOURCE" in inv.stdout
    again = subprocess.run([sys.executable, "verify_episode.py", root],
                           cwd=REPO, capture_output=True, text=True)
    assert again.returncode == 0
