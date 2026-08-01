"""The committed demo assets must stay demo-able.

`scripts/demo.sh` runs off `episode_demo/`, `episode_demo_done/`, `trust/` and
the warm `.cache/`. If a format change breaks any of them the demo fails in
front of an audience rather than here, so this guards them.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from verifier.verify import describe, load_trust, verify_episode

ROOT = Path(__file__).resolve().parents[1]
TRUST = ROOT / "trust"
PRE = ROOT / "episode_demo"
POST = ROOT / "episode_demo_done"


def test_trust_holds_the_four_public_keys():
    assert set(load_trust(TRUST)) == {"recorder", "anchor-1", "investigator", "anchor-2"}


@pytest.mark.parametrize("bundle", [PRE, POST], ids=["pre", "post"])
def test_the_committed_bundles_are_green(bundle):
    ok, reasons = verify_episode(bundle, TRUST)

    assert ok, reasons


def test_the_pre_bundle_shows_the_violation_and_no_verdict_yet():
    summary = describe(PRE)

    assert summary["types"] == ["manifest", "retrieval", "tool_call", "tool_result", "answer"]
    assert [v["tool"] for v in summary["violations"]] == ["transfer_funds"]
    assert summary["violations"][0]["executed"] is False
    assert summary["attribution"] is None


def test_the_post_bundle_carries_a_signed_verdict_naming_doc_07():
    from verifier.verify import resolve_chunk_hash

    summary = describe(POST)

    assert summary["attribution"]["signer"] == "investigator"
    assert summary["attribution"]["method"] == "single-chunk-ablation"
    assert resolve_chunk_hash(ROOT / "data" / "corpus", summary["attribution"]["culprit_chunk_hash"]) == "doc_07"
    assert [anchor["anchor_id"] for anchor in summary["anchors"]] == ["anchor-1", "anchor-2"]
    assert summary["anchors"][-1]["record_count"] == 6


def test_the_warm_cache_covers_the_baseline_and_every_ablation():
    cache = sorted((ROOT / ".cache").glob("*.json"))

    # 2 calls for the recorded episode, plus 2 per ablation over ten documents.
    assert len(cache) == 22
    assert all(json.loads(path.read_text())["content"] for path in cache)


def test_the_demo_runs_end_to_end_without_an_api_key():
    env = {key: value for key, value in os.environ.items() if key != "ANTHROPIC_API_KEY"}
    env["PYTHON"] = sys.executable

    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "demo.sh"), "--no-pause"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.count("GREEN") == 2
    assert result.stdout.count("RED") == 1
    assert "doc_07" in result.stdout


def test_the_demo_leaves_the_committed_bundles_untouched():
    before = {path: path.read_bytes() for path in sorted(PRE.rglob("*.json"))}

    subprocess.run(
        ["bash", str(ROOT / "scripts" / "demo.sh"), "--no-pause"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )

    assert {path: path.read_bytes() for path in sorted(PRE.rglob("*.json"))} == before
