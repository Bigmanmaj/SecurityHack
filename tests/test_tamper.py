"""C3: the tamper tool produces exactly the failures SPEC §5.1 predicts."""

import subprocess
import sys
from pathlib import Path

from verifier.verify import verify_episode

from .bundles import valid_bundle

ROOT = Path(__file__).resolve().parents[1]
TAMPER = ROOT / "scripts" / "tamper.py"


def tamper(action, builder, out, *extra):
    result = subprocess.run(
        [sys.executable, str(TAMPER), action, "--episode", str(builder.episode),
         "--out", str(out), "--force", *extra],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def tokens_after(action, tmp_path, *extra):
    builder = valid_bundle(tmp_path)
    out = tmp_path / f"tampered_{action}"
    output = tamper(action, builder, out, *extra)

    ok, reasons = verify_episode(out, builder.trust)
    assert ok is False
    return {reason.split(":")[0] for reason in reasons}, output, builder


def test_flip_breaks_the_hash_and_the_signature(tmp_path):
    found, output, _ = tokens_after("flip", tmp_path)

    assert found == {"HASH_MISMATCH", "BAD_SIGNATURE"}
    assert "flipped" in output and "->" in output


def test_delete_breaks_the_sequence_the_count_and_the_root(tmp_path):
    found, output, _ = tokens_after("delete", tmp_path)

    assert found == {"SEQ_GAP_OR_DUP", "COUNT_MISMATCH", "ROOT_MISMATCH"}
    assert "deleted" in output


def test_swap_leaves_every_signature_valid_and_only_breaks_the_root(tmp_path):
    """The point of the demo: signing each record cannot bind their order."""
    found, output, _ = tokens_after("swap", tmp_path)

    assert found == {"ROOT_MISMATCH"}
    assert "swapped" in output


def test_the_original_bundle_is_left_green(tmp_path):
    builder = valid_bundle(tmp_path)
    before = sorted(path.read_bytes() for path in builder.episode.rglob("*.json"))

    for action in ("flip", "delete", "swap"):
        tamper(action, builder, tmp_path / f"out_{action}")

    after = sorted(path.read_bytes() for path in builder.episode.rglob("*.json"))
    assert before == after
    assert verify_episode(builder.episode, builder.trust) == (True, [])


def test_the_manifest_record_is_never_the_one_touched(tmp_path):
    builder = valid_bundle(tmp_path)
    out = tmp_path / "out"

    for action in ("flip", "delete", "swap"):
        tamper(action, builder, out)
        manifest = out / "records" / "00000.json"
        assert manifest.exists()
        assert manifest.read_bytes() == (builder.episode / "records" / "00000.json").read_bytes()


def test_a_specific_record_can_be_targeted(tmp_path):
    builder = valid_bundle(tmp_path)

    output = tamper("flip", builder, tmp_path / "out", "--seq", "3")

    assert "seq 3" in output


def test_tampering_refuses_a_directory_that_is_not_a_bundle(tmp_path):
    result = subprocess.run(
        [sys.executable, str(TAMPER), "flip", "--episode", str(tmp_path), "--out",
         str(tmp_path / "out")],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "does not look like an episode bundle" in result.stderr
