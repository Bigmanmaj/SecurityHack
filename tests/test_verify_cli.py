import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "verify_cli.py"), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def test_green_bundle_exits_zero_and_says_green(episode_dir, trust_dir):
    result = run_cli("--episode", str(episode_dir), "--trust", str(trust_dir))
    assert result.returncode == 0
    assert result.stdout.strip().splitlines()[-1] == "GREEN"


def test_tampered_bundle_prints_every_reason_then_red(episode_dir, trust_dir):
    (episode_dir / "records" / "000002.json").unlink()
    result = run_cli("--episode", str(episode_dir), "--trust", str(trust_dir))
    assert result.returncode == 1
    lines = result.stdout.strip().splitlines()
    assert lines[-1] == "RED"
    assert "SEQ_GAP_OR_DUP" in lines
    assert "COUNT_MISMATCH" in lines
    assert "ROOT_MISMATCH" in lines


def test_red_output_is_only_reasons_and_red(episode_dir, trust_dir):
    (episode_dir / "anchor.json").unlink()
    result = run_cli("--episode", str(episode_dir), "--trust", str(trust_dir))
    assert result.returncode == 1
    assert result.stdout.strip().splitlines() == ["BAD_ANCHOR(missing)", "RED"]


def test_missing_episode_dir_is_red(tmp_path, trust_dir):
    result = run_cli("--episode", str(tmp_path / "nope"), "--trust", str(trust_dir))
    assert result.returncode == 1
    assert result.stdout.strip().splitlines()[-1] == "RED"


def test_missing_trust_dir_is_red(episode_dir, tmp_path):
    result = run_cli("--episode", str(episode_dir), "--trust", str(tmp_path / "nope"))
    assert result.returncode == 1
    assert result.stdout.strip().splitlines()[-1] == "RED"


@pytest.mark.parametrize("args", [(), ("--episode", "x"), ("--trust", "y")])
def test_both_arguments_are_required(args):
    assert run_cli(*args).returncode == 2


def test_main_is_importable_and_returns_an_exit_code(episode_dir, trust_dir, capsys):
    sys.path.insert(0, str(REPO_ROOT))
    from verify_cli import main

    assert main(["--episode", str(episode_dir), "--trust", str(trust_dir)]) == 0
    assert capsys.readouterr().out.strip() == "GREEN"
