import pytest

from attest.keys import SIGNER_IDS
from demo.run_scenarios import ROLES, SCENARIOS, main, run_scenario


def by_name(name):
    return next(scenario for scenario in SCENARIOS if scenario["name"] == name)


def test_every_role_says_what_it_holds_and_what_it_does():
    assert [role["name"] for role in ROLES] == [
        "recorder",
        "anchor-1",
        "reviewer",
        "investigator",
        "anchor-2",
        "verifier",
    ]
    assert all(role["holds"] and role["does"] for role in ROLES)


def test_each_signing_key_belongs_to_exactly_one_role():
    owned = [role["key"] for role in ROLES if role["key"]]
    assert sorted(owned) == sorted(SIGNER_IDS)


def test_the_reviewer_and_verifier_hold_no_signing_key():
    keyless = [role["name"] for role in ROLES if role["key"] is None]
    assert keyless == ["reviewer", "verifier"]


def test_the_five_scenarios_cover_both_agents_and_both_tamper_states():
    assert [scenario["name"] for scenario in SCENARIOS] == [
        "behaving_agent",
        "misbehaving_agent",
        "behaving_agent_tampered",
        "misbehaving_agent_tampered",
        "rogue_recorder",
    ]
    assert [scenario["expect_verdict"] for scenario in SCENARIOS] == [
        "GREEN",
        "GREEN",
        "RED",
        "RED",
        "RED",
    ]


@pytest.mark.parametrize("name", [scenario["name"] for scenario in SCENARIOS])
def test_each_scenario_reaches_its_expected_verdict(tmp_path, name):
    scenario = by_name(name)
    result = run_scenario(scenario, tmp_path / name, runs=1)
    assert result["verdict"] == scenario["expect_verdict"]
    for reason in scenario["expect_reasons"]:
        assert reason in result["reasons"]


def test_a_behaving_agent_needs_no_tool_call_and_no_investigation(tmp_path):
    result = run_scenario(by_name("behaving_agent"), tmp_path / "behaving", runs=1)
    assert result["record_types"] == ["manifest", "retrieval", "answer"]
    assert result["violations"] == []
    assert result["culprit_index"] is None
    assert result["anchor_signer"] == "anchor-1"


def test_a_misbehaving_agent_is_recorded_reviewed_and_attributed(tmp_path):
    result = run_scenario(by_name("misbehaving_agent"), tmp_path / "misbehaving", runs=1)
    assert result["record_types"] == [
        "manifest",
        "retrieval",
        "tool_call",
        "answer",
        "attribution",
    ]
    assert result["violations"] == [{"seq": 2, "tool": "shell.exec"}]
    assert result["culprit_index"] == 1
    assert result["anchor_signer"] == "anchor-2"


def test_the_rogue_recorder_fools_the_reviewer_but_not_the_verifier(tmp_path):
    result = run_scenario(by_name("rogue_recorder"), tmp_path / "rogue", runs=1)
    assert result["record_types"] == ["manifest", "retrieval", "tool_call", "answer"]
    assert result["violations"] == []
    assert result["reasons"] == ["ROOT_MISMATCH"]


def test_every_party_runs_as_its_own_process(tmp_path):
    result = run_scenario(by_name("misbehaving_agent"), tmp_path / "processes", runs=1)
    assert [command[0] for command in result["commands"]] == [
        "recorder",
        "anchor",
        "reviewer",
        "investigator",
        "anchor",
        "verify_cli",
    ]


def test_main_narrates_the_roles_then_every_scenario(tmp_path, capsys):
    exit_code = main(["--out", str(tmp_path / "run"), "--runs", "1"])
    output = capsys.readouterr().out
    assert exit_code == 0
    for role in ROLES:
        assert role["name"] in output
    for scenario in SCENARIOS:
        assert scenario["name"] in output
    assert "GREEN" in output and "RED" in output
    assert "5 scenarios matched" in output


def test_main_writes_one_bundle_per_scenario(tmp_path):
    main(["--out", str(tmp_path / "run"), "--runs", "1"])
    for scenario in SCENARIOS:
        assert (tmp_path / "run" / scenario["name"] / "episode" / "anchor.json").exists()
        assert (tmp_path / "run" / scenario["name"] / "trust" / "recorder.pub.hex").exists()
