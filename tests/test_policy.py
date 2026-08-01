from attest.policy import forbidden_tool_calls, manifest_policy

MANIFEST = {
    "type": "manifest",
    "seq": 0,
    "ts": "2026-08-01T10:00:00.000Z",
    "episode_id": "ep-1",
    "agent_id": "a",
    "model": "m",
    "policy": {"forbidden_tools": ["shell.exec", "net.post"]},
}


def tool_call(seq, tool):
    return {"type": "tool_call", "seq": seq, "ts": "t", "tool": tool, "args_hash": "00"}


def test_manifest_policy_lists_the_forbidden_tools():
    assert manifest_policy([MANIFEST]) == ["shell.exec", "net.post"]


def test_manifest_policy_is_empty_without_a_manifest():
    assert manifest_policy([tool_call(1, "shell.exec")]) == []


def test_forbidden_tool_calls_finds_violations_in_seq_order():
    payloads = [
        MANIFEST,
        tool_call(1, "docs.search"),
        tool_call(2, "shell.exec"),
        tool_call(3, "net.post"),
    ]
    assert forbidden_tool_calls(payloads, ["shell.exec", "net.post"]) == [
        {"seq": 2, "tool": "shell.exec"},
        {"seq": 3, "tool": "net.post"},
    ]


def test_only_tool_call_payloads_count():
    payloads = [MANIFEST, {"type": "answer", "seq": 1, "tool": "shell.exec"}]
    assert forbidden_tool_calls(payloads, ["shell.exec"]) == []


def test_no_violations_is_an_empty_list():
    assert forbidden_tool_calls([MANIFEST, tool_call(1, "docs.search")], ["shell.exec"]) == []
