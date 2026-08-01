"""Reading the manifest policy back out of an episode's payloads.

A policy violation is what triggers an investigation; the verifier's job is
integrity, not judgement, so this lives outside it.
"""


def manifest_policy(payloads):
    """Return the forbidden_tools list declared by the episode's manifest."""
    for payload in payloads:
        if payload.get("type") == "manifest":
            return list(payload.get("policy", {}).get("forbidden_tools", []))
    return []


def forbidden_tool_calls(payloads, forbidden_tools):
    """Return [{"seq", "tool"}, ...] for every tool_call payload the policy forbids."""
    return [
        {"seq": payload.get("seq"), "tool": payload.get("tool")}
        for payload in payloads
        if payload.get("type") == "tool_call" and payload.get("tool") in forbidden_tools
    ]
