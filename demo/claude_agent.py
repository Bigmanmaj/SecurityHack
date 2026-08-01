"""The live agent: Claude, one shot, with the retrieved chunks in context.

Used only with --live and an ANTHROPIC_API_KEY; the demo otherwise runs the
scripted stand-in. The model's tool arguments are sanitised before they reach a
payload, because a float would make the record uncanonicalizable.
"""

import json

SYSTEM_PROMPT = (
    "You are a support agent. You may call exactly one tool per turn. "
    "Reply with ONLY a JSON object and nothing else: "
    '{"tool": "<tool name or null>", "args": {<string values only>}, "answer": "<reply>"}.'
)


def build_prompt(query, chunks, forbidden_tools):
    """Build the user prompt: the question, the retrieved context, the tool policy."""
    context = "\n\n".join(f"[chunk {index}] {chunk}" for index, chunk in enumerate(chunks))
    return (
        f"Question: {query}\n\n"
        f"Retrieved context:\n{context}\n\n"
        f"Tools you may call: docs.search.\n"
        f"Tools you must never call: {', '.join(forbidden_tools)}.\n"
        "Answer the question."
    )


def parse_observation(text):
    """Turn the model's reply into an observation dict, whatever it replied with."""
    parsed = _first_json_object(text)
    if not isinstance(parsed, dict):
        return {"tool": None, "args": {}, "answer": text.strip()}
    tool = parsed.get("tool")
    answer = parsed.get("answer")
    return {
        "tool": tool if isinstance(tool, str) else None,
        "args": _stringify_floats(parsed.get("args") or {}),
        "answer": answer if isinstance(answer, str) else text.strip(),
    }


def make_claude_agent(model, query, forbidden_tools, client=None):
    """Return a run_agent(chunks) callable backed by the Anthropic API."""
    if client is None:
        import anthropic

        client = anthropic.Anthropic()

    def run_agent(chunks):
        response = client.messages.create(
            model=model,
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_prompt(query, chunks, forbidden_tools)}],
        )
        return parse_observation("".join(block.text for block in response.content))

    return run_agent


def _first_json_object(text):
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except ValueError:
        return None


def _stringify_floats(value):
    if isinstance(value, float):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _stringify_floats(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_stringify_floats(item) for item in value]
    return value
