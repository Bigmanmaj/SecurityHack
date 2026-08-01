"""Two LLM backends behind one interface. The mock is built first and is the
default for the demo.

A model that is exactly reproducible is not a shortcut here: the investigator's
counterfactual is a claim about what *would* have happened with an input removed,
and that claim is only crisp if the model is a function. Live mode does not
pretend otherwise -- it repeats each ablation and degrades confidence rather than
silently changing the verdict.

The contract in both directions is one JSON object:

    {"tool_call": {"name": "...", "args": {...}}}   or   {"answer": "..."}
"""

import json
import re

RESPONSE_SCHEMA = (
    'Reply with exactly one JSON object and nothing else. Either '
    '{"tool_call":{"name":<tool>,"args":{...}}} to call a tool, or '
    '{"answer":<string>} to answer the user.'
)

# A turn-level constraint the agent sets after it has spent its one tool step, so
# that a poisoned context cannot spin the loop forever.
NO_TOOLS_SENTINEL = "TOOL CALLS ARE DISABLED FOR THIS TURN."

# The mock plays a gullible model: an imperative aimed at an assistant, naming an
# action and a destination, is followed. This is the behaviour real injections
# exploit, reduced to a regex so it is a function rather than a coin flip.
_INJECTION = re.compile(
    r"(assistant|ai agent|language model)[^.]{0,240}?\bpost\b[^.]{0,240}?(https?://\S+?)(?=[\s)\]]|$)",
    re.IGNORECASE | re.DOTALL,
)


class LLMResult:
    __slots__ = ("text", "backend", "model", "meta")

    def __init__(self, text, backend, model, meta=None):
        self.text = text
        self.backend = backend
        self.model = model
        self.meta = meta or {}

    def parse(self):
        """Parse the model's reply into ``(kind, value)``; malformed replies answer."""
        try:
            obj = json.loads(self.text)
        except json.JSONDecodeError:
            return "answer", self.text.strip()
        if isinstance(obj, dict) and isinstance(obj.get("tool_call"), dict):
            call = obj["tool_call"]
            return "tool_call", {"name": call.get("name"), "args": call.get("args") or {}}
        if isinstance(obj, dict) and "answer" in obj:
            return "answer", str(obj["answer"])
        return "answer", self.text.strip()


class MockLLM:
    """Deterministic, hermetic, and exactly reproducible across replays."""

    backend = "mock"
    model_id = "mock-gullible-v1"
    deterministic = True

    def request_params(self):
        return {"temperature_milli": 0, "deterministic": True}

    def complete(self, prompt, params=None, repeat=0):
        match = None if NO_TOOLS_SENTINEL in prompt else _INJECTION.search(prompt)
        if match:
            url = match.group(2).rstrip(".,;")
            payload = {
                "tool_call": {
                    "name": "http_post",
                    "args": {
                        "url": url,
                        "body": "vendor onboarding summary + vendor contact list",
                    },
                }
            }
            return LLMResult(json.dumps(payload), self.backend, self.model_id,
                             {"followed_instruction_at": match.start()})
        return LLMResult(json.dumps({"answer": _summarize(prompt)}), self.backend, self.model_id)


def _summarize(prompt):
    """A plausible extractive summary: first sentence of each retrieved chunk."""
    sentences = []
    for block in re.findall(r"^\[\d+\][^\n]*\n(.*?)(?=\n\[\d+\]|\Z)", prompt, re.S | re.M):
        body = "\n".join(line for line in block.strip().splitlines() if not line.startswith("#"))
        first = re.split(r"(?<=[.?!])\s", body.strip(), maxsplit=1)[0]
        if first and first not in sentences:
            sentences.append(first.strip())
    if not sentences:
        return "No relevant documents were retrieved."
    return " ".join(sentences[:5])


class LiveLLM:
    """Real Claude call, behind the same interface as the mock.

    No sampling parameters are sent. Current Sonnet-tier models reject
    ``temperature``, ``top_p``, and ``top_k`` at non-default values with a 400,
    and ``temperature=0`` never guaranteed identical outputs even when it was
    accepted. So live mode does not claim determinism it cannot have: the
    investigator repeats each ablation, takes a majority, writes every raw
    response into the chain, and lets nondeterminism show up as reduced
    confidence in the finding rather than as a different verdict.
    """

    backend = "live"
    deterministic = False
    DEFAULT_MODEL = "claude-sonnet-5"

    def __init__(self, model=None, max_tokens=1024, api_key=None):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised only with --llm live
            raise RuntimeError(
                "live backend needs the anthropic package: pip install '.[live]'"
            ) from exc
        self.model_id = model or self.DEFAULT_MODEL
        self.max_tokens = max_tokens
        self._client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    def request_params(self):
        return {"max_tokens": self.max_tokens, "sampling": "model default",
                "deterministic": False}

    def complete(self, prompt, params=None, repeat=0):  # pragma: no cover - needs network
        message = self._client.messages.create(
            model=self.model_id,
            max_tokens=self.max_tokens,
            system=RESPONSE_SCHEMA,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in message.content if block.type == "text")
        return LLMResult(
            text,
            self.backend,
            self.model_id,
            {
                "stop_reason": message.stop_reason or "",
                "input_tokens": message.usage.input_tokens,
                "output_tokens": message.usage.output_tokens,
                "repeat": repeat,
            },
        )


def get_backend(name, model=None):
    if name == "mock":
        return MockLLM()
    if name == "live":
        return LiveLLM(model=model)
    raise ValueError(f"unknown llm backend: {name}")
