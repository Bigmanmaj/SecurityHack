"""Model access: a content-addressed response cache, the Anthropic client, and
a fake for tests and offline runs.

The cache is not an optimisation. Attribution by ablation only means anything if
a replay of the same request returns the same response, so every call is keyed
by `sha3_256_hex(canonical_bytes({"model", "messages", "tools"}))` and the raw
response dict is stored at `<cache_dir>/<key>.json`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from .canonical import canonical_bytes, sha3_256_hex

__all__ = [
    "cache_key",
    "ResponseCache",
    "AnthropicLLM",
    "FakeLLM",
    "make_text_response",
    "make_tool_use_response",
    "split_system",
    "DEFAULT_MODEL",
    "DEFAULT_CACHE_DIR",
]

DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
DEFAULT_CACHE_DIR = ".cache"
MAX_TOKENS = 1024
TEMPERATURE = 0.0

Message = dict[str, Any]
Tool = dict[str, Any]
Response = dict[str, Any]


def cache_key(model: str, messages: Sequence[Message], tools: Sequence[Tool]) -> str:
    return sha3_256_hex(
        canonical_bytes({"model": model, "messages": list(messages), "tools": list(tools)})
    )


def split_system(messages: Sequence[Message]) -> tuple[str | None, list[Message]]:
    """Split a leading `{"role": "system"}` entry off the conversation.

    Our wire format keeps the system prompt inside `messages` so that it is
    covered by the cache key; the Anthropic API takes it as its own parameter.
    """
    conversation = [dict(message) for message in messages]
    system: str | None = None
    if conversation and conversation[0].get("role") == "system":
        system = conversation.pop(0)["content"]
    if any(message.get("role") == "system" for message in conversation):
        raise ValueError("a system message may only appear first")
    return system, conversation


def make_text_response(text: str, model: str = DEFAULT_MODEL) -> Response:
    return {
        "type": "message",
        "role": "assistant",
        "model": model,
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": text}],
    }


def make_tool_use_response(
    name: str,
    arguments: dict[str, Any],
    tool_use_id: str | None = None,
    text: str | None = None,
    model: str = DEFAULT_MODEL,
) -> Response:
    content: list[dict[str, Any]] = []
    if text:
        content.append({"type": "text", "text": text})
    content.append(
        {
            "type": "tool_use",
            "id": tool_use_id or f"toolu_{sha3_256_hex(canonical_bytes([name, arguments]))[:16]}",
            "name": name,
            "input": arguments,
        }
    )
    return {
        "type": "message",
        "role": "assistant",
        "model": model,
        "stop_reason": "tool_use",
        "content": content,
    }


class ResponseCache:
    """JSON files named by the hash of the request that produced them."""

    def __init__(self, cache_dir: str | Path = DEFAULT_CACHE_DIR) -> None:
        self.dir = Path(cache_dir)

    def path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def get(self, key: str) -> Response | None:
        target = self.path(key)
        if not target.exists():
            return None
        return json.loads(target.read_text(encoding="utf-8"))

    def put(self, key: str, response: Response) -> Path:
        self.dir.mkdir(parents=True, exist_ok=True)
        target = self.path(key)
        target.write_text(json.dumps(response, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return target


class AnthropicLLM:
    """Cached Claude client.

    `_remote` is the only method that touches the network; tests and the offline
    stand-in model replace exactly that method.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        cache_dir: str | Path = DEFAULT_CACHE_DIR,
        max_tokens: int = MAX_TOKENS,
    ) -> None:
        self.model = model
        self.cache = ResponseCache(cache_dir)
        self.max_tokens = max_tokens
        self.hits = 0
        self.misses = 0
        self._client: Any = None

    def call(self, messages: Sequence[Message], tools: Sequence[Tool]) -> Response:
        key = cache_key(self.model, messages, tools)
        cached = self.cache.get(key)
        if cached is not None:
            self.hits += 1
            return cached

        self.misses += 1
        response = self._remote(list(messages), list(tools))
        self.cache.put(key, response)
        return response

    def _remote(self, messages: list[Message], tools: list[Tool]) -> Response:
        import anthropic

        if self._client is None:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "ANTHROPIC_API_KEY is not set: no cached response for this request "
                    "and no way to fetch one"
                )
            self._client = anthropic.Anthropic(api_key=api_key)

        system, conversation = split_system(messages)
        request: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": TEMPERATURE,
            "messages": conversation,
        }
        if system is not None:
            request["system"] = system
        if tools:
            request["tools"] = tools

        message = self._client.messages.create(**request)
        return json.loads(message.model_dump_json())


class FakeLLM:
    """Offline model for tests and for driving the pipeline without an API key.

    `scripted` is either a sequence of responses (each a response dict or a
    `(messages, tools) -> response` callable, consumed in order) or a single
    callable used for every call. Every call is recorded in `self.calls`.
    """

    def __init__(
        self,
        scripted: Iterable[Response | Callable[..., Response]] | Callable[..., Response],
    ) -> None:
        if callable(scripted):
            self._responder: Callable[..., Response] | None = scripted
            self._queue: list[Response | Callable[..., Response]] = []
        else:
            self._responder = None
            self._queue = list(scripted)
        self.calls: list[dict[str, Any]] = []

    @property
    def remaining(self) -> int:
        return len(self._queue)

    def call(self, messages: Sequence[Message], tools: Sequence[Tool]) -> Response:
        self.calls.append({"messages": list(messages), "tools": list(tools)})

        if self._responder is not None:
            return self._responder(list(messages), list(tools))
        if not self._queue:
            raise RuntimeError(
                f"FakeLLM script exhausted after {len(self.calls) - 1} responses"
            )
        nxt = self._queue.pop(0)
        return nxt(list(messages), list(tools)) if callable(nxt) else nxt
