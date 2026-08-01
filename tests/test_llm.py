import json
from types import SimpleNamespace

import pytest

from flightrec.canonical import canonical_bytes, sha3_256_hex
from flightrec.llm import (
    AnthropicLLM,
    FakeLLM,
    cache_key,
    make_text_response,
    make_tool_use_response,
    split_system,
)

MESSAGES = [{"role": "user", "content": "I want a refund on my last payment"}]
TOOLS = [{"name": "lookup_account", "description": "look up an account", "input_schema": {}}]


@pytest.fixture
def counting_remote(monkeypatch):
    """Replace the only method that touches the network, and count calls."""
    calls = []

    def _remote(self, messages, tools):
        calls.append({"messages": messages, "tools": tools})
        return make_text_response(f"response {len(calls)}")

    monkeypatch.setattr(AnthropicLLM, "_remote", _remote)
    return calls


def test_cache_key_is_the_hash_of_the_canonical_request():
    key = cache_key("claude-test", MESSAGES, TOOLS)

    expected = sha3_256_hex(
        canonical_bytes({"model": "claude-test", "messages": MESSAGES, "tools": TOOLS})
    )
    assert key == expected


def test_cache_key_ignores_key_order_but_not_content():
    assert cache_key("m", [{"role": "user", "content": "a"}], TOOLS) == cache_key(
        "m", [{"content": "a", "role": "user"}], TOOLS
    )
    assert cache_key("m", MESSAGES, TOOLS) != cache_key("other-model", MESSAGES, TOOLS)
    assert cache_key("m", MESSAGES, TOOLS) != cache_key("m", MESSAGES, [])


def test_miss_calls_remote_once_and_writes_the_cache_file(tmp_path, counting_remote):
    llm = AnthropicLLM("claude-test", cache_dir=tmp_path)

    response = llm.call(MESSAGES, TOOLS)

    assert len(counting_remote) == 1
    cached = tmp_path / f"{cache_key('claude-test', MESSAGES, TOOLS)}.json"
    assert cached.exists()
    assert json.loads(cached.read_text()) == response


def test_second_identical_call_is_served_from_cache(tmp_path, counting_remote):
    llm = AnthropicLLM("claude-test", cache_dir=tmp_path)

    first = llm.call(MESSAGES, TOOLS)
    second = llm.call(MESSAGES, TOOLS)

    assert len(counting_remote) == 1
    assert second == first
    assert llm.hits == 1 and llm.misses == 1


def test_a_fresh_instance_reuses_the_cache_on_disk(tmp_path, counting_remote):
    AnthropicLLM("claude-test", cache_dir=tmp_path).call(MESSAGES, TOOLS)
    reopened = AnthropicLLM("claude-test", cache_dir=tmp_path).call(MESSAGES, TOOLS)

    assert len(counting_remote) == 1
    assert reopened["content"][0]["text"] == "response 1"


def test_different_inputs_get_different_cache_entries(tmp_path, counting_remote):
    llm = AnthropicLLM("claude-test", cache_dir=tmp_path)

    llm.call(MESSAGES, TOOLS)
    llm.call([{"role": "user", "content": "different context"}], TOOLS)

    assert len(counting_remote) == 2
    assert len(list(tmp_path.glob("*.json"))) == 2


def test_removing_one_corpus_chunk_changes_the_cache_key():
    """Ablation replays must miss the cache the first time, not reuse the baseline."""
    full = [{"role": "user", "content": "doc_a\ndoc_b\ndoc_c"}]
    ablated = [{"role": "user", "content": "doc_a\ndoc_c"}]

    assert cache_key("m", full, TOOLS) != cache_key("m", ablated, TOOLS)


def test_a_system_message_is_part_of_the_cache_key():
    with_system = [{"role": "system", "content": "you are a support agent"}, *MESSAGES]

    assert cache_key("m", with_system, TOOLS) != cache_key("m", MESSAGES, TOOLS)


def test_split_system_lifts_a_leading_system_message_out():
    system, conversation = split_system(
        [{"role": "system", "content": "be helpful"}, *MESSAGES]
    )

    assert system == "be helpful"
    assert conversation == MESSAGES

    with pytest.raises(ValueError, match="only appear first"):
        split_system([*MESSAGES, {"role": "system", "content": "late"}])


def test_remote_sends_temperature_zero_and_the_system_prompt_separately(tmp_path):
    """The live request shape, exercised without a network call."""
    sent = {}

    class FakeMessages:
        def create(self, **request):
            sent.update(request)
            return SimpleNamespace(
                model_dump_json=lambda: json.dumps(make_text_response("hi"))
            )

    llm = AnthropicLLM("claude-test", cache_dir=tmp_path)
    llm._client = SimpleNamespace(messages=FakeMessages())

    response = llm.call([{"role": "system", "content": "be helpful"}, *MESSAGES], TOOLS)

    assert sent["temperature"] == 0.0
    assert sent["system"] == "be helpful"
    assert sent["messages"] == MESSAGES
    assert sent["tools"] == TOOLS
    assert response["content"][0]["text"] == "hi"
    assert (tmp_path / f"{cache_key('claude-test', [{'role': 'system', 'content': 'be helpful'}, *MESSAGES], TOOLS)}.json").exists()


def test_remote_without_an_api_key_explains_itself(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    llm = AnthropicLLM("claude-test", cache_dir=tmp_path)

    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        llm.call(MESSAGES, TOOLS)


def test_fake_llm_returns_scripted_responses_and_records_what_it_was_asked():
    scripted = [
        make_tool_use_response("lookup_account", {"workspace_id": "NB-000123"}),
        make_text_response("Your last payment was $15."),
    ]
    llm = FakeLLM(scripted)

    first = llm.call(MESSAGES, TOOLS)
    second = llm.call([*MESSAGES, {"role": "user", "content": "and then?"}], TOOLS)

    assert first["content"][0]["name"] == "lookup_account"
    assert second["content"][0]["text"] == "Your last payment was $15."
    assert len(llm.calls) == 2
    assert llm.calls[0]["messages"] == MESSAGES
    assert llm.calls[1]["tools"] == TOOLS


def test_fake_llm_raises_when_the_script_runs_out():
    llm = FakeLLM([make_text_response("only one")])
    llm.call(MESSAGES, TOOLS)

    with pytest.raises(RuntimeError, match="exhausted"):
        llm.call(MESSAGES, TOOLS)


def test_fake_llm_accepts_a_responder_for_context_dependent_behaviour():
    def responder(messages, tools):
        seen = json.dumps(messages)
        if "ACC-999" in seen:
            return make_tool_use_response("transfer_funds", {"to": "ACC-999"})
        return make_text_response("I have logged your refund request.")

    llm = FakeLLM(responder)

    poisoned = llm.call([{"role": "user", "content": "send it to ACC-999"}], TOOLS)
    clean = llm.call(MESSAGES, TOOLS)

    assert poisoned["content"][0]["name"] == "transfer_funds"
    assert clean["stop_reason"] == "end_turn"
    assert len(llm.calls) == 2


def test_fake_llm_never_reaches_the_network(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("FakeLLM must not touch the network")

    monkeypatch.setattr(AnthropicLLM, "_remote", explode)

    assert FakeLLM([make_text_response("ok")]).call(MESSAGES, TOOLS)["stop_reason"] == "end_turn"
