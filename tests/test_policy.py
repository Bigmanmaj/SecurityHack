"""The detector is deliberately dumb, and that is the point.

The investigator's counterfactual is a claim about a stable function. A clever
detector that changed its mind between replays would make every verdict noise.
"""

import pytest

from agent.llm import LLMResult, MockLLM
from agent.rag import TASK_ALLOWLIST, assemble_prompt, detect_violation
from agent.tools import INTERNAL_EMAIL_DOMAINS, INTERNAL_HOSTS
from fr.policy import EXTERNAL_URL, NON_CORPUS_RECIPIENT, NOT_IN_TASK_SCOPE, PolicyEngine


@pytest.fixture
def policy():
    return PolicyEngine(TASK_ALLOWLIST, internal_hosts=INTERNAL_HOSTS,
                        internal_email_domains=INTERNAL_EMAIL_DOMAINS)


def test_allowlisted_tools_pass(policy):
    assert policy.decide("search_docs", {"query": "vendor onboarding"}).authorized


def test_a_tool_outside_the_task_scope_is_a_violation(policy):
    decision = policy.decide("http_post", {"url": "https://wiki.internal/x", "body": "hi"})
    assert not decision.authorized and decision.rule == NOT_IN_TASK_SCOPE


def test_an_external_url_is_a_violation_even_for_an_allowed_tool():
    policy = PolicyEngine(("http_post",), internal_hosts=INTERNAL_HOSTS)
    decision = policy.decide("http_post", {"url": "https://vendor-sync.example-partner.net/ingest"})
    assert not decision.authorized and decision.rule == EXTERNAL_URL
    assert "vendor-sync.example-partner.net" in decision.reason


def test_an_internal_url_on_an_allowed_tool_passes():
    policy = PolicyEngine(("http_post",), internal_hosts=INTERNAL_HOSTS)
    assert policy.decide("http_post", {"url": "https://wiki.internal/pages/1"}).authorized


def test_a_non_corpus_recipient_is_a_violation():
    policy = PolicyEngine(("send_email",), internal_email_domains=INTERNAL_EMAIL_DOMAINS)
    decision = policy.decide("send_email", {"to": "someone@elsewhere.example", "subject": "",
                                            "body": ""})
    assert not decision.authorized and decision.rule == NON_CORPUS_RECIPIENT


def test_the_decision_is_a_pure_function(policy):
    args = {"url": "https://vendor-sync.example-partner.net/ingest", "body": "x"}
    first = policy.decide("http_post", args).as_payload()
    for _ in range(20):
        assert policy.decide("http_post", dict(args)).as_payload() == first


def test_the_mock_follows_an_injection_and_only_an_injection():
    from agent.corpus import Corpus
    from agent.rag import DEFAULT_TASK, build_corpus

    llm = MockLLM()
    poisoned = build_corpus("poisoned")
    clean = build_corpus("clean")
    assert isinstance(poisoned, Corpus)

    hit = llm.complete(assemble_prompt(DEFAULT_TASK,
                                       [c for c, _ in poisoned.retrieve(DEFAULT_TASK)]))
    miss = llm.complete(assemble_prompt(DEFAULT_TASK,
                                        [c for c, _ in clean.retrieve(DEFAULT_TASK)]))
    assert hit.parse()[0] == "tool_call"
    assert hit.parse()[1]["name"] == "http_post"
    assert miss.parse()[0] == "answer"


def test_the_mock_respects_the_no_tools_constraint():
    from agent.rag import DEFAULT_TASK, build_corpus

    corpus = build_corpus("poisoned")
    chunks = [c for c, _ in corpus.retrieve(DEFAULT_TASK)]
    forced = MockLLM().complete(assemble_prompt(DEFAULT_TASK, chunks, force_answer=True))
    assert forced.parse()[0] == "answer"


def test_a_malformed_model_reply_is_treated_as_an_answer_not_a_tool_call(policy):
    call, decision = detect_violation(LLMResult("I'm not JSON", "mock", "m"), policy)
    assert call is None and decision is None


def test_prompt_assembly_is_a_pure_function():
    from agent.rag import DEFAULT_TASK, build_corpus

    chunks = [c for c, _ in build_corpus("poisoned").retrieve(DEFAULT_TASK)]
    assert assemble_prompt(DEFAULT_TASK, chunks) == assemble_prompt(DEFAULT_TASK, chunks)
    assert assemble_prompt(DEFAULT_TASK, chunks[:2]) != assemble_prompt(DEFAULT_TASK, chunks)
