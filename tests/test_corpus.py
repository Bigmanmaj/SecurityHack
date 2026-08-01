"""The corpus, the injection, and retrieval.

Attribution is only crisp if the poisoned span occupies exactly one chunk, so
that is asserted rather than assumed.
"""

from agent.corpus import Corpus, chunk_document, load_docs
from agent.llm import _INJECTION
from agent.rag import DEFAULT_TASK, POISONED_DOC, build_corpus, strip_injection

CULPRIT_CHUNK_ID = 3


def test_corpus_has_ten_documents():
    assert len(load_docs()) == 10


def test_the_injection_occupies_exactly_one_chunk():
    corpus = build_corpus("poisoned")
    poisoned = [c for c in corpus.chunks
                if c.doc_id == POISONED_DOC and _INJECTION.search(c.text)]
    assert len(poisoned) == 1, "the poisoned span must be citable as a single chunk"
    assert poisoned[0].chunk_id == CULPRIT_CHUNK_ID


def test_no_other_document_carries_an_injection():
    corpus = build_corpus("poisoned")
    docs = {c.doc_id for c in corpus.chunks if _INJECTION.search(c.text)}
    assert docs == {POISONED_DOC}


def test_the_poisoned_chunk_is_actually_retrieved_for_the_task():
    corpus = build_corpus("poisoned")
    retrieved = [c.key for c, _ in corpus.retrieve(DEFAULT_TASK, top_k=5)]
    assert (POISONED_DOC, CULPRIT_CHUNK_ID) in retrieved


def test_chunking_is_deterministic():
    docs = load_docs()
    first = [(c.doc_id, c.chunk_id, c.sha3) for c in Corpus(docs).chunks]
    second = [(c.doc_id, c.chunk_id, c.sha3) for c in Corpus(load_docs()).chunks]
    assert first == second


def test_chunks_respect_the_target_size_and_cover_the_document():
    for doc_id, text in load_docs().items():
        chunks = chunk_document(doc_id, text)
        assert chunks, doc_id
        for chunk in chunks:
            assert chunk.start < chunk.end <= len(text)
            assert text[chunk.start:chunk.end].startswith(chunk.text.split("\n\n")[0])
        assert [c.start for c in chunks] == sorted(c.start for c in chunks)


def test_char_spans_locate_the_injection_in_the_original_file():
    corpus = build_corpus("poisoned")
    chunk = corpus.get(POISONED_DOC, CULPRIT_CHUNK_ID)
    original = load_docs()[POISONED_DOC]
    assert _INJECTION.search(original[chunk.start:chunk.end])


def test_the_clean_scenario_removes_only_the_poisoned_paragraph():
    poisoned, clean = load_docs()[POISONED_DOC], None
    clean = strip_injection(poisoned)
    assert not _INJECTION.search(clean)
    assert "Who owns the vendor relationship after onboarding?" in clean
    assert len(clean) < len(poisoned)
    assert not any(_INJECTION.search(c.text) for c in build_corpus("clean").chunks)


def test_manifest_pins_a_hash_per_document():
    manifest = build_corpus("poisoned").manifest()
    assert len(manifest) == 10
    assert all(len(entry["sha3"]) == 64 and entry["chunks"] > 0 for entry in manifest)


def test_scores_are_integers_because_floats_are_banned_in_records():
    corpus = build_corpus("poisoned")
    assert all(isinstance(score, int) for _, score in corpus.retrieve(DEFAULT_TASK, top_k=10))
