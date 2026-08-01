"""Corpus hash to file name resolution for inspect_cli.

The rest of the tool is layout, checked by eye. This is the part with a wrong
answer available: naming the wrong document, or naming one it cannot know.
"""

from verifier.inspect_cli import annotate, corpus_map

from .vectors import canon, h


def test_corpus_map_resolves_chunk_hashes_to_file_names(tmp_path):
    (tmp_path / "doc_00.md").write_text("a clean document", encoding="utf-8")
    (tmp_path / "doc_07.md").write_text("a poisoned document", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not part of the corpus", encoding="utf-8")

    mapping = corpus_map(tmp_path)

    assert mapping == {
        h(canon("a clean document")): "doc_00.md",
        h(canon("a poisoned document")): "doc_07.md",
    }

    poisoned = h(canon("a poisoned document"))
    assert annotate(poisoned, mapping) == f"{poisoned[:8]}... (= doc_07.md)"

    unknown = h(canon("a document this corpus does not have"))
    assert annotate(unknown, mapping) == f"{unknown[:8]}..."
