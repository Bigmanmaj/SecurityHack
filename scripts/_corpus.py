"""Loading the retrieval corpus.

The order of the corpus is part of the evidence: `chunk_hashes` in the
`retrieval` record is written in corpus order, so loading is always by sorted
filename and never by directory iteration order.
"""

from __future__ import annotations

import sys
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parents[1] / "data" / "corpus"

Chunk = tuple[str, str]


def load_corpus(corpus_dir: str | Path = CORPUS_DIR) -> list[Chunk]:
    """Return [(doc_id, text)] in sorted filename order."""
    directory = Path(corpus_dir)
    paths = sorted(directory.glob("*.md"))
    if not paths:
        raise FileNotFoundError(f"no .md documents in {directory}")
    return [(path.stem, path.read_text(encoding="utf-8")) for path in paths]


def drop(corpus: list[Chunk], index: int) -> list[Chunk]:
    """The corpus with chunk `index` removed, order otherwise preserved."""
    return [chunk for position, chunk in enumerate(corpus) if position != index]


def main() -> int:
    corpus = load_corpus()
    for doc_id, text in corpus:
        print(f"{doc_id}  ({len(text)} chars)")
    print(f"{len(corpus)} documents")
    return 0


if __name__ == "__main__":
    sys.exit(main())
