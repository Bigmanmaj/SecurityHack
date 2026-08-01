"""Corpus loading, deterministic chunking, and retrieval.

Everything here is a pure function of the files on disk. The investigator replays
against the same code, so any nondeterminism in retrieval would show up as an
unstable counterfactual rather than a wrong one -- but there is none: the scorer
is integer arithmetic over integer term counts.
"""

import math
import os
import re

from fr.hashes import sha3_hex

CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")
CHUNK_TARGET_CHARS = 400
DEFAULT_TOP_K = 5

_WORD = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    "a an and are as at be by for from how in is it of on or our that the their "
    "this to we what when which who will with your".split()
)


def tokenize(text):
    return [w for w in _WORD.findall(text.lower()) if w not in _STOPWORDS and len(w) > 1]


def load_docs(directory=CORPUS_DIR, exclude=()):
    docs = {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".md") or name in exclude:
            continue
        with open(os.path.join(directory, name), "r", encoding="utf-8") as fh:
            docs[name] = fh.read()
    return docs


class Chunk:
    """One retrievable span, citable by (doc_id, chunk_id, sha3, char span)."""

    __slots__ = ("doc_id", "chunk_id", "text", "start", "end", "sha3")

    def __init__(self, doc_id, chunk_id, text, start, end):
        self.doc_id = doc_id
        self.chunk_id = chunk_id
        self.text = text
        self.start = start
        self.end = end
        self.sha3 = sha3_hex(text.encode("utf-8"))

    @property
    def key(self):
        return (self.doc_id, self.chunk_id)

    def citation(self):
        return {
            "doc_id": self.doc_id,
            "chunk_id": self.chunk_id,
            "sha3": self.sha3,
            "char_span": [self.start, self.end],
        }

    def __repr__(self):
        return f"<Chunk {self.doc_id}#{self.chunk_id} chars {self.start}-{self.end}>"


def chunk_document(doc_id, text, target=CHUNK_TARGET_CHARS):
    """Split on paragraph boundaries, packing greedily up to ``target`` characters.

    Paragraph-aligned so a poisoned span occupies exactly one chunk, which is what
    keeps attribution crisp: the investigator can name a culprit by char offset.
    """
    paragraphs, offset = [], 0
    for para in text.split("\n\n"):
        stripped = para.strip()
        if not stripped:
            continue
        start = text.index(stripped, offset)
        paragraphs.append((stripped, start, start + len(stripped)))
        offset = start + len(stripped)

    groups, current = [], []
    for para in paragraphs:
        packed = sum(len(p[0]) for p in current) + 2 * max(0, len(current) - 1)
        if current and packed + 2 + len(para[0]) > target:
            groups.append(current)
            current = []
        current.append(para)
    if current:
        groups.append(current)

    return [
        Chunk(doc_id, i, "\n\n".join(p[0] for p in group), group[0][1], group[-1][2])
        for i, group in enumerate(groups)
    ]


class Corpus:
    def __init__(self, docs):
        self.docs = docs  # doc_id -> text, in sorted order
        self.chunks = []
        for doc_id in sorted(docs):
            self.chunks.extend(chunk_document(doc_id, docs[doc_id]))
        self._index = {c.key: c for c in self.chunks}
        self._df = {}
        for chunk in self.chunks:
            for term in set(tokenize(chunk.text)):
                self._df[term] = self._df.get(term, 0) + 1

    @classmethod
    def load(cls, directory=CORPUS_DIR, exclude=()):
        return cls(load_docs(directory, exclude))

    def get(self, doc_id, chunk_id):
        return self._index[(doc_id, chunk_id)]

    def manifest(self):
        return [
            {
                "doc_id": doc_id,
                "sha3": sha3_hex(self.docs[doc_id].encode("utf-8")),
                "bytes": len(self.docs[doc_id].encode("utf-8")),
                "chunks": sum(1 for c in self.chunks if c.doc_id == doc_id),
            }
            for doc_id in sorted(self.docs)
        ]

    def score_milli(self, query, chunk):
        """TF-IDF cosine-ish score in integer milli-units. Floats are banned in records."""
        q_terms = tokenize(query)
        if not q_terms:
            return 0
        counts = {}
        for term in tokenize(chunk.text):
            counts[term] = counts.get(term, 0) + 1
        if not counts:
            return 0
        total = len(self.chunks)
        score = 0.0
        norm = math.sqrt(sum(v * v for v in counts.values()))
        for term in set(q_terms):
            tf = counts.get(term, 0)
            if not tf:
                continue
            idf = math.log((total + 1) / (self._df.get(term, 0) + 1)) + 1.0
            score += tf * idf * idf
        return int(round(1000 * score / norm))

    def retrieve(self, query, top_k=DEFAULT_TOP_K):
        """Deterministic top-k. Ties break on (doc_id, chunk_id), never on dict order."""
        scored = [(self.score_milli(query, c), c) for c in self.chunks]
        scored.sort(key=lambda pair: (-pair[0], pair[1].doc_id, pair[1].chunk_id))
        return [(chunk, score) for score, chunk in scored[:top_k] if score > 0]
