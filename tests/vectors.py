"""Shared test vectors, computed straight from the SPEC text.

This module imports neither the producer (`src/flightrec`) nor the verifier
(`verifier/`): it is a third, deliberately dumb transcription of §1 and §4 of
SPEC.md, written so that both implementations can be checked against the same
constants. `python -m tests.vectors` prints the table that appears in the spec.
"""

from __future__ import annotations

import hashlib
import json

__all__ = ["payload_hash", "MERKLE_ROOTS", "CANON_VECTORS"]


def _canon(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _h(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def payload_hash(i: int) -> str:
    """The i-th sample payload hash used by the merkle vectors."""
    return _h(_canon({"i": i}))


def _leaf(seq: int, payload_hash_hex: str) -> str:
    return _h(seq.to_bytes(8, "big") + bytes.fromhex(payload_hash_hex))


def _root(entries: list[tuple[int, str]]) -> str:
    if not entries:
        return "0" * 64
    level = [_leaf(seq, digest) for seq, digest in sorted(entries)]
    while len(level) > 1:
        nxt = []
        for index in range(0, len(level) - 1, 2):
            nxt.append(_h(bytes.fromhex(level[index]) + bytes.fromhex(level[index + 1])))
        if len(level) % 2:
            nxt.append(level[-1])  # promote-odd: carried up unchanged
        level = nxt
    return level[0]


#: merkle_root over the first n sample entries, for n = 1..4.
MERKLE_ROOTS = {n: _root([(i, payload_hash(i)) for i in range(n)]) for n in range(1, 5)}

#: (object, canonical bytes) pairs every implementation must agree on.
CANON_VECTORS = [
    ({}, b"{}"),
    ({"b": 1, "a": 2}, b'{"a":2,"b":1}'),
    ({"a": [1, 2, {"c": None, "b": True}]}, b'{"a":[1,2,{"b":true,"c":null}]}'),
    ({"k": "caf\u00e9 \u2014 \u00fc"}, '{"k":"café — ü"}'.encode("utf-8")),
    ({"n": -0, "big": 10**20}, b'{"big":100000000000000000000,"n":0}'),
    ([], b"[]"),
    ("plain", b'"plain"'),
]


if __name__ == "__main__":
    print("empty root:", "0" * 64)
    for n, root in MERKLE_ROOTS.items():
        print(f"{n}: `{root}`")
    for i in range(4):
        print(f"payload_hash({i}) = {payload_hash(i)}")
