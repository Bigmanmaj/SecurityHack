"""Shared test vectors and a minimal spec transcription.

This module imports neither the producer (`src/flightrec`) nor the verifier
(`verifier/`): it is a third, deliberately dumb transcription of SPEC.md §1 and
§4, so both implementations can be checked against the same constants, and so
tests can build bundles without borrowing either side's code.

`python -m tests.vectors` prints the table that appears in the spec.
"""

from __future__ import annotations

import hashlib
import json
from typing import Iterable, Sequence

__all__ = ["canon", "h", "leaf", "root", "signed_message", "payload_hash",
           "MERKLE_ROOTS", "CANON_VECTORS"]


def canon(obj: object) -> bytes:
    """SPEC §1 canonical bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def h(data: bytes) -> str:
    """SPEC §1 h_hex."""
    return hashlib.sha3_256(data).hexdigest()


def leaf(seq: int, payload_hash_hex: str) -> str:
    """SPEC §4.1."""
    return h(seq.to_bytes(8, "big") + bytes.fromhex(payload_hash_hex))


def root(entries: Iterable[Sequence]) -> str:
    """SPEC §4.2, promote-odd."""
    ordered = sorted((int(seq), str(digest)) for seq, digest in entries)
    if not ordered:
        return "0" * 64
    level = [leaf(seq, digest) for seq, digest in ordered]
    while len(level) > 1:
        parents = [
            h(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            parents.append(level[-1])
        level = parents
    return level[0]


def signed_message(record_type: str, payload: object, binding: str | None, signer: str) -> bytes:
    """SPEC §3.1 — note the absence of seq."""
    return canon({"binding": binding, "payload": payload, "signer": signer, "type": record_type})


def payload_hash(i: int) -> str:
    """The i-th sample payload hash used by the merkle vectors."""
    return h(canon({"i": i}))


#: merkle_root over the first n sample entries, for n = 1..4.
MERKLE_ROOTS = {n: root([(i, payload_hash(i)) for i in range(n)]) for n in range(1, 5)}

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
    for n, value in MERKLE_ROOTS.items():
        print(f"{n}: `{value}`")
    for i in range(4):
        print(f"payload_hash({i}) = {payload_hash(i)}")
