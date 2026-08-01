#!/usr/bin/env python3
"""Standalone flight-recorder verifier.

    python verify_episode.py episode/        ->  GREEN (exit 0) / RED (exit 1)

One file, one dependency (dilithium-py), one trust input: the 32-byte anchor in
``episode/anchor.pub``. No network, no private keys, no database.

This deliberately imports nothing from ``fr/``. It is an independent
reimplementation of the record format, which is itself a feature: two
implementations that must agree byte-for-byte turn spec ambiguity into a test
failure instead of a courtroom argument.
"""

import argparse
import base64
import hashlib
import json
import os
import sys

from dilithium_py.ml_dsa import ML_DSA_65

ZERO = "0" * 64
INT64 = (-(2**63), 2**63 - 1)
PK_LEN, SIG_LEN = 1952, 3309
BODY_FIELDS = {"v", "episode", "seq", "ts_ns", "prev", "next_pk", "type", "actor", "payload"}
TYPES = {
    "GENESIS", "USER_INPUT", "RETRIEVAL", "LLM_CALL", "LLM_RESPONSE", "TOOL_CALL",
    "TOOL_RESULT", "POLICY_VIOLATION", "AGENT_FINAL", "INVESTIGATION_OPEN",
    "REPLAY_RUN", "ATTRIBUTION_FINDING", "ANCHOR", "SEAL",
}


class Fail(Exception):
    """A named verification failure: reason code, location, conflicting values."""

    def __init__(self, code, detail, seq=None, path=None, expected=None, got=None):
        super().__init__(code)
        self.code, self.detail, self.seq, self.path = code, detail, seq, path
        self.expected, self.got = expected, got


def sha3(data):
    return hashlib.sha3_256(data).hexdigest()


def hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


# --- canonical JSON: keys sorted by code point, "," and ":", UTF-8, integers only

def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Fail("SCHEMA_INVALID", f"duplicate object key {key!r}")
        out[key] = value
    return out


def _no_float(text):
    raise Fail("SCHEMA_INVALID", f"float or JSON constant {text!r} is banned")


def parse(text):
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_float=_no_float,
                          parse_constant=_no_float)
    except json.JSONDecodeError as exc:
        raise Fail("SCHEMA_INVALID", f"not valid JSON: {exc}") from exc


def canonical(value):
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        # A lone surrogate parses but has no UTF-8 encoding, so no two
        # implementations could ever agree on the bytes to sign.
        raise Fail("CANON_UNSTABLE", f"body is not encodable as UTF-8: {exc}") from exc


def canonical_stable(body):
    once = canonical(body)
    if canonical(parse(once.decode("utf-8"))) != once:
        raise Fail("CANON_UNSTABLE", "canonical form is not idempotent")
    return once


def check_values(value, path="$"):
    if isinstance(value, float):
        raise Fail("SCHEMA_INVALID", f"{path}: float present")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if not INT64[0] <= value <= INT64[1]:
            raise Fail("SCHEMA_INVALID", f"{path}: integer out of int64 range")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            check_values(item, f"{path}[{i}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            check_values(item, f"{path}.{key}")
    else:
        raise Fail("SCHEMA_INVALID", f"{path}: unsupported type {type(value).__name__}")


# --- per-record checks

def check_schema(body):
    got = set(body) if isinstance(body, dict) else set()
    if got != BODY_FIELDS:
        raise Fail("SCHEMA_INVALID", f"body fields missing={sorted(BODY_FIELDS - got)} "
                                     f"unknown={sorted(got - BODY_FIELDS)}")
    if body["v"] != 1:
        raise Fail("SCHEMA_INVALID", f"unsupported record version {body['v']!r}")
    if body["type"] not in TYPES:
        raise Fail("SCHEMA_INVALID", f"unknown record type {body['type']!r}")
    for field in ("seq", "ts_ns"):
        if isinstance(body[field], bool) or not isinstance(body[field], int) or body[field] < 0:
            raise Fail("SCHEMA_INVALID", f"{field} must be a non-negative integer")
    for field in ("prev", "next_pk"):
        if not hex64(body[field]):
            raise Fail("SCHEMA_INVALID", f"{field} must be 64 lowercase hex characters")
    for field in ("episode", "actor"):
        if not isinstance(body[field], str) or not body[field]:
            raise Fail("SCHEMA_INVALID", f"{field} must be a non-empty string")
    if not isinstance(body["payload"], dict):
        raise Fail("SCHEMA_INVALID", "payload must be an object")
    if (body["seq"] == 0) != (body["type"] == "GENESIS"):
        raise Fail("SCHEMA_INVALID", "GENESIS must be, and must only be, record 0")
    if body["seq"] == 0 and body["prev"] != ZERO:
        raise Fail("SCHEMA_INVALID", "record 0 prev must be 64 zeros")
    check_values(body)


def check_sig_block(sig):
    if not isinstance(sig, dict) or set(sig) != {"alg", "pk", "value"}:
        raise Fail("SCHEMA_INVALID", "sig must have exactly alg, pk, value")
    if sig["alg"] != "ML-DSA-65":
        raise Fail("SCHEMA_INVALID", f"unsupported signature algorithm {sig['alg']!r}")
    try:
        pk = base64.b64decode(sig["pk"], validate=True)
        value = base64.b64decode(sig["value"], validate=True)
    except Exception as exc:
        raise Fail("SCHEMA_INVALID", f"sig is not valid base64: {exc}") from exc
    if (len(pk), len(value)) != (PK_LEN, SIG_LEN):
        raise Fail("SCHEMA_INVALID", f"ML-DSA-65 sizes wrong: pk={len(pk)} sig={len(value)}")
    return pk, value


def check_blobs(payload, root):
    """Large payloads live out of line, referenced by hash. Re-hash every one."""
    stack = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
            continue
        if not isinstance(node, dict):
            continue
        stack.extend(node.values())
        digest = node.get("blob_sha3")
        if not isinstance(digest, str):
            continue
        if not hex64(digest):
            raise Fail("SCHEMA_INVALID", "blob_sha3 must be 64 lowercase hex characters")
        path = os.path.join(root, "blobs", digest + ".bin")
        if not os.path.exists(path):
            raise Fail("BLOB_HASH_MISMATCH", f"referenced blob is missing: blobs/{digest}.bin",
                       expected=digest, got="<absent>")
        with open(path, "rb") as fh:
            data = fh.read()
        if sha3(data) != digest:
            raise Fail("BLOB_HASH_MISMATCH", f"blobs/{digest}.bin content was swapped",
                       expected=digest, got=sha3(data))
        if "blob_len" in node and node["blob_len"] != len(data):
            raise Fail("BLOB_HASH_MISMATCH", f"blobs/{digest}.bin length changed",
                       expected=node["blob_len"], got=len(data))


def committed_hash(records_dir, files, index):
    """What the *next* record says this body hashed to, if it is readable."""
    if index + 1 >= len(files):
        return None
    try:
        with open(os.path.join(records_dir, files[index + 1]), "r", encoding="utf-8") as fh:
            return json.load(fh)["body"]["prev"] + "  per the next record"
    except Exception:
        return None


# --- the walk

def verify(root):
    """Return a summary dict, or raise Fail with a named reason code."""
    anchor_path = os.path.join(root, "anchor.pub")
    if not os.path.isfile(anchor_path):
        raise Fail("ANCHOR_MISMATCH", "anchor.pub is missing: there is no trust input",
                   path=anchor_path)
    with open(anchor_path, "r", encoding="ascii") as fh:
        anchor = fh.read().strip()
    if not hex64(anchor):
        raise Fail("ANCHOR_MISMATCH", "anchor.pub is not 64 lowercase hex characters",
                   path=anchor_path)

    records_dir = os.path.join(root, "records")
    files = sorted(f for f in os.listdir(records_dir)
                   if f.endswith(".json")) if os.path.isdir(records_dir) else []
    if not files:
        raise Fail("TRUNCATED_TAIL", "no records found", path=records_dir)

    expect_pk_hash, prev_hash, episode, last_ts = anchor, ZERO, None, -1
    seen, bodies, pending_seal = {}, [], None

    for index, name in enumerate(files):
        path = os.path.join(records_dir, name)
        with open(path, "rb") as fh:
            raw = fh.read()
        try:
            entry = parse(raw.decode("utf-8"))
            if not isinstance(entry, dict) or set(entry) != {"body", "sig"}:
                raise Fail("SCHEMA_INVALID", "record must have exactly body and sig")
            body = entry["body"]
            check_schema(body)
            message = canonical_stable(body)
            pk, signature = check_sig_block(entry["sig"])
            seq = body["seq"]

            if seq in seen:
                raise Fail("DUPLICATE_SEQ", f"seq {seq} was already claimed by {seen[seq]}",
                           expected=index, got=seq)
            if seq != index:
                raise Fail("SEQUENCE_GAP", f"expected seq {index} at position {index}",
                           expected=index, got=seq)
            if episode is None:
                episode = body["episode"]
            elif body["episode"] != episode:
                raise Fail("EPISODE_MISMATCH", "record belongs to a different episode",
                           expected=episode, got=body["episode"])
            if body["ts_ns"] <= last_ts:
                raise Fail("TIMESTAMP_REGRESSION", "ts_ns did not advance",
                           expected=f">{last_ts}", got=body["ts_ns"])

            if sha3(pk) != expect_pk_hash:
                raise Fail(
                    "ANCHOR_MISMATCH" if index == 0 else "RATCHET_MISMATCH",
                    "record 0's public key does not match anchor.pub" if index == 0 else
                    "signing key is not the one committed by the previous record",
                    expected=expect_pk_hash, got=sha3(pk))
            if not ML_DSA_65.verify(pk, message, signature):
                # The next record's `prev` is a signed commitment to what this
                # body was supposed to hash to, which makes the edit legible.
                raise Fail("SIGNATURE_INVALID", "signature does not cover these body bytes",
                           expected=committed_hash(records_dir, files, index)
                           or "the body these bytes were signed over",
                           got=sha3(message) + "  as it is now")
            if body["prev"] != prev_hash:
                raise Fail("CHAIN_BREAK", "prev does not name the preceding record",
                           expected=prev_hash, got=body["prev"])

            check_blobs(body["payload"], root)

            # An intermediate SEAL is legal only when an INVESTIGATION_OPEN naming
            # that sealed head follows it immediately. One chain, one ratchet.
            if pending_seal is not None:
                if body["type"] != "INVESTIGATION_OPEN":
                    raise Fail("SEAL_MISPLACED",
                               f"SEAL at seq {pending_seal['seq']} is followed by "
                               f"{body['type']}, not INVESTIGATION_OPEN",
                               expected="INVESTIGATION_OPEN", got=body["type"])
                if body["payload"].get("parent_head") != pending_seal["payload"]["head_hash"]:
                    raise Fail("SEAL_MISPLACED",
                               "INVESTIGATION_OPEN does not name the sealed head",
                               expected=pending_seal["payload"]["head_hash"],
                               got=body["payload"].get("parent_head"))
                pending_seal = None

            if body["type"] == "SEAL":
                seal = body["payload"]
                if not all(field in seal for field in ("count", "head_hash", "reason")):
                    raise Fail("SCHEMA_INVALID", "SEAL payload needs count, head_hash, reason")
                if seal["count"] != seq + 1:
                    raise Fail("TRUNCATED_TAIL", "SEAL count disagrees with the records present",
                               expected=seq + 1, got=seal["count"])
                if seal["head_hash"] != prev_hash:
                    raise Fail("CHAIN_BREAK", "SEAL head_hash does not name the sealed head",
                               expected=prev_hash, got=seal["head_hash"])
                pending_seal = body

            seen[seq] = name
            expect_pk_hash, prev_hash, last_ts = body["next_pk"], sha3(message), body["ts_ns"]
            bodies.append(body)
        except Fail as fail:
            fail.seq = index if fail.seq is None else fail.seq
            fail.path = path if fail.path is None else fail.path
            raise

    # Tail truncation is the classic hole: chop the last k records and the rest
    # still verifies. The mandatory terminal SEAL and its count are the answer.
    last, last_path = bodies[-1], os.path.join(records_dir, files[-1])
    if last["type"] != "SEAL":
        raise Fail("TRUNCATED_TAIL", "the final record is not a SEAL: the tail was chopped",
                   seq=last["seq"], path=last_path, expected="SEAL", got=last["type"])
    if last["payload"]["count"] != len(files):
        raise Fail("TRUNCATED_TAIL", "SEAL count disagrees with the number of record files",
                   seq=last["seq"], path=last_path,
                   expected=last["payload"]["count"], got=len(files))
    return {"episode": episode, "count": len(files), "head_hash": prev_hash, "anchor": anchor,
            "seals": [b["seq"] for b in bodies if b["type"] == "SEAL"],
            "types": [b["type"] for b in bodies], "bodies": bodies}


# --- CLI

def _c(text, code, on):
    return f"\033[{code}m{text}\033[0m" if on else text


def _short(value):
    text = str(value)
    return text if len(text) <= 88 else text[:85] + "..."


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify a flight-recorder episode.")
    ap.add_argument("episode", help="path to the episode directory")
    ap.add_argument("--dump", action="store_true", help="print seq/type/prev for every record")
    ap.add_argument("--quiet", action="store_true", help="print only GREEN or the RED reason")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)
    color = not args.no_color and sys.stdout.isatty()

    try:
        summary = verify(args.episode)
    except Fail as fail:
        print(_c(f"  RED - {fail.code}", "1;31", color))
        print(f"    {fail.detail}")
        if fail.seq is not None:
            print(f"    record   {fail.seq}   {fail.path or ''}".rstrip())
        elif fail.path:
            print(f"    file     {fail.path}")
        if fail.expected is not None or fail.got is not None:
            print(f"    expected {_short(fail.expected)}")
            print(f"    got      {_short(fail.got)}")
        return 1

    if args.dump:
        for body in summary["bodies"]:
            print(f"  {body['seq']:>4}  {body['type']:<20} prev={body['prev'][:12]}  {body['actor']}")
    if not args.quiet:
        seals = ", ".join(str(s) for s in summary["seals"])
        print(f"  {summary['count']} records - ML-DSA-65 - ratchet OK - sealed at [{seals}]")
        print(f"  episode  {summary['episode']}")
        print(f"  anchor   {summary['anchor'][:32]}...")
        print(f"  head     {summary['head_hash'][:32]}...")
    print(_c("  GREEN - chain intact", "1;32", color))
    return 0


if __name__ == "__main__":
    sys.exit(main())
