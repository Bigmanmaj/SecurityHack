"""Record schema: the shape of a single line of evidence."""

from . import canon
from .hashes import HASH_HEX_LEN, ZERO_HASH

RECORD_VERSION = 1

GENESIS = "GENESIS"
USER_INPUT = "USER_INPUT"
RETRIEVAL = "RETRIEVAL"
LLM_CALL = "LLM_CALL"
LLM_RESPONSE = "LLM_RESPONSE"
TOOL_CALL = "TOOL_CALL"
TOOL_RESULT = "TOOL_RESULT"
POLICY_VIOLATION = "POLICY_VIOLATION"
AGENT_FINAL = "AGENT_FINAL"
INVESTIGATION_OPEN = "INVESTIGATION_OPEN"
REPLAY_RUN = "REPLAY_RUN"
ATTRIBUTION_FINDING = "ATTRIBUTION_FINDING"
ANCHOR = "ANCHOR"
SEAL = "SEAL"

RECORD_TYPES = (
    GENESIS,
    USER_INPUT,
    RETRIEVAL,
    LLM_CALL,
    LLM_RESPONSE,
    TOOL_CALL,
    TOOL_RESULT,
    POLICY_VIOLATION,
    AGENT_FINAL,
    INVESTIGATION_OPEN,
    REPLAY_RUN,
    ATTRIBUTION_FINDING,
    ANCHOR,
    SEAL,
)

BODY_FIELDS = ("v", "episode", "seq", "ts_ns", "prev", "next_pk", "type", "actor", "payload")

SEAL_REASONS = ("normal", "crash", "phase")

# A blob reference is any object carrying this key; the verifier walks payloads
# looking for it and re-hashes the file it names.
BLOB_REF_KEY = "blob_sha3"
BLOB_LEN_KEY = "blob_len"


def blob_ref(sha3_hex_digest, length):
    return {BLOB_REF_KEY: sha3_hex_digest, BLOB_LEN_KEY: length}


def make_body(episode, seq, ts_ns, prev, next_pk, type_, actor, payload):
    body = {
        "v": RECORD_VERSION,
        "episode": episode,
        "seq": seq,
        "ts_ns": ts_ns,
        "prev": prev,
        "next_pk": next_pk,
        "type": type_,
        "actor": actor,
        "payload": payload,
    }
    validate_body(body)
    return body


def _is_hex64(value):
    return (
        isinstance(value, str)
        and len(value) == HASH_HEX_LEN
        and all(c in "0123456789abcdef" for c in value)
    )


def validate_body(body):
    if not isinstance(body, dict):
        raise canon.SchemaError("body must be an object")
    missing = [f for f in BODY_FIELDS if f not in body]
    if missing:
        raise canon.SchemaError(f"body missing field(s): {', '.join(missing)}")
    extra = [f for f in body if f not in BODY_FIELDS]
    if extra:
        raise canon.SchemaError(f"body has unknown field(s): {', '.join(sorted(extra))}")
    if body["v"] != RECORD_VERSION:
        raise canon.SchemaError(f"unsupported record version: {body['v']!r}")
    if not isinstance(body["episode"], str) or not body["episode"]:
        raise canon.SchemaError("episode must be a non-empty string")
    if isinstance(body["seq"], bool) or not isinstance(body["seq"], int) or body["seq"] < 0:
        raise canon.SchemaError("seq must be a non-negative integer")
    if isinstance(body["ts_ns"], bool) or not isinstance(body["ts_ns"], int) or body["ts_ns"] < 0:
        raise canon.SchemaError("ts_ns must be a non-negative integer")
    if not _is_hex64(body["prev"]):
        raise canon.SchemaError("prev must be 64 lowercase hex characters")
    if not _is_hex64(body["next_pk"]):
        raise canon.SchemaError("next_pk must be 64 lowercase hex characters")
    if body["type"] not in RECORD_TYPES:
        raise canon.SchemaError(f"unknown record type: {body['type']!r}")
    if not isinstance(body["actor"], str) or not body["actor"]:
        raise canon.SchemaError("actor must be a non-empty string")
    if not isinstance(body["payload"], dict):
        raise canon.SchemaError("payload must be an object")
    if body["seq"] == 0:
        if body["type"] != GENESIS:
            raise canon.SchemaError("record 0 must be GENESIS")
        if body["prev"] != ZERO_HASH:
            raise canon.SchemaError("record 0 prev must be 64 zeros")
    elif body["type"] == GENESIS:
        raise canon.SchemaError("GENESIS is only legal at seq 0")
    if body["type"] == SEAL:
        validate_seal_payload(body)
    canon.validate(body)
    return body


def validate_seal_payload(body):
    payload = body["payload"]
    for field in ("count", "head_hash", "reason"):
        if field not in payload:
            raise canon.SchemaError(f"SEAL payload missing field: {field}")
    if payload["count"] != body["seq"] + 1:
        raise canon.SchemaError(
            f"SEAL count {payload['count']} != seq+1 {body['seq'] + 1}"
        )
    if not _is_hex64(payload["head_hash"]):
        raise canon.SchemaError("SEAL head_hash must be 64 lowercase hex characters")
    if payload["head_hash"] != body["prev"]:
        raise canon.SchemaError("SEAL head_hash must equal the sealed record's prev")
    if payload["reason"] not in SEAL_REASONS:
        raise canon.SchemaError(f"unknown SEAL reason: {payload['reason']!r}")


def iter_blob_refs(value):
    """Yield every blob reference object nested anywhere inside ``value``."""
    if isinstance(value, dict):
        if BLOB_REF_KEY in value:
            yield value
        for item in value.values():
            yield from iter_blob_refs(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_blob_refs(item)
