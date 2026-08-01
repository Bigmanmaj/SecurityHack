"""The verifier (SPEC.md).

It trusts nothing in the bundle: payload_hash and signature are recomputed from
the payload, the Merkle root is rebuilt from the recomputed hashes, and public
keys come only from the verifier's own trust dir. Every failure gets a named
reason; an empty reason list is GREEN.

Three reasons go beyond the eight named in SPEC.md, for inputs the spec does not
describe: MALFORMED_RECORD(file) when a record file is too broken to run the
named checks against (unparseable, missing fields, a float in the payload),
WRONG_SIGNER(file) when a trusted key signs a record type it is not the signer
for, and UNREADABLE_TRUST_DIR(dir) when there are no usable keys to check with.
All three only ever turn a bundle RED that could not have been GREEN anyway.
"""

import json
from pathlib import Path

from .canonical import CanonicalizationError
from .hashing import hash_payload
from .keys import load_trust_dir, verify_payload
from .merkle import episode_merkle_root
from .records import anchor_path, record_paths

RECORD_SIGNERS = {
    "manifest": "recorder",
    "retrieval": "recorder",
    "tool_call": "recorder",
    "answer": "recorder",
    "attribution": "investigator",
}
ANCHOR_SIGNERS = ("anchor-1", "anchor-2")
ANCHOR_FIELDS = ("type", "chain_binding", "record_count", "merkle_root", "ts")
CLAIM_FIELDS = ("payload_hash", "signature", "signer_id", "created_at")


def verify_episode(episode_dir, trust_dir):
    """Verify the bundle at ``episode_dir`` against ``trust_dir``.

    Returns the list of failure reasons, in check order; empty means GREEN.
    """
    episode_dir = Path(episode_dir)
    try:
        trusted = load_trust_dir(trust_dir)
    except (FileNotFoundError, ValueError):
        return [f"UNREADABLE_TRUST_DIR({trust_dir})"]

    paths = record_paths(episode_dir)
    parsed = [(path, _parse_record(path)) for path in paths]
    reasons = []

    manifest_hash = _manifest_hash(parsed)
    for path, record in parsed:
        reasons.extend(_record_reasons(_name(episode_dir, path), record, trusted, manifest_hash))

    usable = [record for _, record in parsed if record is not None]
    if len(usable) != len(paths) or sorted(r["payload"]["seq"] for r in usable) != list(
        range(len(paths))
    ):
        reasons.append("SEQ_GAP_OR_DUP")

    reasons.extend(_anchor_reasons(episode_dir, usable, len(paths), trusted, manifest_hash))
    return reasons


def _parse_record(path):
    """Return the record if it is structurally usable, else None."""
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict) or not isinstance(record.get("payload"), dict):
        return None
    if any(not isinstance(record.get(field), str) for field in CLAIM_FIELDS):
        return None
    payload = record["payload"]
    if not isinstance(payload.get("seq"), int) or isinstance(payload.get("seq"), bool):
        return None
    if not isinstance(payload.get("ts"), str):
        return None
    if payload.get("type") not in RECORD_SIGNERS:
        return None
    if (payload["type"] == "manifest") != (payload["seq"] == 0):
        return None
    try:
        record["recomputed_hash"] = hash_payload(payload)
    except CanonicalizationError:
        return None
    return record


def _manifest_hash(parsed):
    """Return the recomputed payload_hash of the seq=0 manifest, or None."""
    for _, record in parsed:
        if record is not None and record["payload"]["type"] == "manifest":
            return record["recomputed_hash"]
    return None


def _record_reasons(name, record, trusted, manifest_hash):
    if record is None:
        return [f"MALFORMED_RECORD({name})"]

    reasons = []
    payload = record["payload"]
    if record["recomputed_hash"] != record["payload_hash"]:
        reasons.append(f"HASH_MISMATCH({name})")

    signer_id = record["signer_id"]
    if signer_id not in trusted:
        reasons.append(f"UNKNOWN_SIGNER({name})")
    elif signer_id != RECORD_SIGNERS[payload["type"]]:
        reasons.append(f"WRONG_SIGNER({name})")
    elif not verify_payload(trusted[signer_id], payload, record["signature"]):
        reasons.append(f"BAD_SIGNATURE({name})")

    if payload["type"] != "manifest" and payload.get("chain_binding") != manifest_hash:
        reasons.append(f"BINDING_BROKEN({name})")
    return reasons


def _name(episode_dir, path):
    """Name a file the way the reasons report it: relative to the episode dir."""
    return path.relative_to(episode_dir).as_posix()


def _anchor_reasons(episode_dir, usable, record_count, trusted, manifest_hash):
    path = anchor_path(episode_dir)
    if not path.is_file():
        return ["BAD_ANCHOR(missing)"]
    anchor = _parse_anchor(path)
    if anchor is None:
        return ["BAD_ANCHOR(malformed)"]

    payload = anchor["payload"]
    if anchor["recomputed_hash"] != anchor["payload_hash"]:
        return ["BAD_ANCHOR(hash_mismatch)"]
    if anchor["signer_id"] not in trusted:
        return ["BAD_ANCHOR(unknown_signer)"]
    if anchor["signer_id"] not in ANCHOR_SIGNERS:
        return ["BAD_ANCHOR(unexpected_signer)"]
    if not verify_payload(trusted[anchor["signer_id"]], payload, anchor["signature"]):
        return ["BAD_ANCHOR(bad_signature)"]

    reasons = []
    if payload["record_count"] != record_count:
        reasons.append("COUNT_MISMATCH")
    if _recomputed_root(usable, record_count) != payload["merkle_root"]:
        reasons.append("ROOT_MISMATCH")
    if payload["chain_binding"] != manifest_hash:
        reasons.append("BAD_ANCHOR(binding_broken)")
    return reasons


def _parse_anchor(path):
    try:
        anchor = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(anchor, dict) or not isinstance(anchor.get("payload"), dict):
        return None
    if any(not isinstance(anchor.get(field), str) for field in CLAIM_FIELDS):
        return None
    payload = anchor["payload"]
    if payload.get("type") != "anchor" or any(field not in payload for field in ANCHOR_FIELDS):
        return None
    if not isinstance(payload["record_count"], int) or isinstance(payload["record_count"], bool):
        return None
    if not isinstance(payload["merkle_root"], str) or not isinstance(payload["chain_binding"], str):
        return None
    try:
        anchor["recomputed_hash"] = hash_payload(payload)
    except CanonicalizationError:
        return None
    return anchor


def _recomputed_root(usable, record_count):
    """Rebuild the root from the recomputed hashes, or None if it cannot be rebuilt."""
    if not usable or len(usable) != record_count:
        return None
    entries = sorted(
        ((record["payload"]["seq"], record["recomputed_hash"]) for record in usable),
        key=lambda entry: entry[0],
    )
    try:
        return episode_merkle_root(entries)
    except ValueError:
        return None
