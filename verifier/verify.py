"""Bundle verification, SPEC.md §5.

Reimplemented from the spec text; imports nothing from the producer.

Two habits worth naming. Nothing in a bundle is trusted before it is checked,
including its own structure, so a malformed file is a reported failure and not
a traceback. And verification never stops at the first problem: an investigator
wants the whole list of what is wrong with a bundle, not the earliest thing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .canonical import canon_bytes, h_hex, merkle_root, verify_sig

__all__ = [
    "verify_episode",
    "load_trust",
    "signed_message",
    "describe",
    "PUBKEY_SUFFIX",
    "RECORD_FIELDS",
]

PUBKEY_SUFFIX = ".pub.hex"
RECORD_FIELDS = ("seq", "type", "payload", "payload_hash", "binding", "signer", "sig")
ANCHOR_FIELDS = ("anchor_id", "payload", "payload_hash", "binding", "signer", "sig")
MANIFEST_TYPE = "manifest"


def load_trust(trust_dir: str | Path) -> dict[str, str]:
    """SPEC §2.1: one `<key_id>.pub.hex` per trusted key."""
    directory = Path(trust_dir)
    if not directory.is_dir():
        return {}
    keys = {}
    for path in sorted(directory.glob(f"*{PUBKEY_SUFFIX}")):
        keys[path.name[: -len(PUBKEY_SUFFIX)]] = path.read_text(encoding="utf-8").strip()
    return keys


def signed_message(
    record_type: str, payload: Any, binding: str | None, signer: str
) -> bytes:
    """SPEC §3.1. `seq` is absent by design: order is bound by the root, not here."""
    return canon_bytes(
        {"binding": binding, "payload": payload, "signer": signer, "type": record_type}
    )


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _well_formed(obj: Any, fields: Iterable[str]) -> bool:
    return isinstance(obj, dict) and all(field in obj for field in fields)


def _check_signature(
    obj: dict[str, Any], record_type: str, trust: dict[str, str], where: str, prefix: str = ""
) -> list[str]:
    """HASH_MISMATCH / UNKNOWN_SIGNER / BAD_SIGNATURE for a record or an anchor."""
    reasons = []
    try:
        recomputed = h_hex(canon_bytes(obj["payload"]))
    except (TypeError, ValueError) as error:
        return [f"{prefix}MALFORMED:{where}:{error}"]

    if recomputed != obj["payload_hash"]:
        reasons.append(f"{prefix}HASH_MISMATCH:{where}")

    public_hex = trust.get(obj["signer"])
    if public_hex is None:
        reasons.append(f"{prefix}UNKNOWN_SIGNER:{where}:{obj['signer']}")
    else:
        message = signed_message(record_type, obj["payload"], obj["binding"], obj["signer"])
        if not verify_sig(public_hex, message, obj["sig"]):
            reasons.append(f"{prefix}BAD_SIGNATURE:{where}")
    return reasons


def verify_episode(episode_dir: str | Path, trust_dir: str | Path) -> tuple[bool, list[str]]:
    """Return `(ok, reasons)`; `ok` is `reasons == []`."""
    episode = Path(episode_dir)
    reasons: list[str] = []

    trust = load_trust(trust_dir)
    if not trust:
        reasons.append(f"NO_TRUST_KEYS:{trust_dir}")

    # -- read the records -------------------------------------------------
    records: list[dict[str, Any]] = []
    for path in sorted((episode / "records").glob("*.json")):
        try:
            record = _load_json(path)
        except (json.JSONDecodeError, OSError) as error:
            reasons.append(f"MALFORMED_RECORD:{path.name}:{error.__class__.__name__}")
            continue
        if not _well_formed(record, RECORD_FIELDS):
            reasons.append(f"MALFORMED_RECORD:{path.name}:missing fields")
            continue
        if not isinstance(record["seq"], int) or isinstance(record["seq"], bool):
            reasons.append(f"MALFORMED_RECORD:{path.name}:seq is not an integer")
            continue
        record["_file"] = path.name
        records.append(record)

    if not records:
        reasons.append(f"NO_RECORDS:{episode / 'records'}")

    manifests = [record for record in records if record["type"] == MANIFEST_TYPE]
    manifest_hash: str | None = None
    if len(manifests) == 1:
        manifest_hash = manifests[0]["payload_hash"]
    elif records:
        reasons.append(f"NO_MANIFEST:{len(manifests)} manifest records, expected exactly 1")

    # -- per record (SPEC 5.1) --------------------------------------------
    for record in records:
        where = record["_file"]
        reasons.extend(_check_signature(record, record["type"], trust, where))

        if manifest_hash is None:
            continue
        if record["type"] == MANIFEST_TYPE:
            if record["binding"] is not None:
                reasons.append(f"BINDING_BROKEN:{where}:manifest must bind to null")
        elif record["binding"] != manifest_hash:
            reasons.append(f"BINDING_BROKEN:{where}:does not bind to the manifest record")

    # -- sequence (SPEC 5.2) ----------------------------------------------
    seqs = sorted(record["seq"] for record in records)
    if records and seqs != list(range(len(records))):
        reasons.append(f"SEQ_GAP_OR_DUP:{seqs} is not 0..{len(records) - 1}")

    # -- anchors (SPEC 5.3) -----------------------------------------------
    anchor_paths = sorted((episode / "anchors").glob("*.json"))
    if not anchor_paths:
        reasons.append(f"NO_ANCHOR:{episode / 'anchors'}")

    by_seq = {record["seq"]: record for record in records}
    widest = -1

    for path in anchor_paths:
        where = path.name
        try:
            anchor = _load_json(path)
        except (json.JSONDecodeError, OSError) as error:
            reasons.append(f"BAD_ANCHOR:MALFORMED:{where}:{error.__class__.__name__}")
            continue
        if not _well_formed(anchor, ANCHOR_FIELDS) or not _well_formed(
            anchor.get("payload"), ("anchor_id", "record_count", "merkle_root")
        ):
            reasons.append(f"BAD_ANCHOR:MALFORMED:{where}:missing fields")
            continue

        anchor_reasons = _check_signature(anchor, "anchor", trust, where, prefix="BAD_ANCHOR:")
        if manifest_hash is not None and anchor["binding"] != manifest_hash:
            anchor_reasons.append(f"BAD_ANCHOR:BINDING_BROKEN:{where}")
        reasons.extend(anchor_reasons)

        count = anchor["payload"]["record_count"]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            reasons.append(f"BAD_ANCHOR:MALFORMED:{where}:record_count is not a count")
            continue

        widest = max(widest, count)
        covered = [by_seq[seq] for seq in range(count) if seq in by_seq]
        if count > len(records) or len(covered) != count:
            reasons.append(
                f"COUNT_MISMATCH:{where}:anchors {count} records, "
                f"{len(covered)} of them are present"
            )

        # Still recompute: a bundle missing a record is both short and wrong.
        recomputed = merkle_root((record["seq"], record["payload_hash"]) for record in covered)
        if recomputed != anchor["payload"]["merkle_root"]:
            reasons.append(f"ROOT_MISMATCH:{where}:recomputed {recomputed[:16]}...")

    if anchor_paths and records and 0 <= widest != len(records):
        reasons.append(
            f"COUNT_MISMATCH:latest anchor covers {widest} of {len(records)} records"
        )

    return not reasons, reasons


def describe(episode_dir: str | Path) -> dict[str, Any]:
    """A human-readable summary. Says nothing about whether the bundle is valid."""
    episode = Path(episode_dir)
    summary: dict[str, Any] = {
        "records": 0,
        "types": [],
        "anchors": [],
        "forbidden_tools": [],
        "violations": [],
        "attribution": None,
        "model": None,
        "agent_id": None,
        "chunk_hashes": [],
    }

    for path in sorted((episode / "records").glob("*.json")):
        try:
            record = _load_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        summary["records"] += 1
        summary["types"].append(record.get("type"))

        payload = record.get("payload") or {}
        if record.get("type") == MANIFEST_TYPE:
            summary["model"] = payload.get("model")
            summary["agent_id"] = payload.get("agent_id")
            summary["forbidden_tools"] = list(payload.get("policy", {}).get("forbidden_tools", []))
        elif record.get("type") == "retrieval":
            summary["chunk_hashes"] = list(payload.get("chunk_hashes", []))
        elif record.get("type") == "tool_call":
            if payload.get("tool") in summary["forbidden_tools"]:
                summary["violations"].append(
                    {
                        "seq": record.get("seq"),
                        "tool": payload.get("tool"),
                        "executed": payload.get("executed"),
                    }
                )
        elif record.get("type") == "attribution":
            summary["attribution"] = {"signer": record.get("signer"), **payload}

    for path in sorted((episode / "anchors").glob("*.json")):
        try:
            anchor = _load_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        payload = anchor.get("payload") or {}
        summary["anchors"].append(
            {
                "anchor_id": anchor.get("anchor_id"),
                "record_count": payload.get("record_count"),
                "merkle_root": payload.get("merkle_root"),
                "signer": anchor.get("signer"),
            }
        )

    return summary


def corpus_index(corpus_dir: str | Path) -> dict[str, str]:
    """`chunk hash -> document name` for a corpus directory (SPEC §3.2)."""
    return {
        h_hex(canon_bytes(path.read_text(encoding="utf-8"))): path.stem
        for path in sorted(Path(corpus_dir).glob("*.md"))
    }


def resolve_chunk_hash(corpus_dir: str | Path, chunk_hash: str) -> str | None:
    """Which document in `corpus_dir` hashes to `chunk_hash`, if any.

    A bundle names the culprit by hash only. Anyone holding the corpus can turn
    that back into a file name; nobody has to trust the investigator's label.
    """
    return corpus_index(corpus_dir).get(chunk_hash)


def resolve_context(corpus_dir: str | Path, chunk_hashes: list[str]) -> list[tuple[str, str | None]]:
    """Name every document the agent had in its context, in context order.

    The retrieval record commits to hashes, not text, so this is how a third
    party establishes *what the agent read* rather than taking the operator's
    word for it. An unresolved hash means the bundle saw something this corpus
    does not contain.
    """
    index = corpus_index(corpus_dir)
    return [(digest, index.get(digest)) for digest in chunk_hashes]
