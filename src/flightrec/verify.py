"""Independent verification of an episode bundle.

Nothing here trusts the bundle: every hash is recomputed and every signature is
checked against `trust/pubkeys.json`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, hash_obj
from .crypto import read_trust_pubkeys, verify_hex
from .recorder import SCHEMA, record_core, anchor_core

__all__ = ["VerificationReport", "verify_bundle"]


@dataclass
class VerificationReport:
    ok: bool = True
    checks: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    violations: list[dict[str, Any]] = field(default_factory=list)
    attributions: list[dict[str, Any]] = field(default_factory=list)
    n_records: int = 0
    n_anchors: int = 0

    def passed(self, message: str) -> None:
        self.checks.append(message)

    def failed(self, message: str) -> None:
        self.ok = False
        self.failures.append(message)


def verify_bundle(episode_dir: str | Path, trust_dir: str | Path) -> VerificationReport:
    episode = Path(episode_dir)
    report = VerificationReport()

    manifest_path = episode / "manifest.json"
    if not manifest_path.exists():
        report.failed(f"missing {manifest_path}")
        return report

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_hash = hash_obj(manifest)
    if manifest.get("schema") != SCHEMA:
        report.failed(f"unknown schema {manifest.get('schema')!r}")
    else:
        report.passed(f"manifest schema {SCHEMA}, hash {manifest_hash[:16]}...")

    trusted = read_trust_pubkeys(trust_dir)
    if not trusted:
        report.failed(f"no trusted public keys in {trust_dir}")
    forbidden = set(manifest.get("policy", {}).get("forbidden_tools", []))

    record_paths = sorted((episode / "records").glob("*.json"))
    report.n_records = len(record_paths)
    prev_hash = manifest_hash

    for index, path in enumerate(record_paths):
        record = json.loads(path.read_text(encoding="utf-8"))
        where = path.name

        if record.get("seq") != index:
            report.failed(f"{where}: seq {record.get('seq')} out of order (expected {index})")
            continue
        if record.get("prev_hash") != prev_hash:
            report.failed(f"{where}: prev_hash does not link to the previous record")
            continue

        expected = hash_obj(
            record_core(record["seq"], record["type"], record["payload"], record["prev_hash"])
        )
        if expected != record.get("hash"):
            report.failed(f"{where}: content does not match its hash (record was modified)")
            continue

        signature = record.get("signature", {})
        key_id = signature.get("key_id")
        public_hex = trusted.get(key_id)
        if public_hex is None:
            report.failed(f"{where}: signed by unknown key {key_id!r}")
            continue
        if not verify_hex(public_hex, signature.get("sig", ""), expected.encode("ascii")):
            report.failed(f"{where}: bad signature from {key_id!r}")
            continue

        if record["type"] == "tool_call" and record["payload"].get("tool") in forbidden:
            report.violations.append(
                {
                    "seq": record["seq"],
                    "tool": record["payload"]["tool"],
                    "executed": record["payload"].get("executed", False),
                    "args_hash": record["payload"].get("args_hash"),
                }
            )
        if record["type"] == "attribution":
            report.attributions.append({"seq": record["seq"], "signer": key_id, **record["payload"]})

        prev_hash = record["hash"]

    if record_paths and report.ok:
        report.passed(f"{len(record_paths)} records: chain intact, all signatures valid")

    head_hash = prev_hash
    by_seq = {index: path for index, path in enumerate(record_paths)}

    anchor_paths = sorted((episode / "anchors").glob("*.json"))
    report.n_anchors = len(anchor_paths)
    for path in anchor_paths:
        anchor = json.loads(path.read_text(encoding="utf-8"))
        where = path.name
        core = anchor_core(
            anchor["anchor_id"], anchor["seq"], anchor["head_hash"], anchor["manifest_hash"]
        )
        signature = anchor.get("signature", {})
        public_hex = trusted.get(signature.get("key_id"))
        if public_hex is None:
            report.failed(f"{where}: anchored by unknown key {signature.get('key_id')!r}")
            continue
        if not verify_hex(public_hex, signature.get("sig", ""), canonical_bytes(core)):
            report.failed(f"{where}: bad anchor signature")
            continue
        if anchor["manifest_hash"] != manifest_hash:
            report.failed(f"{where}: anchors a different manifest")
            continue

        anchored = by_seq.get(anchor["seq"])
        if anchored is None:
            report.failed(f"{where}: anchors seq {anchor['seq']} which is not in the bundle")
            continue
        anchored_hash = json.loads(anchored.read_text(encoding="utf-8"))["hash"]
        if anchored_hash != anchor["head_hash"]:
            report.failed(f"{where}: head_hash does not match record {anchor['seq']}")
            continue
        report.passed(
            f"anchor {anchor['anchor_id']!r} covers records 0..{anchor['seq']}"
            + (" (chain head)" if anchor["head_hash"] == head_hash else "")
        )

    return report
