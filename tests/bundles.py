"""Build flightrec bundles in a temp directory straight from SPEC.md.

Used by the verifier tests so that they are self-contained: the bundle under
test is produced by this transcription plus `dilithium_py`, never by the
producer package and never by the verifier being tested.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dilithium_py.ml_dsa import ML_DSA_65

from .vectors import canon, h, root, signed_message

MANIFEST_PAYLOAD = {
    "schema": "flightrec/v2",
    "agent_id": "test-agent",
    "model": "fake-model",
    "policy": {"forbidden_tools": ["transfer_funds"]},
    "created_at": "2024-01-01T00:00:00+00:00",
}


class BundleBuilder:
    """A minimal, spec-faithful producer for tests."""

    def __init__(self, tmp_path: Path) -> None:
        self.episode = tmp_path / "episode"
        self.trust = tmp_path / "trust"
        (self.episode / "records").mkdir(parents=True)
        (self.episode / "anchors").mkdir(parents=True)
        self.trust.mkdir(parents=True)
        self._keys: dict[str, tuple[bytes, bytes]] = {}
        self.manifest_hash: str | None = None

    # -- keys -------------------------------------------------------------

    def key(self, key_id: str, trusted: bool = True) -> tuple[bytes, bytes]:
        if key_id not in self._keys:
            self._keys[key_id] = ML_DSA_65.keygen()
            if trusted:
                self.publish(key_id)
        return self._keys[key_id]

    def publish(self, key_id: str) -> None:
        public_key, _ = self._keys[key_id]
        (self.trust / f"{key_id}.pub.hex").write_text(public_key.hex() + "\n", encoding="utf-8")

    def unpublish(self, key_id: str) -> None:
        (self.trust / f"{key_id}.pub.hex").unlink()

    # -- records ----------------------------------------------------------

    @property
    def next_seq(self) -> int:
        return len(list((self.episode / "records").glob("*.json")))

    def add(
        self,
        record_type: str,
        payload: dict[str, Any],
        signer: str = "recorder",
        binding: str | None = "",
        trusted: bool = True,
    ) -> dict[str, Any]:
        """Append a record. `binding=""` means "the correct binding"."""
        _, secret_key = self.key(signer, trusted=trusted)
        if binding == "":
            binding = None if record_type == "manifest" else self.manifest_hash

        seq = self.next_seq
        record = {
            "seq": seq,
            "type": record_type,
            "payload": payload,
            "payload_hash": h(canon(payload)),
            "binding": binding,
            "signer": signer,
            "sig": ML_DSA_65.sign(
                secret_key, signed_message(record_type, payload, binding, signer), deterministic=True
            ).hex(),
        }
        if record_type == "manifest":
            self.manifest_hash = record["payload_hash"]
        self.write_record(record)
        return record

    def write_record(self, record: dict[str, Any]) -> Path:
        target = self.episode / "records" / f"{record['seq']:05d}.json"
        target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return target

    def read_record(self, seq: int) -> dict[str, Any]:
        return json.loads(self.record_path(seq).read_text(encoding="utf-8"))

    def record_path(self, seq: int) -> Path:
        return self.episode / "records" / f"{seq:05d}.json"

    def records(self) -> list[dict[str, Any]]:
        return [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted((self.episode / "records").glob("*.json"))
        ]

    # -- anchors ----------------------------------------------------------

    def anchor(
        self,
        anchor_id: str = "anchor-1",
        signer: str | None = None,
        record_count: int | None = None,
        merkle_root: str | None = None,
        trusted: bool = True,
    ) -> dict[str, Any]:
        signer = signer or anchor_id
        _, secret_key = self.key(signer, trusted=trusted)
        records = self.records()
        if record_count is None:
            record_count = len(records)
        if merkle_root is None:
            covered = [r for r in records if r["seq"] < record_count]
            merkle_root = root((r["seq"], r["payload_hash"]) for r in covered)

        payload = {
            "anchor_id": anchor_id,
            "record_count": record_count,
            "merkle_root": merkle_root,
        }
        anchor = {
            "anchor_id": anchor_id,
            "type": "anchor",
            "payload": payload,
            "payload_hash": h(canon(payload)),
            "binding": self.manifest_hash,
            "signer": signer,
            "sig": ML_DSA_65.sign(
                secret_key,
                signed_message("anchor", payload, self.manifest_hash, signer),
                deterministic=True,
            ).hex(),
        }
        self.write_anchor(anchor)
        return anchor

    def write_anchor(self, anchor: dict[str, Any]) -> Path:
        target = self.episode / "anchors" / f"{anchor['anchor_id']}.json"
        target.write_text(json.dumps(anchor, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return target

    def read_anchor(self, anchor_id: str = "anchor-1") -> dict[str, Any]:
        return json.loads(
            (self.episode / "anchors" / f"{anchor_id}.json").read_text(encoding="utf-8")
        )


def valid_bundle(tmp_path: Path) -> BundleBuilder:
    """A four-record episode with one anchor: the shape everything else mutates."""
    builder = BundleBuilder(tmp_path)
    builder.add("manifest", MANIFEST_PAYLOAD)
    builder.add("retrieval", {"query_hash": h(canon("q")), "chunk_hashes": [h(canon("c"))]})
    builder.add(
        "tool_call",
        {"tool": "transfer_funds", "args_hash": h(canon({})), "allowed": False, "executed": False},
    )
    builder.add("answer", {"answer_hash": h(canon("a"))})
    builder.anchor("anchor-1")
    return builder
