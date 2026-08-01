"""The append-only, signed, Merkle-anchored episode recorder (SPEC §3, §4).

Layout produced:

    <episode_dir>/records/00000.json    the manifest record
    <episode_dir>/records/00001.json    ...
    <episode_dir>/anchors/<anchor_id>.json
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .canonical import canonical_bytes, hash_obj
from .crypto import SigningKey
from .merkle import merkle_root

__all__ = [
    "SCHEMA",
    "MANIFEST_TYPE",
    "build_manifest",
    "signed_message",
    "Recorder",
    "NullRecorder",
]

SCHEMA = "flightrec/v2"
MANIFEST_TYPE = "manifest"


def build_manifest(
    agent_id: str,
    model: str,
    forbidden_tools: Sequence[str],
    created_at: str | None = None,
) -> dict[str, Any]:
    """The manifest record's payload (SPEC §3.2)."""
    return {
        "schema": SCHEMA,
        "agent_id": agent_id,
        "model": model,
        "policy": {"forbidden_tools": list(forbidden_tools)},
        "created_at": created_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def signed_message(
    record_type: str, payload: dict[str, Any], binding: str | None, signer: str
) -> bytes:
    """SPEC §3.1. `seq` is deliberately absent: order is bound by the root."""
    return canonical_bytes(
        {"binding": binding, "payload": payload, "signer": signer, "type": record_type}
    )


class Recorder:
    """Appends signed records to an episode bundle.

    Record 0 is the manifest; every later record binds to its payload hash, so
    the policy in force cannot be swapped out after a violation.
    """

    def __init__(
        self,
        episode_dir: str | Path,
        manifest: dict[str, Any],
        recorder_key: SigningKey | None,
    ) -> None:
        self.dir = Path(episode_dir)
        self.records_dir = self.dir / "records"
        self.anchors_dir = self.dir / "anchors"
        self.records_dir.mkdir(parents=True, exist_ok=True)
        self.anchors_dir.mkdir(parents=True, exist_ok=True)

        self.manifest = manifest
        self.manifest_hash = hash_obj(manifest)
        self._recorder_key = recorder_key

        existing = self._record_paths()
        if existing:
            first = json.loads(existing[0].read_text(encoding="utf-8"))
            if first.get("payload_hash") != self.manifest_hash:
                raise ValueError(
                    f"{self.dir} already holds an episode with a different manifest; "
                    "refusing to append under a different policy"
                )
        else:
            self._append(MANIFEST_TYPE, manifest, self._require_key(recorder_key), binding=None)

    @staticmethod
    def _require_key(key: SigningKey | None) -> SigningKey:
        if key is None:
            raise ValueError("a signing key is required to append to this bundle")
        return key

    @classmethod
    def open(cls, episode_dir: str | Path, recorder_key: SigningKey | None = None) -> "Recorder":
        """Reopen a bundle written earlier; its recorder key may be long gone."""
        path = Path(episode_dir)
        manifest_path = path / "records" / "00000.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))["payload"]
        return cls(path, manifest, recorder_key)

    # -- bundle state -----------------------------------------------------

    def _record_paths(self) -> list[Path]:
        return sorted(self.records_dir.glob("*.json"))

    def read_records(self) -> list[dict[str, Any]]:
        return [json.loads(p.read_text(encoding="utf-8")) for p in self._record_paths()]

    @property
    def record_count(self) -> int:
        return len(self._record_paths())

    @property
    def next_seq(self) -> int:
        return self.record_count

    def merkle_root(self) -> str:
        return merkle_root(
            (record["seq"], record["payload_hash"]) for record in self.read_records()
        )

    # -- appending --------------------------------------------------------

    def _append(
        self,
        record_type: str,
        payload: dict[str, Any],
        key: SigningKey,
        binding: str | None,
    ) -> dict[str, Any]:
        seq = self.next_seq
        record = {
            "seq": seq,
            "type": record_type,
            "payload": payload,
            "payload_hash": hash_obj(payload),
            "binding": binding,
            "signer": key.key_id,
            "sig": key.sign(signed_message(record_type, payload, binding, key.key_id)),
        }
        target = self.records_dir / f"{seq:05d}.json"
        target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return record

    def emit(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append a record signed by the recorder key."""
        if record_type == MANIFEST_TYPE:
            raise ValueError("a bundle has exactly one manifest record, written at open")
        return self._append(
            record_type, payload, self._require_key(self._recorder_key), self.manifest_hash
        )

    def append_attribution(
        self, payload: dict[str, Any], investigator_key: SigningKey
    ) -> dict[str, Any]:
        """Append a verdict signed by the investigator, not the recorder.

        The investigation is a later claim by a different party, so it carries a
        different signature while binding to the same manifest.
        """
        return self._append("attribution", payload, investigator_key, self.manifest_hash)

    # -- anchoring --------------------------------------------------------

    def anchor(self, anchor_id: str, anchor_key: SigningKey) -> dict[str, Any]:
        """Sign the record count and Merkle root with an independent key."""
        target = self.anchors_dir / f"{anchor_id}.json"
        if target.exists():
            raise ValueError(f"anchor {anchor_id!r} already exists; use a new anchor id")

        payload = {
            "anchor_id": anchor_id,
            "record_count": self.record_count,
            "merkle_root": self.merkle_root(),
        }
        anchor = {
            "anchor_id": anchor_id,
            "type": "anchor",
            "payload": payload,
            "payload_hash": hash_obj(payload),
            "binding": self.manifest_hash,
            "signer": anchor_key.key_id,
            "sig": anchor_key.sign(
                signed_message("anchor", payload, self.manifest_hash, anchor_key.key_id)
            ),
        }
        target.write_text(json.dumps(anchor, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return anchor

    def reanchor(self, anchor_id: str, anchor_key: SigningKey) -> dict[str, Any]:
        """Anchor again after appending to a bundle that was already anchored."""
        return self.anchor(anchor_id, anchor_key)

    def read_anchors(self) -> list[dict[str, Any]]:
        return [
            json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(self.anchors_dir.glob("*.json"))
        ]


class NullRecorder:
    """Drop-in recorder that writes nothing.

    Ablation replays run the same agent code as the real episode; they must not
    leave anything behind in the bundle they are investigating.
    """

    def __init__(self) -> None:
        self.emitted: list[tuple[str, dict[str, Any]]] = []

    def emit(self, record_type: str, payload: dict[str, Any]) -> None:
        self.emitted.append((record_type, payload))
        return None

    def append_attribution(self, payload: dict[str, Any], investigator_key: Any = None) -> None:
        return None

    def anchor(self, anchor_id: str, anchor_key: Any = None) -> None:
        return None

    def reanchor(self, anchor_id: str, anchor_key: Any = None) -> None:
        return None

    def types(self) -> Iterable[str]:
        return (t for t, _ in self.emitted)
