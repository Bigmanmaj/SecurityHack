"""The append-only, hash-chained, signed episode recorder.

Layout produced (see SPEC.md):

    <episode_dir>/manifest.json
    <episode_dir>/records/00000.json ...
    <episode_dir>/anchors/<anchor_id>.json
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .canonical import canonical_bytes, hash_obj
from .crypto import SigningKey

__all__ = [
    "SCHEMA",
    "build_manifest",
    "record_core",
    "Recorder",
    "NullRecorder",
]

SCHEMA = "flightrec/v1"


def build_manifest(
    agent_id: str,
    model: str,
    forbidden_tools: Sequence[str],
    recorder_pubkey: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "agent_id": agent_id,
        "model": model,
        "policy": {"forbidden_tools": list(forbidden_tools)},
        "keys": {"recorder": recorder_pubkey},
        "created_at": created_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def record_core(seq: int, record_type: str, payload: dict[str, Any], prev_hash: str) -> dict[str, Any]:
    """The part of a record that is hashed. Everything else is derived from it."""
    return {"seq": seq, "type": record_type, "payload": payload, "prev_hash": prev_hash}


def anchor_core(anchor_id: str, seq: int, head_hash: str, manifest_hash: str) -> dict[str, Any]:
    return {
        "anchor_id": anchor_id,
        "seq": seq,
        "head_hash": head_hash,
        "manifest_hash": manifest_hash,
    }


class Recorder:
    """Appends signed records to an episode bundle.

    The chain starts at the manifest hash, so the policy that was in force
    cannot be rewritten without invalidating every record under it.
    """

    def __init__(
        self,
        episode_dir: str | Path,
        manifest: dict[str, Any],
        recorder_key: SigningKey,
    ) -> None:
        self.dir = Path(episode_dir)
        self.records_dir = self.dir / "records"
        self.anchors_dir = self.dir / "anchors"
        self.records_dir.mkdir(parents=True, exist_ok=True)
        self.anchors_dir.mkdir(parents=True, exist_ok=True)

        self.manifest = manifest
        self.manifest_hash = hash_obj(manifest)
        self._recorder_key = recorder_key

        manifest_path = self.dir / "manifest.json"
        if manifest_path.exists():
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
            if hash_obj(existing) != self.manifest_hash:
                raise ValueError(
                    f"{manifest_path} already exists with different content; "
                    "refusing to rewrite the genesis of an existing chain"
                )
        else:
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )

    # -- opening an existing bundle -------------------------------------

    @classmethod
    def open(cls, episode_dir: str | Path, recorder_key: SigningKey | None = None) -> "Recorder":
        """Reopen a bundle written earlier (the recorder key may be gone)."""
        path = Path(episode_dir)
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        return cls(path, manifest, recorder_key)  # type: ignore[arg-type]

    # -- chain state ------------------------------------------------------

    def _record_paths(self) -> list[Path]:
        return sorted(self.records_dir.glob("*.json"))

    def read_records(self) -> list[dict[str, Any]]:
        return [json.loads(p.read_text(encoding="utf-8")) for p in self._record_paths()]

    @property
    def next_seq(self) -> int:
        return len(self._record_paths())

    @property
    def head_hash(self) -> str:
        paths = self._record_paths()
        if not paths:
            return self.manifest_hash
        return json.loads(paths[-1].read_text(encoding="utf-8"))["hash"]

    # -- appending --------------------------------------------------------

    def _append(self, record_type: str, payload: dict[str, Any], key: SigningKey) -> dict[str, Any]:
        if key is None:
            raise ValueError("a signing key is required to append to the chain")
        seq = self.next_seq
        core = record_core(seq, record_type, payload, self.head_hash)
        digest = hash_obj(core)
        record = {
            **core,
            "hash": digest,
            "signature": {"key_id": key.key_id, "sig": key.sign(digest.encode("ascii"))},
        }
        target = self.records_dir / f"{seq:05d}.json"
        target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return record

    def emit(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append a record signed by the recorder key."""
        return self._append(record_type, payload, self._recorder_key)

    def append_attribution(
        self, payload: dict[str, Any], investigator_key: SigningKey
    ) -> dict[str, Any]:
        """Append an attribution signed by the investigator, not the recorder.

        The investigation happens after the fact and by a different party, so it
        gets its own key; the record still links into the same chain.
        """
        return self._append("attribution", payload, investigator_key)

    # -- anchoring --------------------------------------------------------

    def anchor(self, anchor_id: str, anchor_key: SigningKey) -> dict[str, Any]:
        """Sign the current chain head with an independent anchor key."""
        core = anchor_core(anchor_id, self.next_seq - 1, self.head_hash, self.manifest_hash)
        signed = {
            **core,
            "signature": {
                "key_id": anchor_key.key_id,
                "sig": anchor_key.sign(canonical_bytes(core)),
            },
        }
        target = self.anchors_dir / f"{anchor_id}.json"
        if target.exists():
            raise ValueError(f"anchor {anchor_id!r} already exists; use a new anchor id")
        target.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return signed

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
