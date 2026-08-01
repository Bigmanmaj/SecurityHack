"""Record files: episode/records/NNNNNN.json and episode/anchor.json (SPEC.md).

payload_hash and signature are written as claims; the verifier recomputes both
from the payload, so nothing here is trusted at verification time.
"""

import json
from pathlib import Path

from .clock import utc_now_iso
from .hashing import hash_payload
from .keys import SIGNER_IDS, sign_payload

RECORD_FIELDS = ("payload", "payload_hash", "signature", "signer_id", "created_at")


def make_record(payload, signer_id, secret_key, created_at=None):
    """Hash and sign ``payload``, returning the record file dict."""
    if signer_id not in SIGNER_IDS:
        raise ValueError(f"unknown signer_id {signer_id!r}, expected one of {SIGNER_IDS}")
    return {
        "payload": payload,
        "payload_hash": hash_payload(payload),
        "signature": sign_payload(secret_key, payload),
        "signer_id": signer_id,
        "created_at": created_at or utc_now_iso(),
    }


def record_filename(seq):
    """Return the zero-padded record filename for ``seq``."""
    return f"{seq:06d}.json"


def records_dir(episode_dir):
    """Return the records directory of ``episode_dir``."""
    return Path(episode_dir) / "records"


def anchor_path(episode_dir):
    """Return the anchor path of ``episode_dir``."""
    return Path(episode_dir) / "anchor.json"


def write_record(episode_dir, record):
    """Write ``record`` to episode/records/NNNNNN.json, named after its payload seq."""
    seq = record.get("payload", {}).get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValueError(f"record payload needs an int seq, got {seq!r}")
    return write_record_file(records_dir(episode_dir) / record_filename(seq), record)


def write_record_file(path, record):
    """Write ``record`` as indented JSON at ``path``, creating parents; return the path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")
    return path


def read_record_file(path):
    """Parse the record file at ``path``."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def record_paths(episode_dir):
    """Return the NNNNNN.json record paths of ``episode_dir``, sorted by filename."""
    directory = records_dir(episode_dir)
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.glob("*.json") if path.stem.isdigit())
