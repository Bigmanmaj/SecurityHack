"""Anchoring: commit the whole record set to one signed Merkle root (SPEC.md).

The anchor is written by "anchor-1"; after an investigation appends the
attribution record, "anchor-2" re-anchors over the longer record set.
"""

from .clock import utc_now_iso
from .episode import manifest_binding, record_entries
from .merkle import episode_merkle_root
from .payloads import anchor_payload
from .records import anchor_path, make_record, write_record_file

ANCHOR_SIGNERS = ("anchor-1", "anchor-2")


def write_anchor(episode_dir, signer_id, secret_key, ts=None):
    """Write (or overwrite) episode/anchor.json over the current records."""
    if signer_id not in ANCHOR_SIGNERS:
        raise ValueError(f"anchor signer must be one of {ANCHOR_SIGNERS}, got {signer_id!r}")
    entries = record_entries(episode_dir)
    payload = anchor_payload(
        chain_binding=manifest_binding(episode_dir),
        record_count=len(entries),
        merkle_root=episode_merkle_root(entries),
        ts=ts or utc_now_iso(),
    )
    return write_record_file(
        anchor_path(episode_dir), make_record(payload, signer_id, secret_key)
    )
