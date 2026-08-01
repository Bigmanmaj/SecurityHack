"""Reading an episode bundle from disk, for recording and anchoring.

These helpers assume a well-formed bundle written by this package. The verifier
does its own strict parsing: it trusts nothing, including these helpers.
"""

from .hashing import hash_payload
from .records import read_record_file, record_paths


def load_records(episode_dir):
    """Return [(path, record), ...] for the episode, ordered by record filename."""
    return [(path, read_record_file(path)) for path in record_paths(episode_dir)]


def next_seq(episode_dir):
    """Return the seq the next appended record should use."""
    return len(record_paths(episode_dir))


def manifest_binding(episode_dir):
    """Return the manifest's recomputed payload_hash, the chain_binding value."""
    records = record_paths(episode_dir)
    if not records:
        raise FileNotFoundError(f"no manifest in {episode_dir}: start the episode first")
    manifest = read_record_file(records[0])
    if manifest["payload"].get("type") != "manifest" or manifest["payload"].get("seq") != 0:
        raise ValueError(f"{records[0]} is not a seq=0 manifest record")
    return hash_payload(manifest["payload"])


def record_entries(episode_dir):
    """Return [(seq, recomputed payload_hash), ...] in seq order, for the Merkle tree."""
    entries = [
        (record["payload"]["seq"], hash_payload(record["payload"]))
        for _, record in load_records(episode_dir)
    ]
    return sorted(entries, key=lambda entry: entry[0])
