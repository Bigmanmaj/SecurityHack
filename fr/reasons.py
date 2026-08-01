"""The named failure taxonomy.

Both the library and the standalone verifier speak these codes. A verifier that
says "it failed" is useless; a verifier that says
``record 12 in records/000012.json: SIGNATURE_INVALID`` is evidence.

The verifier deliberately does not import this module -- it carries its own copy
of the table so that the two implementations can disagree loudly in tests.
"""

SIGNATURE_INVALID = "SIGNATURE_INVALID"
CHAIN_BREAK = "CHAIN_BREAK"
SEQUENCE_GAP = "SEQUENCE_GAP"
DUPLICATE_SEQ = "DUPLICATE_SEQ"
RATCHET_MISMATCH = "RATCHET_MISMATCH"
ANCHOR_MISMATCH = "ANCHOR_MISMATCH"
TRUNCATED_TAIL = "TRUNCATED_TAIL"
SEAL_MISPLACED = "SEAL_MISPLACED"
EPISODE_MISMATCH = "EPISODE_MISMATCH"
TIMESTAMP_REGRESSION = "TIMESTAMP_REGRESSION"
BLOB_HASH_MISMATCH = "BLOB_HASH_MISMATCH"
SCHEMA_INVALID = "SCHEMA_INVALID"
CANON_UNSTABLE = "CANON_UNSTABLE"

REASONS = {
    SIGNATURE_INVALID: "any byte edited inside body",
    CHAIN_BREAK: "prev mismatch - insertion, reorder, splice from another episode",
    SEQUENCE_GAP: "a record file deleted from the middle",
    DUPLICATE_SEQ: "two records claiming the same seq",
    RATCHET_MISMATCH: "sig.pk is not the key committed by the previous record",
    ANCHOR_MISMATCH: "record 0's pk does not match anchor.pub",
    TRUNCATED_TAIL: "final record is not a SEAL, or SEAL count != records present",
    SEAL_MISPLACED: "intermediate SEAL not followed by a matching INVESTIGATION_OPEN",
    EPISODE_MISMATCH: "episode id differs between records",
    TIMESTAMP_REGRESSION: "ts_ns goes backwards",
    BLOB_HASH_MISMATCH: "a referenced blob's content was swapped",
    SCHEMA_INVALID: "unknown type, float present, duplicate key, missing field",
    CANON_UNSTABLE: "body fails to re-canonicalize to a stable form",
}

ALL = tuple(REASONS)
