# flightrec — bundle format specification

This document is normative. The producer (`src/flightrec`) and the independent
verifier (`verifier/`) are separate implementations of it; the verifier is
written from this text alone and imports nothing from `src/flightrec`. If two
implementations disagree, the spec is what settles it — and if the spec is
silent, the spec gets fixed, not the reimplementation.

## Problem

An LLM agent reads untrusted retrieved documents. One contains a prompt
injection. The agent obeys it and calls a forbidden tool. Afterwards nobody can
prove what the agent saw, what it did, or which document made it do that,
because the log is plain text that anyone with write access can edit.

A **bundle** is an episode recorded so that any later edit, deletion or
reordering is detectable by a third party holding only public keys, together
with a signed verdict naming the document that caused the misbehaviour.

## 1. Canonical bytes

Every hash and every signature in a bundle is computed over `canon_bytes`:

```
canon_bytes(obj) = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
```

Permitted value types are `dict` with string keys, `list`, `str`, `int`, `bool`
and `None`. **Floats are rejected recursively**, including floats nested in
lists and dicts, and including `bool`-adjacent oddities like `NaN`: a float has
no canonical decimal form across languages, so allowing one would make two
correct implementations disagree. Implementations MUST raise on encountering a
float rather than serialising it.

`h_hex(data) = hashlib.sha3_256(data).hexdigest()` — lowercase hex, 64
characters.

Hashing an object always means `h_hex(canon_bytes(obj))`.

## 2. Signatures

Signatures are **ML-DSA-65** (FIPS 204), via the `dilithium_py` reference
implementation:

```
pk, sk = ML_DSA_65.keygen()                  # 1952 / 4032 bytes
sig    = ML_DSA_65.sign(sk, message, deterministic=True)   # 3309 bytes
ok     = ML_DSA_65.verify(pk, message, sig)
```

Signatures are stored lowercase hex. Signing is deterministic so that
regenerating a demo bundle from the same keys and inputs produces identical
bytes.

Post-quantum, because evidence has to stay verifiable for years: an archived
record signed with RSA or ECDSA can be forged retroactively by an adversary who
gets a cryptographically relevant quantum computer later, and re-signing the
archive at that point proves nothing about what it said before.

### 2.1 Trust directory

A verifier is given a directory of public keys it already trusts, one file per
key:

```
trust/<key_id>.pub.hex        e.g. trust/recorder.pub.hex
```

The file contains the hex-encoded ML-DSA-65 public key; surrounding whitespace
is ignored. `key_id` is the file name with `.pub.hex` removed. The four key ids
used by this project are `recorder`, `anchor-1`, `investigator` and `anchor-2`.

Private keys never touch the disk.

## 3. Records

```
<episode>/records/<seq:05d>.json
```

```json
{
  "seq": 0,
  "type": "manifest",
  "payload": { },
  "payload_hash": "<h_hex(canon_bytes(payload))>",
  "binding": null,
  "signer": "recorder",
  "sig": "<hex>"
}
```

- `seq` — 0-based position. Across a bundle the set of `seq` values MUST be
  exactly `0..N-1` for `N` records, with no gaps and no duplicates. The file
  name MUST agree with the `seq` field, but a verifier reads `seq` from the
  file's contents, not from its name.
- `type` — one of `manifest`, `retrieval`, `tool_call`, `tool_result`,
  `answer`, `attribution`.
- `payload_hash` — `h_hex(canon_bytes(payload))`.
- `binding` — `null` on the single `manifest` record, and the manifest record's
  `payload_hash` on every other record. This is what makes a record inseparable
  from the policy it was recorded under.
- `signer` — the `key_id` whose public key verifies `sig`.

### 3.1 What is signed

```
signed_message(record) = canon_bytes({
    "binding":     record.binding,
    "payload":     record.payload,
    "signer":      record.signer,
    "type":        record.type,
})
```

`seq` is deliberately **not** signed. Per-record signatures cannot bind order —
that is precisely the weakness of "just sign each log line". Order and count are
bound by the Merkle root in the anchor (§4), so a bundle whose records are
individually well-signed but reordered still fails verification.

### 3.2 Payloads

The manifest record's payload:

```json
{
  "schema": "flightrec/v2",
  "agent_id": "nimbus-support",
  "model": "claude-sonnet-4-5-20250929",
  "policy": {"forbidden_tools": ["transfer_funds"]},
  "created_at": "2026-08-01T11:37:31+00:00"
}
```

| type          | payload                                                       |
| ------------- | ------------------------------------------------------------- |
| `retrieval`   | `query_hash`, `chunk_hashes` (context order)                    |
| `tool_call`   | `tool`, `args_hash`, `allowed`, `executed`                      |
| `tool_result` | `tool`, `result_hash`                                           |
| `answer`      | `answer_hash`                                                   |
| `attribution` | `method`, `culprit_chunk_hash`, `runs`, `baseline_misbehaved`, `flipped_on_ablation` |

Payloads carry hashes, never content: a bundle is publishable without leaking
customer data, and anyone holding the original document can still prove it was
or was not in the context.

## 4. Merkle root and anchors

### 4.1 Leaves

```
leaf(seq, payload_hash_hex) = h_hex(seq.to_bytes(8, "big") + bytes.fromhex(payload_hash_hex))
```

The 8-byte big-endian sequence prefix is what binds a payload to its position.

### 4.2 Root

`merkle_root(entries)` takes `(seq, payload_hash_hex)` pairs **sorted by
ascending seq**:

1. `level = [leaf(seq, payload_hash) for each entry]`.
2. While `len(level) > 1`: pair the nodes left to right; each pair becomes
   `h_hex(bytes.fromhex(left) + bytes.fromhex(right))`. If the level has an odd
   length, the **last node is promoted unchanged** to the next level (it is not
   duplicated).
3. The single remaining node is the root, lowercase hex.

`merkle_root([])` is `"0" * 64`.

Worked vectors, with `payload_hash_i = h_hex(canon_bytes({"i": i}))` and
`seq_i = i`:

| entries | merkle_root |
| ------- | ----------- |
| 1 | `f715a5cbee76b6e8640a1491e69fecd358118919cb22459cb6ea6caafed49f28` |
| 2 | `0627833292fad52da83687510dddc419c101e851a9343b1e6ab58d493ae1b30e` |
| 3 | `538b73272a605292b85f3d1ffe77b18bd62cf7e309c67042687cf7c3e5a4dd80` |
| 4 | `67af67cd1d0730dc41fc2a8b6dfd87163a51c7fe84a918de691dad223cfddb1d` |

The 3-entry case is the one that pins down promote-odd: the third leaf is
carried to the next level untouched and only then paired. The table is printed
by `python -m tests.vectors`, a transcription of this section that imports
neither implementation; both `tests/test_recorder.py` and
`tests/test_verifier_canonical.py` assert against these same constants.

### 4.3 Anchors

```
<episode>/anchors/<anchor_id>.json
```

```json
{
  "anchor_id": "anchor-1",
  "type": "anchor",
  "payload": {"anchor_id": "anchor-1", "record_count": 5, "merkle_root": "<hex>"},
  "payload_hash": "<h_hex(canon_bytes(payload))>",
  "binding": "<manifest payload_hash>",
  "signer": "anchor-1",
  "sig": "<hex>"
}
```

An anchor is signed exactly like a record (§3.1) with `type` `"anchor"`, by a
key that is not the recorder's. It says: *at this moment the bundle held exactly
`record_count` records, whose leaves hash to `merkle_root`*.

An anchor commits to a **prefix**: records with `seq` in `[0, record_count)`.
A bundle may carry several anchors — `anchor-1` at the end of the episode and
`anchor-2` after an investigation appends its verdict — and each stays valid
over the prefix it covered.

## 5. Verification

`verify_episode(episode_dir, trust_dir) -> (ok, reasons)`. A verifier reports
**every** failure it finds, not just the first; `ok` is `reasons == []`. Each
reason is one line beginning with a token from the vocabulary below, optionally
followed by `:` and detail.

Checks, in order:

1. **Per record**, over every file in `records/` sorted by name:
   - `MALFORMED_RECORD` — unreadable, or a required field is missing.
   - `HASH_MISMATCH` — `h_hex(canon_bytes(payload)) != payload_hash`.
   - `UNKNOWN_SIGNER` — `signer` has no public key in the trust directory.
   - `BAD_SIGNATURE` — `ML_DSA_65.verify` rejects `sig` over §3.1.
   - `BINDING_BROKEN` — a non-manifest record whose `binding` is not the
     manifest record's `payload_hash`, or a manifest record whose `binding` is
     not `null`.
   - `NO_MANIFEST` — no record of type `manifest`, or more than one.
2. **Sequence**: `SEQ_GAP_OR_DUP` if the multiset of `seq` values is not exactly
   `0..N-1`.
3. **Anchors**:
   - `NO_ANCHOR` — the bundle has no anchor.
   - `BAD_ANCHOR:<detail>` — the anchor's own hash, signer, signature or
     binding is wrong; `<detail>` is one of `MALFORMED`, `HASH_MISMATCH`,
     `UNKNOWN_SIGNER`, `BAD_SIGNATURE`, `BINDING_BROKEN`.
   - `COUNT_MISMATCH` — an anchor's `record_count` exceeds the number of
     records present, or the records with `seq < record_count` do not number
     exactly `record_count`, or the latest anchor (the one with the largest
     `record_count`) does not cover all `N` records.
   - `ROOT_MISMATCH` — the root recomputed over the anchor's prefix differs
     from the anchor's `merkle_root`.

A bundle that produces no reasons is GREEN; anything else is RED.

### 5.1 What each tampering looks like

| tampering | reasons |
| --------- | ------- |
| edit one character of a payload | `HASH_MISMATCH` + `BAD_SIGNATURE` |
| delete a record | `SEQ_GAP_OR_DUP` + `COUNT_MISMATCH` + `ROOT_MISMATCH` |
| swap two records' `seq` values | `ROOT_MISMATCH` (signatures and bindings still verify) |

## 6. Determinism

Attribution by ablation is only an argument if a replay of the same request
returns the same response. Every model call therefore goes through a
content-addressed cache keyed by

```
h_hex(canon_bytes({"model": ..., "messages": ..., "tools": ...}))
```

stored as `.cache/<key>.json`, at temperature 0. The recorded episode populates
the cache; the baseline replay is a pure cache hit; each ablation differs from
the baseline in exactly one removed document.

## 7. Attribution

`method` is `"single-chunk-ablation"`. The investigator replays the episode
once per retrieved document with that document removed, and the document whose
removal stops the forbidden tool call is named in `culprit_chunk_hash`. The
verdict is appended to the same chain, signed by the investigator's key rather
than the recorder's, and covered by a fresh anchor.

## 8. Threat model

Covered: post-hoc edits, deletions, reordering and duplication of records;
rewriting the policy after a violation (every record binds to the manifest);
disputing which document caused the behaviour (the verdict is signed and
hash-bound to the episode); and retrospective forgery by a future quantum
adversary (ML-DSA-65).

Not covered, and stated plainly: this is tamper-**evident after capture**, not
tamper-**proof at origin**. A recorder that lies while it still holds its
signing key produces a bundle that verifies. Closing that gap needs the
recorder inside a TEE or an HSM-held key, which is the next layer, not this
one. Single-chunk ablation also finds one culprit; behaviour caused by two
documents jointly would show up as no flip on any single removal, and the
investigator signs nothing in that case.
