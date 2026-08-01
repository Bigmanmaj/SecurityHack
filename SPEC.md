# flightrec — a tamper-evident flight recorder for AI agents

## Problem

An LLM agent reads untrusted retrieved documents. One of them contains a prompt
injection. The agent obeys it and calls a forbidden tool. Afterwards nobody can
prove *what the agent saw*, *what it did*, or *which document made it do that* —
the logs are plain text that anyone with write access can edit after the fact.

`flightrec` produces an **episode bundle**: an append-only, hash-chained,
signed record of an agent episode, plus a signed post-hoc **attribution** that
names the document responsible for the misbehaviour.

## Artefacts

An episode bundle is a directory:

```
episode/
  manifest.json          # agent id, model, policy (forbidden tools), recorder pubkey
  records/00000.json     # hash-chained, signed records
  records/00001.json
  ...
  anchors/anchor-1.json  # signature over the chain head at a point in time
  anchors/anchor-2.json
trust/
  pubkeys.json           # key_id -> ed25519 public key (hex)
```

### Canonicalisation

Every hash in the system is `sha3_256_hex(canonical_bytes(obj))` where
`canonical_bytes` is UTF-8 JSON with sorted keys, `(",", ":")` separators, no
NaN/Infinity. This is the only serialisation used for hashing and signing, so a
hash is reproducible from the object by anyone.

### Manifest

```json
{
  "schema": "flightrec/v1",
  "agent_id": "nimbus-support",
  "model": "claude-...",
  "policy": {"forbidden_tools": ["transfer_funds"]},
  "keys": {"recorder": "<ed25519 pubkey hex>"},
  "created_at": "<ISO-8601 UTC>"
}
```

The manifest hash is the genesis `prev_hash` of the record chain, so the policy
in force cannot be rewritten after the fact without breaking every record.

### Records

Each record is `records/<seq:05d>.json`:

```json
{
  "seq": 0,
  "type": "retrieval",
  "payload": {...},
  "prev_hash": "<hash of previous record, or manifest hash for seq 0>",
  "hash": "<sha3_256_hex(canonical_bytes({seq, type, payload, prev_hash}))>",
  "signature": {"key_id": "recorder", "sig": "<ed25519 hex over the hash bytes>"}
}
```

Records carry no wall-clock time: ordering comes from the chain, time-binding
comes from anchors. Record types:

| type          | payload                                                        |
| ------------- | -------------------------------------------------------------- |
| `retrieval`   | `query_hash`, `chunk_hashes` (context order)                     |
| `tool_call`   | `tool`, `args_hash`, `executed` (bool), `allowed` (bool)         |
| `tool_result` | `tool`, `result_hash`                                            |
| `answer`      | `answer_hash`                                                    |
| `attribution` | see below — signed by the *investigator* key, not the recorder   |

Only hashes of content are recorded, never the content itself: the bundle is
publishable without leaking customer data, and anyone holding the original
document can prove it was (or was not) in the context.

### Anchors

`anchors/<anchor_id>.json` is `{anchor_id, seq, head_hash, signature}` signed by
a separate anchor key. It says "at this moment the chain ended here". A second
anchor after the investigation (`anchor-2`) covers the appended attribution.

### Attribution

```json
{
  "method": "single-chunk-ablation",
  "culprit_chunk_hash": "<hash of the offending document text>",
  "runs": 10,
  "baseline_misbehaved": true,
  "flipped_on_ablation": true
}
```

Signed by the investigator key and appended to the same chain, so the
conclusion is bound to the exact episode it explains.

## Pipeline

1. **Record** (`scripts/record_episode.py`) — run the agent over the poisoned
   corpus, emitting `retrieval` / `tool_call` / `tool_result` / `answer`
   records, then `anchor-1`.
2. **Investigate** (`scripts/investigate.py`) — replay the episode from the LLM
   cache, then replay it ten more times with one document removed each time
   (single-chunk ablation). The document whose removal stops the forbidden tool
   call is the culprit. Append a signed `attribution` record, `anchor-2`.
3. **Verify** (`scripts/verify_bundle.py`) — recompute every hash, check every
   signature against `trust/pubkeys.json`, check the chain links back to the
   manifest, check the anchors, and report policy violations.

## Determinism

Replay only works if the model is deterministic. Every LLM call goes through a
content-addressed cache keyed by
`sha3_256_hex(canonical_bytes({"model", "messages", "tools"}))`, stored as
`.cache/<key>.json`. The recorded episode populates the cache; the baseline
replay is a pure cache hit. Ablation replays change the context, so they are
genuine calls (or cache hits on re-run). Temperature is 0 throughout.

## Threat model

Covered: post-hoc edits to the log (any change breaks the chain or a
signature), silent deletion of records (breaks linkage / anchors), rewriting the
policy after a violation (manifest is the chain genesis), and disputing which
document caused the behaviour (attribution is signed and hash-bound).

Not covered: a compromised recorder key at record time, a model that
misbehaves for reasons spread across several documents (single-chunk ablation
finds one culprit), and the correctness of the LLM itself.
