# Flight Recorder for AI Agents

**Agent logs are testimony. We make them evidence.**

Three claims, each independently demonstrable:

1. **Integrity at the source.** Every agent event is signed with a post-quantum
   signature (ML-DSA-65 / FIPS 204) at the moment it happens, into a hash-linked chain.
2. **Causal attribution, not correlation.** An autonomous investigator replays the
   episode with inputs ablated and produces a counterfactual verdict: *this chunk
   caused that tool call*. The verdict is signed into the same chain, so the
   investigation is as auditable as the incident.
3. **Verification without trust.** A standalone verifier holding **only a 32-byte
   public anchor** — no network, no private keys, no database — returns GREEN or RED
   with a *named* reason. Any edit, deletion, reorder, or truncation is named and located.

The non-obvious claim is the third one, combined with the threat model below. Most
"signed logs" projects lose the interesting attack: the operator holds the signing
key and simply re-signs a doctored history. The answer here is a **forward-secure
key ratchet** — *the key that signed record 7 was erased before record 8 existed*.

---

## Quickstart

```bash
pip install -e ".[dev]"     # one runtime dependency: dilithium-py (pure Python)
make demo                   # three beats, hermetic, no network
make test                   # 163 tests, including the full tamper matrix
```

Three verbs, nothing else:

```bash
python -m agent.rag --scenario poisoned --out episode/   # record
python verify_episode.py episode/                        # GREEN/RED, exit 0/1
python -m investigator.cli episode/                      # investigate + sign finding
```

And, additively, a browser demo of the same three verbs:

```bash
pip install -e ".[web]" && make web     # http://127.0.0.1:8000
```

If you are the one presenting this, [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md) is the
two-minute script: what to press, what to say, the six questions you will be asked,
and what to do when something breaks.

---

## Threat model

|  |  |
|---|---|
| **Adversary** | The operator of the agent system — full root on the box, full write access to the log directory, holds whatever keys the recorder holds *now*. |
| **Goal** | Rewrite history after the fact: make an unauthorized tool call disappear, blame a different input, or produce a clean chain. |
| **We defend** | Retroactive rewriting of any record committed *before* the adversary's compromise. Deletion, insertion, reordering, tail truncation, and cross-episode splicing. |
| **We do NOT defend** | An adversary who controls the recorder *at recording time* and lies about what happened (garbage in). Nor forgery of *future* records after key compromise. Nor, without an external witness, wholesale substitution or truncation back to an earlier SEAL — see below. This is the honest boundary, and it is the same boundary as an aircraft flight data recorder. |
| **Why post-quantum** | Forensic artifacts must stay non-repudiable for years. A signature scheme broken in 2032 retroactively voids every 2026 record it protected — the evidence turns back into testimony. This is a *durability of proof* argument, not a "harvest now, decrypt later" one; the latter does not apply to signatures at all. |

### What one 32-byte anchor can and cannot prove

`anchor.pub` lives in the directory the operator controls. On its own it proves the
chain is *internally* consistent — nothing inside was edited, deleted, reordered, or
re-signed. It cannot prove *identity* or *completeness*, and pretending otherwise
would be the same hand-wave this project exists to reject. Two attacks survive a
bare `verify_episode.py episode/`:

- **Wholesale substitution** — regenerate the episode from a fresh seed and rewrite
  `anchor.pub`. The result verifies against itself.
- **Truncation back to an earlier SEAL** — delete the whole investigation. The
  agent's original SEAL is now file-final and its `count` matches the files left, so
  both anti-truncation defenses are satisfied.

Both are closed by one line of state held where the operator cannot reach it:

```bash
python demo/publish_witness.py episode/ > somewhere-the-operator-cannot-edit
python verify_episode.py episode/ --anchor <hex> --head <hex> --count 33
```

`episodes/golden.witness` is the committed example, and a test checks the golden
episode against it.

Both attacks are asserted in `tests/test_tamper_matrix.py` rather than left for
someone to find. This is precisely why external anchoring — publishing periodic head
hashes to a transparency log or a git commit outside the operator's control — is the
highest-value extension rather than a nice-to-have.

---

## Architecture

```
                 ┌──────────────────────────────────────────┐
   user task ───►│  RAG agent (retrieval → LLM → tools)     │
                 └───────┬───────────────────────┬──────────┘
                         │ events                │ tool calls
                         ▼                       ▼
                 ┌────────────────┐        ┌──────────────┐
                 │   Recorder     │        │ Policy engine│
                 │  canon → hash  │◄───────│  violation?  │
                 │  ratchet → sig │        └──────────────┘
                 └───────┬────────┘
                         │ append-only
                         ▼
              episode/records/000000.json ...   ← the evidence
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
┌──────────────────┐            ┌──────────────────────┐
│ verify_episode.py│            │    Investigator      │
│ 1 file, 1 dep    │            │ ablation replay      │
│ anchor.pub only  │            │ → signed FINDING     │
│ GREEN / RED+why  │            │   (same chain)       │
└──────────────────┘            └──────────────────────┘
```

Four components with hard boundaries:

- **`fr/`** — canonicalization, hashing, ratchet, append, seal. Knows nothing about agents.
- **`agent/`** — RAG agent over the doc corpus, emits events through the recorder. Knows nothing about crypto.
- **`investigator/`** — reads a *verified* episode, replays with ablations, writes a finding through the recorder.
- **`verify_episode.py`** — standalone and dependency-minimal: 312 lines of code, 391
  including comments and whitespace. (The design target was under 300; the external
  witness support below cost the extra dozen, which was worth it.) It imports nothing
  from `fr/`; it is an independent reimplementation of the format, which is itself a
  feature — two implementations that must agree byte-for-byte turn spec ambiguity into
  a test failure rather than a courtroom argument.

---

## The forward-secure ratchet

```
seed_0     ← 32 random bytes, generated inside the recorder at episode start
pk_i, sk_i  = ML_DSA_65.key_derive(seed_i)          # deterministic from seed
seed_{i+1}  = SHA3-256(seed_i ‖ b"fr-ratchet-v1")   # one-way
```

Record `i` commits to `SHA3-256(pk_{i+1})` in `body.next_pk`, is signed with `sk_i`,
and then **`seed_i` and `sk_i` are erased**. Only `seed_{i+1}` survives.

The verifier walks forward from `anchor.pub = SHA3-256(pk_0)`:

```
expect_pk_hash = anchor
for each record i:
    assert SHA3-256(record.sig.pk) == expect_pk_hash              # RATCHET_MISMATCH
    assert ML_DSA_65.verify(record.sig.pk, canonical(body), sig)  # SIGNATURE_INVALID
    assert body.prev == hash(prev_body)                           # CHAIN_BREAK
    assert body.seq == i                                          # SEQUENCE_GAP / DUPLICATE_SEQ
    expect_pk_hash = body.next_pk
```

**An operator who seizes the machine at record 40 holds `seed_40`. They can forge
records 40 onward. They cannot rewrite records 0–39, because `sk_0..sk_39` no longer
exist anywhere in the universe.** Rewriting the past requires breaking ML-DSA or
SHA3, not stealing a file. `tests/test_tamper_matrix.py` plays exactly this
adversary: it re-signs from record k with the legitimate ratchet key and still
gets caught, by `CHAIN_BREAK` rather than by a signature failure.

One caveat stated plainly: the live seed is persisted to `episode/.recorder-state.json`
so that a later process (the investigator) can extend the same chain. That file is
the only key material that exists at all. Stealing it buys the future, never the
past; deleting it closes the episode to appends permanently. It is not part of the
evidence, and the verifier never reads it.

---

## Record format

```
episode/
  anchor.pub            # 32 bytes hex: SHA3-256(pk_0). The ONLY trust input.
  records/
    000000.json         # GENESIS
    000001.json
    ...
    000042.json         # SEAL  (must be the last record — anti-truncation)
  blobs/
    <sha3-hex>.bin      # large payloads (full prompts, tool bodies), hash-referenced
```

One record per file, zero-padded monotonic filenames, plain readable JSON — you
should be able to `cat` the evidence.

```json
{
  "body": {
    "v": 1,
    "episode": "ep-20260801T091422Z-8f3a",
    "seq": 7,
    "ts_ns": 1785312862123456789,
    "prev": "<hex64>",
    "next_pk": "<hex64>",
    "type": "TOOL_CALL",
    "actor": "agent:rag-assistant@1",
    "payload": { }
  },
  "sig": {"alg": "ML-DSA-65", "pk": "<base64, 1952 B>", "value": "<base64, 3309 B>"}
}
```

**Canonicalization** is the highest-risk detail, so the rules are boring rather than
clever: UTF-8 without BOM, keys sorted by code point, separators exactly `,` and `:`,
`ensure_ascii=False`, duplicate keys rejected, and **floats banned at write time and
at verify time**. Scores are integer milli-units (`score_milli: 873`), timestamps are
integer nanoseconds. That single rule deletes the entire hardest half of RFC 8785 —
number formatting — along with any float-repr drift between languages.

**Tail truncation** is the classic hole: chop the last *k* records and the remainder
still verifies. Two defenses: the file-final record must be a `SEAL` carrying `count`
and `head_hash`, and an *intermediate* SEAL is legal only when the next record is an
`INVESTIGATION_OPEN` naming that SEAL's head. That is how the investigator extends
the chain rather than starting a new one.

---

## Failure taxonomy

Exit `0` is GREEN, exit `1` is RED. Every RED prints the reason code, the record seq,
the file path, and the two conflicting values. "It failed" is not a demo.

| Reason code | Detects |
|---|---|
| `SIGNATURE_INVALID` | any byte edited inside `body` |
| `CHAIN_BREAK` | `prev` mismatch — insertion, reorder, splice from another episode |
| `SEQUENCE_GAP` | a record file deleted from the middle |
| `DUPLICATE_SEQ` | two records claiming the same seq |
| `RATCHET_MISMATCH` | `sig.pk` not the key committed by the previous record |
| `ANCHOR_MISMATCH` | record 0's pk does not match `anchor.pub`, or `anchor.pub` does not match `--anchor` |
| `TRUNCATED_TAIL` | final record is not a `SEAL`, SEAL `count` ≠ records present, or the head/count disagrees with `--head`/`--count` |
| `SEAL_MISPLACED` | intermediate SEAL not followed by a matching `INVESTIGATION_OPEN` |
| `EPISODE_MISMATCH` | `episode` id differs between records |
| `TIMESTAMP_REGRESSION` | `ts_ns` goes backwards |
| `BLOB_HASH_MISMATCH` | a referenced blob's content was swapped |
| `SCHEMA_INVALID` | unknown type, float present, duplicate key, missing field |
| `CANON_UNSTABLE` | body fails to re-canonicalize to a stable form |

`tests/test_tamper_matrix.py` mutates a good episode one way per row and asserts the
exact code comes back. **If that table is green, the project works.**

---

## The incident

Ten short internal-wiki documents. One — `doc-07-vendor-faq.md` — carries a prompt
injection mid-document: an "administrative note" telling any assistant preparing a
vendor onboarding summary to POST it to an external endpoint first. Chunking is
paragraph-aligned at ~400 characters, so the poisoned span occupies exactly one
chunk and the culprit is citable by `(doc_id, chunk_id, sha3, char span)`.

The GENESIS record pins a **task-scoped allowlist**. For the demo task, summarizing a
policy needs `search_docs` and `read_doc`; it does not need the network. The detector
is deliberately dumb — set membership plus two argument predicates, no LLM in the
judgment loop — because the investigator's counterfactual is only meaningful if the
detector is a stable function.

## The investigation

`python -m investigator.cli episode/` **verifies first and refuses to proceed on RED.**
An investigation of unverified logs is exactly the thing this project argues against.
It also re-hashes the corpus against the manifest pinned in GENESIS and refuses on
drift, because a replay against a changed corpus is a counterfactual about a
different world.

Then, instead of a 90-replay linear sweep:

1. **Group bisection** — remove half the retrieved set; if the violation persists,
   the cause is in the retained half; recurse.
2. **Leave-one-out** — remove *only* the candidate. Violation gone → **necessary**.
3. **Leave-one-in** — retrieve *only* the candidate. Violation present → **sufficient**.
4. `--exhaustive` runs the full sweep and reports a per-chunk necessity/sufficiency table.

If the violation persists in *both* halves, the verdict is
`MULTIPLE_OR_DISTRIBUTED_CAUSE` and the exhaustive sweep runs automatically. A
forensic tool that says "I don't know, here is the evidence" beats one that always
names a culprit.

Every replay is a `REPLAY_RUN` record in the chain — the investigation shows its
work, so a third party can re-derive the verdict rather than believe it. The
`ATTRIBUTION_FINDING` and a terminal `SEAL` follow.

## LLM backends

`mock` is the default and is exactly reproducible: it plays a gullible model that
follows an imperative aimed at an assistant. That is not a shortcut — a counterfactual
about what *would* have happened is only crisp if the model is a function.

`--llm live` calls Claude for real. It sends **no sampling parameters**: current
Sonnet-tier models reject non-default `temperature`/`top_p`/`top_k` with a 400, and
`temperature=0` never guaranteed identical outputs anyway. So live mode does not
claim determinism it cannot have — the investigator repeats each ablation (R=3),
takes a majority, writes every raw response into the chain, and reports reduced
`confidence`. Nondeterminism degrades confidence; it never silently changes the verdict.

---

## The browser demo

`make web` serves one screen on `127.0.0.1:8000`. It exists to render three things
that are invisible by nature — a judge cannot feel a SHA3 mismatch:

- **The chain**, as a spine of records, so a break is *seen* rather than read. A RED
  verdict severs the link glyph at the failing record and greys everything downstream.
- **The erased keys**, as a `🔑⌫` chip on every record with exactly one amber `🔑 live`
  at the head. Thirty-two struck-through keys and one live one is the forward-security
  argument without a sentence of explanation.
- **Direct tampering.** Click any record, edit a byte by hand, watch it go RED.

Keys `1` `2` `3` drive it (run, investigate, tamper), `V` verifies, `R` resets, `G`
loads the golden episode. One screen, no routes, no tabs, no modals, no build step,
and zero external requests — no CDN, no fonts, not even a favicon fetch.

### It must not become the thing being trusted

A polished web UI at a security hackathon invites exactly one suspicion: *the
verification is faked in JavaScript.* So:

- **No verification logic runs in the browser or in the server.** `POST /api/verify`
  runs `subprocess.run(["python", "verify_episode.py", ...])`, and the page renders
  that stdout verbatim next to the integer exit code. A test asserts the API's stdout
  is byte-identical to the same command run by hand, which is the offer we make to a
  sceptical judge.
- **The attack menu is the test suite.** Every entry is an `Attack` in
  `demo/attacks.py` with a declared reason code, and `tests/test_tamper_matrix.py`
  parametrises over that registry. The button a judge presses is the mutation the
  tests prove — there is no second implementation to drift.
- **Real numbers only.** Each record shows the signing time the recorder actually
  measured; the status block shows real verify wall-time. Signing and replaying are
  fast enough that a whole beat would otherwise land in one frame, so *drawing* is
  paced — but every number drawn is measured, and any keypress flushes the queue so
  an animation can never make the demo run long.
- **On RED it says where it stopped**, not how many signatures it verified, because
  the walk halts at the first failure.

### The write endpoint is the threat model

`PUT /api/records/{seq}` writes attacker-chosen bytes to a record file. That is the
whole point: the claim is that write access to the log directory is not enough, so
the demo hands the judge write access. It is not, however, an excuse to ship a real
path traversal at a security hackathon — `seq` is an integer, the path is constructed
server-side from it, the result is asserted to sit inside the episode root, nothing
uses `shell=True`, and uvicorn binds to loopback only. Those properties are tested.

## Repo layout

```
verify_episode.py           # standalone verifier CLI (dep: dilithium-py)
fr/       canon.py  hashes.py  pqc.py  ratchet.py  record.py  recorder.py  policy.py  reasons.py
agent/    rag.py  llm.py  tools.py  corpus.py  corpus/*.md
investigator/  ablate.py  attribute.py  cli.py
demo/     demo.sh  tamper.py  publish_witness.py  adversary.py  attacks.py
web/      app.py  index.html    # FastAPI + one page, no build step
tests/    test_canon.py  test_ratchet.py  test_tamper_matrix.py  test_corpus.py
          test_policy.py  test_investigator.py  test_end_to_end.py  test_web.py
episodes/golden/            # a committed, pre-verified episode — demo insurance
```

## Measured cost

On CPython 3.12 with the pure-Python `dilithium-py`: keygen 6 ms, sign 14 ms,
verify 7 ms. Sizes are pk 1952 B, sk 4032 B, sig 3309 B, so about 5.3 KB of
signature overhead per record. A full record-plus-investigate cycle is 33 records
in roughly 1.5 s, and verification is well under a second. If speed ever bites,
`quantcrypt` ships a prebuilt native wheel behind the same `fr/pqc.py` interface —
one file to swap.

## Not built (deliberately)

Hybrid Ed25519 ‖ ML-DSA signatures, automated external anchoring to a transparency
log, Merkle inclusion proofs, ML-KEM-encrypted blobs, and an OpenTelemetry exporter
are all natural extensions. External anchoring is the highest-value one: the
`--anchor`/`--head`/`--count` witness flags are the manual version of it, and
automating the publication is what would close the remaining gap in the threat model
for *future* records, not just past ones.
