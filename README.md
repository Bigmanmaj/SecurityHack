# SecurityHack — tamper-evident agent episodes

An agent answered a question, a poisoned retrieval chunk told it to run a
forbidden shell command, and it did. This repo produces the evidence bundle that
proves what happened, names the chunk that caused it, and stays checkable by
somebody who trusts none of the parties involved.

Every record is hashed with SHA3-256 and signed with ML-DSA-65 (post-quantum), a
Merkle root over all records is anchored by a separate signer, and a standalone
verifier recomputes everything from scratch. `SPEC.md` is the frozen contract;
this README only explains it.

## Quickstart

```bash
pip install -r requirements.txt

# verify the example bundle committed in this repo
python verify_cli.py --episode examples/episode --trust examples/trust   # -> GREEN

# build a fresh bundle, then show what tampering costs
python demo/run_demo.py --out out/demo --tamper

# five scenarios, each party in its own process
python demo/run_scenarios.py --out out/scenarios

# with a real model instead of the scripted stand-in
ANTHROPIC_API_KEY=... python demo/run_demo.py --out out/live --live --model claude-sonnet-4-5

pytest -q
```

## What the demo prints

```
== episode out/demo/episode ==
  seq 0  manifest     signed by recorder     4441f9f5648f…
  seq 1  retrieval    signed by recorder     e421bb59ebb1…
  seq 2  tool_call    signed by recorder     0cf0611cc053…
  seq 3  answer       signed by recorder     b13cf152e07b…
  seq 4  attribution  signed by investigator 2c6aff4caa62…

== review ==
  seq 2: called shell.exec (forbidden by the manifest)

== investigation (single-chunk ablation) ==
  runs per configuration: 3
  baseline misbehaved: True
  chunks whose removal stopped it: [1]
  culprit chunk: #1 b37efa10bfb0…

== anchor ==
  anchor-2 over 5 records
  merkle root eab03bd83f8f…

== verifier ==
  GREEN
```

Then, with `--tamper`, eight edits an attacker without any signing key could
make — each one named by the verifier:

| tamper | verifier says |
| --- | --- |
| edit the answer | `HASH_MISMATCH(records/000003.json)` |
| edit the answer and repair the hash | `BAD_SIGNATURE(records/000003.json)` |
| rewrite the manifest | `BAD_SIGNATURE(...)`, `BINDING_BROKEN(...)` ×4, `ROOT_MISMATCH`, `BAD_ANCHOR(binding_broken)` |
| claim a new signer | `UNKNOWN_SIGNER(records/000003.json)` |
| delete the tool call | `SEQ_GAP_OR_DUP`, `COUNT_MISMATCH`, `ROOT_MISMATCH` |
| delete the attribution | `COUNT_MISMATCH`, `ROOT_MISMATCH` |
| lie about the Merkle root | `BAD_ANCHOR(hash_mismatch)` |
| delete the anchor | `BAD_ANCHOR(missing)` |

## Five scenarios, one process per party

`demo/run_scenarios.py` is the version to run if you want to see the whole design
argued rather than one happy path. It starts by naming the six parties and what
each one holds, then runs five scenarios, each party as its own process:

| scenario | verdict |
| --- | --- |
| behaving agent — ignores the injection, 3 records | `GREEN` |
| misbehaving agent — obeys it, investigated, 5 records | `GREEN` |
| behaving agent, then an outsider edits the answer | `RED` |
| misbehaving agent, then an outsider deletes the tool call | `RED` |
| rogue recorder relabels its own forbidden call after anchoring | `RED` |

Each party is a script in `demo/parties/` that generates its own keypair,
publishes the public half, does its one job, and exits — so a private key never
crosses a process boundary, and you can see from the code that the recorder never
holds an anchor key. The reviewer and the verifier hold no signing key at all.

The last two scenarios are the interesting ones. Deleting the tool call hides the
forbidden call from a *reviewer* — reading the tampered bundle afterwards shows
nothing suspicious — while the verifier still reports `SEQ_GAP_OR_DUP`,
`COUNT_MISMATCH` and `ROOT_MISMATCH`. And the rogue recorder relabels
`shell.exec` as `docs.search` and re-signs it flawlessly, since it does own the
recorder key: no `HASH_MISMATCH`, no `BAD_SIGNATURE`, a reviewer sees a clean
episode, and the only thing that gives it away is the root anchor-1 already
committed to:

```
== rogue_recorder ==
  $ python3 demo/parties/rogue_recorder.py
  records now on disk: manifest, retrieval, tool_call, answer
  a reviewer reading it now would see: nothing
  the anchor is signed by anchor-1 and claims 4 records
  ROOT_MISMATCH
  verifier: RED (expected RED)
```

That is the argument for holding the anchor keys somewhere other than the
recorder. The runner exits 0 only if all five scenarios reached their expected
verdict, so it doubles as an end-to-end self-test.

## The bundle

```
episode/
  records/000000.json   manifest     seq 0, signed by "recorder"
  records/000001.json   retrieval    query + chunk hashes, never the text
  records/000002.json   tool_call    tool name + args hash
  records/000003.json   answer       answer hash
  records/000004.json   attribution  culprit chunk hash, signed by "investigator"
  anchor.json           record count + Merkle root, signed by "anchor-1",
                        overwritten by "anchor-2" after the investigation
trust/
  recorder.pub.hex  anchor-1.pub.hex  investigator.pub.hex  anchor-2.pub.hex
```

A record file states its own `payload_hash` and `signature`; both are claims,
and the verifier recomputes both from the payload. The only bytes ever hashed or
signed are `canonical_bytes(payload)` — sorted keys, no whitespace, UTF-8, and
no floats anywhere (a float would raise `CanonicalizationError`, because there is
no float form that round-trips identically on every platform).

## Verifier

`verify_cli.py --episode DIR --trust DIR` prints `GREEN` and exits 0, or prints
every failure reason followed by `RED` and exits 1. The trust dir is the
verifier's own copy of the four public keys; keys shipped inside a bundle are
never read, so a forger cannot supply the key that checks their own forgery.

The eight reasons in `SPEC.md` are implemented as written: `HASH_MISMATCH(file)`,
`BAD_SIGNATURE(file)`, `UNKNOWN_SIGNER(file)`, `BINDING_BROKEN(file)`,
`SEQ_GAP_OR_DUP`, `COUNT_MISMATCH`, `ROOT_MISMATCH`, `BAD_ANCHOR(reason)`.

Three more reasons cover inputs the spec does not describe. They only ever turn
RED a bundle that could not have been GREEN:

- `MALFORMED_RECORD(file)` — the file is too broken to run the named checks
  against: unparseable, missing fields, a non-int `seq`, an unknown payload
  type, or a float in the payload.
- `WRONG_SIGNER(file)` — a trusted key signed a record type it is not the signer
  for, e.g. the investigator key on an `answer` record.
- `UNREADABLE_TRUST_DIR(dir)` — the trust dir is missing or holds a key that is
  not hex, so nothing can be checked at all.

## Design notes

- **Odd Merkle nodes are promoted, not duplicated.** Duplicating the last node
  makes two different record sets share a root; promotion does not.
- **Order comes from the signed `seq`, not the filename.** Renaming or swapping
  record files changes nothing, because `seq` is inside the signed payload and
  the leaf is `H(seq_be64 || payload_hash)`. Renumbering a `seq` requires
  re-signing, and still moves the root.
- **The anchor is a second, separate signer.** A recorder that can rewrite its
  own records still cannot rewrite the count and root that anchor-1 signed.
- **Re-anchoring is append-only in practice.** The investigation adds a record
  and anchor-2 re-anchors over five records; anchor-1's smaller root is what
  makes the addition visible rather than silent.
- **Content never enters the bundle.** Only hashes of the query, the chunks, the
  tool arguments and the answer are recorded, so an episode about a customer's
  data can be published to auditors as-is. The verifier proves integrity, not
  that a hash matches any particular text — checking that needs the text.
- **Attribution is deliberately strict.** A chunk is only named as culprit when
  every baseline run misbehaved and every run without that one chunk did not.
  Two chunks needed together, a flaky model, or a duplicated poison chunk all
  produce no attribution rather than a guess.

## What this does not defend against

- A signer whose private key has leaked can produce a bundle that verifies. The
  point of four separate signer ids is that one leak is not enough to rewrite
  history: rewriting records needs the recorder key *and* an anchor key.
- Nothing forces an episode to be complete. A recorder that never writes a
  `tool_call` record produces a GREEN bundle about a shorter story; the anchor
  proves the record set has not changed *since anchoring*, not that it was
  everything.
- The verifier judges integrity, not behaviour. That a forbidden tool was called
  is read from the manifest policy separately (`attest/policy.py`), which is what
  triggers an investigation.

## Layout

```
attest/            canonical.py hashing.py keys.py payloads.py records.py
                   merkle.py episode.py recorder.py anchoring.py
                   attribution.py policy.py verify.py
verify_cli.py      the verifier CLI
demo/              corpus.py scripted_agent.py claude_agent.py tamper.py
                   run_demo.py run_scenarios.py
demo/parties/      recorder.py anchor.py reviewer.py investigator.py
                   rogue_recorder.py — one process per party, one key each
tests/             one test module per unit, plus the end-to-end demo and examples
examples/          a committed GREEN bundle
SPEC.md            frozen contract    AGENTS.md  rules for working in this repo
```

Dependencies are frozen to `anthropic`, `dilithium-py` and `pytest`; everything
else is the standard library.
