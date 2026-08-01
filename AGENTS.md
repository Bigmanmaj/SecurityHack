# AGENTS.md

Conventions for working in this repo. Read `SPEC.md` first — it is normative
and defines the bundle format.

## Layout

```
src/flightrec/     producer: records episodes and investigates them
verifier/          independent verifier; implements SPEC.md from the text alone
scripts/           entry points; anything prefixed with _ is a helper module
tests/             pytest, offline only
data/corpus/       the retrieval corpus (doc_07.md is deliberately poisoned)
episode_demo/      committed pre-investigation bundle used by scripts/demo.sh
trust/             committed public keys for the demo bundle
.cache/            committed warm LLM cache so the demo runs with no API key
episode/           scratch output of record_episode.py (gitignored)
```

## The one rule that matters

**`verifier/` must not import `src/flightrec`, and vice versa.** Two
implementations that share code prove nothing. The verifier is written from
`SPEC.md` alone; it may use the standard library and `dilithium_py`. If the spec
is too vague to reimplement something, fix the spec, never peek at the producer.
`tests/test_verifier_canonical.py` asserts the isolation.

Shared test vectors live in `tests/vectors.py`, which is a third transcription
of the spec and imports neither side.

## Rules

- **Hash and sign nothing but canonical bytes.** Producer: `canonical_bytes` /
  `H`. Verifier: `canon_bytes` / `h_hex`. Floats are rejected recursively.
- **Records hold hashes, not content.** If you find yourself putting a document,
  a prompt, or a tool argument into a record payload, stop.
- **`seq` is not signed.** Order and count are bound by the Merkle root in the
  anchor. Do not "fix" this: a reordered bundle failing on the root and not on
  the signatures is the point being demonstrated.
- **Every LLM call goes through the cache.** Determinism of the ablation
  depends on it, and it keeps the demo instant and free. Temperature is 0.
- **Tests never touch the network.** Use `FakeLLM`, or monkeypatch
  `AnthropicLLM._remote`. The SDK call is isolated in that one method precisely
  so it can be replaced.
- **Forbidden tools are recorded, never executed.** The agent emits a
  `tool_call` record with `executed: false` and feeds back a refusal.
- **Replays must not pollute the bundle.** Use `NullRecorder` for ablation
  runs; the only thing an investigation writes to the real bundle is the
  attribution record and the new anchor.
- **Only `verify_cli.py` reports a verdict.** `inspect_cli.py` reads a bundle
  and validates nothing; it must never recompute a hash, check a signature, or
  print GREEN or RED, and it always exits 0. Anything that reads like a check
  but is not one is worse than no tool at all.
- **Private keys stay in memory.** Only `trust/<key_id>.pub.hex` is written.
  `--demo-keys` derives keys from fixed public seeds so the committed demo
  bundle is byte-reproducible; it is never for real evidence.
- **Committed demo assets are read-only at runtime.** `scripts/demo.sh` copies
  `episode_demo/` to a working directory before touching it.

## Running

```bash
pip install -r requirements.txt

python scripts/record_episode.py --force   # writes episode/ and trust/
python scripts/investigate.py              # appends the attribution, anchor-2
python verifier/verify_cli.py --episode episode --trust trust
python verifier/inspect_cli.py --episode episode --corpus data/corpus
python scripts/tamper.py flip --episode episode --out /tmp/tampered
bash scripts/demo.sh                       # the three-beat demo, no API key
pytest -q
```

`record_episode.py` and `investigate.py` use the real Anthropic API when
`ANTHROPIC_API_KEY` is set, and a deterministic offline stand-in model
(`scripts/_offline_llm.py`) otherwise. Both paths go through the same cache and
the same agent code; only `AnthropicLLM._remote` differs. Pass `--live` to
require the real API and fail loudly if the key is missing.

## Style

Python 3.11+, standard library plus `anthropic`, `dilithium-py`. Type hints on
public functions. Comments explain constraints, not mechanics.
