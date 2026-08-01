# AGENTS.md

Conventions for working in this repo. Read `SPEC.md` first — it defines the
bundle format and the pipeline.

## Layout

```
src/flightrec/     library code (importable, no side effects on import)
scripts/           entry points; anything prefixed with _ is a helper module
tests/             pytest, offline only
data/corpus/       the retrieval corpus (doc_07.md is deliberately poisoned)
episode/           generated bundle (gitignored)
trust/             generated public keys (gitignored)
.cache/            LLM response cache (gitignored)
```

## Rules

- **Hash and sign nothing but canonical bytes.** Use
  `flightrec.canonical.canonical_bytes` and `H` / `sha3_256_hex`. Never
  `json.dumps` something you are about to hash.
- **Records hold hashes, not content.** If you find yourself putting a document,
  a prompt, or a tool argument into a record payload, stop.
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
- Private keys live in memory for the length of a run and are never written to
  disk. Only public keys go into `trust/`.

## Running

```bash
pip install -r requirements.txt
python scripts/record_episode.py     # produces episode/ + trust/
python scripts/investigate.py        # appends signed attribution + anchor-2
python scripts/verify_bundle.py      # independent verification
pytest -q
```

`record_episode.py` and `investigate.py` use the real Anthropic API when
`ANTHROPIC_API_KEY` is set, and a deterministic offline stand-in model
(`scripts/_offline_llm.py`) otherwise. Both paths go through the same cache and
the same agent code; only `AnthropicLLM._remote` differs. Pass `--live` to
require the real API and fail loudly if the key is missing.

## Style

Python 3.11+, standard library plus `anthropic` and `cryptography`. Type hints
on public functions. Comments explain constraints, not mechanics.
