# Rules for this repo (hackathon, 3h45)

- Read SPEC.md before writing any code. SPEC.md is frozen — if your task seems
  to require changing it, STOP and say so instead of changing it.
- Test-first: write the failing pytest test(s), run `pytest -q` to see them fail,
  implement, run to green, stop. Do not refactor beyond the task.
- Only touch files the prompt names. Never edit files owned by another person.
- Dependencies are frozen: anthropic, dilithium-py, pytest. Do not add any
  package, including "just for tests".
- No floats in any payload dict, ever. Timestamps are ISO-8601 strings.
- Private keys are function arguments only — never written, logged, or printed.
- Keep functions small; no classes where a function does the job.
- Every green test run → suggest a one-line conventional commit message.
