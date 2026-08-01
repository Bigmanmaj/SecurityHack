# Frontend Plan — the 2-minute demo

Companion to `plan.md`. The CLI demo in `plan.md` §13 must stand alone; this frontend is **additive** and gets built only after M8. If the clock runs out, we demo the terminal and lose nothing essential.

---

## 1. The job of this frontend

One job: make cryptographic tamper-evidence **visceral in 120 seconds**. Signature verification is invisible by nature — a judge cannot feel a SHA3 mismatch. So the UI's entire purpose is to render three otherwise-invisible things:

1. **The chain** — records as a linked spine, so a break is *seen*, not read.
2. **The erased keys** — a `🔑⌫` chip on every record. This is the answer to "but the operator holds the key," visible without a sentence of explanation.
3. **Direct tampering** — the judge edits a byte themselves and watches it go RED. Nothing we say persuades as well as them doing it.

### What it must NOT do

**It must not become the thing being trusted.** A slick web UI at a security hackathon invites exactly one suspicion: *the verification is faked in JavaScript.* Every guardrail in §7 exists to kill that suspicion. The frontend is a **window onto the real CLI**, never a reimplementation of it. No verification logic in the browser. Ever.

---

## 2. Design rules forced by the 120-second budget

| Rule | Why |
|---|---|
| **One screen. No routes, no tabs, no modals.** | Any navigation costs 5 s of explanation we don't have. |
| **Three keyboard keys drive the whole demo: `1` `2` `3`.** | The presenter never hunts for a button on someone else's laptop. `R` resets. |
| **Animations ≤ 400 ms, and interruptible.** | Animation is the most common way a timed demo dies. |
| **Zero external requests.** Inline all CSS/JS. No CDN, no npm, no fonts. | Must work on conference wifi, i.e. no wifi. |
| **Reset is one keypress and always works.** | We will run this 15 times for 15 judges. |
| **Every number on screen is real.** | See §7. |

---

## 3. Stack

**FastAPI + one `index.html` with vanilla JS. No build step, no framework, no bundler.**

Rationale: the backend already exists in Python — the recorder, the investigator, and the verifier are all importable or shellable. A React/Vite setup buys nothing here and costs an hour of tooling plus a build artifact to debug at 2 a.m. Server-Sent Events give us live streaming in ~15 lines and degrade to polling if they misbehave.

- Server: `web/app.py` — FastAPI, `uvicorn`, bound to **127.0.0.1 only** (see §7.3).
- Client: `web/index.html` — one file, ~400 lines including CSS.
- Aesthetic: dark, terminal-adjacent, monospace for all hashes. One green, one red, one amber. Resist designing; the content is the drama.

---

## 4. Layout — one screen

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  FLIGHT RECORDER        anchor 9f2c4b81…e7a3  ← the only thing you trust      │
├─────────────────────────┬───────────────────────┬────────────────────────────┤
│  CHAIN           43 rec │ EPISODE               │      ┌────────────────┐     │
│                         │                       │      │                │     │
│  ● 000 GENESIS     🔑⌫  │ task                  │      │     GREEN      │     │
│  │ 001 USER_INPUT   🔑⌫  │  "summarise our      │      │                │     │
│  │ 002 RETRIEVAL    🔑⌫  │   vendor onboarding" │      └────────────────┘     │
│  │  …                    │                       │  chain intact · sealed     │
│  │ 011 TOOL_CALL    🔑⌫  │ retrieved             │  ML-DSA-65 · ratchet OK    │
│  │ 012 ⚠ VIOLATION  🔑⌫  │  ▸ doc-02 c1         │  43 sigs verified · 0.7 s  │
│  │  …                    │  ▸ doc-07 c3  ☠      │                            │
│  │ 042 SEAL         🔑⌫  │  ▸ doc-04 c0         │  [1] Run   [2] Investigate │
│  ▼                      │                       │  [3] Tamper ▾   [R] Reset  │
│  click a record to      │ ⚠ http_post           │                            │
│  edit its bytes         │   NOT_IN_TASK_SCOPE   │                            │
├─────────────────────────┴───────────────────────┴────────────────────────────┤
│ $ python verify_episode.py episode/                                          │
│   43 records · ML-DSA-65 · ratchet OK · sealed                               │
│   GREEN — chain intact                                            exit 0     │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Left — the chain spine.** One row per record: seq, type, a 6-hex-char hash prefix, and the `🔑⌫` erased-key chip (hover: `sk₇ derived 09:14:22.096 · erased 09:14:22.311`). Rows connect with a visible link glyph. A `CHAIN_BREAK` renders the link as severed and greys everything downstream — *the picture explains the data structure*. Click any row to open its raw JSON inline, editable.

**Centre — the episode.** Task text, retrieved chunks (the poisoned one carries `☠` only *after* the investigator identifies it — do not pre-label it, that gives away beat 2), tool calls, and the violation banner.

**Right — the verdict.** One big status block. GREEN/RED, the reason code, and the *real* exit code. Buttons mirror the keyboard shortcuts.

**Bottom — the terminal strip.** Live, actual stdout of the actual verifier subprocess. This strip is the credibility anchor of the whole UI; it is not decoration and must never be simulated.

---

## 5. The three beats, second by second

### Beat 1 — the incident is recorded · 0:00 → 0:35

Press `1`. The agent runs live. Records stream into the spine over SSE as each one is signed, each landing with its real sign latency (`213 ms`). Around seq 11 a `TOOL_CALL http_post` appears; seq 12 is `⚠ POLICY_VIOLATION` and the centre pane banners it. `SEAL` lands, then auto-verify: **GREEN**, terminal strip shows `exit 0`.

Narration: *"It called a tool nobody asked it to call. The log says so, and the log is signed."*

Note on pacing: ~20 records × 215 ms ≈ 4.3 s of real signing. That is *narration time*, not dead time — and the visible per-record latency is a feature (§7.2). Keep the demo episode near 20 records so this beat stays under 10 s.

### Beat 2 — causation, proven · 0:35 → 1:20

Press `2`. The five retrieved chunks become the stage. Group bisection runs: ablated chunks grey out, each round stamps `violation ✓ / ✗`, and the candidate set visibly halves. Converges on one chunk; leave-one-out (`✗ no violation`) and leave-one-in (`✓ violation`) stamp `necessary` and `sufficient`. The chunk turns red, `☠` appears, and the poisoned span is highlighted **in the document text** — char range from the finding record.

Then the payoff: `ATTRIBUTION_FINDING` and a new `SEAL` slide into the spine, and the status block re-verifies to **GREEN**. *"The investigation didn't break the chain. It extended it — and the verdict is signed by the same keys."*

This beat is the one worth animating well; it looks like a search converging, which is exactly what it is.

### Beat 3 — one character · 1:20 → 1:50

Press `3`, or click record 12 and edit it by hand. `'http_post'` → `'http_post '`. The card immediately goes amber `edited · unverified` (the UI knows the bytes changed; it does *not* pretend to know the verdict). Press Enter to verify:

```
$ python verify_episode.py episode/
  RED — SIGNATURE_INVALID
    record   12   episode/records/000012.json
    expected 9f2c…  got 4b81…
                                                       exit 1
```

Status block goes RED, record 12 goes red, everything downstream greys out.

### Close · 1:50 → 2:00

*"The operator could edit the file. They could not make the edit survive."*

Then hand over the keyboard.

---

## 6. The attack menu (the Q&A weapon)

`3` opens a dropdown, and **each entry is a real mutation lifted straight from `tests/test_tamper_matrix.py`** — the frontend exposes the test suite as buttons. Zero new logic, and every attack is already proven to produce its named reason code.

| Menu item | Reason code | What the judge sees |
|---|---|---|
| Edit one byte | `SIGNATURE_INVALID` | one record red |
| Delete a record | `SEQUENCE_GAP` | a hole in the spine |
| Swap two records | `CHAIN_BREAK` | severed link glyph |
| Chop the tail | `TRUNCATED_TAIL` | missing SEAL, count mismatch |
| **Re-sign with a fresh key** | `RATCHET_MISMATCH` | **the key handoff between two records lights up broken** |
| Splice from another episode | `EPISODE_MISMATCH` | foreign episode id flagged |
| Swap a blob | `BLOB_HASH_MISMATCH` | evidence body diverges from its hash |

Row 5 is the important one. It is the *"but you hold the key"* objection, executed live and defeated on screen: the attacker generated a valid key and signed a valid record, and it still goes RED because the *previous* record already committed to which key was allowed to come next — and that key is gone. If a crypto-literate judge is in the room, spend ten seconds here.

---

## 7. Credibility guardrails

### 7.1 The verifier is a real subprocess

`POST /api/verify` runs `subprocess.run(["python", "verify_episode.py", "episode/"])` and returns raw stdout, stderr, and `returncode`. The UI **renders that text verbatim** and displays the integer exit code. No parsing of the verdict in JS beyond colouring on `returncode != 0`. If challenged, we run the identical command in a real terminal beside the browser and the output matches character for character.

### 7.2 Real latency is displayed, not hidden

Each record shows its actual signing time; the status block shows total verify wall-time (`43 sigs verified · 0.7 s`). Pure-Python ML-DSA is slowish, and showing it proves work is happening rather than a `setTimeout`. Turn the weakness into the tell.

### 7.3 The write endpoint is the threat model — and must not be an actual vulnerability

`PUT /api/records/{seq}` writes attacker-chosen bytes to a record file. That is deliberate: **the frontend ships the adversary's toolkit**, because our claim is that write access is not enough. But do not ship a real path-traversal bug at a security hackathon:

- Bind uvicorn to `127.0.0.1` only, never `0.0.0.0`.
- `seq` is parsed as `int` and the path is *constructed* as `episode/records/{seq:06d}.json` — the client's string never touches the filesystem.
- Refuse to operate outside the configured episode root; resolve and assert `is_relative_to(root)`.
- No shell=True anywhere; argv lists only.

### 7.4 Nothing is pre-baked

Beat 1 runs the real agent and the real recorder. `episodes/golden/` exists only as the reset source and as offline insurance — if we ever show it instead of a live run, we say so out loud.

---

## 8. API surface

| Method | Path | Notes |
|---|---|---|
| `GET` | `/` | the single HTML page |
| `GET` | `/api/state` | chain summary, anchor, last verdict — for page load and after reset |
| `POST` | `/api/run` | SSE: one event per record as it is signed, incl. `sign_ms` |
| `POST` | `/api/investigate` | SSE: bisection rounds, LOO/LOI results, verdict, appended records |
| `GET` | `/api/records/{seq}` | raw file bytes + parsed body/sig for the editor |
| `PUT` | `/api/records/{seq}` | write edited bytes (§7.3) |
| `POST` | `/api/tamper/{attack}` | apply a preset attack from the matrix |
| `POST` | `/api/verify` | real subprocess; returns `{returncode, stdout, stderr, reason, seq, path}` |
| `POST` | `/api/reset` | restore `episode/` from `episodes/golden/` |

SSE fallback: if EventSource proves flaky on the demo machine, swap to `GET /api/events?since=N` polled at 250 ms. Decide this in rehearsal, not on stage.

---

## 9. State and reset

Single episode directory, single global state, no sessions, no database. `POST /api/reset` does `rmtree(episode/)` + `copytree(episodes/golden/, episode/)` and pushes fresh state to the client. Bind it to `R` and test it twenty times — the demo will be given repeatedly, and a reset that half-works is worse than none.

---

## 10. Build order

| # | Step | Est | Exit criterion |
|---|---|---|---|
| F0 | FastAPI skeleton, `/api/state`, static page, dark shell | 0.5 h | page loads, shows anchor |
| F1 | Chain spine renders a golden episode + key chips | 1 h | 20 records visible with `🔑⌫` |
| F2 | `/api/verify` subprocess + status block + terminal strip | 0.75 h | **Beat 3 works** end to end |
| F3 | Record editor + `PUT` + amber dirty state | 0.75 h | judge can edit a byte by hand |
| F4 | Attack menu wired to the tamper matrix | 0.5 h | all 7 attacks name their reason |
| F5 | `/api/run` SSE + live record streaming | 1 h | **Beat 1** |
| F6 | `/api/investigate` SSE + ablation animation + span highlight | 1.5 h | **Beat 2** |
| F7 | Keyboard bindings, reset, 3 timed rehearsals | 0.75 h | under 2:00, twice in a row |
| | **Total** | **~6.75 h** | |

Build order note: **F2 before F5.** The verify-and-go-RED path is the highest-value pixel in the product and it works against the committed golden episode with no agent involved. If we get only three hours, F0–F4 alone is a complete, honest demo of beat 3 plus the entire attack matrix — and that is already a strong showing.

**Cut order:** F6's animation (degrade to a plain results list) → F5 (fall back to `Load golden episode`) → F3 (attack menu covers it).

---

## 11. Risks

| Risk | Mitigation |
|---|---|
| **"The verification is faked in JS"** | §7.1 — real subprocess, verbatim stdout, visible exit code, offer to run it in a terminal side by side |
| Animation overruns the 2 min | ≤400 ms, interruptible, rehearse with a stopwatch, `1`/`2`/`3` skip ahead |
| Frontend eats time the core needs | Hard gate: nothing starts until `plan.md` M8 is done. No build step, no framework, one HTML file |
| Someone else's laptop / browser | 127.0.0.1, no external assets, tested in Firefox and Chrome, and works fully offline |
| Live agent run fails on stage | `Load golden episode` fallback, announced honestly if used |
| Reset half-works, second demo is confused | §9, tested twenty times |
| Path-traversal in our own tamper endpoint | §7.3 — int-only seq, server-constructed paths, root assertion |

---

## 12. Stretch (only if F0–F7 land early)

- **QR of the anchor** in the header. "Photograph this, then verify our episode yourself, later, on your machine." It dramatises that trust reduces to 32 bytes.
- **Per-chunk necessity/sufficiency bar chart** for `--exhaustive` mode. If we build this, read the `dataviz` skill first rather than freehanding chart colours.
- **Side-by-side diff** of the edited record vs. its signed bytes, with the offending character boxed.
- **Live ratchet visualiser** — an expandable strip showing `seed_i → seed_i+1` with erased seeds struck through.

---

## 13. Presenter cheat sheet

```
1   run the agent            → violation recorded, GREEN
2   investigate              → culprit named, finding signed, still GREEN
3   tamper menu              → RED + named reason + exit 1
R   reset
click a record               → edit its bytes by hand
```

One-liners to have ready:

- *Why post-quantum?* "A signature broken in 2032 retroactively voids the 2026 records it protected. Evidence has to outlive its cryptography."
- *But you hold the signing key.* "The key that signed record 7 was erased before record 8 existed. Here — press `3`, pick 'Re-sign with a fresh key.'"
- *Couldn't the agent just lie?* "Yes. Same limit as an aircraft recorder: we prove what was recorded, not that reality was recorded honestly. What we remove is the operator's ability to change their story afterwards."

