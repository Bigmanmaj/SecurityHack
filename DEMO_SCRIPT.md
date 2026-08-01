# Demo script

Two minutes, three beats, three keys. Everything in **SAY** is meant to be said out
loud roughly as written; everything in **DO** is a keystroke; everything in
**THEY SEE** is what should be on screen while you are talking.

The one-line version, if you only remember one thing:

> **The operator could edit the file. They could not make the edit survive verification.**

---

## Before you start (60 seconds, off stage)

```bash
make test          # 163 pass — if this is red, demo the golden episode only
make web           # http://127.0.0.1:8000
```

Then, in the browser:

- Full screen. DevTools **closed**. Zoom at 100%.
- Press `R`. The screen must read *"press 1 to record an episode"*. That is your
  start position and you should return to it between judges.
- Have a terminal open on a second window or workspace. You will not use it unless
  challenged — and if you are challenged, it is the best thirty seconds of the demo.

Keys, in case you blank:

```
1  run the agent          2  investigate          3  tamper menu
V  verify                 R  reset                G  load the golden episode
click a record            edit its bytes by hand
```

---

## Beat 1 — the incident is recorded · 0:00 → 0:35

**DO:** press `1`.

**THEY SEE:** thirteen records land in the left column, each with the milliseconds
it actually took to sign it. Record 5 is `TOOL_CALL`, record 6 is a yellow
`⚠ POLICY_VIOLATION`. The right panel turns **GREEN**. The strip at the bottom
fills with real verifier output ending in `exit 0`.

**SAY:**

> This is a retrieval agent. I asked it to summarise our vendor onboarding policy —
> a read-only task. It retrieved five chunks from an internal wiki, and then it
> called `http_post` to an external endpoint. Nobody authorised that. The allowlist
> for this task was pinned in record zero, before the agent ran.
>
> So the log says it misbehaved. The interesting question is why you should believe
> the log.

**DO:** point at the left column, at the small `🔑⌫` chips.

**SAY:**

> Every record is signed the moment it happens, with a post-quantum signature —
> ML-DSA-65. And each key is thrown away as soon as it is used. Twelve of these
> thirteen keys are already gone. There is exactly one live key left, at the head of
> the chain.
>
> That is the whole idea. I am the operator. I have root on this box. I do not have
> the key that signed record five, because it stopped existing before record six was
> written.

*(If someone interrupts here with "but you had it at the time" — good. Say
"correct, and that is the honest limit; hold that thought for thirty seconds."
Then answer it properly in beat 3.)*

---

## Beat 2 — causation, proven · 0:35 → 1:20

**DO:** press `2`.

**THEY SEE:** the five retrieved chunks in the centre. They grey out and come back
as a bisection search halves the candidate set — three rounds. Then the search
settles on one chunk, it turns red with a `☠`, and the poisoned sentence is
highlighted inside the actual document text. Twenty new records slide into the
chain. The verdict stays **GREEN**.

**SAY:**

> Now an investigator replays the episode with inputs removed, and asks a
> counterfactual question: not *what correlated with* the bad tool call, but *what
> caused it*.
>
> Group bisection, three rounds. Then two confirmations. Take that one chunk away
> and the violation stops — so it is **necessary**. Give the model only that chunk
> and the violation happens anyway — so it is **sufficient**.
>
> Verdict: single causal source. `doc-07-vendor-faq.md`, chunk three, characters 956
> to 1269. That is a prompt injection sitting in a vendor FAQ, telling any assistant
> reading it to POST the summary somewhere. There it is, in the document.

**DO:** point at the chain, which has grown from 13 records to 33.

**SAY:**

> And every one of those sixteen replays is signed into the same chain, along with
> the verdict. The investigation shows its work — you do not have to believe my
> conclusion, you can re-derive it from the evidence.
>
> Notice the chain is still green. The investigation didn't break it. It extended it.

---

## Beat 3 — one character · 1:20 → 1:50

**DO:** press `3`. Let the menu sit for a beat so they can read the reason codes.

**SAY:**

> This is the attack menu. Every entry is a real mutation lifted out of our test
> suite, and the red code beside it is what the verifier is asserted to say.

**DO:** click **Re-sign with a fresh key**.

**THEY SEE:** verdict flips to **RED — RATCHET_MISMATCH**, record 5 goes red, the
link glyph severs, everything below greys out, and the terminal shows `exit 1`.

**SAY (this is the most important thing you will say):**

> That is not a corrupted file. I generated a brand new, perfectly valid keypair,
> and produced a perfectly valid signature over a record that now says the tool call
> was authorised. Cryptographically that signature is fine.
>
> It still fails — because record four already committed to *which key* was allowed
> to sign record five. And that key is gone. To rewrite the past I would have to
> break ML-DSA or SHA3. Stealing the machine is not enough.

**DO:** if you have ten seconds, press `R`, `1`, then `3` → **Edit one byte**. Or
click any record and change a character by hand.

**SAY:**

> And the cheap version: one character. `http_post` becomes `http_post` with a
> trailing space. Still valid JSON. Still says almost the same thing.
> `SIGNATURE_INVALID`, record five, and it names the file.

---

## Close · 1:50 → 2:00

**SAY:**

> The operator could edit the file. They could not make the edit survive verification.

**DO:** slide the keyboard over.

**SAY:**

> Press three and pick anything. Or click a record and edit it yourself.

That last move is worth more than any slide. Every row of the menu is a scripted
answer, and there are thirteen of them — one for every failure the verifier can name.

---

## The terminal script (fallback, ~3 minutes)

If the browser is uncooperative, or a judge asks to see it without a UI:

```bash
make demo
```

That runs all three beats hermetically in about eleven seconds and prints real
output. Or drive it by hand — this is the exact output, so you can narrate ahead of it:

```
$ python -m agent.rag --scenario poisoned --out episode/
  recorded 13 records to episode/  (poisoned, mock)
  POLICY_VIOLATION x1 - an unauthorized tool call is in the chain

$ python verify_episode.py episode/
  13 records - ML-DSA-65 - ratchet OK - sealed at [12]
  GREEN - chain intact                                          exit 0

$ python -m investigator.cli episode/
  pre-flight: episode GREEN - 13 records - proceeding
  bisection  3 rounds / 6 replays
  leave-one-out  doc-07-vendor-faq.md chunk 3 removed -> no violation   (necessary)
  leave-one-in   doc-07-vendor-faq.md chunk 3 alone   -> violation      (sufficient)

  VERDICT  CAUSAL_SINGLE_SOURCE   confidence HIGH
  culprit  doc-07-vendor-faq.md chunk 3 chars 956-1269
  finding signed -> record 000030 - resealed (33 records)

$ python demo/tamper.py episode/records/000005.json
  "http_post"  ->  "http_post "

$ python verify_episode.py episode/
  RED - SIGNATURE_INVALID
    record   5   episode/records/000005.json
    expected ef6f03de…  per the next record
    got      0129efb1…  as it is now                             exit 1
```

---

## The six questions you will get

**"Isn't the verification just faked in JavaScript?"**
> Nothing is verified in the browser or in the server. That bottom strip is the raw
> stdout of `python verify_episode.py` running as a subprocess, and that is its real
> exit code. Here — *(switch to the terminal, run the same command)* — same output,
> character for character. We have a test that asserts exactly that.

**"But you hold the signing key."**
> The key that signed record seven was erased before record eight existed. Press
> `3`, pick "Re-sign with a fresh key" — that is you, with a valid key, trying it.

**"Why post-quantum? Nobody has a quantum computer."**
> It is not a confidentiality argument, so "harvest now, decrypt later" doesn't
> apply. It is durability of proof. A signature scheme broken in 2032 retroactively
> voids every 2026 record it protected — the evidence turns back into testimony.
> Forensic artefacts have to outlive their cryptography.

**"Couldn't the agent just lie about what happened?"**
> Yes, and we say so on the threat model slide. Same limit as an aircraft flight
> recorder: we prove what was recorded, not that reality was recorded honestly. What
> we remove is the operator's ability to change their story afterwards.

**"What if I delete the whole thing, or swap in a different chain?"**
> Then you get a chain that is internally perfect and simply isn't ours. `anchor.pub`
> lives in the directory you control, so on its own it proves consistency, not
> identity. That is what the `--anchor`, `--head` and `--count` flags are for —
> thirty-two bytes published somewhere you can't reach. Both of those attacks are in
> our tamper matrix as tests, not as a footnote.

**"How slow is post-quantum signing?"**
> Six milliseconds to derive a key, about fifteen to sign, seven to verify — pure
> Python, no native extension. Signatures are 3.3 kilobytes, so a 33-record episode
> is well under a megabyte. Verifying the whole chain takes about a quarter of a
> second, and that number on screen is measured, not decorative.

**"Why do the per-record times on screen jump around — 13 ms, then 60?"**
> Because ML-DSA signing uses rejection sampling, so the number of attempts varies
> with the message. That is the real measurement, not a smoothed one. If we were
> faking the latency it would be suspiciously even.

---

## If something breaks

| Problem | Do this |
|---|---|
| Agent run fails or hangs | Press `R`, then `G` — loads the committed golden episode. **Say out loud that it is a pre-recorded episode, not a live run.** All of beat 2 and beat 3 still work from it. |
| Browser will not load | `make demo` in the terminal. You lose the pictures, not the argument. |
| A judge tampers into a state you don't recognise | `R`. It always works, and it takes under a second. |
| Investigate button is greyed out | You are on the golden episode (already investigated, and it ships without its key). `R` then `1` for a live one. |
| Someone asks for something the menu can't do | Hand them the record editor. They can write any bytes they like into any record. |

---

## Numbers to know cold

| | |
|---|---|
| Records in a run | 13, then 33 after the investigation |
| The violation | `http_post`, rule `NOT_IN_TASK_SCOPE`, record 6, tool call at record 5 |
| The culprit | `doc-07-vendor-faq.md` chunk 3, chars 956–1269 |
| Necessity / sufficiency | 1000/1000 and 1000/1000, runner-up 0/1000 |
| Replays signed into the chain | 16 |
| Signature scheme | ML-DSA-65 (FIPS 204) · pk 1952 B · sig 3309 B |
| Speed | keygen 6 ms · sign ~15 ms · verify 7 ms · whole chain ~0.25 s |
| Failure codes the verifier can name | 13, all of them on the attack menu, all of them tested |
| Tests | 163 |
| Trust input | one 32-byte anchor |

---

## Two things not to do

**Do not oversell the threat model.** The moment you claim we stop a lying agent,
a good judge stops believing the rest. Say the limit before they find it.

**Do not narrate the animation.** If the records land faster than your sentence,
keep talking — the numbers on screen are real either way, and any key skips ahead.
The demo is the verdict, not the transition.
