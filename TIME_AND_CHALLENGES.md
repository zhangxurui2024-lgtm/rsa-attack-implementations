# Time Allocation, Challenges, and What I'd Do Differently

*Supplementary reflection — RSA Cryptography Research — Xurui Zhang (z5530809) — COMP6441 T2 2026*

This is a companion piece to [JOURNEY.md](JOURNEY.md) (the narrative version) — a more
structured breakdown of where the 30-hour project budget actually went, what was genuinely
difficult, and what I'd change with another 30 hours.

## 1. How the 30 hours were spent

The table below is an honest reconstruction rather than a log kept in real time. Research
and writing overlapped heavily in practice (I frequently went back to a paper while drafting
a section), so the numbers are best read as "roughly this much effort went into this
category" rather than a precise timesheet.

| Activity | Hours | What it covered |
|---|---|---|
| Research | 6 | Reading the four original attack papers (Wiener, Boneh, Bleichenbacher, Kocher) plus supporting sources on RSA history, PKCS#1, and post-quantum standardisation. |
| Report writing | 7 | Background/foundations, methodology, the five attack-analysis sections, reflection, conclusion, and the Appendix A/B worked examples. |
| Implementation | 8 | Writing and debugging `wieners_attack.py`, `common_modulus_attack.py`, `bleichenbacher_toy.py`, `timing_attack_demo.py` (see Section 2 below for where this time actually went). |
| Diagrams | 2 | Building the seven flowcharts (RSA basics, attack taxonomy, and one per attack) and placing them at the right point in the report. |
| Presentation | 2 | Slide deck, speaker notes, and rehearsal timing for the 5-minute live presentation. |
| Documentation & submission format | 3 | This repository (README, OUTPUT.md, JOURNEY.md), resolving the project-output/report/video submission-format ambiguity with the tutor, and restructuring the report once that was resolved. |
| Final polish | 2 | Proofreading, consistency checking between the report and this repository, and verifying every cross-reference and link. |
| **Total** | **~30** | |

## 2. What was actually difficult, and how it was resolved

**Not knowing what "done" looked like, early on.** The submission-format guidance I had
access to at different points didn't agree with itself — course slides implied three
separate deliverables (output, report, video), the written project brief implied one report
with everything folded in and a live talk. I initially built toward the three-deliverable
version, which meant a substantial rebuild once I checked directly with the tutor and got a
definitive answer.
**Resolution:** ask early rather than infer from indirect sources — the rebuild cost more
time than asking would have.

**Trusting my own hand-worked examples too much.** Appendix A and Appendix B of the report
both contain small numerical errors that survived multiple read-throughs of my own writing.
Re-reading your own arithmetic tends to follow the same reasoning path that produced the
error in the first place, so the mistake feels invisible.
**Resolution:** writing verification code that actually executes the mathematics rather than
re-deriving it by hand a second time — the code caught both errors within the first test run
of each script (see [OUTPUT.md](OUTPUT.md#debugging-note--errors-found-in-the-reports-own-appendices)).

**A silent, hard-to-diagnose bug.** An early version of the Wiener's Attack implementation
used ordinary floating-point arithmetic for a perfect-square check. It produced no error and
no crash — it just quietly returned the wrong answer for any modulus above roughly 50 bits,
which is easy to miss because the function "worked" on small test cases.
**Resolution:** switching to Python's exact-integer square root (`math.isqrt`) once the
pattern of failures (worked small, failed large) pointed at a precision issue rather than a
logic issue.

**Bleichenbacher's interval-narrowing search.** This was the single hardest piece of the
whole project. Translating the paper's step 2a/2b/2c/3 description into working code took
three attempts: the first looped indefinitely, the second terminated but converged on a
value that didn't correspond to a real answer.
**Resolution:** going back to the algebra behind the search bounds by hand, rather than
continuing to adjust the code by trial and error, and re-deriving why each bound is what it
is.

**Deciding what "realistic" meant for the toy demonstrations.** Bleichenbacher's attack in
particular needed a modulus small enough to run in seconds but large enough that the result
meant something. Too small and the whole exercise is trivial; too large (a real 2048-bit
key) and a single demonstration run would need millions of queries and take hours.
**Resolution:** settling on ~128 bits as a deliberate, disclosed trade-off, and stating that
trade-off explicitly rather than presenting the toy scale as if it were representative.

## 3. If I had another 30 hours

Roughly in priority order — these are the improvements I'd actually make first, not an
exhaustive wish list:

1. **Implement Shor's Algorithm on a quantum circuit simulator (e.g. Qiskit), even at a toy
   scale (factoring a small N like 15 or 21).** This is the one attack in the report that
   stayed purely analytical, and a working simulation — even one factoring a two-digit
   number — would close that gap and let the report make the same "verified, not just
   described" claim for all five attacks.
2. **Replace the timing attack's operation-count model with a real, statistically rigorous
   timing measurement.** This would mean running many thousands of trials in a more
   controlled environment (or on dedicated rather than shared hardware), applying proper
   statistical tests to separate signal from noise, and being explicit about the sample
   sizes needed — turning a demonstration of the mechanism into an actual measurement.
3. **Resolve the submission-format question in the first week, not partway through.** Given
   how much rework the eventual answer caused, I'd build a short list of open questions
   about requirements and send it to the tutor before writing anything substantial, rather
   than after a full draft existed.
4. **Push the Bleichenbacher demo closer to a realistic key size.** With more time budgeted
   for it specifically, a 256- or 512-bit demonstration (still short of 2048-bit, but a
   meaningful step up from 128) would make the query-count scaling argument more concrete
   rather than asserted.
5. **Set up automated tests (pytest) for the four scripts from the start**, rather than the
   ad-hoc "run it and read the output" verification I actually used — this would have caught
   the isqrt precision bug earlier and made regressions during the Bleichenbacher rewrites
   easier to catch immediately rather than by re-reading output by eye.

---

*Xurui Zhang (z5530809) — COMP6441 Security Engineering, Term 2 2026*
