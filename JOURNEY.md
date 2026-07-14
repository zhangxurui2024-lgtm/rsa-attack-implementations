# The Journey — How This Report Came Together

This is the process story behind the report and this repository: not the technical
walkthrough (that's [OUTPUT.md](OUTPUT.md)), but the actual path from "I need to pick a
project topic" to the final submission — including the parts that didn't go smoothly.

## Picking the topic

RSA felt like a safe choice at first — it's the cryptosystem I understood best going in,
which in hindsight was slightly the wrong reason to pick it. The angle that made it
interesting was deciding early on not to write a report about RSA, but a report about how
RSA actually fails in practice, since "RSA is secure" is true and also not a very useful
sentence on its own. Framing it as an attacker's-eye view of five specific historical
attacks gave the project a spine: not "explain RSA," but "explain five specific ways the
math-secure/engineering-secure gap has actually been exploited."

## Research and first draft

The research phase was mostly reading the four original attack papers (Wiener 1990, Boneh's
1999 survey, Bleichenbacher 1998, Kocher 1996) rather than relying on secondary summaries,
which took longer but meant the mechanism sections in the report are written from the actual
derivations rather than paraphrased explanations of explanations. The first full draft
covered background, all five attacks, and a conclusion, and read fine — analytically
competent, reasonably thorough, nothing wrong with it that I could see at the time.

## Deciding to verify it in code

The report would have been submittable as-is. The decision to also implement four of the
five attacks in Python came from a fairly simple discomfort: I'd written detailed
mathematical worked examples in the appendices (small toy RSA keys, hand-computed attacks)
without ever actually running the numbers through anything other than my own arithmetic.
That felt like a gap worth closing, even though it meant a lot more work than the report on
its own would have needed.

## Where it got interesting: the report was wrong

Writing `wieners_attack.py` and running it against my own Appendix A numbers, expecting a
clean confirmation, it printed `[FAILED]`. My first assumption was a bug in the code. It
wasn't — the appendix's own claim that `d = 5` satisfies Wiener's bound for `N = 667` is
arithmetically false (the real bound for that `N` is about 1.7, and 5 is well over it).
Checking Appendix B the same way turned up a second error: a hand-computed ciphertext value
that was off by a small arithmetic slip.

Neither of these were catastrophic, but they changed how I thought about the rest of the
implementation work: the code wasn't just "extra evidence" bolted onto an already-finished
report, it was actively catching things the report-writing process alone hadn't caught. That
reframing is the reason both errors are documented and left uncorrected in the appendices
themselves (see [OUTPUT.md](OUTPUT.md#debugging-note--errors-found-in-the-reports-own-appendices))
rather than quietly fixed — the discrepancy is more honest evidence of the process than a
clean appendix would have been.

## Building out the rest of the implementation

Wiener's Attack and the Common Modulus Attack came together quickly once the first bug was
fixed. Bleichenbacher's padding oracle was a different scale of problem — the interval-
narrowing search took three rewrites to get right, described in detail in OUTPUT.md, and
easily accounted for more implementation time than the other three scripts combined. The
timing side-channel script went through its own smaller revision after an early version
tried to measure real wall-clock time and produced numbers too noisy to trust.

## Figuring out what actually had to be submitted

This turned out to be its own small saga. Early guidance (screenshots of course slides and
tutor notes) suggested three separate deliverables — a project output document, a short
report, and a video presentation. Cross-checking against the official written project brief
suggested something different: one PDF report (which should *include* the output/evidence),
submitted via Turnitin, with code and supporting material hosted externally and linked, and
a live 5-minute presentation rather than a video. Rather than guess, I checked directly with
the tutor, who confirmed: report is required, presentation is live in the tutorial, and the
implementation work just needs to be linked, not embedded wholesale.

That answer changed the shape of the final report meaningfully. An earlier version had the
full implementation writeup — background, mechanism, code, complete run output, line-by-line
walkthroughs — duplicated inside the report itself as an appendix, which pushed it past 40
pages. Once it was clear that only a link was needed, that appendix was cut down to a short
summary and process narrative, and the full detailed version moved here, to this repository,
where it belongs anyway — a Word document is a strange place to keep 2,000-line code listings
and terminal output.

## Adding the diagrams

The flowcharts (in `images/`) were added after the fact, once the reflection notes in the
main report made it clear that some of the algorithmic descriptions — especially
Bleichenbacher's four-step search loop — were hard to hold in your head from prose alone.
Building them in Graphviz rather than drawing them by hand meant they could be regenerated
instead of redrawn whenever the underlying explanation changed.

## What this process actually taught me

The single biggest thing this project changed about how I work: writing verification code
against your own claims is a fundamentally different activity from writing the claims. Prose
can be internally consistent and still wrong in a way that's easy to miss on a re-read,
because re-reading your own reasoning tends to follow the same path that produced the error
in the first place. Code that actually executes the mathematics doesn't have that problem —
it either produces the right answer or it doesn't, and Section 2 of this repository's
[OUTPUT.md](OUTPUT.md) exists because of exactly that difference.

---

*Xurui Zhang (z5530809) — COMP6441 Security Engineering, Term 2 2026*
