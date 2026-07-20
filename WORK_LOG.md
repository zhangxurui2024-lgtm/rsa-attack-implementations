# Work Log — Time Distribution

Total estimated: ~32 hours across Week 2 to Week 8.

---

## Week 2 — Project Proposal (3 hours)

Defined project scope and identified five attack categories. Initial reading focused on secondary sources (textbooks, Wikipedia) to establish baseline RSA understanding before approaching primary literature. Wrote the Week 2 proposal.

**What I thought at this point:** RSA is a well-understood algorithm; the project would mainly be about summarising known attacks.

---

## Week 3 — Mathematical Foundations (5 hours)

Worked through RSA key generation from first principles. Modular arithmetic and Euler's theorem were accessible. The CRT optimisation required more time.

Attempted to read Wiener's 1990 paper directly but found the continued fraction theory prerequisites unfamiliar. Spent additional time revisiting Legendre's theorem on best rational approximations before the attack mechanism became clear.

**Key moment:** Realised secondary sources had significantly understated the mathematical depth required. The Wikipedia article on Wiener's Attack describes the result without explaining *why* the continued fraction expansion converges to k/d — this took reading the original paper and a number theory textbook to understand properly.

---

## Week 4 — Wiener's Attack and Common Modulus Attack (5 hours)

Worked through the continued fraction algorithm manually using p=23, q=29, d=5. Verified at each step that the convergents of e/N converged toward k/d. The hand calculation (now Appendix A) was the step that made the proof feel concrete.

Started implementing `wiener_attack.py`. First run on Appendix A numbers returned [FAILED] — traced to two issues:
1. d=5 does not satisfy Wiener's bound for N=667 (5 > 1.7) — the appendix example was wrong
2. Floating-point precision bug in the perfect-square check above ~50-bit numbers

Fixed both. See `C0_DEBUGGING_NOTES.md` for full detail.

Common Modulus Attack hand calculation was completed in under an hour. `common_modulus_attack.py` caught a second arithmetic error: Appendix B stated c₁=578 but 42⁵ mod 667 = 586.

**What changed:** Discovering errors in my own hand calculations by writing code to verify them was the most concrete demonstration that implementation and analysis are not independent activities.

---

## Week 5 — Bleichenbacher and DROWN (6 hours)

Reading Bleichenbacher's 1998 paper was the most difficult single task in this project. Read it three times across two sessions before the interval narrowing argument was clear. Secondary sources consistently understate how the adaptive procedure works — they describe the result (oracle queries converge on plaintext) without explaining the algebraic structure that makes convergence happen.

DROWN paper was more accessible and provided concrete numbers (33% of HTTPS servers, $440 on AWS) that made the abstract vulnerability tangible.

Implemented `bleichenbacher_toy.py`. Three rewrites of the step 2c interval-narrowing loop:
- Version 1: infinite loop (wrong inequality direction in search bounds)
- Version 2: terminated but converged on wrong s (off-by-one in r range)
- Version 3: correct — derived bounds from algebra in original paper rather than secondary summaries

**Key lesson:** The secondary sources describing the attack were good enough to understand it conceptually but not good enough to implement it correctly. The original paper was necessary for the implementation.

---

## Week 6 (Flexibility Week) — Timing Attacks (4 hours)

Worked through Kocher's 1996 paper. The statistical nature of this attack was harder to internalise than algebraic attacks — the signal emerges from timing noise across many measurements rather than from a mathematical relationship that can be verified by hand.

Attempted `timing_attack_demo.py` with real wall-clock measurements. Scheduling noise in the container environment dominated — two runs of identical exponents sometimes differed by more than the expected timing signal between different exponents. Abandoned real timing; rebuilt on operation-count model.

**Limitation acknowledged:** The operation-count model demonstrates the mechanism correctly but is not a real timing attack. The statistical aggregation across hundreds of measurements that makes Kocher's attack work in practice was not reproduced.

---

## Week 7 — Shor's Algorithm and Post-Quantum (4 hours)

Reading Shor's original paper required background on quantum computing that was largely new. Understanding why the Quantum Fourier Transform enables polynomial-time period finding took most of this week. The NIST post-quantum standardisation context was more accessible and directly connected to course themes.

No implementation: a real implementation requires a quantum circuit simulator. Qiskit exists and would be usable, but getting a meaningful result (factoring even a small semiprime) requires understanding gate-level quantum circuits that was outside the practical scope of this project.

---

## Week 7–8 — Report Writing (5 hours)

Drafting revealed several gaps requiring additional reading:
- OAEP padding section required revisiting Bellare and Rogaway's original paper
- CRT optimisation section required understanding why CRT achieves comparable performance without reducing d

Total implementation time across all weeks: approximately 7–8 hours (included in the week-by-week totals above). See `C0_DEBUGGING_NOTES.md` for the per-script breakdown.

---

## Summary Table

| Week | Focus | Hours | Key Output |
|------|-------|-------|------------|
| 2 | Proposal | 3 | Week 2 portfolio entry |
| 3 | RSA foundations + Wiener prerequisites | 5 | Notes; started Appendix A |
| 4 | Wiener + Common Modulus (analysis + code) | 5 | Appendix A, B; wiener_attack.py; common_modulus_attack.py |
| 5 | Bleichenbacher + DROWN (analysis + code) | 6 | Section 4.3; bleichenbacher_toy.py |
| 6 | Timing attacks (analysis + code) | 4 | Section 4.4; timing_attack_demo.py |
| 7 | Shor's Algorithm + post-quantum | 4 | Section 4.5 |
| 7–8 | Report writing + gap-filling reading | 5 | Final report |
| **Total** | | **~32 hours** | |
