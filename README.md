# RSA Attack Implementations

COMP6441 Security Engineering — Project Repository  
Student: Xurui Zhang (z5530809)  
Tutor: Jason Phua  
Submission: 25 July 2026

---

## What This Repository Contains

This repository accompanies the project report *RSA Cryptography Research: Mathematical Foundations and Attack Analysis*. It contains:

- Python implementations of four RSA attacks verified against test cases
- Debugging notes documenting errors found (including two errors in the report's own appendices)
- Work log with weekly time distribution (~32 hours total)
- Project goals vs outcomes tracking
- Ethics and professional considerations

The report PDF is submitted separately via Moodle as `Report-z5530809.pdf`.

---

## Attack Implementations

| File | Attack | Status |
|------|--------|--------|
| `wiener_attack.py` | Wiener's Attack on small private exponents | ✅ Working — 4 test cases including real-scale |
| `common_modulus_attack.py` | Common Modulus Attack | ✅ Working — includes control case with non-coprime exponents |
| `bleichenbacher_toy.py` | Bleichenbacher padding oracle (toy modulus) | ✅ Working — 128-bit modulus, ~43,000 oracle queries |
| `timing_attack_demo.py` | Timing side-channel (operation-count model) | ✅ Working — demonstrates leak without real clock measurement |

Shor's Algorithm is not implemented — a real implementation requires a quantum circuit simulator. It is covered analytically in Section 4.5 of the report.

---

## Supporting Documents

| File | Contents |
|------|----------|
| `README.md` | This file |
| `WORK_LOG.md` | Weekly time distribution, what happened each week |
| `PROJECT_GOALS.md` | Original proposal goals vs actual outcomes |
| `C0_DEBUGGING_NOTES.md` | Every error found during implementation, including appendix corrections |
| `ETHICS_AND_PROFESSIONAL.md` | Dual-use considerations, responsible disclosure, scope boundaries |

---

## How to Run

Requires Python 3.8+. No external dependencies.

```bash
python wiener_attack.py
python common_modulus_attack.py
python bleichenbacher_toy.py      # takes ~10-30 seconds
python timing_attack_demo.py
```

Each script prints its own test results. Every script has at least one case designed to fail (demonstrating the precondition is enforced) and one designed to succeed.

---

## Key Finding from Implementation

Writing code to verify the hand calculations in the report's appendices caught two arithmetic errors:

1. **Appendix A (Wiener's Attack):** d=5 does not satisfy Wiener's bound for N=667. The report states d < N^(1/4)/3 ≈ 1.7, but 5 > 1.7. The code correctly returns FAILED on these parameters.

2. **Appendix B (Common Modulus Attack):** The report states c₁ = 42⁵ mod 667 = 578, but the correct value is 586. The code uses the corrected value and recovers m=42 as expected.

Both errors are left uncorrected in the report appendices deliberately — the discrepancy between the appendix numbers and the repository numbers is itself evidence that the code independently verified the analysis. See `C0_DEBUGGING_NOTES.md` for full detail.

---

## Scope and Limitations

These implementations use toy parameters or simulated environments. None of them were tested against real deployed systems. The specific limitations of each are documented in `C0_DEBUGGING_NOTES.md` and in the report's Section 5 (Reflection).

The most significant gap: `bleichenbacher_toy.py` uses a 128-bit simulated oracle rather than a real TLS server. Query counts (~43,000) are not directly comparable to a real attack against RSA-2048 (~millions of queries). The mechanism is correct; the scale is not representative.
