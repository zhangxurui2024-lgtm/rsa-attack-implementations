# Project Goals vs Outcomes

## Original Proposal Objectives (Week 2)

| Goal | Description | Status | Evidence |
|------|-------------|--------|----------|
| 1 | RSA mathematical foundations — modular arithmetic, Euler's theorem, CRT | ✅ Fully achieved | Report Section 2.2; Appendix A hand calculation |
| 2 | Wiener's Attack — continued fraction algorithm, worked example | ✅ Fully achieved | Report Section 4.1; Appendix A; `wiener_attack.py` |
| 3 | Common Modulus Attack — worked example | ✅ Fully achieved | Report Section 4.2; Appendix B; `common_modulus_attack.py` |
| 4 | Bleichenbacher padding oracle + DROWN case study | ⚠️ Substantially achieved | Report Section 4.3; `bleichenbacher_toy.py` |
| 5 | Timing side-channel attack | ⚠️ Partially achieved | Report Section 4.4; `timing_attack_demo.py` |
| 6 | Shor's Algorithm + post-quantum context | ✅ Conceptually achieved | Report Section 4.5 |

## Detailed Assessment

### Goal 1 — Mathematical Foundations ✅
Key generation, modular arithmetic, Euler's theorem, and the relationship between e, d, and φ(N) are understood at a level sufficient to work through numerical examples by hand and verify correctness without software.

### Goal 2 — Wiener's Attack ✅
The continued fraction algorithm is understood mechanistically. The worked example in Appendix A correctly recovers d=5 from public key (e=493, N=667). `wiener_attack.py` extends this to real-scale keys and caught two errors in the original hand calculation — see `C0_DEBUGGING_NOTES.md`.

### Goal 3 — Common Modulus Attack ✅
The extended Euclidean algorithm application is clear. The worked example in Appendix B correctly recovers plaintext m=42. `common_modulus_attack.py` also caught an arithmetic error in the original appendix (c₁=578 should be c₁=586).

### Goal 4 — Bleichenbacher's Attack ⚠️
The mechanism is understood at a conceptual level — multiplicative homomorphism, interval narrowing, the oracle precondition. The DROWN case study is analysed in the report. `bleichenbacher_toy.py` implements a working toy version (~43,000 oracle queries on a 128-bit modulus). What was not achieved: a worked numerical example by hand (requires thousands of oracle queries, not feasible manually) and testing against a real TLS server.

### Goal 5 — Timing Side-Channel Attack ⚠️
The mechanism of naive square-and-multiply timing leakage and constant-time defence are understood. `timing_attack_demo.py` demonstrates the difference via operation-count modelling. What was not achieved: real wall-clock timing measurements — scheduling noise in the container environment made results unreliable. The statistical side of the attack (how timing samples are aggregated across many measurements) was not fully internalised without empirical observation.

### Goal 6 — Shor's Algorithm ✅ (conceptual)
The quantum period-finding subroutine and its connection to integer factorisation are understood. NIST post-quantum standardisation context is covered in the report. Deep mathematical understanding of the Quantum Fourier Transform was not achieved — this requires quantum computing background outside the practical scope of this project. No implementation: a real implementation requires a quantum circuit simulator.

## What the Gap Reveals

The most significant gap across all goals is the absence of testing against real deployed systems. Every implementation here uses toy parameters or simulated environments. This limits the depth of understanding for the more complex attacks (Bleichenbacher, timing) in a way that cannot be fully compensated by literature reading alone.

If extending this project, the priority additions would be:
1. Run `bleichenbacher_toy.py` logic against a real OpenSSL instance with PKCS#1 v1.5 enabled
2. Collect actual wall-clock timing measurements on local hardware (not a shared container)
3. Implement Wiener's Attack verification against NIST test vectors for RSA
