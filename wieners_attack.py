"""
Wiener's Attack on RSA
======================
Demonstrates recovery of a small RSA private exponent d from the public
key (e, N) alone, using the continued fraction expansion of e/N.

Reference: M. J. Wiener, "Cryptanalysis of short RSA secret exponents,"
IEEE Transactions on Information Theory, vol. 36, no. 3, pp. 553-558, 1990.

This reproduces:
  1. The small worked example from Appendix A of the report (p=23, q=29, d=5)
  2. A larger example to show the attack still works instantly once
     d < N^0.25 / 3
  3. A "safe" key with a large d, to show the attack correctly FAILS
     to recover the key (demonstrating the defence works)
"""

from sympy import nextprime
import random
import math


def continued_fraction(num, denom):
    """Return the continued fraction expansion of num/denom as a list of quotients."""
    cf = []
    while denom:
        q = num // denom
        cf.append(q)
        num, denom = denom, num - q * denom
    return cf


def convergents(cf):
    """Given a continued fraction (list of quotients), return all convergents k/d."""
    convs = []
    for i in range(len(cf)):
        num, denom = cf[i], 1
        for j in range(i - 1, -1, -1):
            num, denom = cf[j] * num + denom, num
        convs.append((num, denom))
    return convs


def is_perfect_square(n):
    if n < 0:
        return False, 0
    r = math.isqrt(n)  # exact integer square root, safe for arbitrarily large ints
    if r * r == n:
        return True, r
    return False, r


def wiener_attack(e, N):
    """
    Attempt to recover the RSA private exponent d from the public key (e, N).
    Returns (d, p, q) on success, or None if the attack fails (d not small enough).
    """
    cf = continued_fraction(e, N)
    convs = convergents(cf)

    for (k, d) in convs:
        if k == 0 or d == 0:
            continue
        # Candidate phi(N) derived from this convergent: ed - 1 = k * phi(N)
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k

        # p and q are roots of x^2 - (N - phi + 1)x + N = 0
        b = N - phi + 1
        disc = b * b - 4 * N
        is_sq, root = is_perfect_square(disc)
        if not is_sq:
            continue

        p_candidate = (b + root) // 2
        q_candidate = (b - root) // 2
        if p_candidate * q_candidate == N and p_candidate > 1 and q_candidate > 1:
            return d, p_candidate, q_candidate
    return None


def run_demo(name, e, N, d_expected=None):
    print(f"--- {name} ---")
    print(f"N = {N}")
    print(f"e = {e}")
    result = wiener_attack(e, N)
    if result:
        d, p_found, q_found = result
        print(f"[SUCCESS] Recovered d = {d}")
        print(f"[SUCCESS] Recovered factors: p = {p_found}, q = {q_found}")
        if d_expected is not None:
            assert d == d_expected, "Recovered d does not match expected value!"
            print(f"Verified against expected d = {d_expected}: MATCH")
    else:
        print("[FAILED] Attack did not recover a valid private key "
              "(expected when d is not sufficiently small).")
    print()


if __name__ == "__main__":
    # -----------------------------------------------------------------
    # 1a. The ORIGINAL Appendix A numbers from the report (p=23, q=29, d=5)
    #     NOTE: N^(1/4)/3 for N=667 is only ~1.7, so d=5 does NOT actually
    #     satisfy Wiener's bound d < N^(1/4)/3. This demo shows the attack
    #     correctly FAILS on these numbers -- the original report's Appendix A
    #     has an arithmetic inconsistency (d=5 was claimed to satisfy the
    #     bound when it does not) that should be corrected.
    # -----------------------------------------------------------------
    p, q = 23, 29
    N = p * q
    phi = (p - 1) * (q - 1)
    d = 5
    e = pow(d, -1, phi)
    print(f"Wiener bound N^(1/4)/3 for N={N}: {N ** 0.25 / 3:.3f}  (d={d} exceeds this)")
    run_demo("Original Appendix A numbers (d=5) -- expected to FAIL, bound violated", e, N, d_expected=None)

    # -----------------------------------------------------------------
    # 1b. CORRECTED small worked example: same style, but d actually
    #     satisfies the bound, so the attack succeeds.
    # -----------------------------------------------------------------
    p, q = 1009, 1013
    N = p * q
    phi = (p - 1) * (q - 1)
    d = 5
    while math.gcd(d, phi) != 1:
        d += 2
    e = pow(d, -1, phi)
    print(f"Wiener bound N^(1/4)/3 for N={N}: {N ** 0.25 / 3:.3f}  (d={d} satisfies this)")
    run_demo(f"Corrected small worked example (d={d}, bound satisfied)", e, N, d_expected=d)

    # -----------------------------------------------------------------
    # 2. Larger example: realistic-size modulus, deliberately small d
    #    chosen to satisfy Wiener's bound d < N^0.25 / 3
    # -----------------------------------------------------------------
    random.seed(42)
    p = nextprime(random.randint(2**63, 2**64))
    q = nextprime(random.randint(2**63, 2**64))
    N = p * q
    phi = (p - 1) * (q - 1)
    bound = int(N ** 0.25 / 3)
    d = nextprime(random.randint(2, min(bound, 10**6)))
    while math.gcd(d, phi) != 1:
        d = nextprime(d + 1)
    e = pow(d, -1, phi)
    run_demo(f"Realistic modulus, vulnerable small d  (Wiener bound ~ {bound})", e, N, d_expected=d)

    # -----------------------------------------------------------------
    # 3. Safe key: d chosen large (the recommended defence)
    #    The attack should fail to recover the key.
    # -----------------------------------------------------------------
    p = nextprime(random.randint(2**63, 2**64))
    q = nextprime(random.randint(2**63, 2**64))
    N = p * q
    phi = (p - 1) * (q - 1)
    d = nextprime(random.randint(phi // 3, phi - 1))
    while phi % d == 0:
        d = nextprime(d + 1)
    e = pow(d, -1, phi)
    run_demo("Safe key with large d (defence demonstration)", e, N)
