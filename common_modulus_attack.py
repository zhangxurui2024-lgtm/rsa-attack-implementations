"""
Common Modulus Attack on RSA
=============================
Demonstrates recovery of a plaintext m that was encrypted twice under the
same modulus N with two different, coprime public exponents e1 and e2 --
without any knowledge of either private key.

Reference: D. Boneh, "Twenty years of attacks on the RSA cryptosystem,"
Notices of the American Mathematical Society, vol. 46, no. 2, pp. 203-213, 1999.

This reproduces:
  1. The Appendix B worked example (N=667, e1=5, e2=7, m=42)
  2. A realistic-size modulus example with randomly generated primes
  3. A control case where gcd(e1, e2) != 1, showing the attack correctly
     fails when its precondition is not met
"""

from sympy import nextprime
import random
import math


def extended_gcd(a, b):
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t  # g, x, y


def common_modulus_attack(N, e1, c1, e2, c2):
    """
    Recover plaintext m given two ciphertexts of the SAME message m,
    encrypted under the SAME modulus N but different exponents e1, e2.
    Requires gcd(e1, e2) == 1. Returns m, or None if the precondition fails.
    """
    g, r, s = extended_gcd(e1, e2)
    if g != 1:
        return None  # precondition violated: e1, e2 not coprime

    if r < 0:
        c1 = pow(c1, -1, N)   # modular inverse, since c1^r needs r >= 0
        r = -r
    if s < 0:
        c2 = pow(c2, -1, N)
        s = -s

    m = (pow(c1, r, N) * pow(c2, s, N)) % N
    return m


def run_demo(name, N, e1, e2, m_true):
    print(f"--- {name} ---")
    print(f"N = {N}")
    print(f"e1 = {e1}, e2 = {e2}, gcd(e1, e2) = {math.gcd(e1, e2)}")

    c1 = pow(m_true, e1, N)
    c2 = pow(m_true, e2, N)
    print(f"c1 = {c1}")
    print(f"c2 = {c2}")

    recovered = common_modulus_attack(N, e1, c1, e2, c2)
    if recovered is None:
        print("[FAILED] Attack precondition not met (gcd(e1, e2) != 1); "
              "as expected, the plaintext cannot be recovered this way.")
    elif recovered == m_true:
        print(f"[SUCCESS] Recovered plaintext m = {recovered} (matches true m = {m_true})")
    else:
        print(f"[ERROR] Recovered m = {recovered} does NOT match true m = {m_true}")
    print()


if __name__ == "__main__":
    # -----------------------------------------------------------------
    # 1. Reproduce the Appendix B worked example
    # -----------------------------------------------------------------
    run_demo("Appendix B worked example (toy, N=667)", N=667, e1=5, e2=7, m_true=42)

    # -----------------------------------------------------------------
    # 2. Realistic-size modulus
    # -----------------------------------------------------------------
    random.seed(7)
    p = nextprime(random.randint(2**63, 2**64))
    q = nextprime(random.randint(2**63, 2**64))
    N = p * q
    e1, e2 = 17, 65537
    m_true = random.randint(2, N - 1)
    run_demo("Realistic modulus, coprime exponents", N=N, e1=e1, e2=e2, m_true=m_true)

    # -----------------------------------------------------------------
    # 3. Control case: e1, e2 share a common factor -> attack must fail
    # -----------------------------------------------------------------
    e1, e2 = 6, 10  # gcd = 2
    run_demo("Control case: non-coprime exponents (attack should fail)",
             N=N, e1=e1, e2=e2, m_true=m_true)
