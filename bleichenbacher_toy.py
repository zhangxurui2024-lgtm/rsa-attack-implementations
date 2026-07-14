"""
Bleichenbacher's Padding Oracle Attack on RSA (toy / educational simulation)
=============================================================================
Demonstrates the CONCEPT of Bleichenbacher's 1998 adaptive chosen-ciphertext
attack against PKCS#1 v1.5 padding, using a small RSA modulus so the full
interval-narrowing search completes in seconds rather than requiring the
millions of queries needed against a real 2048-bit key.

Reference: D. Bleichenbacher, "Chosen ciphertext attacks against protocols
based on the RSA encryption standard PKCS #1," CRYPTO '98, 1998.

IMPORTANT: This is a local, self-contained simulation against a modulus we
generate ourselves purely to illustrate the mathematics of the attack for
this report. It is not directed at any real service, and the key size is
deliberately small (toy-sized) purely so the demo runs quickly -- it is not
meant to represent an attack against production RSA.
"""

import math
from sympy import randprime


def generate_keypair(bits=64):
    """Generate a small toy RSA keypair. bits = bit length of each prime."""
    p = randprime(2 ** (bits - 1), 2 ** bits)
    q = randprime(2 ** (bits - 1), 2 ** bits)
    while q == p:
        q = randprime(2 ** (bits - 1), 2 ** bits)
    N = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    d = pow(e, -1, phi)
    return (e, N), (d, N), N.bit_length()


def pkcs1_pad(msg_bytes, k):
    """
    Build a (simplified) PKCS#1 v1.5 block: 0x00 0x02 || PS || 0x00 || M
    k = length of the modulus in bytes.
    """
    ps_len = k - 3 - len(msg_bytes)
    if ps_len < 8:
        raise ValueError("message too long for this modulus")
    ps = bytes([0xFF] * ps_len)  # non-zero padding bytes (fixed for reproducibility)
    return b"\x00\x02" + ps + b"\x00" + msg_bytes


def bytes_to_int(b):
    return int.from_bytes(b, "big")


def int_to_bytes(i, length):
    return i.to_bytes(length, "big")


class PaddingOracle:
    """Simulates a server that leaks ONLY whether a ciphertext decrypts to
    a validly PKCS#1 v1.5-padded block (i.e. starts with 0x00 0x02)."""

    def __init__(self, priv_key, k):
        self.d, self.N = priv_key
        self.k = k
        self.queries = 0

    def check(self, c):
        self.queries += 1
        m = pow(c, self.d, self.N)
        block = int_to_bytes(m, self.k)
        return block[0] == 0x00 and block[1] == 0x02


def ceil_div(a, b):
    return -(-a // b)


def bleichenbacher_attack(pub_key, oracle, c0, k):
    """
    Simplified Bleichenbacher attack. Recovers m0 = c0^d mod N using only
    the oracle's valid/invalid padding signal. Follows the standard
    step 1 / step 2a / step 2b / step 3 structure from the original paper,
    simplified for a single-interval fast path (typical for these toy sizes).
    """
    e, N = pub_key
    B = 2 ** (8 * (k - 2))

    s = 1
    M = [(2 * B, 3 * B - 1)]

    if not oracle.check(c0):
        raise ValueError("c0 is not PKCS#1-conforming; step 1 blinding needed (not implemented in this toy demo)")

    step = 0
    while True:
        step += 1
        if step == 1 or len(M) > 1:
            s += 1
            while True:
                c = (c0 * pow(s, e, N)) % N
                if oracle.check(c):
                    break
                s += 1
        else:
            a, b = M[0]
            r = ceil_div(2 * (b * s - 2 * B), N)
            found = False
            while not found:
                s_lo = ceil_div(2 * B + r * N, b)
                s_hi = (3 * B + r * N) // a
                for s_try in range(s_lo, s_hi + 1):
                    c = (c0 * pow(s_try, e, N)) % N
                    if oracle.check(c):
                        s = s_try
                        found = True
                        break
                if not found:
                    r += 1

        new_M = []
        for (a, b) in M:
            r_lo = ceil_div(a * s - 3 * B + 1, N)
            r_hi = (b * s - 2 * B) // N
            for r in range(r_lo, r_hi + 1):
                new_a = max(a, ceil_div(2 * B + r * N, s))
                new_b = min(b, (3 * B - 1 + r * N) // s)
                if new_a <= new_b:
                    interval = (new_a, new_b)
                    if interval not in new_M:
                        new_M.append(interval)
        M = new_M

        if len(M) == 1 and M[0][0] == M[0][1]:
            return M[0][0], step


if __name__ == "__main__":
    print("Generating toy RSA keypair (small, for demo speed only)...")
    pub, priv, bitlen = generate_keypair(bits=64)  # ~128-bit modulus, toy size
    e, N = pub
    k = (N.bit_length() + 7) // 8
    print(f"N bit length = {N.bit_length()}, k (bytes) = {k}\n")

    secret_message = b"HI"
    block = pkcs1_pad(secret_message, k)
    m0 = bytes_to_int(block)
    c0 = pow(m0, e, N)

    print(f"True secret message: {secret_message}")
    print("Encrypting with PKCS#1 v1.5 padding, then attacking using ONLY "
          "the padding-oracle signal (no private key used by the attacker)...\n")

    oracle = PaddingOracle(priv, k)
    recovered_m, steps = bleichenbacher_attack(pub, oracle, c0, k)
    recovered_bytes = int_to_bytes(recovered_m, k)

    sep_index = recovered_bytes.index(b"\x00", 2)
    recovered_message = recovered_bytes[sep_index + 1:]

    print(f"[RESULT] Oracle queried {oracle.queries} times over {steps} steps")
    print(f"[RESULT] Recovered message: {recovered_message}")
    if recovered_message == secret_message:
        print("[SUCCESS] Recovered message matches the true secret message.")
    else:
        print("[ERROR] Recovered message does NOT match.")

    print("\nNote: against a real 2048-bit key this attack requires on the")
    print("order of hundreds of thousands to millions of oracle queries; the")
    print("toy modulus here is used purely to keep the demo runtime short")
    print("while preserving the exact mathematical structure of the attack.")
