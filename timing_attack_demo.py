"""
Timing Side-Channel Attack on RSA Decryption (educational simulation)
========================================================================
Demonstrates Kocher's 1996 observation that a naive (non-constant-time)
square-and-multiply modular exponentiation leaks information about the
private exponent's bits through execution time, and that a Montgomery-
ladder-style constant-time implementation removes that signal.

Reference: P. Kocher, "Timing attacks on implementations of Diffie-Hellman,
RSA, DSS, and other systems," CRYPTO '96, 1996.

This uses an operation-count MODEL rather than measuring real wall-clock
time, because real hardware timing noise on a shared cloud container is
far too noisy to reproduce Kocher's result reliably in a short demo. The
model captures the real mechanism: naive square-and-multiply performs an
extra multiplication only when the current exponent bit is 1, so total
operation count (which determines wall-clock time on real hardware)
correlates with the number of 1-bits processed.
"""

import random


def naive_modexp(base, exponent, modulus, op_counter):
    """
    Textbook square-and-multiply. Branches on each bit of the exponent:
    an EXTRA multiplication happens only when the bit is 1.
    op_counter is a mutable [int] used to count multiplications performed,
    standing in for "time" in this simulation.
    """
    result = 1
    base = base % modulus
    for bit in bin(exponent)[2:]:
        result = (result * result) % modulus
        op_counter[0] += 1
        if bit == "1":
            result = (result * base) % modulus
            op_counter[0] += 1  # extra multiply only happens on 1-bits
    return result


def constant_time_modexp(base, exponent, modulus, op_counter):
    """
    Montgomery-ladder style: ALWAYS performs a squaring and a multiplication
    at every bit position, regardless of the bit's value, so operation count
    (and real timing) is independent of the exponent's bit pattern.
    """
    r0, r1 = 1, base % modulus
    for bit in bin(exponent)[2:]:
        if bit == "0":
            r1 = (r0 * r1) % modulus
            r0 = (r0 * r0) % modulus
        else:
            r0 = (r0 * r1) % modulus
            r1 = (r1 * r1) % modulus
        op_counter[0] += 2  # always two multiplications, every bit
    return r0


def measure(modexp_fn, base, exponent, modulus):
    counter = [0]
    modexp_fn(base, exponent, modulus, counter)
    return counter[0]


if __name__ == "__main__":
    random.seed(1)
    p, q = 1009, 1013
    N = p * q

    d1 = 733   # arbitrary private exponent #1 for this demo
    d2 = 611   # arbitrary private exponent #2, different bit pattern

    d1_bits = bin(d1)[2:]
    d2_bits = bin(d2)[2:]
    hw1 = d1_bits.count("1")
    hw2 = d2_bits.count("1")

    print(f"d1 = {d1}  (binary: {d1_bits}, {len(d1_bits)} bits, {hw1} one-bits)")
    print(f"d2 = {d2}  (binary: {d2_bits}, {len(d2_bits)} bits, {hw2} one-bits)\n")

    print("=== Naive square-and-multiply: operation count vs number of 1-bits ===")
    m = random.randint(2, N - 1)
    ops_naive_d1 = measure(naive_modexp, m, d1, N)
    ops_naive_d2 = measure(naive_modexp, m, d2, N)
    print(f"naive_modexp with d1: {ops_naive_d1} multiplications "
          f"(expected len+weight = {len(d1_bits) + hw1})")
    print(f"naive_modexp with d2: {ops_naive_d2} multiplications "
          f"(expected len+weight = {len(d2_bits) + hw2})")
    print("-> Operation count (and hence real execution time) DIFFERS "
          "between d1 and d2, correlated with hamming weight.\n")

    print("=== Constant-time (Montgomery-ladder style) implementation ===")
    ops_ct_d1 = measure(constant_time_modexp, m, d1, N)
    ops_ct_d2 = measure(constant_time_modexp, m, d2, N)
    print(f"constant_time_modexp with d1: {ops_ct_d1} multiplications "
          f"(expected 2*len = {2 * len(d1_bits)})")
    print(f"constant_time_modexp with d2: {ops_ct_d2} multiplications "
          f"(expected 2*len = {2 * len(d2_bits)})")
    print("-> Operation count depends ONLY on bit length, never on which "
          "bits are 1: the timing side-channel is eliminated.\n")

    print("=== Determinism check across many random messages (naive impl) ===")
    print("Naive op-count is a function of d alone (never the message), which")
    print("is exactly why an attacker who can measure many decryptions of")
    print("different messages can isolate the signal caused by d's bits from")
    print("measurement noise:\n")
    counts_d1 = {measure(naive_modexp, random.randint(2, N - 1), d1, N) for _ in range(50)}
    counts_d2 = {measure(naive_modexp, random.randint(2, N - 1), d2, N) for _ in range(50)}
    print(f"d1: distinct op-counts across 50 random messages = {counts_d1} "
          f"(always the same value -> pure function of d)")
    print(f"d2: distinct op-counts across 50 random messages = {counts_d2} "
          f"(always the same value -> pure function of d)")
