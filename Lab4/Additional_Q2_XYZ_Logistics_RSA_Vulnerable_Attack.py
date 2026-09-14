
# ======================================================================
# 1. FULL QUESTION
# ======================================================================
# Suppose XYZ Logistics uses RSA to secure sensitive communications.
# Eve has obtained a partial copy of the RSA private key and attempts to
# recover the full private key to decrypt company communications.
#
# Eve exploits a vulnerability in RSA key generation: the prime factors
# p and q used to generate n are not sufficiently large or random.
#
# Develop a Python script demonstrating the attack on the vulnerable RSA
# cryptosystem and discuss mitigation steps.
#
# ======================================================================
# 2. QUESTION / CONTEXT EXPLANATION
# ======================================================================
# RSA security depends heavily on keeping p and q secret and making them
# unpredictable. If n can be factored, the private exponent can be rebuilt.
#
# ======================================================================
# 3. THEORY AND FORMULAS
# ======================================================================
# n = p*q
# phi(n) = (p-1)*(q-1)
# d = e^(-1) mod phi(n)
# Encryption: c = m^e mod n
# Decryption: m = c^d mod n
#
# ======================================================================
# 4. DETAILED COMMENTS / IMPLEMENTATION PLAN
# ======================================================================
# 1. Use intentionally tiny toy primes.
# 2. Publish n and e.
# 3. Recover p by trial division or a supplied weak factor.
# 4. Compute q = n//p.
# 5. Recompute phi(n), then d.
# 6. Decrypt a toy ciphertext.
#
# ======================================================================
# 5. ENCRYPTION / DECRYPTION LOGIC
# ======================================================================
# Once p and q are known, calculate phi(n), find d, and apply c^d mod n.
#
# ======================================================================
# 6. BRUTE-FORCE / ATTACK EXERCISES
# ======================================================================
# - Trial-divide a tiny n.
# - Test weak/predictable prime generation.
# - Demonstrate partial-key recovery when a factor is known.
# - Discuss why factoring a properly generated 2048-bit modulus is not
#   feasible using ordinary brute force.
#
# ======================================================================
# 7. CHARACTER MAPPING AND ASSUMPTIONS
# ======================================================================
# RSA works with integers. Encode text as bytes and ensure m < n.
# This is a controlled educational attack using toy values only.
# Mitigations: secure randomness, sufficiently large keys, OAEP,
# hardware-backed key storage, rotation, revocation, and monitoring.
# ======================================================================

"""
LAB 4 - ADVANCED ASYMMETRIC KEY CIPHERS
ADDITIONAL QUESTION 2

XYZ Logistics uses RSA. Eve has obtained a partial private key and tries
to recover the full private key because the RSA modulus was generated
using small or insufficiently random prime factors.

Demonstration:
1. Generate deliberately small vulnerable RSA primes.
2. Publish n and e.
3. Eve factors n by trial division.
4. Eve computes phi(n) and private exponent d.
5. Eve decrypts a ciphertext.

This is an educational toy attack. It must not be used against systems
without authorization.

Mitigations:
- Use sufficiently large RSA keys, normally at least 2048 bits.
- Generate primes with a cryptographically secure random generator.
- Never reuse primes across keys.
- Use a vetted cryptographic library.
- Use OAEP for RSA encryption.
- Protect private keys with HSMs and access controls.
- Rotate and revoke compromised keys.
- Monitor for weak moduli and shared factors.
"""

from math import gcd


def is_prime(number):
    if number < 2:
        return False
    for divisor in range(2, int(number ** 0.5) + 1):
        if number % divisor == 0:
            return False
    return True


def generate_vulnerable_rsa():
    # Deliberately tiny primes: insecure by design.
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = pow(e, -1, phi)
    return p, q, n, e, d


def factor_by_trial_division(n):
    """Eve's attack: find p and q because n is very small."""
    for p in range(2, int(n ** 0.5) + 1):
        if n % p == 0 and is_prime(p):
            q = n // p
            if is_prime(q):
                return p, q
    raise ValueError("Could not factor modulus")


def rsa_encrypt(message_int, e, n):
    return pow(message_int, e, n)


def rsa_decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n)


if __name__ == "__main__":
    original_p, original_q, n, e, original_d = generate_vulnerable_rsa()

    plaintext = 65
    ciphertext = rsa_encrypt(plaintext, e, n)

    print("Public key (n, e):", (n, e))
    print("Ciphertext:", ciphertext)

    # Eve only knows the public modulus n and exponent e.
    recovered_p, recovered_q = factor_by_trial_division(n)
    recovered_phi = (recovered_p - 1) * (recovered_q - 1)
    recovered_d = pow(e, -1, recovered_phi)
    recovered_plaintext = rsa_decrypt(ciphertext, recovered_d, n)

    print("Eve recovered p and q:", recovered_p, recovered_q)
    print("Eve recovered private exponent d:", recovered_d)
    print("Recovered plaintext:", recovered_plaintext)
    print("Attack successful:", recovered_plaintext == plaintext)

    print("\nMitigation summary:")
    print("1. Use RSA-2048 or stronger with secure random prime generation.")
    print("2. Use OAEP padding, not textbook RSA.")
    print("3. Protect, rotate, and revoke private keys.")
    print("4. Audit key generation and detect shared prime factors.")
