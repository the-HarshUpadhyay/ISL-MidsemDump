
# ======================================================================
# 1. FULL QUESTION
# ======================================================================
# Lab Exercises 1:
# Try using the ElGammal, Schnorr asymmetric encryption standard and
# verify the above digital-signature steps.
#
# ======================================================================
# 2. QUESTION / CONTEXT EXPLANATION
# ======================================================================
# Demonstrate how a public/private-key signature system can be used to
# sign a message and verify its authenticity and integrity.
#
# ======================================================================
# 3. THEORY AND FORMULAS
# ======================================================================
# ElGamal-style signature systems use modular arithmetic in a group.
# Schnorr signatures use a private signing key, a public verification key,
# a random nonce, a commitment, a challenge, and a response.
#
# Generic Schnorr equations:
#   R = g^k mod p
#   e = H(message || R)
#   s = k + e*x mod q
# Verification checks whether:
#   g^s == R * y^e (mod p)
#
# ======================================================================
# 4. DETAILED COMMENTS
# ======================================================================
# The code uses educational parameters. Real signatures require secure
# parameter generation, cryptographic randomness, and a standard library.
#
# ======================================================================
# 5. SIGNING / VERIFICATION LOGIC
# ======================================================================
# Signing uses the private key and message hash. Verification uses the
# public key and recomputes the challenge from the message and commitment.
#
# ======================================================================
# 6. BRUTE-FORCE / ATTACK EXERCISES
# ======================================================================
# - Try tiny parameters and recover the private key by discrete-log search.
# - Reuse a signing nonce and show why it can reveal the private key.
# - Modify one message character and observe verification failure.
#
# ======================================================================
# 7. CHARACTER MAPPING AND ASSUMPTIONS
# ======================================================================
# Messages are encoded as UTF-8 bytes and hashed. No A=0 character map is
# required for the signature itself; the hash converts arbitrary text into
# a fixed-size integer.
# ======================================================================

"""
LAB 6 - DIGITAL SIGNATURE
QUESTION 1

Try ElGamal and Schnorr-style asymmetric digital signatures.

This program demonstrates:
1. ElGamal signature generation and verification.
2. Schnorr-style signature generation and verification.

Educational parameters are used. Real applications must use standardized,
well-tested libraries and secure large parameters.
"""

import hashlib
import secrets


def hash_to_int(message, modulus):
    digest = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(digest, "big") % modulus


# ---------------- ELGAMAL SIGNATURE ----------------

def elgamal_sign(message, p, g, private_key):
    y = pow(g, private_key, p)
    while True:
        k = secrets.randbelow(p - 2) + 1
        if secrets.SystemRandom().randrange(1, p - 1) and __import__("math").gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inverse = pow(k, -1, p - 1)
    h = hash_to_int(message, p - 1)
    s = ((h - private_key * r) * k_inverse) % (p - 1)

    return y, r, s


def elgamal_verify(message, p, g, public_key, signature):
    y, r, s = public_key, *signature
    if not (0 < r < p and 0 <= s < p - 1):
        return False

    h = hash_to_int(message, p - 1)
    left = pow(g, h, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right


# ---------------- SCHNORR-STYLE SIGNATURE ----------------

def schnorr_sign(message, p, q, g, private_key):
    public_key = pow(g, private_key, p)
    nonce = secrets.randbelow(q - 1) + 1
    commitment = pow(g, nonce, p)
    challenge = hash_to_int(
        f"{commitment}:{message}", q
    )
    response = (nonce + private_key * challenge) % q
    return public_key, commitment, response


def schnorr_verify(message, p, q, g, public_key, signature):
    commitment, response = signature
    challenge = hash_to_int(f"{commitment}:{message}", q)

    left = pow(g, response, p)
    right = (commitment * pow(public_key, challenge, p)) % p
    return left == right


if __name__ == "__main__":
    # Toy values only.
    p = 467
    g = 2
    q = 233
    private_key = 127
    message = "Alice signs this document"

    elgamal_public, r, s = elgamal_sign(
        message, p, g, private_key
    )
    print("ElGamal signature:", (r, s))
    print("ElGamal verified:",
          elgamal_verify(message, p, g, elgamal_public, (r, s)))

    schnorr_public, commitment, response = schnorr_sign(
        message, p, q, g, private_key
    )
    print("Schnorr-style signature:", (commitment, response))
    print("Schnorr verified:",
          schnorr_verify(
              message, p, q, g, schnorr_public,
              (commitment, response)
          ))
