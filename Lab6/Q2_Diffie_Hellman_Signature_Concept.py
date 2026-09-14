
# ======================================================================
# 1. FULL QUESTION
# ======================================================================
# Lab Exercises 2:
# Try using the Diffie-Hellman asymmetric encryption standard and verify
# the above digital-signature steps.
#
# ======================================================================
# 2. QUESTION / CONTEXT EXPLANATION
# ======================================================================
# Diffie-Hellman establishes a shared secret, but ordinary DH alone does
# not create or verify digital signatures. Authentication must be added
# using certificates, signatures, or authenticated public keys.
#
# ======================================================================
# 3. THEORY AND FORMULAS
# ======================================================================
# Public parameters: p, g
# Alice private value: a
# Bob private value: b
# Alice public value: A = g^a mod p
# Bob public value: B = g^b mod p
# Shared secret:
#   K = B^a mod p = A^b mod p = g^(ab) mod p
#
# ======================================================================
# 4. DETAILED COMMENTS
# ======================================================================
# The program demonstrates key agreement and explains why DH must be
# authenticated to prevent a man-in-the-middle attack.
#
# ======================================================================
# 5. ENCRYPTION / DECRYPTION LOGIC
# ======================================================================
# DH normally derives a shared secret; a symmetric cipher such as AES
# then encrypts the actual message. It does not directly sign a document.
#
# ======================================================================
# 6. BRUTE-FORCE / ATTACK EXERCISES
# ======================================================================
# - Solve the discrete logarithm for deliberately tiny p.
# - Demonstrate a man-in-the-middle attack with unauthenticated DH.
# - Add RSA/Schnorr signatures to authenticate DH public values.
#
# ======================================================================
# 7. CHARACTER MAPPING AND ASSUMPTIONS
# ======================================================================
# DH operates on integers modulo p. Text is encoded separately and should
# be encrypted using a symmetric cipher after key derivation.
# ======================================================================

"""
LAB 6 - DIGITAL SIGNATURE
QUESTION 2

Demonstrate Diffie-Hellman key exchange and explain why DH alone is not
a digital signature.

Steps:
1. Alice and Bob choose private values.
2. They calculate public values.
3. They calculate the same shared secret.
4. The shared secret is used with SHA-256 to derive a key.

Important:
Diffie-Hellman provides key agreement, not authentication. In practice,
combine it with digital signatures or use an authenticated protocol.
"""

import hashlib


def derive_key(shared_secret):
    return hashlib.sha256(
        str(shared_secret).encode("utf-8")
    ).hexdigest()


if __name__ == "__main__":
    p = 23
    g = 5

    alice_private = 6
    bob_private = 15

    alice_public = pow(g, alice_private, p)
    bob_public = pow(g, bob_private, p)

    alice_shared = pow(bob_public, alice_private, p)
    bob_shared = pow(alice_public, bob_private, p)

    print("Alice public value:", alice_public)
    print("Bob public value:", bob_public)
    print("Alice shared secret:", alice_shared)
    print("Bob shared secret:", bob_shared)
    print("Shared secrets match:", alice_shared == bob_shared)
    print("Derived key:", derive_key(alice_shared))

    print("\nObservation:")
    print("DH establishes a shared secret but does not prove identity.")
    print("Digital signatures are required to prevent man-in-the-middle attacks.")
