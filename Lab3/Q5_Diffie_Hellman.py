"""
============================================================
LAB 3 - QUESTION 5: DIFFIE-HELLMAN KEY EXCHANGE
============================================================

QUESTION:
As part of a project to enhance the security of communication
in a peer-to-peer file sharing system, implement a secure key
exchange mechanism using the Diffie-Hellman algorithm.

Each peer must establish a shared secret key with another peer
over an insecure channel.

Requirements:
1. Generate public and private keys for each peer.
2. Exchange public keys.
3. Compute the shared secret key.
4. Measure key generation and key exchange time.

CONTEXT:
Diffie-Hellman allows two parties to establish a common secret
over an insecure channel without directly transmitting the
secret key.

PUBLIC PARAMETERS:
    p = large prime
    g = generator

ALICE:
    private_a = random private key
    public_A = g^a mod p

BOB:
    private_b = random private key
    public_B = g^b mod p

SHARED SECRET:
    Alice computes:
        S = B^a mod p

    Bob computes:
        S = A^b mod p

Both values are equal to:
        S = g^(ab) mod p

LIBRARY:
    pip install pycryptodome

NOTE:
This demonstrates textbook Diffie-Hellman. In real systems,
use authenticated key exchange and a standardized group or
protocol to prevent man-in-the-middle attacks.
"""

import time

from Crypto.Util.number import getPrime
from secrets import randbelow


def generate_dh_parameters(prime_bits=2048):
    """Generate public DH parameters p and g."""
    p = getPrime(prime_bits)
    g = 2
    return p, g


def generate_private_key(p):
    """Generate a private DH key."""
    return randbelow(p - 2) + 1


def generate_public_key(private_key, g, p):
    """Calculate public key: g^private_key mod p."""
    return pow(g, private_key, p)


def calculate_shared_secret(peer_public_key,
                            private_key, p):
    """Calculate shared secret using peer's public key."""
    return pow(peer_public_key, private_key, p)


def main():
    print("===== DIFFIE-HELLMAN KEY EXCHANGE =====")

    # Step 1: Generate public parameters
    start_time = time.perf_counter()
    p, g = generate_dh_parameters()
    parameter_time = time.perf_counter() - start_time

    # Step 2: Alice generates private and public keys
    start_time = time.perf_counter()

    alice_private = generate_private_key(p)
    alice_public = generate_public_key(
        alice_private,
        g,
        p
    )

    alice_time = time.perf_counter() - start_time

    # Step 3: Bob generates private and public keys
    start_time = time.perf_counter()

    bob_private = generate_private_key(p)
    bob_public = generate_public_key(
        bob_private,
        g,
        p
    )

    bob_time = time.perf_counter() - start_time

    # Step 4: Exchange public keys and calculate secrets
    start_time = time.perf_counter()

    alice_shared_secret = calculate_shared_secret(
        bob_public,
        alice_private,
        p
    )

    bob_shared_secret = calculate_shared_secret(
        alice_public,
        bob_private,
        p
    )

    exchange_time = time.perf_counter() - start_time

    # Step 5: Display results
    print("\nPublic parameters generated.")
    print("Prime modulus bit length:", p.bit_length())
    print("Generator:", g)

    print("\nAlice public key:")
    print(alice_public)

    print("\nBob public key:")
    print(bob_public)

    print("\nShared secret matches:",
          alice_shared_secret == bob_shared_secret)

    print("\n===== TIMING RESULTS =====")
    print(f"Parameter generation: {parameter_time:.6f} seconds")
    print(f"Alice key generation: {alice_time:.6f} seconds")
    print(f"Bob key generation:   {bob_time:.6f} seconds")
    print(f"Key exchange:         {exchange_time:.6f} seconds")


if __name__ == "__main__":
    main()
