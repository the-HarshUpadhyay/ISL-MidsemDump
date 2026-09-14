"""
ADDITIONAL EXERCISE 5: COMPARISON OF RSA, ELGAMAL AND ECC

Question:
Compare RSA 2048-bit, ElGamal and ECC for secure communication.

The comparison should discuss:

1. Key generation
2. Encryption/decryption performance
3. Key size
4. Storage overhead
5. Security considerations
6. Strengths and weaknesses

Context:
The lab manual may describe "ElGamal using secp256r1". This is technically
incorrect because:

    - ElGamal is traditionally defined over a finite multiplicative group.
    - secp256r1 is an elliptic curve.
    - ECC-based encryption normally uses ECDH or an ECIES-style hybrid scheme.

Therefore, this program compares:

    RSA-2048
    ElGamal over a finite field
    ECC secp256r1 using ECDH + AES-GCM

The program measures key-generation and small-message encryption/decryption
times. Results vary depending on the computer.
"""

import os
import time
from secrets import getPrime, randbelow

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ------------------------------- RSA Functions -------------------------------

def generate_rsa_key_pair():
    return RSA.generate(2048)


def rsa_encrypt(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode("utf-8"))


def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext).decode("utf-8")


# ----------------------------- ElGamal Functions -----------------------------

def generate_elgamal_key_pair(prime_bits=512):
    p = getPrime(prime_bits)
    g = 2
    private_key = randbelow(p - 2) + 1
    public_key = pow(g, private_key, p)

    return p, g, public_key, private_key


def text_to_integer(message):
    return int.from_bytes(message.encode("utf-8"), byteorder="big")


def integer_to_text(number):
    byte_length = max(1, (number.bit_length() + 7) // 8)
    return number.to_bytes(byte_length, byteorder="big").decode("utf-8")


def elgamal_encrypt(message, p, g, public_key):
    message_integer = text_to_integer(message)

    if message_integer >= p:
        raise ValueError("Message is too large for ElGamal prime.")

    k = randbelow(p - 2) + 1
    c1 = pow(g, k, p)
    shared_secret = pow(public_key, k, p)
    c2 = (message_integer * shared_secret) % p

    return c1, c2


def elgamal_decrypt(ciphertext, p, private_key):
    c1, c2 = ciphertext
    shared_secret = pow(c1, private_key, p)
    inverse_secret = pow(shared_secret, -1, p)
    message_integer = (c2 * inverse_secret) % p

    return integer_to_text(message_integer)


# ------------------------------- ECC Functions -------------------------------

def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key


def derive_aes_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Comparison-Demo"
    ).derive(shared_secret)


def ecc_encrypt(message, sender_private_key, receiver_public_key):
    aes_key = derive_aes_key(
        sender_private_key,
        receiver_public_key
    )

    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return nonce, ciphertext


def ecc_decrypt(
    nonce,
    ciphertext,
    receiver_private_key,
    sender_public_key
):
    aes_key = derive_aes_key(
        receiver_private_key,
        sender_public_key
    )

    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


# ------------------------------- Timing Helper -------------------------------

def measure_time(function, *args):
    start_time = time.perf_counter()
    result = function(*args)
    elapsed_time = time.perf_counter() - start_time

    return result, elapsed_time


# ----------------------------------- Main ------------------------------------

def main():
    message = "Secure Communication"

    print("Message used for comparison:", message)
    print()

    # -------------------------------- RSA --------------------------------
    print("========== RSA-2048 ==========")

    rsa_keys, rsa_keygen_time = measure_time(generate_rsa_key_pair)
    rsa_private_key = rsa_keys
    rsa_public_key = rsa_keys.publickey()

    rsa_ciphertext, rsa_encrypt_time = measure_time(
        rsa_encrypt,
        message,
        rsa_public_key
    )

    rsa_plaintext, rsa_decrypt_time = measure_time(
        rsa_decrypt,
        rsa_ciphertext,
        rsa_private_key
    )

    print(f"Key generation time: {rsa_keygen_time:.6f} seconds")
    print(f"Encryption time:     {rsa_encrypt_time:.6f} seconds")
    print(f"Decryption time:     {rsa_decrypt_time:.6f} seconds")
    print("Verification:", rsa_plaintext == message)
    print("Approximate modulus size: 2048 bits")
    print()

    # ------------------------------- ElGamal -------------------------------
    print("========== ElGamal ==========")

    elgamal_keys, elgamal_keygen_time = measure_time(
        generate_elgamal_key_pair
    )
    p, g, elgamal_public_key, elgamal_private_key = elgamal_keys

    elgamal_ciphertext, elgamal_encrypt_time = measure_time(
        elgamal_encrypt,
        message,
        p,
        g,
        elgamal_public_key
    )

    elgamal_plaintext, elgamal_decrypt_time = measure_time(
        elgamal_decrypt,
        elgamal_ciphertext,
        p,
        elgamal_private_key
    )

    print(f"Key generation time: {elgamal_keygen_time:.6f} seconds")
    print(f"Encryption time:     {elgamal_encrypt_time:.6f} seconds")
    print(f"Decryption time:     {elgamal_decrypt_time:.6f} seconds")
    print("Verification:", elgamal_plaintext == message)
    print("Educational prime size: 512 bits")
    print()

    # -------------------------------- ECC --------------------------------
    print("========== ECC secp256r1 Hybrid ==========")

    ecc_keys, ecc_keygen_time = measure_time(
        lambda: (
            generate_ecc_key_pair(),
            generate_ecc_key_pair()
        )
    )

    (sender_private_key, sender_public_key), (
        receiver_private_key,
        receiver_public_key
    ) = ecc_keys

    ecc_ciphertext_data, ecc_encrypt_time = measure_time(
        ecc_encrypt,
        message,
        sender_private_key,
        receiver_public_key
    )

    nonce, ecc_ciphertext = ecc_ciphertext_data

    ecc_plaintext, ecc_decrypt_time = measure_time(
        ecc_decrypt,
        nonce,
        ecc_ciphertext,
        receiver_private_key,
        sender_public_key
    )

    print(f"Key generation time: {ecc_keygen_time:.6f} seconds")
    print(f"Encryption time:     {ecc_encrypt_time:.6f} seconds")
    print(f"Decryption time:     {ecc_decrypt_time:.6f} seconds")
    print("Verification:", ecc_plaintext == message)
    print("Curve: secp256r1")
    print("ECC public-key size: approximately 256-bit security level curve")
    print()

    # ----------------------------- Summary -----------------------------
    print("========== Comparison Summary ==========")
    print("RSA:")
    print("- Mature and widely supported.")
    print("- Larger keys and comparatively expensive operations.")
    print("- OAEP padding is required for secure encryption.")

    print("\nElGamal:")
    print("- Ciphertext is larger than the plaintext.")
    print("- Requires a fresh random ephemeral key for every encryption.")
    print("- Textbook implementation is not suitable for production.")

    print("\nECC:")
    print("- Small public keys for comparable security.")
    print("- Efficient key exchange.")
    print("- Usually combined with symmetric encryption such as AES-GCM.")
    print("- Requires correct curve validation and authenticated protocols.")


if __name__ == "__main__":
    main()
