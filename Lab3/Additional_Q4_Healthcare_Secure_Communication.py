"""
ADDITIONAL EXERCISE 4: HEALTHCARE SECURE COMMUNICATION

Question:
A hospital wants to securely transmit patient data over an insecure
network. Implement secure communication using:

1. ElGamal encryption for educational public-key encryption.
2. ECC using ECDH + AES-GCM for practical hybrid encryption.

Encrypt and decrypt sample patient data and measure the execution time.

Context:
Patient information is sensitive and must be protected against
eavesdropping and tampering.

This program demonstrates:

    ElGamal:
        - Public/private key encryption
        - Text-to-integer conversion
        - Encryption and decryption timing

    ECC hybrid encryption:
        - ECDH shared-secret derivation
        - HKDF key derivation
        - AES-GCM authenticated encryption
        - Encryption and decryption timing

Important:
The ElGamal section is textbook and educational. The ECC section is
closer to a practical design because AES-GCM provides confidentiality
and integrity.
"""

import os
import time
from secrets import getPrime, randbelow

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ----------------------------- ElGamal Functions -----------------------------

def text_to_integer(message):
    return int.from_bytes(message.encode("utf-8"), byteorder="big")


def integer_to_text(number):
    byte_length = max(1, (number.bit_length() + 7) // 8)
    return number.to_bytes(byte_length, byteorder="big").decode("utf-8")


def generate_elgamal_keys(prime_bits=512):
    p = getPrime(prime_bits)
    g = 2
    private_key = randbelow(p - 2) + 1
    public_key = pow(g, private_key, p)

    return p, g, public_key, private_key


def elgamal_encrypt(message, p, g, public_key):
    message_integer = text_to_integer(message)

    if message_integer >= p:
        raise ValueError(
            "Message is too large for the selected ElGamal prime."
        )

    ephemeral_key = randbelow(p - 2) + 1

    c1 = pow(g, ephemeral_key, p)
    shared_secret = pow(public_key, ephemeral_key, p)
    c2 = (message_integer * shared_secret) % p

    return c1, c2


def elgamal_decrypt(ciphertext, p, private_key):
    c1, c2 = ciphertext

    shared_secret = pow(c1, private_key, p)
    inverse_secret = pow(shared_secret, -1, p)

    message_integer = (c2 * inverse_secret) % p

    return integer_to_text(message_integer)


# ------------------------------- ECC Functions ------------------------------

def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key


def derive_ecc_aes_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Healthcare-Secure-Communication"
    ).derive(shared_secret)


def ecc_encrypt(message, sender_private_key, receiver_public_key):
    aes_key = derive_ecc_aes_key(
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
    aes_key = derive_ecc_aes_key(
        receiver_private_key,
        sender_public_key
    )

    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


# ----------------------------------- Main ------------------------------------

def main():
    patient_data = (
        "Patient ID: P1024 | Name: Rahul | "
        "Diagnosis: Routine Checkup | Blood Group: O+"
    )

    print("Original patient data:")
    print(patient_data)
    print()

    # -------------------------- ElGamal Measurement --------------------------
    print("========== ElGamal Communication ==========")

    start_time = time.perf_counter()
    p, g, public_key, private_key = generate_elgamal_keys()
    key_generation_time = time.perf_counter() - start_time

    start_time = time.perf_counter()
    elgamal_ciphertext = elgamal_encrypt(
        patient_data,
        p,
        g,
        public_key
    )
    encryption_time = time.perf_counter() - start_time

    start_time = time.perf_counter()
    elgamal_plaintext = elgamal_decrypt(
        elgamal_ciphertext,
        p,
        private_key
    )
    decryption_time = time.perf_counter() - start_time

    print("Decrypted patient data:", elgamal_plaintext)
    print("Verification:", elgamal_plaintext == patient_data)
    print(f"Key generation time: {key_generation_time:.6f} seconds")
    print(f"Encryption time:     {encryption_time:.6f} seconds")
    print(f"Decryption time:     {decryption_time:.6f} seconds")
    print()

    # ---------------------------- ECC Measurement ----------------------------
    print("========== ECC Hybrid Communication ==========")

    start_time = time.perf_counter()
    sender_private_key, sender_public_key = generate_ecc_key_pair()
    receiver_private_key, receiver_public_key = generate_ecc_key_pair()
    key_generation_time = time.perf_counter() - start_time

    start_time = time.perf_counter()
    nonce, ecc_ciphertext = ecc_encrypt(
        patient_data,
        sender_private_key,
        receiver_public_key
    )
    encryption_time = time.perf_counter() - start_time

    start_time = time.perf_counter()
    ecc_plaintext = ecc_decrypt(
        nonce,
        ecc_ciphertext,
        receiver_private_key,
        sender_public_key
    )
    decryption_time = time.perf_counter() - start_time

    print("Decrypted patient data:", ecc_plaintext)
    print("Verification:", ecc_plaintext == patient_data)
    print(f"Key generation time: {key_generation_time:.6f} seconds")
    print(f"Encryption time:     {encryption_time:.6f} seconds")
    print(f"Decryption time:     {decryption_time:.6f} seconds")


if __name__ == "__main__":
    main()
