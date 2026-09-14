"""
============================================================
LAB 3 - QUESTION 2: ECC ENCRYPTION AND DECRYPTION
============================================================

QUESTION:
Using ECC (Elliptic Curve Cryptography), encrypt the message
"Secure Transactions" with the public key. Then decrypt the
ciphertext with the private key to verify the original message.

CONTEXT:
ECC is an asymmetric cryptographic technique based on the
algebraic structure of elliptic curves over finite fields.

ECC KEY GENERATION:
1. Select an elliptic curve, such as secp256r1.
2. Generate a private key d.
3. Calculate the public key:
       Q = d * G

where G is the base point on the curve.

IMPORTANT:
ECC is normally used for key exchange rather than directly
encrypting strings. Therefore, this program uses:

    ECDH  -> derive a shared secret
    HKDF  -> derive a symmetric AES key
    AES-GCM -> encrypt and authenticate the message

LIBRARY:
    pip install cryptography
"""

import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_ecc_key_pair():
    """Generate an ECC private key and its public key."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_aes_key(private_key, peer_public_key):
    """
    Derive a 256-bit AES key using ECDH and HKDF.
    Both parties derive the same key.
    """
    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Lab 3 ECC Encryption"
    ).derive(shared_secret)

    return aes_key


def encrypt_message(message, sender_private_key,
                    receiver_public_key):
    """Encrypt a message using ECDH-derived AES-GCM key."""
    aes_key = derive_aes_key(
        sender_private_key,
        receiver_public_key
    )

    # AES-GCM requires a unique nonce for each encryption
    nonce = os.urandom(12)

    cipher = AESGCM(aes_key)

    ciphertext = cipher.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return nonce, ciphertext


def decrypt_message(nonce, ciphertext,
                    receiver_private_key,
                    sender_public_key):
    """Decrypt AES-GCM ciphertext using the ECDH-derived key."""
    aes_key = derive_aes_key(
        receiver_private_key,
        sender_public_key
    )

    cipher = AESGCM(aes_key)

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


def main():
    print("===== ECC-BASED ENCRYPTION AND DECRYPTION =====")

    # Original message from the lab question
    message = "Secure Transactions"

    # Sender generates an ECC key pair
    sender_private, sender_public = generate_ecc_key_pair()

    # Receiver generates an ECC key pair
    receiver_private, receiver_public = generate_ecc_key_pair()

    # Sender encrypts using receiver's public key
    nonce, ciphertext = encrypt_message(
        message,
        sender_private,
        receiver_public
    )

    print("\nOriginal message:", message)
    print("Ciphertext:", ciphertext.hex())

    # Receiver decrypts using receiver's private key
    # and sender's public key
    decrypted_message = decrypt_message(
        nonce,
        ciphertext,
        receiver_private,
        sender_public
    )

    print("Decrypted message:", decrypted_message)
    print("Verification:", message == decrypted_message)


if __name__ == "__main__":
    main()
