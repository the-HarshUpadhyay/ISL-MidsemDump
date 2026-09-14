"""
ADDITIONAL EXERCISE 2: ECC ENCRYPTION AND DECRYPTION

Question:
Using Elliptic Curve Cryptography, encrypt and decrypt the message:

    "Secure Transactions"

Context:
ECC is normally used for public-key operations such as ECDH key exchange
and digital signatures. It is not normally used by directly encrypting
text with an ECC public key.

Therefore, this program uses a practical hybrid approach:

1. Generate ECC private/public key pairs.
2. Use ECDH to derive a shared secret.
3. Use HKDF to derive a symmetric AES key.
4. Encrypt the message using AES-GCM.
5. Derive the same key during decryption and recover the message.

Curve used:
    SECP256R1

This is a practical educational design for ECC-based encryption.
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Generate an ECC private/public key pair.
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key


# Derive a 256-bit AES key using ECDH and HKDF.
def derive_aes_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECC-Hybrid-Encryption"
    ).derive(shared_secret)

    return aes_key


# Encrypt a message using ECC-derived AES key.
def encrypt_message(message, sender_private_key, receiver_public_key):
    aes_key = derive_aes_key(
        sender_private_key,
        receiver_public_key
    )

    nonce = os.urandom(12)
    aes_cipher = AESGCM(aes_key)

    ciphertext = aes_cipher.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return nonce, ciphertext


# Decrypt a message using the same ECDH-derived AES key.
def decrypt_message(
    nonce,
    ciphertext,
    receiver_private_key,
    sender_public_key
):
    aes_key = derive_aes_key(
        receiver_private_key,
        sender_public_key
    )

    aes_cipher = AESGCM(aes_key)

    plaintext = aes_cipher.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


def main():
    message = "Secure Transactions"

    # Sender and receiver generate their ECC key pairs.
    sender_private_key, sender_public_key = generate_ecc_key_pair()
    receiver_private_key, receiver_public_key = generate_ecc_key_pair()

    print("Original message:", message)

    nonce, ciphertext = encrypt_message(
        message,
        sender_private_key,
        receiver_public_key
    )

    print("Ciphertext:", ciphertext.hex())

    decrypted_message = decrypt_message(
        nonce,
        ciphertext,
        receiver_private_key,
        sender_public_key
    )

    print("Decrypted message:", decrypted_message)
    print("Verification:", decrypted_message == message)


if __name__ == "__main__":
    main()
