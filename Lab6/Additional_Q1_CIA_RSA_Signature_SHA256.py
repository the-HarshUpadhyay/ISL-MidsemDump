
# ======================================================================
# 1. FULL QUESTION
# ======================================================================
# Additional Exercise 1:
# Explore the link https://www.nmichaels.org/rsa.py for better
# understanding.
#
# Demonstrate the CIA triad using RSA encryption and digital signature
# along with SHA hashing.
#
# ======================================================================
# 2. QUESTION / CONTEXT EXPLANATION
# ======================================================================
# Demonstrate:
# - Confidentiality using RSA encryption or hybrid encryption.
# - Integrity using SHA-256 hashing and signature verification.
# - Authenticity using a digital signature created with a private key.
#
# ======================================================================
# 3. THEORY AND FORMULAS
# ======================================================================
# SHA-256:
#   digest = SHA256(message)
#
# RSA textbook concept:
#   c = m^e mod n
#   m = c^d mod n
#
# Signature concept:
#   signature = Sign(private_key, hash(message))
#   Verify(public_key, hash(message), signature)
#
# In production, use RSA-OAEP for encryption and RSA-PSS for signatures.
#
# ======================================================================
# 4. DETAILED COMMENTS
# ======================================================================
# Hashing alone does not provide authenticity because anyone can compute
# a hash. Signing the hash with a private key provides authenticity and
# tamper detection.
#
# ======================================================================
# 5. ENCRYPTION / DECRYPTION LOGIC
# ======================================================================
# Encrypt the message for confidentiality, hash the original message,
# sign the hash for authenticity/integrity, then verify and decrypt at
# the receiver.
#
# ======================================================================
# 6. BRUTE-FORCE / ATTACK EXERCISES
# ======================================================================
# - Change one message byte and compare SHA-256 digests.
# - Modify a signature and verify failure.
# - Demonstrate why hashing without signing is not authentication.
# - Use tiny RSA values to show why textbook RSA is insecure.
#
# ======================================================================
# 7. CHARACTER MAPPING AND ASSUMPTIONS
# ======================================================================
# SHA-256 accepts arbitrary bytes, including UTF-8 text. RSA operates on
# integers internally. Real applications must use padding, secure random
# keys, certificate validation, and hybrid encryption for long messages.
# ======================================================================

"""
LAB 6 - ADDITIONAL EXERCISE 1

Demonstrate the CIA triad using:
- RSA encryption for confidentiality.
- RSA-PSS digital signature for authenticity and integrity.
- SHA-256 hashing for integrity verification.

Install:
    pip install cryptography
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import secrets


def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":
    # Generate RSA keys.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    document = b"Confidential XYZ Logistics document"

    # Confidentiality:
    # Hybrid encryption: random AES key encrypts the document.
    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    encrypted_document = AESGCM(aes_key).encrypt(
        nonce, document, None
    )

    # RSA encrypts/wraps the AES session key.
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Integrity and authenticity:
    document_hash = sha256_hash(document)
    signature = private_key.sign(
        document,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # Receiver decrypts AES key and document.
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    recovered_document = AESGCM(
        decrypted_aes_key
    ).decrypt(nonce, encrypted_document, None)

    recovered_hash = sha256_hash(recovered_document)

    public_key.verify(
        signature,
        recovered_document,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    print("Original SHA-256:", document_hash)
    print("Recovered SHA-256:", recovered_hash)
    print("Hash matches:", document_hash == recovered_hash)
    print("Recovered document:", recovered_document.decode())
    print("\nCIA Triad:")
    print("Confidentiality: AES-GCM + RSA-OAEP")
    print("Integrity: SHA-256 + AES-GCM authentication tag")
    print("Authenticity: RSA-PSS digital signature")
