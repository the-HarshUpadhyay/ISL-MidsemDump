
# ======================================================================
# 1. FULL QUESTION
# ======================================================================
# SecureCorp is a large enterprise with multiple subsidiaries and business
# units located across different geographical regions. As part of their
# digital transformation initiative, the IT team at SecureCorp has been
# tasked with building a secure and scalable communication system to
# enable seamless collaboration and information sharing between their
# various subsystems.
#
# The enterprise system consists of the following key subsystems:
# 1. Finance System (System A): Responsible for all financial record-keeping,
#    accounting, and reporting.
# 2. HR System (System B): Manages employee data, payroll, and personnel-
#    related processes.
# 3. Supply Chain Management (System C): Coordinates the flow of goods,
#    services, and information across the organization's supply chain.
#
# These subsystems need to communicate securely and exchange critical
# documents, such as financial reports, employee contracts, and procurement
# orders, to ensure the enterprise's overall efficiency.
#
# Requirements:
# 1. Secure Communication: Establish secure communication channels using
#    RSA encryption and Diffie-Hellman key exchange.
# 2. Key Management: Generate, distribute, and revoke keys as needed.
# 3. Scalability: Support the addition of new subsystems in the future.
#
# Implement a Python program which incorporates the requirements.
#
# ======================================================================
# 2. QUESTION / CONTEXT EXPLANATION
# ======================================================================
# This is a modular demonstration: each subsystem is represented by an
# identifier, keys are generated centrally, and key lifecycle operations
# are exposed through functions or classes.
#
# ======================================================================
# 3. THEORY AND FORMULAS
# ======================================================================
# RSA:
#   n = p*q
#   phi(n) = (p-1)*(q-1)
#   d*e ≡ 1 (mod phi(n))
#   Encryption: c = m^e mod n
#   Decryption: m = c^d mod n
#
# Diffie-Hellman:
#   A = g^a mod p
#   B = g^b mod p
#   Shared secret = A^b mod p = B^a mod p
#
# ======================================================================
# 4. DETAILED COMMENTS / IMPLEMENTATION PLAN
# ======================================================================
# 1. Define a registry for subsystems.
# 2. Generate or assign keys.
# 3. Use public keys for encryption and private keys for decryption.
# 4. Use DH to derive a shared secret.
# 5. Add revoke_key() and rotate_key() operations.
# 6. Avoid printing private keys in real deployments.
#
# ======================================================================
# 5. ENCRYPTION / DECRYPTION LOGIC
# ======================================================================
# RSA encrypts a numeric message smaller than n. For long documents, use
# hybrid encryption: AES encrypts the document and RSA encrypts the AES key.
#
# ======================================================================
# 6. BRUTE-FORCE / ATTACK EXERCISES
# ======================================================================
# Educational extensions:
# - Try factoring a deliberately tiny RSA modulus.
# - Demonstrate why small or predictable primes are insecure.
# - Compare key-generation and encryption timings.
# - Demonstrate DH man-in-the-middle risk when public keys are not
#   authenticated.
#
# ======================================================================
# 7. CHARACTER MAPPING AND ASSUMPTIONS
# ======================================================================
# RSA and DH operate on integers, not directly on characters.
# Text must be encoded to bytes and converted to integers.
# The demonstration parameters are small and are NOT secure for production.
# Real systems require large keys, secure randomness, authentication,
# padding such as OAEP, and authenticated key exchange.
# ======================================================================

"""
LAB 4 - ADVANCED ASYMMETRIC KEY CIPHERS
QUESTION 1

SecureCorp has Finance (System A), HR (System B), and Supply Chain
(System C). Implement a scalable secure communication solution that:

1. Establishes secure communication using RSA and Diffie-Hellman.
2. Generates, distributes, rotates, and revokes keys.
3. Supports adding new subsystems in the future.

Educational demonstration:
- RSA signs/verifies and wraps a symmetric session key.
- Diffie-Hellman derives a shared secret.
- AES-GCM encrypts the actual document.
- KeyManager stores public keys and revocation status.

Install:
    pip install cryptography
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class Subsystem:
    name: str
    rsa_private_key: object
    rsa_public_key: object
    dh_private_key: object
    dh_public_key: object
    revoked: bool = False


class KeyManager:
    """Centralized demo key-management service."""

    def __init__(self):
        self.subsystems = {}
        self.audit_log = []

        # Generate DH parameters only once.
        self.dh_parameters = dh.generate_parameters(
            generator=2,
            key_size=2048
        )

    def _log(self, operation, subsystem):
        self.audit_log.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "operation": operation,
            "subsystem": subsystem,
        })

    def register_subsystem(self, name):

        if name in self.subsystems and not self.subsystems[name].revoked:
            raise ValueError("Subsystem already exists")

        # Generate RSA private key
        rsa_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Generate DH private key using shared parameters
        dh_private = self.dh_parameters.generate_private_key()

        self.subsystems[name] = Subsystem(
            name=name,
            rsa_private_key=rsa_private,
            rsa_public_key=rsa_private.public_key(),
            dh_private_key=dh_private,
            dh_public_key=dh_private.public_key(),
        )

        self._log("REGISTER/GENERATE_KEYS", name)

    def revoke_subsystem(self, name):

        if name not in self.subsystems:
            raise ValueError("Subsystem not found")

        if self.subsystems[name].revoked:
            raise ValueError("Subsystem already revoked")

        self.subsystems[name].revoked = True

        self._log("REVOKE_KEYS", name)

    def rotate_subsystem(self, name):

        self.revoke_subsystem(name)

        self.register_subsystem(name)

        self._log("ROTATE_KEYS", name)

        return self.subsystems[name]

    def get_public_keys(self, name):

        if name not in self.subsystems:
            raise ValueError("Subsystem not found")

        subsystem = self.subsystems[name]

        if subsystem.revoked:
            raise PermissionError("Subsystem is revoked")

        return (
            subsystem.rsa_public_key,
            subsystem.dh_public_key
        )


def derive_session_key(sender, receiver):
    """
    Derive the same 256-bit key at both endpoints
    using Diffie-Hellman + HKDF.
    """

    if sender.revoked or receiver.revoked:
        raise PermissionError(
            "A revoked subsystem cannot communicate"
        )

    # Sender computes shared secret
    sender_shared = sender.dh_private_key.exchange(
        receiver.dh_public_key
    )

    # Receiver computes shared secret
    receiver_shared = receiver.dh_private_key.exchange(
        sender.dh_public_key
    )

    assert sender_shared == receiver_shared

    # Derive AES session key
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SecureCorp session key",
    ).derive(sender_shared)


def encrypt_document(sender, receiver, document):

    session_key = derive_session_key(sender, receiver)

    # Generate a unique nonce
    nonce = secrets.token_bytes(12)

    # Encrypt document using AES-GCM
    ciphertext = AESGCM(session_key).encrypt(
        nonce,
        document,
        None
    )

    # Sign ciphertext using sender's RSA private key
    signature = sender.rsa_private_key.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return nonce, ciphertext, signature


def decrypt_document(sender, receiver, package):

    nonce, ciphertext, signature = package

    # Verify sender signature before decrypting
    sender.rsa_public_key.verify(
        signature,
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # Derive same session key at receiver
    session_key = derive_session_key(receiver, sender)

    # Decrypt document
    return AESGCM(session_key).decrypt(
        nonce,
        ciphertext,
        None
    )


if __name__ == "__main__":

    manager = KeyManager()

    # Register existing subsystems
    for subsystem_name in [
        "Finance-System-A",
        "HR-System-B",
        "SupplyChain-System-C"
    ]:
        manager.register_subsystem(subsystem_name)

    # Scalability: register a new subsystem
    manager.register_subsystem(
        "Future-Analytics-System-D"
    )

    # Retrieve Finance and HR
    finance = manager.subsystems[
        "Finance-System-A"
    ]

    hr = manager.subsystems[
        "HR-System-B"
    ]

    # Document to be transmitted
    document = b"Confidential financial report for HR."

    # Encrypt document
    package = encrypt_document(
        finance,
        hr,
        document
    )

    # Decrypt document
    recovered = decrypt_document(
        finance,
        hr,
        package
    )

    print("Recovered document:", recovered.decode())

    print("Audit entries:", len(manager.audit_log))

    # Revoke a subsystem
    manager.revoke_subsystem(
        "Future-Analytics-System-D"
    )

    print(
        "Future-Analytics-System-D revoked successfully."
    )