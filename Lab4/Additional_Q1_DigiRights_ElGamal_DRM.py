
# ======================================================================
# 1. FULL QUESTION
# ======================================================================
# DigiRights Inc. is a leading provider of digital content, including
# e-books, movies, and music. The company uses ElGamal to protect assets.
#
# Implement a centralized key management and access control service that:
# • Generates a configurable master ElGamal key pair, e.g. 2048 bits.
# • Encrypts creator-uploaded content using the master public key.
# • Distributes the master private key only to authorized customers.
# • Supports limited-time access, revocation, and creator-managed access.
# • Revokes the master private key after a breach.
# • Renews the key pair regularly, e.g. every 24 months.
# • Securely stores the master private key.
# • Audits key-management and access-control operations.
#
# ======================================================================
# 2. QUESTION / CONTEXT EXPLANATION
# ======================================================================
# This models DRM as a combination of public-key encryption and policy
# enforcement. Cryptography protects content; access control decides who
# may receive decryption capability.
#
# ======================================================================
# 3. THEORY AND FORMULAS
# ======================================================================
# Public parameters: p,g
# Private key: x
# y = g^x mod p
# Encryption:
#   c1 = g^k mod p
#   s  = y^k mod p
#   c2 = m*s mod p
# Decryption:
#   s = c1^x mod p
#   m = c2*s^(-1) mod p
#
# ======================================================================
# 4. DETAILED COMMENTS / IMPLEMENTATION PLAN
# ======================================================================
# - Maintain content records and customer permissions.
# - Check ownership before creators modify access.
# - Check expiry and revocation before distributing keys.
# - Log every grant, denial, revocation, and renewal.
#
# ======================================================================
# 5. ENCRYPTION / DECRYPTION LOGIC
# ======================================================================
# Textbook ElGamal encrypts an integer m with m < p. For files, use hybrid
# encryption: AES-GCM encrypts the file and ElGamal protects the AES key.
#
# ======================================================================
# 6. BRUTE-FORCE / ATTACK EXERCISES
# ======================================================================
# - Use tiny p to demonstrate discrete-log brute force.
# - Reuse the random k and explain why it is dangerous.
# - Demonstrate unauthorized access denial and revocation.
# - Compare textbook ElGamal with hybrid encryption.
#
# ======================================================================
# 7. CHARACTER MAPPING AND ASSUMPTIONS
# ======================================================================
# Characters are encoded as bytes and converted to integers.
# The message integer must be smaller than p.
# Real systems require secure randomness, authenticated encryption,
# key wrapping, access tokens, and protected private-key storage.
# ======================================================================

"""
LAB 4 - ADVANCED ASYMMETRIC KEY CIPHERS
ADDITIONAL QUESTION 1

DigiRights Inc. requires an ElGamal-based DRM key-management and access
control service supporting:

- Master key generation.
- Content encryption.
- Authorized key distribution.
- Limited-time access.
- Access revocation.
- Creator-controlled permissions.
- Key revocation and renewal.
- Secure storage demonstration.
- Auditing.

This is a small educational ElGamal implementation. Real DRM systems
should normally use hybrid encryption and established libraries.
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import secrets
import hashlib


def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


def find_prime(start=100000):
    candidate = start | 1
    while not is_prime(candidate):
        candidate += 2
    return candidate


def mod_inverse(a, p):
    return pow(a, -1, p)


@dataclass
class AccessGrant:
    customer: str
    content_id: str
    expires_at: datetime
    revoked: bool = False


class ElGamalDRMService:
    def __init__(self, p=None, g=2):
        # Small parameters are used only so the lab runs quickly.
        self.p = p or find_prime(1000003)
        self.g = g
        self.private_x = secrets.randbelow(self.p - 2) + 1
        self.public_y = pow(self.g, self.private_x, self.p)

        self.contents = {}
        self.grants = {}
        self.audit_log = []
        self.revoked = False

    def audit(self, action, details):
        self.audit_log.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details,
        })

    def encrypt_content(self, content_id, creator, plaintext):
        if self.revoked:
            raise PermissionError("Master key is revoked")

        message_int = int.from_bytes(plaintext, "big")
        if message_int >= self.p:
            raise ValueError("Use hybrid encryption for large content")

        k = secrets.randbelow(self.p - 2) + 1
        c1 = pow(self.g, k, self.p)
        shared_secret = pow(self.public_y, k, self.p)
        c2 = (message_int * shared_secret) % self.p

        self.contents[content_id] = {
            "creator": creator,
            "ciphertext": (c1, c2),
        }
        self.audit("CONTENT_ENCRYPTED", content_id)
        return c1, c2

    def grant_access(self, creator, customer, content_id, hours=24):
        if content_id not in self.contents:
            raise KeyError("Unknown content")
        if self.contents[content_id]["creator"] != creator:
            raise PermissionError("Only the creator can grant access")

        grant = AccessGrant(
            customer=customer,
            content_id=content_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=hours),
        )
        self.grants[(customer, content_id)] = grant
        self.audit("ACCESS_GRANTED", f"{customer}:{content_id}")

    def revoke_access(self, creator, customer, content_id):
        if self.contents[content_id]["creator"] != creator:
            raise PermissionError("Only the creator can revoke access")
        self.grants[(customer, content_id)].revoked = True
        self.audit("ACCESS_REVOKED", f"{customer}:{content_id}")

    def decrypt_content(self, customer, content_id):
        if self.revoked:
            raise PermissionError("Master key is revoked")

        grant = self.grants.get((customer, content_id))
        if not grant or grant.revoked:
            raise PermissionError("Customer has no active grant")
        if datetime.now(timezone.utc) > grant.expires_at:
            raise PermissionError("Access grant has expired")

        c1, c2 = self.contents[content_id]["ciphertext"]
        shared_secret = pow(c1, self.private_x, self.p)
        message_int = (c2 * mod_inverse(shared_secret, self.p)) % self.p
        plaintext = message_int.to_bytes(
            max(1, (message_int.bit_length() + 7) // 8), "big"
        )
        self.audit("CONTENT_DECRYPTED", f"{customer}:{content_id}")
        return plaintext

    def revoke_master_key(self):
        self.revoked = True
        self.audit("MASTER_KEY_REVOKED", "emergency")

    def renew_master_key(self):
        self.revoked = True
        self.__init__(p=self.p, g=self.g)
        self.audit("MASTER_KEY_RENEWED", "scheduled renewal")


if __name__ == "__main__":
    service = ElGamalDRMService()

    service.encrypt_content(
        content_id="ebook-001",
        creator="creator-A",
        plaintext=b"Digital book sample",
    )
    service.grant_access("creator-A", "customer-1", "ebook-001", hours=24)

    print("Decrypted:", service.decrypt_content("customer-1", "ebook-001"))

    service.revoke_access("creator-A", "customer-1", "ebook-001")
    try:
        service.decrypt_content("customer-1", "ebook-001")
    except PermissionError as error:
        print("After revocation:", error)

    print("Audit entries:", len(service.audit_log))
