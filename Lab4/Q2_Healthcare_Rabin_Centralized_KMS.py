
# ======================================================================
# 1. FULL QUESTION
# ======================================================================
# HealthCare Inc., a leading healthcare provider, has implemented a secure
# patient data management system using the Rabin cryptosystem. The system
# allows authorized healthcare professionals to securely access and manage
# patient records across multiple hospitals and clinics.
#
# Implement a Python-based centralized key management service that can:
# • Generate public/private key pairs for each hospital and clinic using
#   Rabin; key size configurable, e.g. 1024 bits.
# • Provide secure key distribution APIs.
# • Revoke and update keys when a facility is closed or compromised.
# • Automatically renew keys regularly, e.g. every 12 months.
# • Securely store private keys.
# • Maintain detailed audit logs for generation, distribution, revocation,
#   and renewal.
# • Ensure compliance with relevant privacy regulations, e.g. HIPAA.
# • Perform a trade-off analysis comparing Rabin and RSA.
#
# ======================================================================
# 2. QUESTION / CONTEXT EXPLANATION
# ======================================================================
# The program models a centralized KMS. Each facility has a key record,
# status, creation time, expiry time, and audit history.
#
# ======================================================================
# 3. THEORY AND FORMULAS
# ======================================================================
# Choose p and q such that p ≡ q ≡ 3 (mod 4).
# n = p*q
# Public key = n
# Private key = (p,q)
# Encryption: c = m^2 mod n
# Decryption:
#   mp = c^((p+1)/4) mod p
#   mq = c^((q+1)/4) mod q
# Then combine roots using the Chinese Remainder Theorem.
# Rabin normally gives four possible square roots.
#
# ======================================================================
# 4. DETAILED COMMENTS / IMPLEMENTATION PLAN
# ======================================================================
# - Use a dictionary keyed by facility ID.
# - Store public keys separately from private keys.
# - Mark records revoked instead of deleting audit history.
# - Generate a new version during renewal.
# - Log every sensitive operation.
# - In production, encrypt private keys at rest and use an HSM/KMS.
#
# ======================================================================
# 5. ENCRYPTION / DECRYPTION LOGIC
# ======================================================================
# Rabin encryption squares the message modulo n. Decryption computes
# modular square roots modulo p and q, then combines them using CRT.
# Message redundancy or padding is required to identify the correct root.
#
# ======================================================================
# 6. BRUTE-FORCE / ATTACK EXERCISES
# ======================================================================
# - Factor a tiny Rabin modulus by trial division.
# - Show that knowing p and q makes decryption possible.
# - Compare Rabin and RSA timings.
# - Demonstrate the four-root ambiguity.
#
# ======================================================================
# 7. CHARACTER MAPPING AND ASSUMPTIONS
# ======================================================================
# Rabin works on integers. Convert text to bytes/int before encryption.
# Ensure m < n. For real data, use padding and hybrid encryption.
# This classroom implementation is not a HIPAA-compliant service by itself.
# ======================================================================

"""
LAB 4 - ADVANCED ASYMMETRIC KEY CIPHERS
QUESTION 2

HealthCare Inc. uses Rabin encryption. Implement a centralized key
management service that supports:

- Configurable Rabin key size.
- Key generation for hospitals/clinics.
- Public/private key distribution.
- Revocation and renewal.
- Secure private-key storage demonstration.
- Auditing and logging.
- A Rabin versus RSA trade-off analysis.

This is an educational implementation. In production, private keys must
be stored inside an HSM or a properly encrypted secrets manager.

Install:
    pip install cryptography
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import hashlib
import secrets


def is_prime(number):
    if number < 2:
        return False
    if number % 2 == 0:
        return number == 2
    divisor = 3
    while divisor * divisor <= number:
        if number % divisor == 0:
            return False
        divisor += 2
    return True


def generate_prime_3_mod_4(bits):
    """Generate a prime p such that p % 4 == 3."""
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 3
        if candidate % 4 == 3 and is_prime(candidate):
            return candidate


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = egcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def mod_inverse(a, modulus):
    gcd, x, _ = egcd(a, modulus)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % modulus


def rabin_keygen(bits=256):
    p = generate_prime_3_mod_4(bits // 2)
    q = generate_prime_3_mod_4(bits // 2)
    while q == p:
        q = generate_prime_3_mod_4(bits // 2)
    return {"public": p * q, "private": (p, q)}


def rabin_encrypt(message, public_n):
    message_int = int.from_bytes(message, "big")
    if message_int >= public_n:
        raise ValueError("Message is too large for this demonstration")
    return pow(message_int, 2, public_n)


def rabin_decrypt_all(ciphertext, private_key, public_n):
    """Return the four possible Rabin square roots."""
    p, q = private_key
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    yp = mod_inverse(p, q)
    yq = mod_inverse(q, p)

    r1 = (yp * p * mq + yq * q * mp) % public_n
    r2 = public_n - r1
    r3 = (yp * p * mq - yq * q * mp) % public_n
    r4 = public_n - r3
    return [r1, r2, r3, r4]


@dataclass
class FacilityKeyRecord:
    facility_id: str
    public_n: int
    private_key: tuple
    created_at: datetime
    expires_at: datetime
    revoked: bool = False


class CentralizedKeyManagementService:
    def __init__(self, key_bits=256, renewal_days=365):
        self.key_bits = key_bits
        self.renewal_days = renewal_days
        self.records = {}
        self.audit_log = []

    def _audit(self, action, facility_id):
        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "facility": facility_id,
        })

    def generate_keys(self, facility_id):
        keys = rabin_keygen(self.key_bits)
        now = datetime.now(timezone.utc)
        self.records[facility_id] = FacilityKeyRecord(
            facility_id=facility_id,
            public_n=keys["public"],
            private_key=keys["private"],
            created_at=now,
            expires_at=now + timedelta(days=self.renewal_days),
        )
        self._audit("KEY_GENERATED", facility_id)

    def distribute_public_key(self, facility_id):
        record = self.records[facility_id]
        if record.revoked:
            raise PermissionError("Facility key is revoked")
        self._audit("PUBLIC_KEY_DISTRIBUTED", facility_id)
        return record.public_n

    def distribute_private_key(self, facility_id, authorized=False):
        if not authorized:
            raise PermissionError("Private-key distribution requires authorization")
        record = self.records[facility_id]
        if record.revoked:
            raise PermissionError("Facility key is revoked")
        self._audit("PRIVATE_KEY_DISTRIBUTED", facility_id)
        return record.private_key

    def revoke_keys(self, facility_id):
        self.records[facility_id].revoked = True
        self._audit("KEY_REVOKED", facility_id)

    def renew_keys(self, facility_id):
        self.revoke_keys(facility_id)
        self.generate_keys(facility_id)
        self._audit("KEY_RENEWED", facility_id)

    def show_audit_log(self):
        for entry in self.audit_log:
            print(entry)


if __name__ == "__main__":
    kms = CentralizedKeyManagementService(key_bits=256, renewal_days=365)

    for facility in ["Hospital-A", "Clinic-B", "Hospital-C"]:
        kms.generate_keys(facility)

    public_n = kms.distribute_public_key("Hospital-A")
    private_key = kms.distribute_private_key("Hospital-A", authorized=True)

    message = b"Patient"
    ciphertext = rabin_encrypt(message, public_n)
    roots = rabin_decrypt_all(ciphertext, private_key, public_n)

    expected = int.from_bytes(message, "big")
    print("Original integer:", expected)
    print("Recovered roots contain original:", expected in roots)

    kms.revoke_keys("Clinic-B")
    kms.renew_keys("Hospital-C")
    kms.show_audit_log()

    print("\nRabin vs RSA trade-off:")
    print("- Rabin encryption is mathematically simple: c = m^2 mod n.")
    print("- Rabin decryption produces four possible roots, so padding/encoding is required.")
    print("- Rabin security is closely related to integer factorization.")
    print("- RSA uses exponentiation and can provide unambiguous decoding with padding.")
    print("- RSA has mature standards and library support; Rabin is less commonly deployed.")
    print("- Both require strong random primes, protected private keys, rotation, and auditing.")
