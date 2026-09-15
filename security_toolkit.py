"""
Security Algorithms and Application Template
============================================

Install required libraries:
    pip install pycryptodome cryptography

This file contains modular functions for:
- Classical cryptography
- Symmetric encryption
- Asymmetric encryption
- Hashing
- Digital signatures
- File I/O
- Login and role-based access control
- Basic networking
- Main application menu

Educational template: use authenticated encryption such as AES-GCM
for real applications. DES, MD5, and textbook RSA/ElGamal are included
mainly for lab/examination practice.
"""

import base64
import hashlib
import json
import os
import random
import socket
import string
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# ---------------------------------------------------------------------
# Optional third-party imports
# ---------------------------------------------------------------------

try:
    from Crypto.Cipher import AES, DES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
except ImportError:
    AES = DES = PKCS1_OAEP = RSA = get_random_bytes = None
    pkcs1_15 = SHA256 = None

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    hashes = serialization = rsa = padding = dh = HKDF = None


# =====================================================================
# Classical Cryptography
# =====================================================================

def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypt text using the Caesar cipher."""
    result = []

    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        elif char.islower():
            result.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        else:
            result.append(char)

    return "".join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt text using the Caesar cipher."""
    return caesar_encrypt(ciphertext, -shift)


def _clean_key(key: str) -> str:
    key = "".join(char for char in key if char.isalpha())
    if not key:
        raise ValueError("Key must contain at least one alphabetic character.")
    return key.upper()


def vigenere_encrypt(text: str, key: str) -> str:
    """Encrypt text using the Vigenere cipher."""
    key = _clean_key(key)
    result = []
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord("A")

            if char.isupper():
                result.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
            else:
                result.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))

            key_index += 1
        else:
            result.append(char)

    return "".join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt text using the Vigenere cipher."""
    key = _clean_key(key)
    result = []
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord("A")

            if char.isupper():
                result.append(chr((ord(char) - ord("A") - shift) % 26 + ord("A")))
            else:
                result.append(chr((ord(char) - ord("a") - shift) % 26 + ord("a")))

            key_index += 1
        else:
            result.append(char)

    return "".join(result)


def _mod_inverse(a: int, m: int) -> int:
    """Return modular inverse of a modulo m."""
    return pow(a, -1, m)


def affine_encrypt(text: str, a: int, b: int) -> str:
    """Encrypt text using the Affine cipher: E(x) = (a*x + b) mod 26."""
    if __import__("math").gcd(a, 26) != 1:
        raise ValueError("a must be coprime with 26.")

    result = []

    for char in text:
        if char.isupper():
            x = ord(char) - ord("A")
            result.append(chr((a * x + b) % 26 + ord("A")))
        elif char.islower():
            x = ord(char) - ord("a")
            result.append(chr((a * x + b) % 26 + ord("a")))
        else:
            result.append(char)

    return "".join(result)


def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    """Decrypt text using the Affine cipher."""
    inverse_a = _mod_inverse(a, 26)
    result = []

    for char in ciphertext:
        if char.isupper():
            y = ord(char) - ord("A")
            result.append(chr((inverse_a * (y - b)) % 26 + ord("A")))
        elif char.islower():
            y = ord(char) - ord("a")
            result.append(chr((inverse_a * (y - b)) % 26 + ord("a")))
        else:
            result.append(char)

    return "".join(result)


# =====================================================================
# Symmetric Encryption
# =====================================================================

def _require_pycryptodome() -> None:
    if AES is None:
        raise ImportError("Install PyCryptodome: pip install pycryptodome")


def _to_bytes(data: Any) -> bytes:
    return data if isinstance(data, bytes) else str(data).encode("utf-8")


def aes_encrypt(data: Any, key: bytes) -> Dict[str, str]:
    """
    AES-GCM encryption.

    Returns a JSON-friendly dictionary containing nonce, ciphertext,
    and authentication tag, all Base64 encoded.
    """
    _require_pycryptodome()

    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes.")

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(_to_bytes(data))

    return {
        "nonce": base64.b64encode(cipher.nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
    }


def aes_decrypt(encrypted: Dict[str, str], key: bytes) -> bytes:
    """Decrypt and authenticate AES-GCM data."""
    _require_pycryptodome()

    nonce = base64.b64decode(encrypted["nonce"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])
    tag = base64.b64decode(encrypted["tag"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def des_encrypt(data: Any, key: bytes) -> Dict[str, str]:
    """
    DES-CBC encryption for lab practice.

    DES is obsolete and should not be used in real systems.
    """
    _require_pycryptodome()

    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    plaintext = _to_bytes(data)
    pad_len = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([pad_len]) * pad_len

    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    return {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def des_decrypt(encrypted: Dict[str, str], key: bytes) -> bytes:
    """Decrypt DES-CBC data and remove PKCS-style padding."""
    _require_pycryptodome()

    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    iv = base64.b64decode(encrypted["iv"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])

    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)

    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding.")

    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding.")

    return padded[:-pad_len]


# =====================================================================
# Asymmetric Cryptography
# =====================================================================

def rsa_generate_keys(bits: int = 2048) -> Tuple[bytes, bytes]:
    """Generate an RSA private/public key pair in PEM format."""
    _require_pycryptodome()

    private_key = RSA.generate(bits)
    private_pem = private_key.export_key()
    public_pem = private_key.publickey().export_key()

    return private_pem, public_pem


def rsa_encrypt(data: Any, public_key_pem: bytes) -> str:
    """Encrypt data using RSA-OAEP and return Base64 ciphertext."""
    _require_pycryptodome()

    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(_to_bytes(data))

    return base64.b64encode(ciphertext).decode("utf-8")


def rsa_decrypt(ciphertext_b64: str, private_key_pem: bytes) -> bytes:
    """Decrypt Base64 RSA-OAEP ciphertext."""
    _require_pycryptodome()

    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(ciphertext_b64)

    return cipher.decrypt(ciphertext)


def _elgamal_parameters() -> Tuple[int, int]:
    """
    Small educational ElGamal parameters.

    Do not use these parameters for real security.
    """
    p = 467
    g = 2
    return p, g


def elgamal_encrypt(message: int, public_key: Tuple[int, int, int]) -> Tuple[int, int]:
    """
    Educational ElGamal encryption.

    public_key = (p, g, y)
    Returns (c1, c2).
    """
    p, g, y = public_key

    if not 0 <= message < p:
        raise ValueError("Message must be in the range 0 <= message < p.")

    k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p

    return c1, c2


def elgamal_decrypt(ciphertext: Tuple[int, int], private_key: Tuple[int, int]) -> int:
    """
    Educational ElGamal decryption.

    private_key = (p, x)
    """
    c1, c2 = ciphertext
    p, x = private_key

    shared_secret = pow(c1, x, p)
    inverse_secret = pow(shared_secret, -1, p)

    return (c2 * inverse_secret) % p


def dh_generate_shared_key() -> Tuple[int, int, int, int, int]:
    """
    Demonstrate Diffie-Hellman shared-key generation.

    Returns:
        p, g, public_a, public_b, shared_secret
    """
    p = 23
    g = 5

    private_a = random.randint(2, p - 2)
    private_b = random.randint(2, p - 2)

    public_a = pow(g, private_a, p)
    public_b = pow(g, private_b, p)

    shared_a = pow(public_b, private_a, p)
    shared_b = pow(public_a, private_b, p)

    assert shared_a == shared_b

    return p, g, public_a, public_b, shared_a


# =====================================================================
# Hashing
# =====================================================================

def custom_hash(data: Any) -> str:
    """Simple educational hash; not cryptographically secure."""
    data_bytes = _to_bytes(data)
    value = 0

    for byte in data_bytes:
        value = (value * 31 + byte) % (2 ** 32)

    return f"{value:08x}"


def sha256_hash(data: Any) -> str:
    """Return SHA-256 hexadecimal digest."""
    return hashlib.sha256(_to_bytes(data)).hexdigest()


def md5_hash(data: Any) -> str:
    """Return MD5 hexadecimal digest; not recommended for security."""
    return hashlib.md5(_to_bytes(data)).hexdigest()


# =====================================================================
# Digital Signature
# =====================================================================

def sign_data(data: Any, private_key_pem: bytes) -> str:
    """Create an RSA-PKCS#1 v1.5 SHA-256 digital signature."""
    _require_pycryptodome()

    private_key = RSA.import_key(private_key_pem)
    digest = SHA256.new(_to_bytes(data))
    signature = pkcs1_15.new(private_key).sign(digest)

    return base64.b64encode(signature).decode("utf-8")


def verify_signature(
    data: Any,
    signature_b64: str,
    public_key_pem: bytes,
) -> bool:
    """Verify an RSA-PKCS#1 v1.5 SHA-256 signature."""
    _require_pycryptodome()

    public_key = RSA.import_key(public_key_pem)
    digest = SHA256.new(_to_bytes(data))
    signature = base64.b64decode(signature_b64)

    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


# =====================================================================
# File I/O
# =====================================================================

def read_file(filename: str, mode: str = "r") -> Any:
    """Read text or binary data from a file."""
    with open(filename, mode) as file:
        return file.read()


def write_file(filename: str, data: Any, mode: str = "w") -> None:
    """Write text or binary data to a file."""
    with open(filename, mode) as file:
        file.write(data)


def save_json(filename: str, data: Any) -> None:
    """Save Python data as formatted JSON."""
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def load_json(filename: str) -> Any:
    """Load JSON data from a file."""
    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


# =====================================================================
# Security: Login, Roles, Permissions
# =====================================================================

def login(username: str, password: str, users: Dict[str, Dict[str, str]]) -> Optional[Dict[str, str]]:
    """
    Authenticate a user.

    Example users dictionary:
    {
        "alice": {
            "password_hash": sha256_hash("1234"),
            "role": "student"
        }
    }
    """
    user = users.get(username)

    if user is None:
        return None

    if user.get("password_hash") == sha256_hash(password):
        return {
            "username": username,
            "role": user.get("role", "guest"),
        }

    return None


def check_role(user: Optional[Dict[str, str]], allowed_roles) -> bool:
    """Return True if the logged-in user has an allowed role."""
    if user is None:
        return False

    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    return user.get("role") in allowed_roles


def check_permission(
    user: Optional[Dict[str, str]],
    permission: str,
    role_permissions: Dict[str, list],
) -> bool:
    """Return True if the user's role has the requested permission."""
    if user is None:
        return False

    role = user.get("role")
    permissions = role_permissions.get(role, [])

    return permission in permissions


# =====================================================================
# Networking
# =====================================================================

def send_data(
    host: str,
    port: int,
    data: Any,
    timeout: float = 5.0,
) -> None:
    """Send UTF-8 data to a TCP server."""
    payload = _to_bytes(data)

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)


def receive_data(
    host: str,
    port: int,
    buffer_size: int = 4096,
    timeout: float = 5.0,
) -> bytes:
    """Receive data from a TCP server."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        return sock.recv(buffer_size)


# =====================================================================
# Demonstration Helpers
# =====================================================================

def demo_classical() -> None:
    text = "Hello World"
    print("\n--- Classical Cryptography ---")

    caesar = caesar_encrypt(text, 3)
    print("Caesar:", caesar, "->", caesar_decrypt(caesar, 3))

    vigenere = vigenere_encrypt(text, "KEY")
    print("Vigenere:", vigenere, "->", vigenere_decrypt(vigenere, "KEY"))

    affine = affine_encrypt(text, 5, 8)
    print("Affine:", affine, "->", affine_decrypt(affine, 5, 8))


def demo_hashing() -> None:
    text = "Hello World"
    print("\n--- Hashing ---")
    print("Custom:", custom_hash(text))
    print("SHA-256:", sha256_hash(text))
    print("MD5:", md5_hash(text))


def demo_asymmetric() -> None:
    print("\n--- RSA and Diffie-Hellman ---")

    private_key, public_key = rsa_generate_keys()
    encrypted = rsa_encrypt("Secret Message", public_key)
    decrypted = rsa_decrypt(encrypted, private_key)

    print("RSA decrypted:", decrypted.decode())

    p, g, public_a, public_b, shared = dh_generate_shared_key()
    print("DH parameters:", p, g)
    print("Public A:", public_a)
    print("Public B:", public_b)
    print("Shared secret:", shared)


def demo_signature() -> None:
    print("\n--- Digital Signature ---")

    private_key, public_key = rsa_generate_keys()
    message = "Important academic record"

    signature = sign_data(message, private_key)
    valid = verify_signature(message, signature, public_key)

    print("Signature:", signature)
    print("Valid:", valid)


# =====================================================================
# Main Menu
# =====================================================================

def main_menu() -> None:
    """Run a simple interactive menu."""
    while True:
        print("\n========== SECURITY TOOLKIT ==========")
        print("1. Classical cryptography")
        print("2. Hashing")
        print("3. RSA and Diffie-Hellman")
        print("4. Digital signature")
        print("5. Exit")

        choice = input("Enter choice: ").strip()

        try:
            if choice == "1":
                demo_classical()
            elif choice == "2":
                demo_hashing()
            elif choice == "3":
                demo_asymmetric()
            elif choice == "4":
                demo_signature()
            elif choice == "5":
                print("Exiting...")
                break
            else:
                print("Invalid choice.")

        except Exception as error:
            print("Error:", error)


# =====================================================================
# Program Entry Point
# =====================================================================

if __name__ == "__main__":
    main_menu()
