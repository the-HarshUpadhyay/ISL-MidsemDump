"""
╔══════════════════════════════════════════════════════════════════╗
║   IS LAB – MASTER CRYPTO SNIPPETS  (Labs 1–6)                   ║
║   HOW TO USE IN THE EXAM                                         ║
║   ─────────────────────────────────────────────────────────────  ║
║   1. Find the block labelled with the algo you need.             ║
║   2. Copy the encrypt() + decrypt() (or sign/verify) functions.  ║
║   3. Paste them into edusecure.py REPLACING the marked block.    ║
║   4. Change the KEY / IV / params as the question specifies.     ║
║   5. The rest of the program (menus, roles, storage) stays.      ║
╚══════════════════════════════════════════════════════════════════╝

WHERE TO SUBSTITUTE IN edusecure.py
─────────────────────────────────────
Encryption/Decryption  →  Replace  des_encrypt()  and  des_decrypt()
Hashing                →  Replace  compute_hash()
Signing/Verifying      →  Replace  rsa_sign()  and  rsa_verify()
                           Also replace  generate_rsa_keys(),
                           load_private_key(),  load_public_key()
Access Control         →  Edit the  ACCESS  dict  and  check_access()
"""

# ══════════════════════════════════════════════════════════════════
#  MASTER IMPORT BLOCK  – paste ALL of these at the top of any file
#  Remove the ones you don't use (or just leave them; Python ignores
#  unused imports at runtime).
# ══════════════════════════════════════════════════════════════════
import os
import sys
import json
import hashlib
import base64
import socket
import threading
import datetime
import time
import math
import random
import struct

# ── pycryptodome (Crypto.*) ──────────────────────────────────────
from Crypto.Cipher    import DES, DES3, AES               # symmetric
from Crypto.PublicKey import RSA, ElGamal, DSA, ECC       # asymmetric
from Crypto.Signature import pkcs1_15, DSS                # signing
from Crypto.Signature import eddsa                        # EdDSA (Ed25519)
from Crypto.Hash      import SHA256, SHA512, SHA1, MD5    # hash objects
from Crypto.Hash      import SHA3_256                     # SHA-3
from Crypto.Util.Padding  import pad, unpad               # PKCS7 padding
from Crypto.Util.number   import getPrime, inverse, GCD   # math helpers
from Crypto.Random        import get_random_bytes         # secure RNG
from Crypto.Protocol.KDF  import PBKDF2, scrypt           # key derivation


# ══════════════════════════════════════════════════════════════════
#  SECTION 1 – LAB 1: CLASSICAL CIPHERS  (pure Python, no imports)
# ══════════════════════════════════════════════════════════════════
# These don't use pycryptodome – all plain math on letters.
# HOW TO USE: call encrypt/decrypt from student_encrypt_and_upload()
#             in place of des_encrypt()/des_decrypt()

# ── 1A. ADDITIVE / CAESAR / SHIFT CIPHER ────────────────────────
# CHANGE: key (integer 0-25)

ADDITIVE_KEY = 20   # ← change this for the exam

def additive_encrypt(plaintext, key=ADDITIVE_KEY):
    """C = (P + key) mod 26. Non-alpha chars pass unchanged."""
    result = []
    for ch in plaintext.upper():
        if ch.isalpha():
            result.append(chr((ord(ch) - ord('A') + key) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)

def additive_decrypt(ciphertext, key=ADDITIVE_KEY):
    """P = (C - key) mod 26"""
    return additive_encrypt(ciphertext, (-key) % 26)


# ── 1B. MULTIPLICATIVE CIPHER ────────────────────────────────────
# CHANGE: key (must be coprime with 26; valid: 1,3,5,7,9,11,15,17,19,21,23,25)

MULT_KEY = 15  # ← change this

def _mod_inverse(a, m):
    """Extended Euclidean Algorithm: find x s.t. a*x ≡ 1 (mod m)"""
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a},{m})={g}")
    return x % m

def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def multiplicative_encrypt(plaintext, key=MULT_KEY):
    """C = (P * key) mod 26"""
    result = []
    for ch in plaintext.upper():
        if ch.isalpha():
            result.append(chr((ord(ch) - ord('A')) * key % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)

def multiplicative_decrypt(ciphertext, key=MULT_KEY):
    """P = (C * key_inv) mod 26"""
    return multiplicative_encrypt(ciphertext, _mod_inverse(key, 26))


# ── 1C. AFFINE CIPHER ────────────────────────────────────────────
# CHANGE: a (mult part, coprime with 26), b (additive part)

AFFINE_A = 15   # ← change
AFFINE_B = 20   # ← change

def affine_encrypt(plaintext, a=AFFINE_A, b=AFFINE_B):
    """C = (a*P + b) mod 26"""
    result = []
    for ch in plaintext.upper():
        if ch.isalpha():
            result.append(chr((a * (ord(ch) - ord('A')) + b) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)

def affine_decrypt(ciphertext, a=AFFINE_A, b=AFFINE_B):
    """P = a_inv * (C - b) mod 26"""
    a_inv = _mod_inverse(a, 26)
    result = []
    for ch in ciphertext.upper():
        if ch.isalpha():
            result.append(chr(a_inv * (ord(ch) - ord('A') - b) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


# ── 1D. VIGENERE CIPHER ──────────────────────────────────────────
# CHANGE: key (a word/phrase, only alpha characters matter)

VIGENERE_KEY = "dollars"   # ← change

def vigenere_encrypt(plaintext, key=VIGENERE_KEY):
    """Cᵢ = (Pᵢ + Kᵢ) mod 26. Key repeats cyclically."""
    key = key.upper()
    result, ki = [], 0
    for ch in plaintext.upper():
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

def vigenere_decrypt(ciphertext, key=VIGENERE_KEY):
    """Pᵢ = (Cᵢ - Kᵢ) mod 26"""
    key = key.upper()
    result, ki = [], 0
    for ch in ciphertext.upper():
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


# ── 1E. AUTOKEY CIPHER ───────────────────────────────────────────
# CHANGE: initial_key (a single integer 0-25)

AUTOKEY_INIT = 7   # ← change

def autokey_encrypt(plaintext, initial_key=AUTOKEY_INIT):
    """Key stream = (initial_key, P₁, P₂, ...). Cᵢ = (Pᵢ + kᵢ) mod 26"""
    plaintext_clean = ''.join(c for c in plaintext.upper() if c.isalpha())
    key_stream = [initial_key] + [ord(c) - ord('A') for c in plaintext_clean]
    result = []
    for i, ch in enumerate(plaintext_clean):
        result.append(chr((ord(ch) - ord('A') + key_stream[i]) % 26 + ord('A')))
    return ''.join(result)

def autokey_decrypt(ciphertext, initial_key=AUTOKEY_INIT):
    """Recover plaintext; each decrypted char becomes next key"""
    ciphertext_clean = ''.join(c for c in ciphertext.upper() if c.isalpha())
    result = []
    key_stream = [initial_key]
    for i, ch in enumerate(ciphertext_clean):
        p = (ord(ch) - ord('A') - key_stream[i]) % 26
        result.append(chr(p + ord('A')))
        key_stream.append(p)
    return ''.join(result)


# ── 1F. PLAYFAIR CIPHER ──────────────────────────────────────────
# CHANGE: key (word used to fill the 5×5 matrix first)

PLAYFAIR_KEY = "GUIDANCE"   # ← change

def _build_playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    seen, matrix = set(), []
    for ch in key:
        if ch.isalpha() and ch not in seen:
            matrix.append(ch)
            seen.add(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            matrix.append(ch)
            seen.add(ch)
    return [matrix[i*5:(i+1)*5] for i in range(5)]

def _playfair_pos(matrix, ch):
    for r, row in enumerate(matrix):
        if ch in row:
            return r, row.index(ch)

def _playfair_process(matrix, a, b, encrypt=True):
    r1, c1 = _playfair_pos(matrix, a)
    r2, c2 = _playfair_pos(matrix, b)
    d = 1 if encrypt else -1
    if r1 == r2:
        return matrix[r1][(c1+d)%5], matrix[r2][(c2+d)%5]
    elif c1 == c2:
        return matrix[(r1+d)%5][c1], matrix[(r2+d)%5][c2]
    else:
        return matrix[r1][c2], matrix[r2][c1]

def playfair_encrypt(plaintext, key=PLAYFAIR_KEY):
    matrix = _build_playfair_matrix(key)
    text = plaintext.upper().replace('J','I')
    text = ''.join(c for c in text if c.isalpha())
    # prepare digraphs
    pairs, i = [], 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return ''.join(c for pair in pairs for c in _playfair_process(matrix, *pair, encrypt=True))

def playfair_decrypt(ciphertext, key=PLAYFAIR_KEY):
    matrix = _build_playfair_matrix(key)
    text = ciphertext.upper()
    pairs = [(text[i], text[i+1]) for i in range(0, len(text)-1, 2)]
    return ''.join(c for pair in pairs for c in _playfair_process(matrix, *pair, encrypt=False))


# ── 1G. HILL CIPHER (2×2 key) ────────────────────────────────────
# CHANGE: HILL_KEY_MATRIX (2×2 list of lists, must be invertible mod 26)

HILL_KEY_MATRIX = [[3, 3], [2, 7]]   # ← change – [[a,b],[c,d]]

def _mat_mul_mod26(mat, vec):
    return [(sum(mat[r][c]*vec[c] for c in range(len(vec)))) % 26 for r in range(len(mat))]

def _mat_inv_mod26(mat):
    a, b, c, d = mat[0][0], mat[0][1], mat[1][0], mat[1][1]
    det = (a*d - b*c) % 26
    det_inv = _mod_inverse(det, 26)
    return [[(d*det_inv)%26, (-b*det_inv)%26], [(-c*det_inv)%26, (a*det_inv)%26]]

def hill_encrypt(plaintext, key=None):
    if key is None:
        key = HILL_KEY_MATRIX
    text = ''.join(c for c in plaintext.upper() if c.isalpha())
    if len(text) % 2 != 0:
        text += 'X'
    result = []
    for i in range(0, len(text), 2):
        vec = [ord(text[i])-ord('A'), ord(text[i+1])-ord('A')]
        enc = _mat_mul_mod26(key, vec)
        result += [chr(v + ord('A')) for v in enc]
    return ''.join(result)

def hill_decrypt(ciphertext, key=None):
    if key is None:
        key = HILL_KEY_MATRIX
    return hill_encrypt(ciphertext, _mat_inv_mod26(key))


# ══════════════════════════════════════════════════════════════════
#  SECTION 2 – LAB 2: ADVANCED SYMMETRIC (DES, 3DES, AES + MODES)
# ══════════════════════════════════════════════════════════════════
# HOW TO SUBSTITUTE:
#   Replace des_encrypt() + des_decrypt() in edusecure.py with
#   whichever pair you need below.  The function SIGNATURES stay
#   the same (takes str, returns str) so nothing else changes.

# ── 2A. DES ECB (current default in edusecure.py) ────────────────
# CHANGE: DES_KEY (must be exactly 8 bytes)

DES_KEY = b"EduSec8B"   # ← 8 bytes exactly

def des_ecb_encrypt(plaintext: str, key=DES_KEY) -> str:
    """DES ECB – same block always produces same ciphertext. Simplest mode."""
    cipher = DES.new(key, DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode(), DES.block_size))).decode()

def des_ecb_decrypt(ct_b64: str, key=DES_KEY) -> str:
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(ct_b64)), DES.block_size).decode()

# ── 2B. DES CBC ──────────────────────────────────────────────────
# CHANGE: DES_KEY (8 bytes), IV is random 8 bytes prepended to output

def des_cbc_encrypt(plaintext: str, key=DES_KEY) -> str:
    """DES CBC – IV prepended to ciphertext (first 8 bytes)."""
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
    return base64.b64encode(iv + ct).decode()   # IV prepended

def des_cbc_decrypt(ct_b64: str, key=DES_KEY) -> str:
    raw = base64.b64decode(ct_b64)
    iv, ct = raw[:8], raw[8:]   # split IV from ciphertext
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size).decode()

# ── 2C. TRIPLE DES (3DES) ────────────────────────────────────────
# CHANGE: DES3_KEY (16 or 24 bytes)

DES3_KEY = b"1234567890ABCDEF"  # ← 16 bytes (or 24 for full 3-key)

def des3_encrypt(plaintext: str, key=DES3_KEY) -> str:
    """3DES ECB: C = Eₖ₃(Dₖ₂(Eₖ₁(P)))"""
    cipher = DES3.new(key, DES3.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode(), DES3.block_size))).decode()

def des3_decrypt(ct_b64: str, key=DES3_KEY) -> str:
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(ct_b64)), DES3.block_size).decode()

# ── 2D. AES-128 ECB ──────────────────────────────────────────────
# CHANGE: AES128_KEY (exactly 16 bytes)

AES128_KEY = b"0123456789ABCDEF"   # ← 16 bytes

def aes128_ecb_encrypt(plaintext: str, key=AES128_KEY) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode(), AES.block_size))).decode()

def aes128_ecb_decrypt(ct_b64: str, key=AES128_KEY) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(ct_b64)), AES.block_size).decode()

# ── 2E. AES-256 CBC ──────────────────────────────────────────────
# CHANGE: AES256_KEY (exactly 32 bytes), IV is random 16 bytes

AES256_KEY = b"0123456789ABCDEF0123456789ABCDEF"   # ← 32 bytes

def aes256_cbc_encrypt(plaintext: str, key=AES256_KEY) -> str:
    """AES-256 CBC. IV (16 bytes) prepended to output."""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ct).decode()

def aes256_cbc_decrypt(ct_b64: str, key=AES256_KEY) -> str:
    raw = base64.b64decode(ct_b64)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# ── 2F. AES CTR (Counter Mode) ────────────────────────────────────
# CHANGE: AES_CTR_KEY (16/24/32 bytes), nonce is random 8 bytes

AES_CTR_KEY = b"0123456789ABCDEF"   # ← 16 bytes

def aes_ctr_encrypt(plaintext: str, key=AES_CTR_KEY) -> str:
    """AES CTR – no padding needed; nonce prepended."""
    nonce = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(plaintext.encode())
    return base64.b64encode(nonce + ct).decode()

def aes_ctr_decrypt(ct_b64: str, key=AES_CTR_KEY) -> str:
    raw = base64.b64decode(ct_b64)
    nonce, ct = raw[:8], raw[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct).decode()

# ── 2G. AES GCM (authenticated encryption) ───────────────────────
# CHANGE: AES_GCM_KEY (16/24/32 bytes)

AES_GCM_KEY = b"0123456789ABCDEF"   # ← 16 bytes

def aes_gcm_encrypt(plaintext: str, key=AES_GCM_KEY) -> str:
    """AES GCM – includes authentication tag; nonce+tag+ct stored together."""
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(nonce + tag + ct).decode()

def aes_gcm_decrypt(ct_b64: str, key=AES_GCM_KEY) -> str:
    raw = base64.b64decode(ct_b64)
    nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()


# ══════════════════════════════════════════════════════════════════
#  SECTION 3 – LAB 5: HASHING
# ══════════════════════════════════════════════════════════════════
# HOW TO SUBSTITUTE: replace compute_hash() in edusecure.py
# All functions take a string and return a hex digest string.

def hash_sha256(data: str) -> str:
    """SHA-256 – 64 hex chars. Standard secure hash."""
    return hashlib.sha256(data.encode()).hexdigest()

def hash_sha512(data: str) -> str:
    """SHA-512 – 128 hex chars. Stronger."""
    return hashlib.sha512(data.encode()).hexdigest()

def hash_sha1(data: str) -> str:
    """SHA-1 – 40 hex chars. Deprecated but still asked in labs."""
    return hashlib.sha1(data.encode()).hexdigest()

def hash_md5(data: str) -> str:
    """MD5 – 32 hex chars. Broken for security, but common in lab exercises."""
    return hashlib.md5(data.encode()).hexdigest()

def hash_sha3_256(data: str) -> str:
    """SHA-3 / Keccak-256 – newest NIST standard."""
    return hashlib.sha3_256(data.encode()).hexdigest()

def hash_custom_djb2(data: str) -> int:
    """
    DJB2 custom hash (Lab 5, Exercise 1).
    Start=5381, each char: hash = hash*33 + ord(c), keep 32-bit.
    Returns an integer.
    """
    h = 5381
    for ch in data:
        h = ((h << 5) + h) + ord(ch)   # h*33 + ord(c)
        h = h & 0xFFFFFFFF              # keep 32-bit unsigned
    return h

# ── compare all hashes side-by-side (useful for Lab 5 Exercise 3) ─
def compare_all_hashes(data: str):
    print(f"Input   : {data}")
    print(f"MD5     : {hash_md5(data)}")
    print(f"SHA-1   : {hash_sha1(data)}")
    print(f"SHA-256 : {hash_sha256(data)}")
    print(f"SHA-512 : {hash_sha512(data)}")
    print(f"SHA-3   : {hash_sha3_256(data)}")
    print(f"DJB2    : {hash_custom_djb2(data)}")


# ══════════════════════════════════════════════════════════════════
#  SECTION 4 – LAB 3+6: DIGITAL SIGNATURES
# ══════════════════════════════════════════════════════════════════
# HOW TO SUBSTITUTE: replace generate_rsa_keys(), rsa_sign(),
#   rsa_verify(), load_private_key(), load_public_key()
# Each scheme: generate keys → sign(data, username) → verify(data, sig, username)

# ── 4A. RSA PKCS#1 v1.5 Signature (current in edusecure.py) ──────
# CHANGE: key size bits (2048, 1024, 4096)

RSA_KEY_BITS = 2048   # ← change
KEYS_DIR = "keys"

def rsa_generate(username: str):
    """Generate RSA key pair. Saves PEM files to keys/ directory."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    pub_path  = os.path.join(KEYS_DIR, f"{username}_public.pem")
    if os.path.exists(priv_path):
        return  # already exists
    key = RSA.generate(RSA_KEY_BITS)
    with open(priv_path, "wb") as f: f.write(key.export_key())
    with open(pub_path,  "wb") as f: f.write(key.publickey().export_key())
    print(f"  [RSA] Keys generated for {username}")

def rsa_sign(data: str, username: str) -> str:
    """Sign with RSA private key. Returns Base64 signature."""
    with open(os.path.join(KEYS_DIR, f"{username}_private.pem"), "rb") as f:
        key = RSA.import_key(f.read())
    h = SHA256.new(data.encode())
    sig = pkcs1_15.new(key).sign(h)
    return base64.b64encode(sig).decode()

def rsa_verify(data: str, sig_b64: str, username: str) -> bool:
    """Verify RSA signature. Returns True if valid."""
    try:
        with open(os.path.join(KEYS_DIR, f"{username}_public.pem"), "rb") as f:
            key = RSA.import_key(f.read())
        h = SHA256.new(data.encode())
        pkcs1_15.new(key).verify(h, base64.b64decode(sig_b64))
        return True
    except (ValueError, TypeError):
        return False

# ── 4B. RSA PSS Signature (more secure variant) ───────────────────
# Same key generation as 4A. Only sign/verify change.
# HOW TO SUBSTITUTE: replace rsa_sign() + rsa_verify() only.

from Crypto.Signature import pss as _pss

def rsa_pss_sign(data: str, username: str) -> str:
    """RSA-PSS signature. More secure than PKCS#1 v1.5."""
    with open(os.path.join(KEYS_DIR, f"{username}_private.pem"), "rb") as f:
        key = RSA.import_key(f.read())
    h = SHA256.new(data.encode())
    sig = _pss.new(key).sign(h)
    return base64.b64encode(sig).decode()

def rsa_pss_verify(data: str, sig_b64: str, username: str) -> bool:
    try:
        with open(os.path.join(KEYS_DIR, f"{username}_public.pem"), "rb") as f:
            key = RSA.import_key(f.read())
        h = SHA256.new(data.encode())
        _pss.new(key).verify(h, base64.b64decode(sig_b64))
        return True
    except (ValueError, TypeError):
        return False

# ── 4C. DSA (Digital Signature Algorithm) ────────────────────────
# HOW TO SUBSTITUTE: replace all four rsa_* functions.

def dsa_generate(username: str):
    """Generate DSA key pair."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    priv_path = os.path.join(KEYS_DIR, f"{username}_dsa_priv.pem")
    pub_path  = os.path.join(KEYS_DIR, f"{username}_dsa_pub.pem")
    if os.path.exists(priv_path):
        return
    key = DSA.generate(2048)
    with open(priv_path, "wb") as f: f.write(key.export_key())
    with open(pub_path,  "wb") as f: f.write(key.publickey().export_key())
    print(f"  [DSA] Keys generated for {username}")

def dsa_sign(data: str, username: str) -> str:
    with open(os.path.join(KEYS_DIR, f"{username}_dsa_priv.pem"), "rb") as f:
        key = DSA.import_key(f.read())
    h = SHA256.new(data.encode())
    sig = DSS.new(key, 'fips-186-3').sign(h)
    return base64.b64encode(sig).decode()

def dsa_verify(data: str, sig_b64: str, username: str) -> bool:
    try:
        with open(os.path.join(KEYS_DIR, f"{username}_dsa_pub.pem"), "rb") as f:
            key = DSA.import_key(f.read())
        h = SHA256.new(data.encode())
        DSS.new(key, 'fips-186-3').verify(h, base64.b64decode(sig_b64))
        return True
    except (ValueError, TypeError):
        return False

# ── 4D. ECC / ECDSA Signature ─────────────────────────────────────
# HOW TO SUBSTITUTE: replace all four rsa_* functions.
# CHANGE: curve name ('P-256', 'P-384', 'P-521', 'Ed25519')

ECC_CURVE = 'P-256'   # ← change curve

def ecc_generate(username: str):
    """Generate ECC key pair on the specified curve."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    priv_path = os.path.join(KEYS_DIR, f"{username}_ecc_priv.pem")
    pub_path  = os.path.join(KEYS_DIR, f"{username}_ecc_pub.pem")
    if os.path.exists(priv_path):
        return
    key = ECC.generate(curve=ECC_CURVE)
    with open(priv_path, "w") as f: f.write(key.export_key(format='PEM'))
    with open(pub_path,  "w") as f: f.write(key.public_key().export_key(format='PEM'))
    print(f"  [ECC] Keys generated for {username} (curve={ECC_CURVE})")

def ecc_sign(data: str, username: str) -> str:
    with open(os.path.join(KEYS_DIR, f"{username}_ecc_priv.pem"), "r") as f:
        key = ECC.import_key(f.read())
    h = SHA256.new(data.encode())
    sig = DSS.new(key, 'fips-186-3').sign(h)
    return base64.b64encode(sig).decode()

def ecc_verify(data: str, sig_b64: str, username: str) -> bool:
    try:
        with open(os.path.join(KEYS_DIR, f"{username}_ecc_pub.pem"), "r") as f:
            key = ECC.import_key(f.read())
        h = SHA256.new(data.encode())
        DSS.new(key, 'fips-186-3').verify(h, base64.b64decode(sig_b64))
        return True
    except (ValueError, TypeError):
        return False


# ══════════════════════════════════════════════════════════════════
#  SECTION 5 – LAB 3+4: ASYMMETRIC ENCRYPTION (RSA, ElGamal, Rabin)
# ══════════════════════════════════════════════════════════════════
# These are for ENCRYPTING/DECRYPTING data (not signing).
# HOW TO SUBSTITUTE: replace des_encrypt() + des_decrypt()
#   WARNING: asymmetric encryption is slow for large data.
#   In practice: encrypt a symmetric key with RSA, then use AES.
#   For lab exercises, short messages are fine.

# ── 5A. RSA ENCRYPTION (OAEP) ─────────────────────────────────────
from Crypto.Cipher import PKCS1_OAEP

def rsa_encrypt_msg(plaintext: str, username: str) -> str:
    """Encrypt short message with RSA public key (OAEP padding)."""
    with open(os.path.join(KEYS_DIR, f"{username}_public.pem"), "rb") as f:
        pub_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(pub_key)
    ct = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ct).decode()

def rsa_decrypt_msg(ct_b64: str, username: str) -> str:
    """Decrypt RSA-encrypted message with private key."""
    with open(os.path.join(KEYS_DIR, f"{username}_private.pem"), "rb") as f:
        priv_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(base64.b64decode(ct_b64)).decode()

# ── 5B. ELGAMAL ENCRYPTION (manual implementation) ────────────────
# pycryptodome's ElGamal only does signatures, not encryption.
# This is a correct manual implementation.
# CHANGE: ELGAMAL_P, ELGAMAL_G (large prime and generator)

ELGAMAL_P = 7919   # ← use a MUCH larger prime in practice
ELGAMAL_G = 2

def elgamal_generate(username: str):
    """Generate ElGamal key pair and store as JSON."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    path = os.path.join(KEYS_DIR, f"{username}_elgamal.json")
    if os.path.exists(path):
        return
    p, g = ELGAMAL_P, ELGAMAL_G
    x = random.randint(2, p-2)            # private key
    y = pow(g, x, p)                      # public key component
    with open(path, "w") as f:
        json.dump({"p": p, "g": g, "y": y, "x": x}, f)
    print(f"  [ElGamal] Keys generated for {username}")

def elgamal_encrypt(plaintext: str, username: str) -> str:
    """
    ElGamal encrypt. Encrypts each character separately.
    Returns JSON string of list of (c1,c2) pairs.
    NOTE: for real use, convert message to integer first.
    """
    with open(os.path.join(KEYS_DIR, f"{username}_elgamal.json")) as f:
        keys = json.load(f)
    p, g, y = keys['p'], keys['g'], keys['y']
    ciphertext = []
    for ch in plaintext:
        m = ord(ch)                         # convert char to int
        k = random.randint(2, p-2)          # random per character
        c1 = pow(g, k, p)
        c2 = (m * pow(y, k, p)) % p
        ciphertext.append((c1, c2))
    return json.dumps(ciphertext)

def elgamal_decrypt(ct_json: str, username: str) -> str:
    """ElGamal decrypt. Recovers each character."""
    with open(os.path.join(KEYS_DIR, f"{username}_elgamal.json")) as f:
        keys = json.load(f)
    p, x = keys['p'], keys['x']
    pairs = json.loads(ct_json)
    result = []
    for c1, c2 in pairs:
        s = pow(c1, x, p)                  # s = c1^x mod p
        s_inv = pow(s, p-2, p)             # modular inverse via Fermat
        m = (c2 * s_inv) % p               # recover integer
        result.append(chr(m))              # convert back to char
    return ''.join(result)

# ── 5C. RABIN ENCRYPTION ──────────────────────────────────────────
# CHANGE: use larger primes in practice (≥512 bits each)

def rabin_generate():
    """
    Generate Rabin keys.
    p and q must satisfy p ≡ 3 (mod 4) and q ≡ 3 (mod 4).
    Returns dict with n (public) and p,q (private).
    """
    # For demo: small primes. In production: getPrime(512)
    # and check p%4==3. For exam, these small values are fine.
    p = 127   # 127 % 4 = 3 ✓
    q = 131   # 131 % 4 = 3 ✓
    n = p * q
    print(f"  [Rabin] p={p}, q={q}, n={n} (public key)")
    return {"n": n, "p": p, "q": q}

def rabin_encrypt(plaintext: str, n: int) -> list:
    """
    Rabin encrypt: C = M² mod n for each char.
    Returns list of ciphertexts (one per char).
    """
    return [pow(ord(ch), 2, n) for ch in plaintext]

def rabin_decrypt(ciphertexts: list, p: int, q: int) -> str:
    """
    Rabin decrypt using Chinese Remainder Theorem.
    Returns one of 4 possible plaintexts – caller picks the meaningful one.
    """
    n = p * q
    result = []
    for c in ciphertexts:
        # Square roots mod p and q
        mp = pow(c, (p+1)//4, p)
        mq = pow(c, (q+1)//4, q)
        # Extended Euclidean: yp*p + yq*q = 1
        _, yp, yq = _extended_gcd(p, q)
        # Four square roots via CRT
        r1 = (yp*p*mq + yq*q*mp) % n
        r2 = n - r1
        r3 = (yp*p*mq - yq*q*mp) % n
        r4 = n - r3
        # Pick the one that gives a printable ASCII character
        chosen = None
        for r in [r1, r2, r3, r4]:
            if 32 <= r <= 126:   # printable ASCII
                chosen = chr(r)
                break
        result.append(chosen if chosen else '?')
    return ''.join(result)

# ── 5D. DIFFIE-HELLMAN KEY EXCHANGE ───────────────────────────────
# Not encryption itself – gives a shared secret for use with AES etc.
# CHANGE: DH_P, DH_G

DH_P = 23   # ← use large prime in practice
DH_G = 5

def dh_generate_keypair(p=DH_P, g=DH_G):
    """Generate DH private/public key pair. Returns (private, public)."""
    private = random.randint(2, p-2)
    public  = pow(g, private, p)
    return private, public

def dh_compute_shared(their_public: int, my_private: int, p=DH_P) -> int:
    """Compute shared secret: their_public^my_private mod p"""
    return pow(their_public, my_private, p)

def dh_demo():
    """Full DH key exchange demo."""
    a_priv, a_pub = dh_generate_keypair()
    b_priv, b_pub = dh_generate_keypair()
    shared_a = dh_compute_shared(b_pub, a_priv)
    shared_b = dh_compute_shared(a_pub, b_priv)
    assert shared_a == shared_b, "DH failed!"
    print(f"  Alice public: {a_pub}, Bob public: {b_pub}")
    print(f"  Shared secret: {shared_a}  (both match: {shared_a==shared_b})")
    return shared_a


# ══════════════════════════════════════════════════════════════════
#  SECTION 6 – ACCESS CONTROL MODELS
# ══════════════════════════════════════════════════════════════════
# HOW TO SUBSTITUTE: replace the ACCESS dict and check_access()
#   in edusecure.py with whichever model the exam specifies.

# ── 6A. RBAC (current in edusecure.py) ───────────────────────────
# CHANGE: role names and their allowed operations

RBAC_ACCESS = {
    "student": {"encrypt", "sign", "upload", "view_own"},
    "faculty": {"decrypt", "verify_sig", "hash_check", "view_all"},
    "hod"    : {"view_hashes", "verify_sig"},
    # ← add new roles here: "admin": {"all"},  "auditor": {"view_logs"}
}

def rbac_check(role: str, operation: str) -> bool:
    """RBAC: user has role, role has permissions."""
    allowed = RBAC_ACCESS.get(role, set())
    if operation in allowed:
        return True
    print(f"  [RBAC Denied] '{role}' cannot do '{operation}'")
    return False

# ── 6B. ABAC (Attribute-Based Access Control) ────────────────────
# CHANGE: attribute dicts and the policy() function

def abac_check(user_attrs: dict, object_attrs: dict, operation: str) -> bool:
    """
    ABAC: access based on attributes.
    user_attrs:   e.g. {"dept": "finance", "clearance": 3}
    object_attrs: e.g. {"classification": 2, "dept": "finance"}
    CHANGE the policy logic below to match the exam scenario.
    """
    # Policy 1: clearance must be >= classification
    if user_attrs.get("clearance", 0) < object_attrs.get("classification", 0):
        print(f"  [ABAC Denied] Insufficient clearance")
        return False
    # Policy 2: same department required for write
    if operation == "write" and user_attrs.get("dept") != object_attrs.get("dept"):
        print(f"  [ABAC Denied] Cross-department write not allowed")
        return False
    return True

# ── 6C. Bell-LaPadula (No Read Up, No Write Down) ────────────────
# CHANGE: SECURITY_LEVELS and the assignment of subjects/objects

SECURITY_LEVELS = {"unclassified": 0, "confidential": 1, "secret": 2, "top_secret": 3}

def blp_can_read(subject_level: str, object_level: str) -> bool:
    """No Read Up: subject level must be >= object level."""
    sl = SECURITY_LEVELS.get(subject_level, -1)
    ol = SECURITY_LEVELS.get(object_level, 99)
    ok = sl >= ol
    if not ok:
        print(f"  [BLP Denied] {subject_level} cannot read {object_level} (No Read Up)")
    return ok

def blp_can_write(subject_level: str, object_level: str) -> bool:
    """No Write Down: subject level must be <= object level."""
    sl = SECURITY_LEVELS.get(subject_level, 99)
    ol = SECURITY_LEVELS.get(object_level, -1)
    ok = sl <= ol
    if not ok:
        print(f"  [BLP Denied] {subject_level} cannot write {object_level} (No Write Down)")
    return ok

# ── 6D. Time-Based Access Control ────────────────────────────────
# CHANGE: allowed time windows per role

TIME_WINDOWS = {
    "student": ("08:00", "20:00"),   # ← change hours
    "faculty": ("07:00", "22:00"),
    "hod"    : ("00:00", "23:59"),   # always
}

def time_based_check(role: str, now: datetime.datetime = None) -> bool:
    """Grant access only within role's allowed time window."""
    if now is None:
        now = datetime.datetime.now()
    current = now.strftime("%H:%M")
    window = TIME_WINDOWS.get(role)
    if window is None:
        print(f"  [Time Denied] Unknown role '{role}'")
        return False
    start, end = window
    ok = start <= current <= end
    if not ok:
        print(f"  [Time Denied] '{role}' not allowed at {current} (window: {start}–{end})")
    return ok

# ── 6E. MAC (Mandatory Access Control) ───────────────────────────
# CHANGE: CLEARANCE_LEVELS and user/object assignments

CLEARANCE_LEVELS = {"low": 0, "medium": 1, "high": 2}
OBJECT_CLASSIFICATION = {"public_record": 0, "student_data": 1, "exam_paper": 2}

def mac_check(subject_clearance: str, object_name: str, operation: str) -> bool:
    """MAC: clearance >= classification required for read."""
    sc = CLEARANCE_LEVELS.get(subject_clearance, -1)
    oc = OBJECT_CLASSIFICATION.get(object_name, 99)
    ok = sc >= oc
    if not ok:
        print(f"  [MAC Denied] Clearance '{subject_clearance}' insufficient for '{object_name}'")
    return ok


# ══════════════════════════════════════════════════════════════════
#  QUICK-TEST: run this file directly to verify everything works
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("TESTING CLASSICAL CIPHERS")
    print("=" * 60)
    msg = "HELLOWORLD"
    print(f"Original : {msg}")
    enc = additive_encrypt(msg, 20); dec = additive_decrypt(enc, 20)
    print(f"Additive  enc={enc}  dec={dec}  OK={dec==msg}")
    enc = multiplicative_encrypt(msg, 15); dec = multiplicative_decrypt(enc, 15)
    print(f"Multiply  enc={enc}  dec={dec}  OK={dec==msg}")
    enc = affine_encrypt(msg); dec = affine_decrypt(enc)
    print(f"Affine    enc={enc}  dec={dec}  OK={dec==msg}")
    enc = vigenere_encrypt(msg, "KEY"); dec = vigenere_decrypt(enc, "KEY")
    print(f"Vigenere  enc={enc}  dec={dec}  OK={dec==msg}")
    enc = autokey_encrypt(msg, 5); dec = autokey_decrypt(enc, 5)
    print(f"AutoKey   enc={enc}  dec={dec}  OK={dec==msg}")

    print()
    print("=" * 60)
    print("TESTING SYMMETRIC CIPHERS")
    print("=" * 60)
    msg2 = "Secret Message 123"
    enc = des_ecb_encrypt(msg2);    print(f"DES-ECB   OK={des_ecb_decrypt(enc)==msg2}")
    enc = des_cbc_encrypt(msg2);    print(f"DES-CBC   OK={des_cbc_decrypt(enc)==msg2}")
    enc = des3_encrypt(msg2);       print(f"3DES      OK={des3_decrypt(enc)==msg2}")
    enc = aes128_ecb_encrypt(msg2); print(f"AES128    OK={aes128_ecb_decrypt(enc)==msg2}")
    enc = aes256_cbc_encrypt(msg2); print(f"AES256CBC OK={aes256_cbc_decrypt(enc)==msg2}")
    enc = aes_ctr_encrypt(msg2);    print(f"AES-CTR   OK={aes_ctr_decrypt(enc)==msg2}")
    enc = aes_gcm_encrypt(msg2);    print(f"AES-GCM   OK={aes_gcm_decrypt(enc)==msg2}")

    print()
    print("=" * 60)
    print("TESTING HASHES")
    print("=" * 60)
    compare_all_hashes("hello")

    print()
    print("=" * 60)
    print("TESTING RSA SIGN/VERIFY")
    print("=" * 60)
    rsa_generate("testuser")
    sig = rsa_sign("my data", "testuser")
    print(f"RSA PKCS sig valid  : {rsa_verify('my data', sig, 'testuser')}")
    print(f"RSA PKCS tampered   : {rsa_verify('bad data', sig, 'testuser')}")
    sig2 = rsa_pss_sign("my data", "testuser")
    print(f"RSA PSS  sig valid  : {rsa_pss_verify('my data', sig2, 'testuser')}")

    print()
    print("=" * 60)
    print("TESTING DIFFIE-HELLMAN")
    print("=" * 60)
    dh_demo()

    print()
    print("=" * 60)
    print("TESTING ACCESS CONTROL")
    print("=" * 60)
    print(f"RBAC student encrypt : {rbac_check('student','encrypt')}")
    print(f"RBAC student decrypt : {rbac_check('student','decrypt')}")
    print(f"BLP  secret read confidential  : {blp_can_read('secret','confidential')}")
    print(f"BLP  confidential read secret  : {blp_can_read('confidential','secret')}")
    print(f"Time student check             : {time_based_check('student')}")
    print()
    print("ALL TESTS COMPLETE")
