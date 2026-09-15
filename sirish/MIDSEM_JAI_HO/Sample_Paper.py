"""
============================================================
EduSecure – Secure Education Data Management System
============================================================
Subject : Information Security Lab (ICT 3141)
Exam    : Lab Mid-Term

Algorithms used
  • DES   – symmetric encryption of academic records
  • RSA   – digital signatures for user authentication
  • SHA-256 – integrity hashing of records

HOW TO ADAPT THIS FOR THE ACTUAL EXAM
--------------------------------------
The question will keep the same skeleton but may change:
  1. The cipher  → swap the DES block (search "# --- DES ---")
     with AES/3DES/etc.  Only encrypt() / decrypt() change.
  2. The signing scheme → swap the RSA block
     (search "# --- RSA ---") with ElGamal / ECC / Schnorr.
     Only sign() / verify() change.
  3. The hash → swap SHA-256 with MD5 / SHA-1 / SHA-512 in
     compute_hash().
  4. The roles / access rules → edit the ACCESS dict and the
     role checks in each menu handler.
  5. The storage format → currently plain JSON; swap with
     SQLite, pickle, or a flat file if asked.

Everything else – the menu loop, the data-flow, the
timestamp handling – stays the same.
============================================================
"""

import os
import json
import hashlib
import base64
import datetime

# ── crypto imports ──────────────────────────────────────────
from Crypto.Cipher    import DES          # symmetric  (Lab 2)
from Crypto.PublicKey import RSA          # asymmetric (Lab 3)
from Crypto.Signature import pkcs1_15    # RSA-PKCS#1 signing
from Crypto.Hash      import SHA256 as _SHA256  # for RSA
from Crypto.Util.Padding import pad, unpad

# ============================================================
# CONFIGURATION – change these if the exam uses different
# roles, key sizes, or file names
# ============================================================

# ── role names (case-insensitive at login) ───────────────────
ROLES = ["student", "faculty", "hod"]

# ── what each role is ALLOWED to do ─────────────────────────
# This is the "access control" part.  In the actual exam the
# allowed operations might differ – just edit this dict.
ACCESS = {
    "student": {"encrypt", "sign", "upload", "view_own"},
    "faculty": {"decrypt", "verify_sig", "hash_check", "view_all"},
    "hod"    : {"view_hashes", "verify_sig"},
}

# ── DES key – must be exactly 8 bytes ───────────────────────
# *** CHANGE THIS to whatever key the exam specifies ***
DES_KEY = b"EduSec8B"          # 8 bytes for DES

# ── storage file ────────────────────────────────────────────
RECORDS_FILE = "records.json"  # JSON database of all records
KEYS_DIR     = "keys"          # folder that holds RSA key-pairs

# ============================================================
# UTILITY HELPERS
# ============================================================

def timestamp() -> str:
    """Return current date-time as a readable string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_records() -> dict:
    """Load the JSON records file; return empty dict if missing."""
    if os.path.exists(RECORDS_FILE):
        with open(RECORDS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_records(records: dict) -> None:
    """Persist the records dict to the JSON file."""
    with open(RECORDS_FILE, "w") as f:
        json.dump(records, f, indent=2)


def ensure_keys_dir() -> None:
    """Create the keys directory if it does not exist."""
    os.makedirs(KEYS_DIR, exist_ok=True)


# ============================================================
# --- DES ---
# To swap cipher: replace only these two functions.
# For AES  → from Crypto.Cipher import AES; key = 16/24/32 bytes
# For 3DES → from Crypto.Cipher import DES3; key = 16/24 bytes
# ============================================================

def des_encrypt(plaintext: str, key: bytes = DES_KEY) -> str:
    """
    Encrypt plaintext (str) with DES in ECB mode.
    Returns a Base64 string so it's safe to store in JSON.

    ECB mode is used here for simplicity.
    *** If the exam asks for CBC, add an IV:
        iv     = b"\x00" * 8
        cipher = DES.new(key, DES.MODE_CBC, iv)
        and prepend iv to the ciphertext before Base64-encoding ***
    """
    cipher       = DES.new(key, DES.MODE_ECB)
    padded_data  = pad(plaintext.encode(), DES.block_size)   # PKCS7 padding
    ciphertext   = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext).decode()             # store as str


def des_decrypt(ciphertext_b64: str, key: bytes = DES_KEY) -> str:
    """
    Decrypt a Base64-encoded DES ciphertext back to plaintext.
    """
    cipher     = DES.new(key, DES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    padded     = cipher.decrypt(ciphertext)
    return unpad(padded, DES.block_size).decode()


# ============================================================
# --- HASHING ---
# To swap: replace hashlib.sha256 with hashlib.md5 / sha1 / sha512
# ============================================================

def compute_hash(data: str) -> str:
    """
    Compute SHA-256 hash of a string.
    Returns hex digest.
    """
    return hashlib.sha256(data.encode()).hexdigest()


# ============================================================
# --- RSA ---
# To swap scheme: replace only generate_rsa_keys(),
# rsa_sign(), rsa_verify().
# For ElGamal / ECC / Schnorr the interface stays identical –
# sign(data) → signature_str,  verify(data, sig, pub) → bool
# ============================================================

def get_key_paths(username: str):
    """Return (private_key_path, public_key_path) for a user."""
    ensure_keys_dir()
    return (
        os.path.join(KEYS_DIR, f"{username}_private.pem"),
        os.path.join(KEYS_DIR, f"{username}_public.pem"),
    )


def generate_rsa_keys(username: str) -> None:
    """
    Generate a 2048-bit RSA key-pair for `username` and save
    PEM files under keys/.

    *** The exam might ask for 1024-bit or 4096-bit → change
        the bits= argument below ***
    """
    priv_path, pub_path = get_key_paths(username)
    if os.path.exists(priv_path):
        # Keys already exist – no need to regenerate
        return
    key = RSA.generate(2048)                         # RSA key generation
    with open(priv_path, "wb") as f:
        f.write(key.export_key())                    # private PEM
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())        # public PEM
    print(f"  [Key Gen] RSA 2048-bit key pair created for '{username}'.")


def load_private_key(username: str):
    """Load and return the RSA private key object for `username`."""
    priv_path, _ = get_key_paths(username)
    if not os.path.exists(priv_path):
        raise FileNotFoundError(
            f"No private key found for '{username}'. "
            "Register/upload first."
        )
    with open(priv_path, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key(username: str):
    """Load and return the RSA public key object for `username`."""
    _, pub_path = get_key_paths(username)
    if not os.path.exists(pub_path):
        raise FileNotFoundError(
            f"No public key found for '{username}'."
        )
    with open(pub_path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_sign(data: str, username: str) -> str:
    """
    Sign `data` with the RSA private key of `username`.
    Steps:
      1. Compute SHA-256 hash of data using pycryptodome's Hash object
         (needed by pkcs1_15 – different from hashlib above)
      2. Sign the hash with PKCS#1 v1.5
      3. Return Base64-encoded signature string

    *** If the exam asks PKCS#1 PSS (more secure):
        from Crypto.Signature import pss
        signer = pss.new(private_key)
        sig = signer.sign(_SHA256.new(data.encode())) ***
    """
    private_key = load_private_key(username)
    h           = _SHA256.new(data.encode())         # hash object for RSA
    signature   = pkcs1_15.new(private_key).sign(h) # PKCS#1 v1.5 signature
    return base64.b64encode(signature).decode()      # Base64 string


def rsa_verify(data: str, signature_b64: str, username: str) -> bool:
    """
    Verify `signature_b64` against `data` using `username`'s public key.
    Returns True if valid, False otherwise.
    """
    try:
        public_key = load_public_key(username)
        h          = _SHA256.new(data.encode())
        sig        = base64.b64decode(signature_b64)
        pkcs1_15.new(public_key).verify(h, sig)      # raises on failure
        return True
    except (ValueError, TypeError):
        return False


# ============================================================
# STUDENT OPERATIONS
# ============================================================

def student_encrypt_and_upload(username: str, records: dict) -> None:
    """
    Student workflow:
      1. Read the plaintext academic record (from file or typed input)
      2. Encrypt with DES
      3. Compute SHA-256 of the ENCRYPTED text  (integrity seal)
      4. Sign the hash with student's RSA private key
      5. Store everything with a timestamp
    """
    print("\n--- Encrypt & Upload Record ---")

    # Generate RSA keys on first use
    generate_rsa_keys(username)

    # ── Input: read from a file or type manually ─────────────
    choice = input("Load record from file? (y/n): ").strip().lower()
    if choice == "y":
        filepath = input("Enter file path: ").strip()
        if not os.path.exists(filepath):
            print("  [Error] File not found.")
            return
        with open(filepath, "r") as f:
            plaintext = f.read()
        record_name = os.path.basename(filepath)
    else:
        plaintext   = input("Type the academic record content:\n> ").strip()
        record_name = input("Enter a name for this record: ").strip()

    if not plaintext:
        print("  [Error] Empty record – nothing uploaded.")
        return

    # ── Step 1: DES encrypt ───────────────────────────────────
    encrypted = des_encrypt(plaintext)
    print(f"  [DES]  Encrypted (Base64, first 40 chars): {encrypted[:40]}…")

    # ── Step 2: SHA-256 hash of the encrypted text ───────────
    record_hash = compute_hash(encrypted)
    print(f"  [SHA-256] Hash of encrypted record: {record_hash}")

    # ── Step 3: RSA sign the hash ─────────────────────────────
    signature = rsa_sign(record_hash, username)
    print(f"  [RSA Sig] Signature (first 40 chars): {signature[:40]}…")

    # ── Step 4: Store ─────────────────────────────────────────
    if username not in records:
        records[username] = []

    records[username].append({
        "record_name" : record_name,
        "encrypted"   : encrypted,    # DES-encrypted, Base64
        "hash"        : record_hash,  # SHA-256 of encrypted text
        "signature"   : signature,    # RSA sig of hash
        "timestamp"   : timestamp(),
        "owner"       : username,
    })
    save_records(records)
    print(f"  [OK] Record '{record_name}' uploaded successfully at {timestamp()}.")


def student_view_own(username: str, records: dict) -> None:
    """Student views their own records (encrypted form + hash + timestamp)."""
    print(f"\n--- Records for {username} ---")
    user_records = records.get(username, [])
    if not user_records:
        print("  No records found.")
        return
    for i, r in enumerate(user_records, 1):
        print(f"\n  Record #{i}: {r['record_name']}")
        print(f"    Timestamp  : {r['timestamp']}")
        print(f"    Encrypted  : {r['encrypted'][:50]}…")
        print(f"    SHA-256    : {r['hash']}")
        print(f"    Signature  : {r['signature'][:50]}…")


# ============================================================
# FACULTY OPERATIONS
# ============================================================

def faculty_decrypt_and_verify(records: dict) -> None:
    """
    Faculty workflow:
      1. Choose which student's record to inspect
      2. Verify RSA signature (authenticity check)
      3. DES decrypt the record
      4. Compute SHA-256 of the decrypted text & compare with stored hash
         *** Note: We compare SHA-256(encrypted) stored at upload time
             against a freshly computed SHA-256(encrypted) –
             this detects tampering of the stored ciphertext. ***
    """
    print("\n--- Faculty: Decrypt & Verify Record ---")

    # List all students who have records
    students = list(records.keys())
    if not students:
        print("  No records in the system.")
        return
    print("  Students with records:")
    for i, s in enumerate(students, 1):
        print(f"    {i}. {s}  ({len(records[s])} record(s))")

    try:
        s_idx = int(input("  Select student number: ")) - 1
        student_name = students[s_idx]
    except (ValueError, IndexError):
        print("  [Error] Invalid selection.")
        return

    student_records = records[student_name]
    print(f"\n  Records of '{student_name}':")
    for i, r in enumerate(student_records, 1):
        print(f"    {i}. {r['record_name']}  [{r['timestamp']}]")

    try:
        r_idx  = int(input("  Select record number: ")) - 1
        record = student_records[r_idx]
    except (ValueError, IndexError):
        print("  [Error] Invalid selection.")
        return

    # ── Step 1: Verify RSA signature ──────────────────────────
    # The student signed SHA-256(encrypted).
    # Faculty re-verifies using the student's PUBLIC key.
    print("\n  [RSA] Verifying signature…")
    sig_valid = rsa_verify(record["hash"], record["signature"], student_name)
    if sig_valid:
        print("  [RSA] ✓ Signature VALID – record is authentic.")
    else:
        print("  [RSA] ✗ Signature INVALID – record may be tampered!")

    # ── Step 2: Integrity check – recompute hash of stored ciphertext ──
    print("\n  [SHA-256] Verifying integrity…")
    recomputed_hash = compute_hash(record["encrypted"])
    if recomputed_hash == record["hash"]:
        print("  [SHA-256] ✓ Hash matches – ciphertext is intact.")
    else:
        print("  [SHA-256] ✗ Hash MISMATCH – ciphertext was altered!")

    # ── Step 3: DES decrypt ───────────────────────────────────
    print("\n  [DES] Decrypting record…")
    try:
        plaintext = des_decrypt(record["encrypted"])
        print(f"  [DES] Decrypted content:\n\n{plaintext}\n")
    except Exception as e:
        print(f"  [DES] Decryption failed: {e}")
        return

    # ── Step 4: Log verification result ──────────────────────
    record.setdefault("verification_log", []).append({
        "by"       : "faculty",
        "time"     : timestamp(),
        "sig_ok"   : sig_valid,
        "hash_ok"  : (recomputed_hash == record["hash"]),
    })
    save_records(records)
    print(f"  [Log] Verification result stored at {timestamp()}.")


# ============================================================
# HOD OPERATIONS
# ============================================================

def hod_view_hashes(records: dict) -> None:
    """
    HoD can view ONLY the hashed academic records with timestamps.
    (Access control: HoD cannot see plaintext or encrypted data.)
    """
    print("\n--- HoD: View Hashed Records ---")
    if not records:
        print("  No records in the system.")
        return
    for student, recs in records.items():
        print(f"\n  Student: {student}")
        for i, r in enumerate(recs, 1):
            print(f"    #{i} {r['record_name']}  [{r['timestamp']}]")
            print(f"         SHA-256: {r['hash']}")


def hod_verify_signatures(records: dict) -> None:
    """
    HoD verifies RSA signatures on stored records for accreditation.
    """
    print("\n--- HoD: Verify Signatures ---")
    if not records:
        print("  No records in the system.")
        return
    for student, recs in records.items():
        print(f"\n  Student: {student}")
        for i, r in enumerate(recs, 1):
            ok = rsa_verify(r["hash"], r["signature"], student)
            status = "✓ VALID" if ok else "✗ INVALID"
            print(f"    #{i} {r['record_name']} – Signature: {status}")


# ============================================================
# ROLE-BASED MENU DISPATCH
# ============================================================

def check_access(role: str, operation: str) -> bool:
    """
    Return True if `role` is allowed to perform `operation`.
    Prints an error message if denied.
    """
    if operation in ACCESS.get(role, set()):
        return True
    print(f"  [Access Denied] Role '{role}' cannot perform '{operation}'.")
    return False


def student_menu(username: str, records: dict) -> None:
    while True:
        print(f"""
╔══════════════════════════════╗
║ STUDENT MENU –{username:<13} ║
╚══════════════════════════════╝
  1. Encrypt & Upload Record
  2. View My Records
  3. Logout
""")
        choice = input("  Select: ").strip()
        if choice == "1":
            if check_access("student", "encrypt"):
                student_encrypt_and_upload(username, records)
        elif choice == "2":
            if check_access("student", "view_own"):
                student_view_own(username, records)
        elif choice == "3":
            print("  Logged out.")
            break
        else:
            print("  Invalid option.")


def faculty_menu(username: str, records: dict) -> None:
    while True:
        print(f"""
╔══════════════════════════════╗
║ FACULTY MENU –{username:<13} ║
╚══════════════════════════════╝
  1. Decrypt & Verify Record
  2. Logout
""")
        choice = input("  Select: ").strip()
        if choice == "1":
            if check_access("faculty", "decrypt"):
                faculty_decrypt_and_verify(records)
        elif choice == "2":
            print("  Logged out.")
            break
        else:
            print("  Invalid option.")


def hod_menu(username: str, records: dict) -> None:
    while True:
        print(f"""
╔══════════════════════════════╗
║   HOD MENU –{username:<17}   ║
╚══════════════════════════════╝
  1. View Hashed Records
  2. Verify All Signatures
  3. Logout
""")
        choice = input("  Select: ").strip()
        if choice == "1":
            if check_access("hod", "view_hashes"):
                hod_view_hashes(records)
        elif choice == "2":
            if check_access("hod", "verify_sig"):
                hod_verify_signatures(records)
        elif choice == "3":
            print("  Logged out.")
            break
        else:
            print("  Invalid option.")


# ============================================================
# MAIN – LOGIN & ROLE DISPATCH
# ============================================================

def main() -> None:
    print("""
╔═══════════════════════════════════════╗
║   EduSecure – Academic Record System  ║
║   DES · RSA Digital Signatures · SHA  ║
╚═══════════════════════════════════════╝
""")
    records = load_records()

    while True:
        print("""
  [LOGIN]
  Roles: student | faculty | hod
  (type 'exit' to quit)
""")
        username = input("  Username: ").strip().lower()
        if username == "exit":
            print("  Goodbye.")
            break
        if not username:
            continue

        role = input("  Role    : ").strip().lower()
        if role not in ROLES:
            print(f"  [Error] Unknown role '{role}'. Choose from {ROLES}.")
            continue

        print(f"\n  Welcome, {username} ({role})!\n")

        # Route to the correct role menu
        if role == "student":
            student_menu(username, records)
        elif role == "faculty":
            faculty_menu(username, records)
        elif role == "hod":
            hod_menu(username, records)

        # Reload records after each session (in case another
        # role modified them)
        records = load_records()


if __name__ == "__main__":
    main()