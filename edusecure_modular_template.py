
# ======================================================================
# EduSecure / Generic Secure Record Management Template
# ======================================================================
# Reusable for questions involving:
#   - Role-Based Access Control (RBAC)
#   - DES encryption/decryption
#   - RSA digital signatures
#   - SHA-256 hashing
#   - File I/O
#   - JSON storage
#   - Menu-driven programs
#
# Install:
#   pip install pycryptodome
#
# IMPORTANT:
# Change ONLY the PERMISSIONS dictionary when a question gives different
# role permissions.
#
# Example roles:
#   STUDENT -> encrypt, sign, upload, view_own
#   FACULTY -> decrypt, verify_signature, verify_integrity, view_records
#   HOD     -> view_hashes, verify_signature
# ======================================================================

import os
import json
import base64
import hashlib
from datetime import datetime

from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# ======================================================================
# 1. CONFIGURATION
# ======================================================================

BASE_DIR = "edusecure_data"
RECORD_DIR = os.path.join(BASE_DIR, "records")
KEY_DIR = os.path.join(BASE_DIR, "keys")

USER_FILE = os.path.join(BASE_DIR, "users.json")
RECORD_FILE = os.path.join(BASE_DIR, "records.json")
RESULT_FILE = os.path.join(BASE_DIR, "verification_results.json")

DES_KEY_FILE = os.path.join(KEY_DIR, "des_key.bin")

RSA_BITS = 2048

# ----------------------------------------------------------------------
# CHANGE PERMISSIONS HERE
# ----------------------------------------------------------------------
# action -> list of roles allowed to perform that action
#
# This is the main RBAC dictionary.
# Add/remove roles without changing the rest of the program.
# ----------------------------------------------------------------------

PERMISSIONS = {
    "encrypt": ["student"],
    "sign": ["student"],
    "upload": ["student"],
    "view_own": ["student"],

    "decrypt": ["faculty"],
    "verify_signature": ["faculty", "hod"],
    "verify_integrity": ["faculty"],
    "view_records": ["faculty"],
    "store_verification": ["faculty"],

    "view_hashes": ["hod"],
}


# ======================================================================
# 2. BASIC FILE / FOLDER FUNCTIONS
# ======================================================================

def setup_directories():
    """Create required directories/files if they do not exist."""
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(RECORD_DIR, exist_ok=True)
    os.makedirs(KEY_DIR, exist_ok=True)

    if not os.path.exists(USER_FILE):
        save_json(USER_FILE, [])

    if not os.path.exists(RECORD_FILE):
        save_json(RECORD_FILE, [])

    if not os.path.exists(RESULT_FILE):
        save_json(RESULT_FILE, [])


def save_json(path, data):
    """Save Python data as formatted JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def load_json(path, default=None):
    """Load JSON file safely."""
    if not os.path.exists(path):
        return [] if default is None else default

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return [] if default is None else default


def append_json(path, item):
    """Append one item to a JSON list."""
    data = load_json(path, [])
    data.append(item)
    save_json(path, data)


def read_file_bytes(path):
    """Read a file as bytes."""
    with open(path, "rb") as f:
        return f.read()


def write_file_bytes(path, data):
    """Write bytes to a file."""
    with open(path, "wb") as f:
        f.write(data)


def timestamp():
    """Return a readable UTC timestamp."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


# ======================================================================
# 3. USER / RBAC FUNCTIONS
# ======================================================================

def add_user(username, role):
    """
    Add a user to users.json.

    role examples:
        student
        faculty
        hod
    """
    role = role.lower()

    users = load_json(USER_FILE, [])

    # Prevent duplicates
    for user in users:
        if user["username"] == username:
            print("User already exists.")
            return False

    users.append({
        "username": username,
        "role": role
    })

    save_json(USER_FILE, users)
    print("User added successfully.")
    return True


def get_user(username):
    """Return user dictionary or None."""
    users = load_json(USER_FILE, [])

    for user in users:
        if user["username"] == username:
            return user

    return None


def get_role(username):
    """Return user's role or None."""
    user = get_user(username)
    return user["role"] if user else None


def has_permission(role, action):
    """
    Check RBAC permission.

    This is the only function other modules need to call for access
    control.
    """
    role = role.lower()
    allowed_roles = PERMISSIONS.get(action, [])
    return role in allowed_roles


def require_permission(role, action):
    """
    Return True if allowed, otherwise print an access-denied message.
    """
    if not has_permission(role, action):
        print(f"ACCESS DENIED: role '{role}' cannot perform '{action}'.")
        return False

    return True


# ======================================================================
# 4. DES KEY MANAGEMENT
# ======================================================================

def generate_des_key():
    """
    DES requires an 8-byte key.

    For an actual security system DES is obsolete; it is used here
    because the assignment specifically requires DES.
    """
    if not os.path.exists(DES_KEY_FILE):
        key = get_random_bytes(8)
        write_file_bytes(DES_KEY_FILE, key)
        print("DES key generated.")
    else:
        print("DES key already exists.")

    return read_file_bytes(DES_KEY_FILE)


def load_des_key():
    """Load the shared DES key."""
    if not os.path.exists(DES_KEY_FILE):
        return generate_des_key()

    key = read_file_bytes(DES_KEY_FILE)

    if len(key) != 8:
        raise ValueError("Invalid DES key. DES key must be exactly 8 bytes.")

    return key


# ======================================================================
# 5. DES ENCRYPTION / DECRYPTION
# ======================================================================

def pad_data(data):
    """PKCS-style padding for DES block size."""
    block_size = DES.block_size
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len]) * padding_len


def unpad_data(data):
    """Remove padding added by pad_data()."""
    padding_len = data[-1]

    if padding_len < 1 or padding_len > DES.block_size:
        raise ValueError("Invalid padding.")

    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding.")

    return data[:-padding_len]


def des_encrypt(data, key):
    """
    Encrypt bytes using DES-CBC.
    Returns IV + ciphertext.
    """
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes.")

    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)

    encrypted = cipher.encrypt(pad_data(data))

    # Store IV together with ciphertext.
    return iv + encrypted


def des_decrypt(encrypted_data, key):
    """Decrypt data produced by des_encrypt()."""
    if len(encrypted_data) < 16:
        raise ValueError("Invalid encrypted data.")

    iv = encrypted_data[:8]
    ciphertext = encrypted_data[8:]

    cipher = DES.new(key, DES.MODE_CBC, iv)

    decrypted = cipher.decrypt(ciphertext)

    return unpad_data(decrypted)


def encrypt_file(input_file, output_file, key):
    """Encrypt a file using DES and save ciphertext to output_file."""
    data = read_file_bytes(input_file)
    encrypted = des_encrypt(data, key)
    write_file_bytes(output_file, encrypted)
    return encrypted


def decrypt_file(input_file, output_file, key):
    """Decrypt a DES-encrypted file."""
    encrypted = read_file_bytes(input_file)
    decrypted = des_decrypt(encrypted, key)
    write_file_bytes(output_file, decrypted)
    return decrypted


# ======================================================================
# 6. SHA-256 HASHING
# ======================================================================

def sha256_bytes(data):
    """Return SHA-256 hexadecimal digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    """Return SHA-256 hexadecimal digest of a file."""
    data = read_file_bytes(path)
    return sha256_bytes(data)


# ======================================================================
# 7. RSA KEY MANAGEMENT
# ======================================================================

def user_private_key_path(username):
    return os.path.join(KEY_DIR, f"{username}_private.pem")


def user_public_key_path(username):
    return os.path.join(KEY_DIR, f"{username}_public.pem")


def generate_rsa_keys(username):
    """
    Generate RSA public/private key pair for a user.
    Files:
        username_private.pem
        username_public.pem
    """
    private_path = user_private_key_path(username)
    public_path = user_public_key_path(username)

    if os.path.exists(private_path) and os.path.exists(public_path):
        return

    key = RSA.generate(RSA_BITS)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    write_file_bytes(private_path, private_key)
    write_file_bytes(public_path, public_key)

    print(f"RSA keys generated for {username}.")


def load_private_key(username):
    """Load user's RSA private key."""
    path = user_private_key_path(username)
    return RSA.import_key(read_file_bytes(path))


def load_public_key(username):
    """Load user's RSA public key."""
    path = user_public_key_path(username)
    return RSA.import_key(read_file_bytes(path))


# ======================================================================
# 8. RSA DIGITAL SIGNATURES
# ======================================================================

def rsa_sign(data, username):
    """
    Sign SHA-256 digest of data using user's RSA private key.

    Returns Base64 signature so it can be stored in JSON.
    """
    private_key = load_private_key(username)

    digest = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(digest)

    return base64.b64encode(signature).decode("utf-8")


def rsa_verify(data, signature_b64, username):
    """
    Verify Base64 RSA signature using user's public key.
    Returns True/False.
    """
    try:
        public_key = load_public_key(username)
        signature = base64.b64decode(signature_b64)

        digest = SHA256.new(data)
        pkcs1_15.new(public_key).verify(digest, signature)

        return True

    except (ValueError, TypeError):
        return False


# ======================================================================
# 9. RECORD STORAGE
# ======================================================================

def get_record(record_id):
    """Return one stored record by ID."""
    records = load_json(RECORD_FILE, [])

    for record in records:
        if record["record_id"] == record_id:
            return record

    return None


def generate_record_id():
    """Generate simple sequential record ID."""
    records = load_json(RECORD_FILE, [])

    return f"REC-{len(records) + 1:04d}"


def save_record(record):
    """Save one academic record in records.json."""
    append_json(RECORD_FILE, record)


# ======================================================================
# 10. STUDENT FUNCTIONS
# ======================================================================

def upload_student_record(username, input_file):
    """
    Complete student workflow:

        1. Check role
        2. Read plaintext record
        3. Compute plaintext SHA-256
        4. Encrypt with DES
        5. Compute encrypted-record SHA-256
        6. Sign encrypted-record hash/data using RSA
        7. Store metadata
    """
    role = get_role(username)

    if role is None:
        print("Unknown user.")
        return False

    if not require_permission(role, "encrypt"):
        return False

    if not require_permission(role, "sign"):
        return False

    if not require_permission(role, "upload"):
        return False

    if not os.path.exists(input_file):
        print("Input file not found.")
        return False

    generate_rsa_keys(username)
    des_key = load_des_key()

    # Read original/plaintext record.
    plaintext = read_file_bytes(input_file)

    # Hash plaintext for later integrity checking.
    plaintext_hash = sha256_bytes(plaintext)

    # Encrypt plaintext.
    encrypted = des_encrypt(plaintext, des_key)

    # Save encrypted copy.
    record_id = generate_record_id()
    encrypted_file = os.path.join(
        RECORD_DIR,
        f"{record_id}_{os.path.basename(input_file)}.enc"
    )

    write_file_bytes(encrypted_file, encrypted)

    # Hash encrypted record.
    encrypted_hash = sha256_bytes(encrypted)

    # Sign encrypted content/hash.
    signature = rsa_sign(encrypted, username)

    record = {
        "record_id": record_id,
        "owner": username,
        "original_filename": os.path.basename(input_file),
        "encrypted_file": encrypted_file,
        "plaintext_hash": plaintext_hash,
        "encrypted_hash": encrypted_hash,
        "signature": signature,
        "timestamp": timestamp()
    }

    save_record(record)

    print("\nRecord uploaded successfully.")
    print("Record ID:", record_id)
    print("Timestamp:", record["timestamp"])
    print("Plaintext SHA-256:", plaintext_hash)
    print("Encrypted SHA-256:", encrypted_hash)

    return True


def student_view_records(username):
    """Student can view only their own record metadata."""
    role = get_role(username)

    if role is None or not require_permission(role, "view_own"):
        return

    records = load_json(RECORD_FILE, [])

    own_records = [r for r in records if r["owner"] == username]

    if not own_records:
        print("No records found.")
        return

    for r in own_records:
        print("-" * 60)
        print("Record ID       :", r["record_id"])
        print("File             :", r["original_filename"])
        print("Timestamp        :", r["timestamp"])
        print("Plaintext Hash   :", r["plaintext_hash"])
        print("Encrypted Hash   :", r["encrypted_hash"])
        print("Signature        :", r["signature"])


# ======================================================================
# 11. FACULTY FUNCTIONS
# ======================================================================

def faculty_decrypt_record(faculty_username, record_id):
    """
    Faculty decrypts a student's encrypted record.
    """
    faculty_role = get_role(faculty_username)

    if faculty_role is None:
        print("Unknown faculty user.")
        return None

    if not require_permission(faculty_role, "decrypt"):
        return None

    record = get_record(record_id)

    if record is None:
        print("Record not found.")
        return None

    des_key = load_des_key()

    try:
        encrypted = read_file_bytes(record["encrypted_file"])
        decrypted = des_decrypt(encrypted, des_key)

        output_file = os.path.join(
            RECORD_DIR,
            f"{record_id}_decrypted.txt"
        )

        write_file_bytes(output_file, decrypted)

        print("Record decrypted successfully.")
        print("Decrypted file:", output_file)

        return decrypted

    except Exception as e:
        print("Decryption failed:", e)
        return None


def faculty_verify_signature(faculty_username, record_id):
    """
    Faculty verifies the student's RSA signature.

    Signature is verified against the encrypted record.
    """
    role = get_role(faculty_username)

    if role is None or not require_permission(role, "verify_signature"):
        return False

    record = get_record(record_id)

    if record is None:
        print("Record not found.")
        return False

    encrypted = read_file_bytes(record["encrypted_file"])

    result = rsa_verify(
        encrypted,
        record["signature"],
        record["owner"]
    )

    print("RSA Signature Verification:",
          "VALID" if result else "INVALID")

    return result


def faculty_verify_integrity(faculty_username, record_id):
    """
    Faculty decrypts the record, hashes plaintext, and compares it
    with stored plaintext_hash.
    """
    role = get_role(faculty_username)

    if role is None or not require_permission(role, "verify_integrity"):
        return False

    record = get_record(record_id)

    if record is None:
        print("Record not found.")
        return False

    des_key = load_des_key()

    try:
        encrypted = read_file_bytes(record["encrypted_file"])
        decrypted = des_decrypt(encrypted, des_key)

        calculated_hash = sha256_bytes(decrypted)
        stored_hash = record["plaintext_hash"]

        result = calculated_hash == stored_hash

        print("SHA-256 Integrity:",
              "MATCH" if result else "MISMATCH")
        print("Stored hash    :", stored_hash)
        print("Calculated hash:", calculated_hash)

        return result

    except Exception as e:
        print("Integrity verification failed:", e)
        return False


def faculty_verify_record(faculty_username, record_id):
    """
    Run the complete faculty verification workflow:
        RSA signature + SHA-256 integrity
    """
    role = get_role(faculty_username)

    if role is None:
        return False

    signature_ok = faculty_verify_signature(
        faculty_username,
        record_id
    )

    integrity_ok = faculty_verify_integrity(
        faculty_username,
        record_id
    )

    overall = signature_ok and integrity_ok

    print("\nOverall Verification:",
          "PASSED" if overall else "FAILED")

    if has_permission(role, "store_verification"):
        result = {
            "record_id": record_id,
            "verified_by": faculty_username,
            "signature_valid": signature_ok,
            "integrity_valid": integrity_ok,
            "overall_result": overall,
            "timestamp": timestamp()
        }

        append_json(RESULT_FILE, result)

        print("Verification result stored.")

    return overall


def faculty_view_records(faculty_username):
    """Faculty can view record metadata."""
    role = get_role(faculty_username)

    if role is None or not require_permission(role, "view_records"):
        return

    records = load_json(RECORD_FILE, [])

    for r in records:
        print("-" * 60)
        print("Record ID :", r["record_id"])
        print("Owner     :", r["owner"])
        print("File      :", r["original_filename"])
        print("Timestamp :", r["timestamp"])


# ======================================================================
# 12. HOD FUNCTIONS
# ======================================================================

def hod_view_hashes(hod_username):
    """
    HoD sees only hashes/timestamps, not plaintext data.
    """
    role = get_role(hod_username)

    if role is None or not require_permission(role, "view_hashes"):
        return

    records = load_json(RECORD_FILE, [])

    for r in records:
        print("-" * 60)
        print("Record ID       :", r["record_id"])
        print("Owner            :", r["owner"])
        print("Plaintext SHA256 :", r["plaintext_hash"])
        print("Encrypted SHA256 :", r["encrypted_hash"])
        print("Timestamp        :", r["timestamp"])


def hod_verify_signature(hod_username, record_id):
    """HoD verifies stored student's RSA signature."""
    role = get_role(hod_username)

    if role is None or not require_permission(role, "verify_signature"):
        return False

    record = get_record(record_id)

    if record is None:
        print("Record not found.")
        return False

    encrypted = read_file_bytes(record["encrypted_file"])

    result = rsa_verify(
        encrypted,
        record["signature"],
        record["owner"]
    )

    print("HoD RSA Signature:",
          "VALID" if result else "INVALID")

    return result


# ======================================================================
# 13. DISPLAY / MENU HELPERS
# ======================================================================

def list_all_records():
    """Display record IDs for easy exam/demo use."""
    records = load_json(RECORD_FILE, [])

    if not records:
        print("No records available.")
        return

    for r in records:
        print(
            f"{r['record_id']} | "
            f"{r['owner']} | "
            f"{r['original_filename']} | "
            f"{r['timestamp']}"
        )


def student_menu(username):
    while True:
        print("\n========== STUDENT MENU ==========")
        print("1. Upload / Encrypt / Sign record")
        print("2. View my records")
        print("3. Logout")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            path = input("Enter input file path: ").strip()
            upload_student_record(username, path)

        elif choice == "2":
            student_view_records(username)

        elif choice == "3":
            break

        else:
            print("Invalid choice.")


def faculty_menu(username):
    while True:
        print("\n========== FACULTY MENU ==========")
        print("1. View records")
        print("2. Decrypt record")
        print("3. Verify RSA signature")
        print("4. Verify SHA-256 integrity")
        print("5. Complete verification")
        print("6. Logout")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            faculty_view_records(username)

        elif choice == "2":
            record_id = input("Record ID: ").strip()
            faculty_decrypt_record(username, record_id)

        elif choice == "3":
            record_id = input("Record ID: ").strip()
            faculty_verify_signature(username, record_id)

        elif choice == "4":
            record_id = input("Record ID: ").strip()
            faculty_verify_integrity(username, record_id)

        elif choice == "5":
            record_id = input("Record ID: ").strip()
            faculty_verify_record(username, record_id)

        elif choice == "6":
            break

        else:
            print("Invalid choice.")


def hod_menu(username):
    while True:
        print("\n========== HOD MENU ==========")
        print("1. View hashes")
        print("2. Verify RSA signature")
        print("3. Logout")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            hod_view_hashes(username)

        elif choice == "2":
            record_id = input("Record ID: ").strip()
            hod_verify_signature(username, record_id)

        elif choice == "3":
            break

        else:
            print("Invalid choice.")


# ======================================================================
# 14. LOGIN
# ======================================================================

def login():
    """Simple username/role lookup for a lab/demo system."""
    username = input("Enter username: ").strip()

    user = get_user(username)

    if user is None:
        print("User not found.")
        return None, None

    role = user["role"]

    print(f"Logged in as {username} ({role})")

    # Generate RSA keys automatically for cryptographic users.
    if role in ("student", "faculty", "hod"):
        generate_rsa_keys(username)

    return username, role


# ======================================================================
# 15. INITIAL USER SETUP
# ======================================================================

def create_demo_users():
    """
    Create users only if they do not already exist.
    Change these names/roles according to the question.
    """
    demo_users = [
        ("student1", "student"),
        ("faculty1", "faculty"),
        ("hod1", "hod"),
    ]

    for username, role in demo_users:
        if get_user(username) is None:
            add_user(username, role)
        generate_rsa_keys(username)


# ======================================================================
# 16. MAIN MENU
# ======================================================================

def main():
    setup_directories()

    # Generate shared DES key.
    load_des_key()

    # Demo users for lab use.
    create_demo_users()

    while True:
        print("\n" + "=" * 60)
        print("              EDUSECURE SYSTEM")
        print("=" * 60)
        print("1. Login")
        print("2. List stored records")
        print("3. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            username, role = login()

            if username is None:
                continue

            if role == "student":
                student_menu(username)

            elif role == "faculty":
                faculty_menu(username)

            elif role == "hod":
                hod_menu(username)

            else:
                print("Unknown role.")

        elif choice == "2":
            list_all_records()

        elif choice == "3":
            print("Exiting EduSecure.")
            break

        else:
            print("Invalid choice.")


# ======================================================================
# 17. PROGRAM START
# ======================================================================

if __name__ == "__main__":
    main()


# ======================================================================
# QUICK EXAM REFERENCE
# ======================================================================
#
# RBAC:
#   PERMISSIONS = {
#       "encrypt": ["student"],
#       "decrypt": ["faculty"],
#       "verify_signature": ["faculty", "hod"],
#   }
#
# Check:
#   require_permission(role, "encrypt")
#
# DES:
#   key = load_des_key()
#   encrypted = des_encrypt(data, key)
#   decrypted = des_decrypt(encrypted, key)
#
# SHA-256:
#   digest = sha256_bytes(data)
#   file_digest = sha256_file(path)
#
# RSA:
#   generate_rsa_keys(username)
#   signature = rsa_sign(data, username)
#   valid = rsa_verify(data, signature, username)
#
# File I/O:
#   data = read_file_bytes(path)
#   write_file_bytes(path, data)
#
# JSON:
#   save_json(path, data)
#   data = load_json(path)
#   append_json(path, item)
#
# Common modification patterns:
#
#   1. Different role names:
#      change PERMISSIONS and demo users.
#
#   2. Different permissions:
#      add/remove action names in PERMISSIONS.
#
#   3. Different crypto:
#      replace only des_encrypt/des_decrypt or rsa_sign/rsa_verify.
#
#   4. Database instead of JSON:
#      replace save_json/load_json/append_json.
#
#   5. Different record fields:
#      modify the "record" dictionary inside upload_student_record().
#
#   6. Different workflow:
#      keep the crypto and RBAC functions and write a new menu.
#
# NOTE ON HASHES:
#   The assignment mixes "sign hash of encrypted record" with
#   "hash decrypted record and compare with stored hash".
#   To make both checks logically correct, this template stores:
#       plaintext_hash -> integrity after decryption
#       encrypted_hash -> integrity of encrypted file
#   The RSA signature is over the encrypted record.
#
# NOTE ON REAL SECURITY:
#   DES is obsolete and should not be used for modern production systems.
#   It is used here only because the lab question explicitly requires DES.
# ======================================================================
