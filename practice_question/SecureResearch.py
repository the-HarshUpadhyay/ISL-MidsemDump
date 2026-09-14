import os
import json
import base64
import hashlib
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import base64


# ======================================================================
# 1. CONFIGURATION
# ======================================================================

BASE_DIR = "secureresearch_data"
REPORT_DIR = os.path.join(BASE_DIR, "reports")
KEY_DIR = os.path.join(BASE_DIR, "keys")

USER_FILE = os.path.join(BASE_DIR, "users.json")
REPORT_FILE = os.path.join(BASE_DIR, "reports.json")
RESULT_FILE = os.path.join(BASE_DIR, "verification_results.json")

AES_KEY_FILE = os.path.join(KEY_DIR, "aes_key.bin")

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
    "encrypt": ["researcher"],
    "sign": ["researcher"],
    "upload": ["researcher"],
    "view_own": ["researcher"],

    "decrypt": ["supervisor"],
    "verify_signature": ["supervisor", "research_director"],
    "verify_integrity": ["supervisor"],
    "view_reports": ["supervisor"],
    "store_verification": ["supervisor"],

    "view_hashes": ["research_director"],
}


# ======================================================================
# 2. BASIC FILE / FOLDER FUNCTIONS
# ======================================================================

def setup_directories():
    """Create required directories/files if they do not exist."""
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs(KEY_DIR, exist_ok=True)

    if not os.path.exists(USER_FILE):
        save_json(USER_FILE, [])

    if not os.path.exists(REPORT_FILE):
        save_json(REPORT_FILE, [])

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
        researcher
        supervisor
        research_director
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
# 4. AES KEY MANAGEMENT
# ======================================================================

def generate_aes_key():
    """

    For an actual security system AES is obsolete; it is used here
    because the assignment specifically requires AES.

    AES: 8 bytes
    AES-128: 16 bytes
    AES-192: 24 bytes
    AES-256: 32 bytes
    """
    if not os.path.exists(AES_KEY_FILE):
        key = get_random_bytes(32)
        write_file_bytes(AES_KEY_FILE, key)
        print("AES key generated.")
    else:
        print("AES key already exists.")

    return read_file_bytes(AES_KEY_FILE)


def load_aes_key():
    """Load the shared AES key."""
    if not os.path.exists(AES_KEY_FILE):
        return generate_aes_key()

    key = read_file_bytes(AES_KEY_FILE)
    keylength = 32
    if len(key) != keylength:
        raise ValueError("Invalid AES key. AES key must be exactly 32 bytes.")
    
    return key


# ======================================================================
# 5. AES ENCRYPTION / DECRYPTION
# ======================================================================

def aes_encrypt(data, key):
    """
    Encrypt bytes using AES-CBC.
    Returns IV + ciphertext.

    FOR AES: 8
    FOR AES-128: 16
    FOR AES-192: 24
    FOR AES-256: 32
    """
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes.")

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    encrypted = cipher.encrypt(pad(data,AES.block_size))

    # Store IV together with ciphertext.
    return iv + encrypted


def aes_decrypt(encrypted_data, key):
    """Decrypt data produced by aes_encrypt()."""
    if len(encrypted_data) < 2*AES.block_size:
    # encrypted data cannot be less than IV+1 AES_BLOCK
        raise ValueError("Invalid encrypted data.")

    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]

    if len(ciphertext) % AES.block_size != 0:
        raise ValueError("Invalid ciphertext length.")

    cipher = AES.new(key, AES.MODE_CBC, iv)


    decrypted = cipher.decrypt(ciphertext)

    return unpad(decrypted,AES.block_size)


def encrypt_file(input_file, output_file, key):
    """Encrypt a file using AES and save ciphertext to output_file."""
    data = read_file_bytes(input_file)
    encrypted = aes_encrypt(data, key)
    write_file_bytes(output_file, encrypted)
    return encrypted


def decrypt_file(input_file, output_file, key):
    """Decrypt a AES-encrypted file."""
    encrypted = read_file_bytes(input_file)
    decrypted = aes_decrypt(encrypted, key)
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
# 9. REPORT STORAGE
# ======================================================================

def get_report(report_id):
    """Return one stored report by ID."""
    reports = load_json(REPORT_FILE, [])

    for report in reports:
        if report["report_id"] == report_id:
            return report

    return None


def generate_report_id():
    """Generate simple sequential report ID."""
    reports = load_json(REPORT_FILE, [])

    return f"REC-{len(reports) + 1:04d}"


def save_report(report):
    """Save one academic report in reports.json."""
    append_json(REPORT_FILE, report)

# ======================================================================
# 10. RESEARCHER FUNCTIONS
# ======================================================================

def upload_researcher_report(username, input_file):
    """
    Complete researcher workflow:

        1. Check role
        2. Read plaintext report
        3. Compute plaintext SHA-256
        4. Encrypt with AES
        5. Compute encrypted-report SHA-256
        6. Sign encrypted-report hash/data using RSA
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
    aes_key = load_aes_key()

    # Read original/plaintext report.
    plaintext = read_file_bytes(input_file)

    # Hash plaintext for later integrity checking.
    plaintext_hash = sha256_bytes(plaintext)

    # Encrypt plaintext.
    encrypted = aes_encrypt(plaintext, aes_key)

    # Save encrypted copy.
    report_id = generate_report_id()
    encrypted_file = os.path.join(
        REPORT_DIR,
        f"{report_id}_{os.path.basename(input_file)}.enc"
    )

    write_file_bytes(encrypted_file, encrypted)

    # Hash encrypted report.
    encrypted_hash = sha256_bytes(encrypted)

    # Sign encrypted content/hash.
    signature = rsa_sign(encrypted, username)

    report = {
        "report_id": report_id,
        "owner": username,
        "original_filename": os.path.basename(input_file),
        "encrypted_file": encrypted_file,
        "plaintext_hash": plaintext_hash,
        "encrypted_hash": encrypted_hash,
        "signature": signature,
        "timestamp": timestamp()
    }

    save_report(report)

    print("\nReport uploaded successfully.")
    print("Report ID:", report_id)
    print("Timestamp:", report["timestamp"])
    print("Plaintext SHA-256:", plaintext_hash)
    print("Encrypted SHA-256:", encrypted_hash)

    return True


def researcher_view_reports(username):
    """Researcher can view only their own report metadata."""
    role = get_role(username)

    if role is None or not require_permission(role, "view_own"):
        return

    reports = load_json(REPORT_FILE, [])

    own_reports = [r for r in reports if r["owner"] == username]

    if not own_reports:
        print("No reports found.")
        return

    for r in own_reports:
        print("-" * 60)
        print("Report ID       :", r["report_id"])
        print("File             :", r["original_filename"])
        print("Timestamp        :", r["timestamp"])
        print("Plaintext Hash   :", r["plaintext_hash"])
        print("Encrypted Hash   :", r["encrypted_hash"])
        print("Signature        :", r["signature"])

# ======================================================================
# 11. SUPERVISOR FUNCTIONS
# ======================================================================

def supervisor_decrypt_report(supervisor_username, report_id):
    """
    Supervisor decrypts a researcher's encrypted report.
    """
    supervisor_role = get_role(supervisor_username)

    if supervisor_role is None:
        print("Unknown supervisor user.")
        return None

    if not require_permission(supervisor_role, "decrypt"):
        return None

    report = get_report(report_id)

    if report is None:
        print("Report not found.")
        return None

    aes_key = load_aes_key()

    try:
        encrypted = read_file_bytes(report["encrypted_file"])
        decrypted = aes_decrypt(encrypted, aes_key)

        output_file = os.path.join(
            REPORT_DIR,
            f"{report_id}_decrypted.txt"
        )

        write_file_bytes(output_file, decrypted)

        print("Report decrypted successfully.")
        print("Decrypted file:", output_file)

        return decrypted

    except Exception as e:
        print("Decryption failed:", e)
        return None


def supervisor_verify_signature(supervisor_username, report_id):
    """
    Supervisor verifies the researcher's RSA signature.

    Signature is verified against the encrypted report.
    """
    role = get_role(supervisor_username)

    if role is None or not require_permission(role, "verify_signature"):
        return False

    report = get_report(report_id)

    if report is None:
        print("Report not found.")
        return False

    encrypted = read_file_bytes(report["encrypted_file"])

    result = rsa_verify(
        encrypted,
        report["signature"],
        report["owner"]
    )

    print("RSA Signature Verification:",
          "VALID" if result else "INVALID")

    return result


def supervisor_verify_integrity(supervisor_username, report_id):
    """
    Supervisor decrypts the report, hashes plaintext, and compares it
    with stored plaintext_hash.
    """
    role = get_role(supervisor_username)

    if role is None or not require_permission(role, "verify_integrity"):
        return False

    report = get_report(report_id)

    if report is None:
        print("Report not found.")
        return False

    aes_key = load_aes_key()

    try:
        encrypted = read_file_bytes(report["encrypted_file"])
        decrypted = aes_decrypt(encrypted, aes_key)

        calculated_hash = sha256_bytes(decrypted)
        stored_hash = report["plaintext_hash"]

        result = calculated_hash == stored_hash

        print("SHA-256 Integrity:",
              "MATCH" if result else "MISMATCH")
        print("Stored hash    :", stored_hash)
        print("Calculated hash:", calculated_hash)

        return result

    except Exception as e:
        print("Integrity verification failed:", e)
        return False


def supervisor_verify_report(supervisor_username, report_id):
    """
    Run the complete supervisor verification workflow:
        RSA signature + SHA-256 integrity
    """
    role = get_role(supervisor_username)

    if role is None:
        return False

    signature_ok = supervisor_verify_signature(
        supervisor_username,
        report_id
    )

    integrity_ok = supervisor_verify_integrity(
        supervisor_username,
        report_id
    )

    overall = signature_ok and integrity_ok

    print("\nOverall Verification:",
          "PASSED" if overall else "FAILED")

    if has_permission(role, "store_verification"):
        result = {
            "report_id": report_id,
            "verified_by": supervisor_username,
            "signature_valid": signature_ok,
            "integrity_valid": integrity_ok,
            "overall_result": overall,
            "timestamp": timestamp()
        }

        append_json(RESULT_FILE, result)

        print("Verification result stored.")

    return overall


def supervisor_view_reports(supervisor_username):
    """Supervisor can view report metadata."""
    role = get_role(supervisor_username)

    if role is None or not require_permission(role, "view_reports"):
        return

    reports = load_json(REPORT_FILE, [])

    for r in reports:
        print("-" * 60)
        print("Report ID :", r["report_id"])
        print("Owner     :", r["owner"])
        print("File      :", r["original_filename"])
        print("Timestamp :", r["timestamp"])


# ======================================================================
# 12. RESEARCH_DIRECTOR FUNCTIONS
# ======================================================================

def research_director_view_hashes(research_director_username):
    """
    Research_director sees only hashes/timestamps, not plaintext data.
    """
    role = get_role(research_director_username)

    if role is None or not require_permission(role, "view_hashes"):
        return

    reports = load_json(REPORT_FILE, [])

    for r in reports:
        print("-" * 60)
        print("Report ID       :", r["report_id"])
        print("Owner            :", r["owner"])
        print("Plaintext SHA256 :", r["plaintext_hash"])
        print("Encrypted SHA256 :", r["encrypted_hash"])
        print("Timestamp        :", r["timestamp"])


def research_director_verify_signature(research_director_username, report_id):
    """Research_director verifies stored researcher's RSA signature."""
    role = get_role(research_director_username)

    if role is None or not require_permission(role, "verify_signature"):
        return False

    report = get_report(report_id)

    if report is None:
        print("Report not found.")
        return False

    encrypted = read_file_bytes(report["encrypted_file"])

    result = rsa_verify(
        encrypted,
        report["signature"],
        report["owner"]
    )

    print("Research_director RSA Signature:",
          "VALID" if result else "INVALID")

    return result

# ======================================================================
# 13. DISPLAY / MENU HELPERS
# ======================================================================

def list_all_reports():
    """Display report IDs for easy exam/demo use."""
    reports = load_json(REPORT_FILE, [])

    if not reports:
        print("No reports available.")
        return

    for r in reports:
        print(
            f"{r['report_id']} | "
            f"{r['owner']} | "
            f"{r['original_filename']} | "
            f"{r['timestamp']}"
        )


def researcher_menu(username):
    while True:
        print("\n========== RESEARCHER MENU ==========")
        print("1. Upload / Encrypt / Sign report")
        print("2. View my reports")
        print("3. Logout")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            path = input("Enter input file path: ").strip()
            upload_researcher_report(username, path)

        elif choice == "2":
            researcher_view_reports(username)

        elif choice == "3":
            break

        else:
            print("Invalid choice.")


def supervisor_menu(username):
    while True:
        print("\n========== SUPERVISOR MENU ==========")
        print("1. View reports")
        print("2. Decrypt report")
        print("3. Verify RSA signature")
        print("4. Verify SHA-256 integrity")
        print("5. Complete verification")
        print("6. Logout")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            supervisor_view_reports(username)

        elif choice == "2":
            report_id = input("Report ID: ").strip()
            supervisor_decrypt_report(username, report_id)

        elif choice == "3":
            report_id = input("Report ID: ").strip()
            supervisor_verify_signature(username, report_id)

        elif choice == "4":
            report_id = input("Report ID: ").strip()
            supervisor_verify_integrity(username, report_id)

        elif choice == "5":
            report_id = input("Report ID: ").strip()
            supervisor_verify_report(username, report_id)

        elif choice == "6":
            break

        else:
            print("Invalid choice.")


def research_director_menu(username):
    while True:
        print("\n========== RESEARCH_DIRECTOR MENU ==========")
        print("1. View hashes")
        print("2. Verify RSA signature")
        print("3. Logout")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            research_director_view_hashes(username)

        elif choice == "2":
            report_id = input("Report ID: ").strip()
            research_director_verify_signature(username, report_id)

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
    if role in ("researcher", "supervisor", "research_director"):
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
        ("researcher1", "researcher"),
        ("supervisor1", "supervisor"),
        ("research_director1", "research_director"),
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

    # Generate shared AES key.
    load_aes_key()

    # Demo users for lab use.
    create_demo_users()

    while True:
        print("\n" + "=" * 60)
        print("              SECURERESEARCH SYSTEM")
        print("=" * 60)
        print("1. Login")
        print("2. List stored reports")
        print("3. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            username, role = login()

            if username is None:
                continue

            if role == "researcher":
                researcher_menu(username)

            elif role == "supervisor":
                supervisor_menu(username)

            elif role == "research_director":
                research_director_menu(username)

            else:
                print("Unknown role.")

        elif choice == "2":
            list_all_reports()

        elif choice == "3":
            print("Exiting Secureresearch.")
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
#       "encrypt": ["researcher"],
#       "decrypt": ["faculty"],
#       "verify_signature": ["faculty", "research_director"],
#   }
#
# Check:
#   require_permission(role, "encrypt")
#
# AES:
#   key = load_aes_key()
#   encrypted = aes_encrypt(data, key)
#   decrypted = aes_decrypt(encrypted, key)
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
#      replace only aes_encrypt/aes_decrypt or rsa_sign/rsa_verify.
#
#   4. Database instead of JSON:
#      replace save_json/load_json/append_json.
#
#   5. Different report fields:
#      modify the "report" dictionary inside upload_researcher_report().
#
#   6. Different workflow:
#      keep the crypto and RBAC functions and write a new menu.
#
# NOTE ON HASHES:
#   The assignment mixes "sign hash of encrypted report" with
#   "hash decrypted report and compare with stored hash".
#   To make both checks logically correct, this template stores:
#       plaintext_hash -> integrity after decryption
#       encrypted_hash -> integrity of encrypted file
#   The RSA signature is over the encrypted report.
#
# NOTE ON REAL SECURITY:
#   AES is obsolete and should not be used for modern production systems.
#   It is used here only because the lab question explicitly requires AES.
# ======================================================================


