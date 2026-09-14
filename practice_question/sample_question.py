'''
Question:

You are tasked with developing a secure education data management system called EduSecure. This system ensures that students’ academic records are stored confidentially, accessed only by authorized users, and verified for authenticity. The system supports three types of users: Students, Faculties, and HoDs, each with specific roles and permissions.

The platform uses DES symmetric encryption for storing sensitive academic records, RSA digital signatures for authenticating users, and SHA-256 hashing to verify record integrity.

User Roles & Permissions

Student:
· Encrypts a student’s academic records (for example: - ISL-5CCE-A2.txt) using DES before uploading.
· Signs the SHA-256 hash of the encrypted record using his/her RSA private key.
· Can view past uploaded records and his/her encrypted/hashed forms with timestamps.

Faculty:
· Decrypts the student’s records using the shared DES key.
· Verifies RSA signatures of the students to ensure authenticity.
· Computes SHA-256 hash of decrypted records and compares with the stored hash.
· Stores verification results with timestamps.

HoD:
· Can view only the hashed academic records with timestamps.
· Verifies RSA signatures on stored records for accreditation purposes.

Access Roles:
· Allow Students to encrypt records with DES, sign using RSA, and upload securely.
· Enable Faculties to decrypt with DES, verify RSA signatures, and hash the records.
· Allow HoDs to view only hashes and verify signatures.

Task:
Develop a menu-driven Python program that implements these functionalities using:
· DES symmetric encryption,
· RSA digital signatures, and
· SHA-256 hashing.

Ensure secure handling of academic records and proper role-based access. Use any file or database structure to store and retrieve the records securely.


FILE STRUCTURE:
EduSecure/
│
├── edusecure.py
│   └── Contains:
│       - Python imports
│       - Configuration and folder paths
│       - Utility functions
│       - SHA-256 hashing
│       - DES key generation and loading
│       - DES encryption and decryption
│       - RSA key generation
│       - RSA digital signatures
│       - User management and login
│       - Student functionalities
│       - Faculty functionalities
│       - HoD functionalities
│       - Role-based menus
│       - Main program
│
├── ISL-5CCE-A2.txt
│   └── Contains:
│       - Original academic record
│       - Student name
│       - USN / Roll number
│       - Subject details
│       - Marks and grades
│       - Other academic information
│
└── edusecure_data/
    │
    ├── users.json
    │   └── Contains:
    │       - Username
    │       - Password
    │       - Role
    │       - Student / Faculty / HoD details
    │
    ├── verification_results.json
    │   └── Contains:
    │       - Record ID
    │       - Student username
    │       - Encrypted hash validity
    │       - RSA signature validity
    │       - Decryption status
    │       - Original hash validity
    │       - Verification timestamp
    │
    ├── keys/
    │   │
    │   ├── des_key.bin
    │   │   └── Contains:
    │   │       - 8-byte DES secret key
    │   │       - Used for encryption and decryption
    │   │
    │   ├── student1_private.pem
    │   │   └── Contains:
    │   │       - Student's RSA private key
    │   │       - Used to create digital signatures
    │   │
    │   └── student1_public.pem
    │       └── Contains:
    │           - Student's RSA public key
    │           - Used to verify digital signatures
    │
    └── records/
        │
        ├── student1_YYYYMMDDHHMMSS.enc
        │   └── Contains:
        │       - DES-encrypted academic record
        │       - Ciphertext bytes
        │       - No readable original marks
        │
        └── student1_YYYYMMDDHHMMSS.json
            └── Contains:
                - Record ID
                - Student username
                - Original filename
                - Encrypted file path
                - Initialization Vector (IV)
                - Original SHA-256 hash
                - Encrypted SHA-256 hash
                - RSA digital signature
                - Upload timestamp
'''
# ================================================================
# EduSecure: Secure Academic Record Management System
# DES Encryption + RSA Digital Signatures + SHA-256 + RBAC
# ================================================================

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
from Crypto.Util.Padding import pad, unpad


# ================================================================
# 1. CONFIGURATION
# ================================================================

BASE_DIR = "edusecure_data"

RECORD_DIR = os.path.join(BASE_DIR, "records")
KEY_DIR = os.path.join(BASE_DIR, "keys")
USER_FILE = os.path.join(BASE_DIR, "users.json")
RESULT_FILE = os.path.join(BASE_DIR, "verification_results.json")
DES_KEY_FILE = os.path.join(KEY_DIR, "des_key.bin")

os.makedirs(RECORD_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)


# ================================================================
# 2. UTILITY FUNCTIONS
# ================================================================

def timestamp():
    return datetime.now().isoformat(timespec="seconds")


def sha256_hash(data):
    """
    Calculate SHA-256 hash of bytes.
    Return hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def save_json(filename, data):
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)


def load_json(filename, default):
    if not os.path.exists(filename):
        return default

    with open(filename, "r") as file:
        return json.load(file)


def b64encode(data):
    return base64.b64encode(data).decode("utf-8")


def b64decode(data):
    return base64.b64decode(data.encode("utf-8"))


# ================================================================
# 3. DES KEY MANAGEMENT
# ================================================================

def initialize_des_key():
    """
    Generate a DES key only once.
    DES requires an 8-byte key.
    """

    if not os.path.exists(DES_KEY_FILE):

        key = get_random_bytes(8)

        with open(DES_KEY_FILE, "wb") as file:
            file.write(key)

        print("DES key generated.")

    else:
        print("Existing DES key loaded.")


def load_des_key():
    with open(DES_KEY_FILE, "rb") as file:
        return file.read()


# ================================================================
# 4. DES ENCRYPTION AND DECRYPTION
# ================================================================

def encrypt_des(data):
    """
    Encrypt bytes using DES-CBC.

    Returns:
        ciphertext, iv
    """

    key = load_des_key()

    iv = get_random_bytes(8)

    cipher = DES.new(key, DES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(
        pad(data, DES.block_size)
    )

    return ciphertext, iv


def decrypt_des(ciphertext, iv):
    """
    Decrypt DES-CBC ciphertext.
    """

    key = load_des_key()

    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv
    )

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        DES.block_size
    )

    return plaintext


# ================================================================
# 5. RSA KEY GENERATION
# ================================================================

def generate_rsa_keys(username):
    """
    Generate RSA private and public keys for a student.
    """

    private_path = os.path.join(
        KEY_DIR, username + "_private.pem"
    )

    public_path = os.path.join(
        KEY_DIR, username + "_public.pem"
    )

    if os.path.exists(private_path):
        return

    key = RSA.generate(2048)

    private_key = key.export_key()

    public_key = key.publickey().export_key()

    with open(private_path, "wb") as file:
        file.write(private_key)

    with open(public_path, "wb") as file:
        file.write(public_key)

    print("RSA key pair generated for", username)


def load_private_key(username):
    path = os.path.join(
        KEY_DIR, username + "_private.pem"
    )

    with open(path, "rb") as file:
        return RSA.import_key(file.read())


def load_public_key(username):
    path = os.path.join(
        KEY_DIR, username + "_public.pem"
    )

    with open(path, "rb") as file:
        return RSA.import_key(file.read())


# ================================================================
# 6. RSA DIGITAL SIGNATURE
# ================================================================

def sign_hash(username, encrypted_data):
    """
    Sign the SHA-256 hash of encrypted record
    using the student's RSA private key.
    """

    private_key = load_private_key(username)

    digest = SHA256.new(encrypted_data)

    signature = pkcs1_15.new(
        private_key
    ).sign(digest)

    return signature


def verify_signature(username, encrypted_data, signature):
    """
    Verify RSA signature using student's public key.
    """

    try:

        public_key = load_public_key(username)

        digest = SHA256.new(encrypted_data)

        pkcs1_15.new(public_key).verify(
            digest,
            signature
        )

        return True

    except (ValueError, TypeError, FileNotFoundError):

        return False


# ================================================================
# 7. USER MANAGEMENT
# ================================================================

def initialize_users():
    """
    Create demo users if users.json does not exist.
    """

    users = load_json(USER_FILE, None)

    if users is not None:
        return

    users = {
        "student1": {
            "password": "student123",
            "role": "Student"
        },

        "faculty1": {
            "password": "faculty123",
            "role": "Faculty"
        },

        "hod1": {
            "password": "hod123",
            "role": "HoD"
        }
    }

    save_json(USER_FILE, users)

    generate_rsa_keys("student1")

    print("Demo users initialized.")



def login():
    """
    Authenticate user and return username and role.
    """

    users = load_json(USER_FILE, {})

    username = input("Username: ")
    password = input("Password: ")

    if username not in users:
        print("Invalid username.")
        return None, None

    if users[username]["password"] != password:
        print("Invalid password.")
        return None, None

    role = users[username]["role"]

    print("Login successful.")
    print("Role:", role)

    return username, role


# ================================================================
# 8. STUDENT FUNCTIONALITIES
# ================================================================

def student_upload(username):
    """
    Student encrypts, hashes, signs, and uploads a record.
    """

    filename = input(
        "Enter academic record filename: "
    )

    if not os.path.exists(filename):
        print("File does not exist.")
        return

    with open(filename, "rb") as file:
        original_data = file.read()

    # Hash original plaintext record
    original_hash = sha256_hash(original_data)

    # Encrypt original record using DES
    ciphertext, iv = encrypt_des(original_data)

    # Hash encrypted record
    encrypted_hash = sha256_hash(ciphertext)

    # Sign encrypted hash using student's RSA private key
    signature = sign_hash(username, ciphertext)

    record_id = (
        username + "_" +
        datetime.now().strftime("%Y%m%d%H%M%S")
    )

    encrypted_path = os.path.join(
        RECORD_DIR,
        record_id + ".enc"
    )

    # Store encrypted bytes only
    with open(encrypted_path, "wb") as file:
        file.write(ciphertext)

    # Store metadata
    metadata = {
        "record_id": record_id,
        "student": username,
        "filename": os.path.basename(filename),

        "encrypted_file": encrypted_path,

        "iv": b64encode(iv),

        "original_hash": original_hash,
        "encrypted_hash": encrypted_hash,

        "signature": b64encode(signature),

        "uploaded_at": timestamp()
    }

    metadata_path = os.path.join(
        RECORD_DIR,
        record_id + ".json"
    )

    save_json(metadata_path, metadata)

    print("\nRecord uploaded successfully.")
    print("Record ID:", record_id)
    print("Original SHA-256:", original_hash)
    print("Encrypted SHA-256:", encrypted_hash)


def student_view_records(username):
    """
    Student can view own uploaded records.
    """

    found = False

    for filename in os.listdir(RECORD_DIR):

        if not filename.endswith(".json"):
            continue

        path = os.path.join(RECORD_DIR, filename)

        record = load_json(path, {})

        if record.get("student") == username:

            found = True

            print("\n------------------------------")
            print("Record ID:", record["record_id"])
            print("Filename:", record["filename"])
            print("Original Hash:", record["original_hash"])
            print("Encrypted Hash:", record["encrypted_hash"])
            print("Uploaded At:", record["uploaded_at"])

    if not found:
        print("No uploaded records found.")


# ================================================================
# 9. RECORD SELECTION
# ================================================================

def get_record(record_id=None):
    """
    Load record metadata by record ID.
    """

    if record_id is None:
        record_id = input("Enter Record ID: ")

    metadata_path = os.path.join(
        RECORD_DIR,
        record_id + ".json"
    )

    if not os.path.exists(metadata_path):
        print("Record not found.")
        return None

    return load_json(metadata_path, {})


def load_ciphertext(record):
    with open(record["encrypted_file"], "rb") as file:
        return file.read()


# ================================================================
# 10. FACULTY FUNCTIONALITIES
# ================================================================

def faculty_verify_record():
    """
    Faculty:
    1. Load encrypted record.
    2. Verify encrypted hash.
    3. Verify RSA signature.
    4. Decrypt using DES.
    5. Compute plaintext hash.
    6. Compare with stored original hash.
    7. Save verification result.
    """

    record = get_record()

    if record is None:
        return

    record_id = record["record_id"]
    student = record["student"]

    ciphertext = load_ciphertext(record)

    # ------------------------------------------------------------
    # STEP 1: Verify encrypted record hash
    # ------------------------------------------------------------

    calculated_encrypted_hash = sha256_hash(ciphertext)

    encrypted_hash_valid = (
        calculated_encrypted_hash ==
        record["encrypted_hash"]
    )

    # ------------------------------------------------------------
    # STEP 2: Verify RSA digital signature
    # ------------------------------------------------------------

    signature = b64decode(record["signature"])

    signature_valid = verify_signature(
        student,
        ciphertext,
        signature
    )

    # ------------------------------------------------------------
    # STEP 3: Decrypt record using DES
    # ------------------------------------------------------------

    plaintext = None
    decryption_valid = False
    original_hash_valid = False

    try:

        iv = b64decode(record["iv"])

        plaintext = decrypt_des(
            ciphertext,
            iv
        )

        decryption_valid = True

        # --------------------------------------------------------
        # STEP 4: Hash decrypted record
        # --------------------------------------------------------

        calculated_original_hash = sha256_hash(
            plaintext
        )

        original_hash_valid = (
            calculated_original_hash ==
            record["original_hash"]
        )

    except Exception as error:

        print("Decryption failed:", error)

    # ------------------------------------------------------------
    # STEP 5: Store verification result
    # ------------------------------------------------------------

    result = {
        "record_id": record_id,
        "student": student,

        "encrypted_hash_valid": encrypted_hash_valid,
        "rsa_signature_valid": signature_valid,
        "decryption_successful": decryption_valid,
        "original_hash_valid": original_hash_valid,

        "verified_at": timestamp()
    }

    results = load_json(RESULT_FILE, [])

    results.append(result)

    save_json(RESULT_FILE, results)

    # ------------------------------------------------------------
    # DISPLAY RESULTS
    # ------------------------------------------------------------

    print("\n========== VERIFICATION RESULT ==========")

    print("Encrypted Hash Valid:",
          encrypted_hash_valid)

    print("RSA Signature Valid:",
          signature_valid)

    print("Decryption Successful:",
          decryption_valid)

    print("Original Hash Valid:",
          original_hash_valid)

    if (
        encrypted_hash_valid
        and signature_valid
        and decryption_valid
        and original_hash_valid
    ):
        print("\nRESULT: RECORD AUTHENTIC AND INTACT")

    else:
        print("\nRESULT: VERIFICATION FAILED")

    print("Verified At:", result["verified_at"])


# ================================================================
# 11. HOD FUNCTIONALITIES
# ================================================================

def hod_view_hashes():
    """
    HoD can view only hashed academic records.
    No encrypted content or plaintext is displayed.
    """

    found = False

    for filename in os.listdir(RECORD_DIR):

        if not filename.endswith(".json"):
            continue

        path = os.path.join(RECORD_DIR, filename)

        record = load_json(path, {})

        found = True

        print("\n------------------------------")

        print("Record ID:", record["record_id"])
        print("Student:", record["student"])

        print("Original SHA-256:",
              record["original_hash"])

        print("Encrypted SHA-256:",
              record["encrypted_hash"])

        print("Uploaded At:",
              record["uploaded_at"])

    if not found:
        print("No records found.")


def hod_verify_signature():
    """
    HoD verifies RSA signature without decrypting.
    """

    record = get_record()

    if record is None:
        return

    ciphertext = load_ciphertext(record)

    signature = b64decode(
        record["signature"]
    )

    valid = verify_signature(
        record["student"],
        ciphertext,
        signature
    )

    print("\n========== HOD SIGNATURE VERIFICATION ==========")

    print("Record ID:", record["record_id"])
    print("Student:", record["student"])

    print("RSA Signature Valid:", valid)

    print("Verified At:", timestamp())


# ================================================================
# 12. ROLE-BASED MENUS
# ================================================================

def student_menu(username):

    while True:

        print("\n========== STUDENT MENU ==========")

        print("1. Upload academic record")
        print("2. View my records")
        # print("3. Print Keys")
        print("0. Logout")

        choice = input("Enter choice: ")

        if choice == "1":
            student_upload(username)

        elif choice == "2":
            student_view_records(username)
        
        # elif choice == "3":
            # print_keys(username)
        
        elif choice == "0":
            break

        else:
            print("Invalid choice.")


def faculty_menu(username):

    while True:

        print("\n========== FACULTY MENU ==========")

        print("1. Verify academic record")
        print("2. Logout")

        choice = input("Enter choice: ")

        if choice == "1":
            faculty_verify_record()

        elif choice == "2":
            break

        else:
            print("Invalid choice.")


def hod_menu(username):

    while True:

        print("\n========== HOD MENU ==========")

        print("1. View hashed records")
        print("2. Verify RSA signature")
        print("3. Logout")

        choice = input("Enter choice: ")

        if choice == "1":
            hod_view_hashes()

        elif choice == "2":
            hod_verify_signature()

        elif choice == "3":
            break

        else:
            print("Invalid choice.")


# ================================================================
# 13. MAIN PROGRAM
# ================================================================

def main():

    initialize_des_key()
    # for des key in raw byte representation
    # print(load_des_key()) 

    #for des key in hex representation
    # print_des_key

    initialize_users()

    while True:

        print("\n====================================")
        print("       EDUSECURE SYSTEM")
        print("====================================")

        print("1. Login")
        print("2. Exit")

        choice = input("Enter choice: ")

        if choice == "1":

            username, role = login()

            if username is None:
                continue

            if role == "Student":
                student_menu(username)

            elif role == "Faculty":
                faculty_menu(username)

            elif role == "HoD":
                hod_menu(username)

            else:
                print("Access denied.")

        elif choice == "2":

            print("Exiting EduSecure...")
            break

        else:
            print("Invalid choice.")

# ================================================================
# PRINT KEYS (OPTIONAL)
# ================================================================

def print_keys(username=None):
    """
    Print DES key and RSA keys on stdout.
    Use only when the question requires displaying keys.
    """

    print("\n========== KEY DISPLAY ==========")

    # ------------------------------------------------------------
    # 1. DES SECRET KEY
    # ------------------------------------------------------------

    des_key = load_des_key()

    print("\nDES KEY:")
    print(des_key.hex())

    # ------------------------------------------------------------
    # 2. RSA KEYS
    # ------------------------------------------------------------

    if username is not None:

        private_key = load_private_key(username)
        public_key = load_public_key(username)

        print("\nRSA PRIVATE KEY:")
        print(private_key.export_key().decode("utf-8"))

        print("\nRSA PUBLIC KEY:")
        print(public_key.export_key().decode("utf-8"))

    print("\n================================")

def print_des_key():

    key = load_des_key()

    print("DES Key:", key.hex())


if __name__ == "__main__":
    main()
