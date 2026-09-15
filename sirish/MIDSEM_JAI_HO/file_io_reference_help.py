"""
╔══════════════════════════════════════════════════════════════════╗
║   IS LAB – FILE I/O & KEY MANAGEMENT REFERENCE                  ║
║   Everything you need to read/write/delete files in the exam     ║
╚══════════════════════════════════════════════════════════════════╝

WHAT IS COVERED HERE
─────────────────────
1.  Text files  – read, write, append, overwrite
2.  JSON files  – the "database" used in edusecure.py
3.  Binary files  – reading bytes (for encryption output)
4.  PEM key files  – how RSA/ECC keys are stored and loaded
5.  Directory operations  – create, list, check existence, delete
6.  Key lifecycle  – generate → store → load → replace → delete
7.  Base64  – how binary ciphertext/signatures become storable strings
8.  Logging  – writing audit/event logs
9.  Config / params  – storing algorithm settings in JSON
10. Patterns from edusecure.py  – exactly which lines do what

HOW THIS CONNECTS TO edusecure.py
───────────────────────────────────
  save_records()  / load_records()   →  Section 2 (JSON)
  generate_rsa_keys()               →  Section 4 (PEM keys)
  base64.b64encode / b64decode       →  Section 7 (Base64)
  KEYS_DIR / os.makedirs             →  Section 5 (dirs)
"""

import os
import json
import base64
import shutil
import datetime
import logging


# ══════════════════════════════════════════════════════════════════
#  SECTION 1 – TEXT FILES
# ══════════════════════════════════════════════════════════════════

# ── READ entire file into a string ───────────────────────────────
def read_text_file(filepath: str) -> str:
    """
    Read the whole file and return it as one string.
    'r'  = read mode (default, text)
    If the file doesn't exist this raises FileNotFoundError.
    """
    with open(filepath, 'r') as f:       # 'with' auto-closes the file
        content = f.read()               # entire file as one string
    return content

# ── READ line by line ─────────────────────────────────────────────
def read_lines(filepath: str) -> list:
    """
    Returns a list of lines. Each line still has '\n' at the end.
    Use line.strip() to remove it.
    """
    with open(filepath, 'r') as f:
        lines = f.readlines()            # list of strings, one per line
    return [line.strip() for line in lines]

# ── WRITE (overwrite) ─────────────────────────────────────────────
def write_text_file(filepath: str, content: str):
    """
    'w' = write mode. CREATES file if it doesn't exist.
    OVERWRITES if it does. Be careful.
    """
    with open(filepath, 'w') as f:
        f.write(content)
    print(f"  [File] Written: {filepath}")

# ── APPEND (add to end without overwriting) ───────────────────────
def append_text_file(filepath: str, content: str):
    """
    'a' = append mode. Adds to the end of the file.
    Safe for log files – won't erase old content.
    """
    with open(filepath, 'a') as f:
        f.write(content + '\n')          # '\n' adds a new line after each entry

# ── PRACTICAL EXAMPLE: save encrypted record to .txt ─────────────
def save_encrypted_to_txt(filename: str, plaintext_label: str, ciphertext_b64: str, hash_hex: str):
    """
    Write a human-readable output file.
    Used when the exam says 'save ciphertext to a file'.
    """
    content = (
        f"=== Encrypted Record ===\n"
        f"Label     : {plaintext_label}\n"
        f"Timestamp : {datetime.datetime.now()}\n"
        f"Ciphertext: {ciphertext_b64}\n"
        f"SHA-256   : {hash_hex}\n"
        f"========================\n"
    )
    write_text_file(filename, content)

# ── READ encrypted record back from .txt ─────────────────────────
def read_ciphertext_from_txt(filename: str) -> dict:
    """
    Parse the file written by save_encrypted_to_txt().
    Returns dict with keys: label, timestamp, ciphertext, hash
    """
    result = {}
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if ':' in line and not line.startswith('='):
                key, _, value = line.partition(':')
                result[key.strip().lower()] = value.strip()
    return result


# ══════════════════════════════════════════════════════════════════
#  SECTION 2 – JSON FILES  (the "database" in edusecure.py)
# ══════════════════════════════════════════════════════════════════
# JSON stores Python dicts/lists as human-readable text.
# edusecure.py uses records.json as its entire database.

RECORDS_FILE = "records.json"   # ← change filename if exam specifies

# ── LOAD all records ──────────────────────────────────────────────
def load_records() -> dict:
    """
    Load records.json → Python dict.
    Returns empty dict {} if file doesn't exist yet.
    This is the EXACT function used in edusecure.py.
    """
    if os.path.exists(RECORDS_FILE):
        with open(RECORDS_FILE, 'r') as f:
            return json.load(f)          # JSON string → Python dict/list
    return {}                            # first run: no file yet

# ── SAVE all records ──────────────────────────────────────────────
def save_records(records: dict):
    """
    Save Python dict → records.json.
    indent=2 makes the file human-readable (pretty-printed).
    This is the EXACT function used in edusecure.py.
    """
    with open(RECORDS_FILE, 'w') as f:
        json.dump(records, f, indent=2)  # dict → JSON string
    print(f"  [DB] Records saved to {RECORDS_FILE}")

# ── ADD one record for a user ─────────────────────────────────────
def add_record(username: str, record_data: dict):
    """
    Append one record to a user's list.
    records = { "alice": [ {...}, {...} ], "bob": [ {...} ] }
    """
    records = load_records()
    if username not in records:
        records[username] = []           # first record for this user
    records[username].append(record_data)
    save_records(records)

# ── UPDATE one field in a record ──────────────────────────────────
def update_record_field(username: str, record_index: int, field: str, value):
    """
    Update a specific field in a specific record.
    Example: mark a record as 'verified'.
    record_index: 0-based index in the user's list.
    """
    records = load_records()
    records[username][record_index][field] = value
    save_records(records)

# ── DELETE one user's all records ────────────────────────────────
def delete_user_records(username: str):
    """Remove all records for a user from the JSON database."""
    records = load_records()
    if username in records:
        del records[username]
        save_records(records)
        print(f"  [DB] Deleted all records for '{username}'")

# ── WHAT A RECORD LOOKS LIKE in the JSON file ────────────────────
# {
#   "alice": [
#     {
#       "record_name": "ISL-5CCE-A2.txt",
#       "encrypted"  : "base64string==",
#       "hash"       : "64hexchars",
#       "signature"  : "base64string==",
#       "timestamp"  : "2024-01-15 10:30:00",
#       "owner"      : "alice"
#     }
#   ]
# }

# ── STORE ALGORITHM PARAMETERS in JSON ───────────────────────────
def save_algo_config(config: dict, filepath: str = "algo_config.json"):
    """
    Save algorithm configuration (key size, mode, etc.) to JSON.
    Useful if the exam asks you to make settings configurable.
    Example config:
      {"cipher": "AES", "mode": "CBC", "key_size": 256, "hash": "SHA-256"}
    """
    with open(filepath, 'w') as f:
        json.dump(config, f, indent=2)

def load_algo_config(filepath: str = "algo_config.json") -> dict:
    with open(filepath, 'r') as f:
        return json.load(f)


# ══════════════════════════════════════════════════════════════════
#  SECTION 3 – BINARY FILES
# ══════════════════════════════════════════════════════════════════
# Use binary mode ('rb' / 'wb') for:
#   - raw ciphertext bytes (before Base64)
#   - PEM key files (though PEM is technically text, Crypto uses bytes)
#   - any file you want to encrypt (PDF, image, etc.)

def read_binary_file(filepath: str) -> bytes:
    """Read a file as raw bytes. 'rb' = read binary."""
    with open(filepath, 'rb') as f:
        return f.read()

def write_binary_file(filepath: str, data: bytes):
    """Write raw bytes to a file. 'wb' = write binary."""
    with open(filepath, 'wb') as f:
        f.write(data)
    print(f"  [File] Binary written: {filepath}")

def encrypt_file(input_path: str, output_path: str, encrypt_fn):
    """
    Encrypt any file and save the result.
    encrypt_fn: one of the encrypt functions from crypto_snippets.py
    The file content is read as text, encrypted, saved as Base64 text.
    If the file is binary (PDF/image), read as bytes and encode to str first.
    """
    with open(input_path, 'r') as f:
        plaintext = f.read()
    ciphertext = encrypt_fn(plaintext)   # call e.g. aes256_cbc_encrypt
    with open(output_path, 'w') as f:
        f.write(ciphertext)
    print(f"  [Enc] {input_path} → {output_path}")

def decrypt_file(input_path: str, output_path: str, decrypt_fn):
    """Decrypt a file encrypted by encrypt_file()."""
    with open(input_path, 'r') as f:
        ciphertext = f.read()
    plaintext = decrypt_fn(ciphertext)
    with open(output_path, 'w') as f:
        f.write(plaintext)
    print(f"  [Dec] {input_path} → {output_path}")


# ══════════════════════════════════════════════════════════════════
#  SECTION 4 – PEM KEY FILES  (RSA, ECC, DSA)
# ══════════════════════════════════════════════════════════════════
# PEM = Privacy-Enhanced Mail format.
# A PEM file looks like:
#   -----BEGIN RSA PRIVATE KEY-----
#   MIIEowIBAAKCAQEA... (base64 encoded key data)
#   -----END RSA PRIVATE KEY-----
#
# pycryptodome uses bytes for PEM (open with 'rb'/'wb').
# ECC export_key() returns a string (open with 'r'/'w').

from Crypto.PublicKey import RSA, ECC, DSA

KEYS_DIR = "keys"   # ← all key files go here

# ── CREATE KEYS DIR if it doesn't exist ──────────────────────────
def ensure_keys_dir():
    """Create the keys/ directory. exist_ok=True means no error if it exists."""
    os.makedirs(KEYS_DIR, exist_ok=True)

# ── KEY FILE PATH CONVENTIONS ─────────────────────────────────────
# RSA:  keys/{username}_private.pem   keys/{username}_public.pem
# ECC:  keys/{username}_ecc_priv.pem  keys/{username}_ecc_pub.pem
# DSA:  keys/{username}_dsa_priv.pem  keys/{username}_dsa_pub.pem
# ElGamal: keys/{username}_elgamal.json  (stored as JSON, see crypto_snippets.py)

def rsa_key_path(username: str, kind: str) -> str:
    """
    kind = 'private' or 'public'
    Returns: 'keys/alice_private.pem'
    """
    return os.path.join(KEYS_DIR, f"{username}_{kind}.pem")

# ── GENERATE AND SAVE RSA KEYS ────────────────────────────────────
def generate_and_save_rsa(username: str, bits: int = 2048):
    """
    Generate RSA key pair and save as PEM files.
    bits: 1024 (weak, fast), 2048 (standard), 4096 (strong, slow)
    ← CHANGE bits to match what the exam specifies
    """
    ensure_keys_dir()
    priv_path = rsa_key_path(username, 'private')
    pub_path  = rsa_key_path(username, 'public')

    if os.path.exists(priv_path):
        print(f"  [Key] Keys already exist for '{username}'. Skipping.")
        return

    key = RSA.generate(bits)                      # generate keypair
    with open(priv_path, 'wb') as f:              # 'wb' = write bytes
        f.write(key.export_key())                 # PEM bytes of private key
    with open(pub_path, 'wb') as f:
        f.write(key.publickey().export_key())     # PEM bytes of public key

    print(f"  [Key] RSA-{bits} keys saved: {priv_path}, {pub_path}")

# ── LOAD RSA KEYS ─────────────────────────────────────────────────
def load_rsa_private(username: str):
    """Load RSA private key object from PEM file."""
    path = rsa_key_path(username, 'private')
    if not os.path.exists(path):
        raise FileNotFoundError(f"No private key for '{username}' at {path}")
    with open(path, 'rb') as f:                   # 'rb' = read bytes
        return RSA.import_key(f.read())           # bytes → RSA key object

def load_rsa_public(username: str):
    """Load RSA public key object from PEM file."""
    path = rsa_key_path(username, 'public')
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

# ── REPLACE / REVOKE A KEY ────────────────────────────────────────
def revoke_and_replace_key(username: str, bits: int = 2048):
    """
    Delete old keys and generate fresh ones.
    Use this when: key is compromised, periodic rotation required.
    Algorithm:
      1. Delete old PEM files
      2. Generate new keypair
      3. Save new PEM files
    """
    priv_path = rsa_key_path(username, 'private')
    pub_path  = rsa_key_path(username, 'public')

    # Step 1: delete old keys
    for path in [priv_path, pub_path]:
        if os.path.exists(path):
            os.remove(path)
            print(f"  [Revoke] Deleted: {path}")

    # Step 2+3: generate fresh keys
    generate_and_save_rsa(username, bits)
    print(f"  [Revoke] New keys issued for '{username}'")

# ── EXPORT PUBLIC KEY AS STRING (for sharing over network) ────────
def export_public_key_str(username: str) -> str:
    """
    Read the public key PEM file and return it as a string.
    This is what you'd send over a socket to the other party.
    """
    with open(rsa_key_path(username, 'public'), 'rb') as f:
        return f.read().decode('utf-8')

def import_public_key_from_str(pem_str: str):
    """
    Reconstruct RSA public key object from a PEM string received over the network.
    """
    return RSA.import_key(pem_str.encode('utf-8'))

# ── CHECK IF KEYS EXIST ───────────────────────────────────────────
def keys_exist(username: str) -> bool:
    """Return True only if BOTH private and public PEM files exist."""
    return (os.path.exists(rsa_key_path(username, 'private')) and
            os.path.exists(rsa_key_path(username, 'public')))


# ══════════════════════════════════════════════════════════════════
#  SECTION 5 – DIRECTORY OPERATIONS
# ══════════════════════════════════════════════════════════════════

def create_directory(path: str):
    """
    Create a directory (and any missing parents).
    exist_ok=True → no error if directory already exists.
    """
    os.makedirs(path, exist_ok=True)

def list_directory(path: str) -> list:
    """
    List all files in a directory.
    Returns: ['alice_private.pem', 'alice_public.pem', ...]
    """
    if not os.path.exists(path):
        return []
    return os.listdir(path)

def list_files_with_extension(path: str, ext: str) -> list:
    """
    List only files with a specific extension.
    Example: list_files_with_extension('keys', '.pem')
    """
    return [f for f in os.listdir(path) if f.endswith(ext)]

def file_exists(path: str) -> bool:
    """Check if a file (or directory) exists."""
    return os.path.exists(path)

def delete_file(path: str):
    """Delete a single file. Raises FileNotFoundError if missing."""
    if os.path.exists(path):
        os.remove(path)
        print(f"  [Del] Deleted: {path}")
    else:
        print(f"  [Del] File not found: {path}")

def delete_directory(path: str):
    """
    Delete an entire directory and ALL its contents.
    shutil.rmtree = recursive delete (like rm -rf).
    USE WITH CAUTION – irreversible.
    """
    if os.path.exists(path):
        shutil.rmtree(path)
        print(f"  [Del] Deleted directory: {path}")

def get_file_size_bytes(path: str) -> int:
    """Return file size in bytes. Useful for Lab 3 performance comparisons."""
    return os.path.getsize(path)


# ══════════════════════════════════════════════════════════════════
#  SECTION 6 – KEY LIFECYCLE  (full flow used in exams)
# ══════════════════════════════════════════════════════════════════
#
# LIFECYCLE:
#   generate → store (PEM) → load → use → rotate → revoke → delete
#
# KEY MANAGEMENT JSON DATABASE
# The exam may ask you to track key metadata (created, expires, status).
# Store this in a separate JSON file alongside the PEM files.

KEY_REGISTRY = "keys/key_registry.json"

def load_key_registry() -> dict:
    """Load key metadata registry. Returns {} if not found."""
    if os.path.exists(KEY_REGISTRY):
        with open(KEY_REGISTRY, 'r') as f:
            return json.load(f)
    return {}

def save_key_registry(registry: dict):
    ensure_keys_dir()
    with open(KEY_REGISTRY, 'w') as f:
        json.dump(registry, f, indent=2)

def register_key(username: str, key_type: str = "RSA-2048",
                 lifetime_days: int = 365):
    """
    Register a new key in the registry with metadata.
    Stores: created timestamp, expiry, status ('active'/'revoked').
    CHANGE lifetime_days to match the exam (e.g. 365 for 12 months).
    """
    registry = load_key_registry()
    created  = datetime.datetime.now()
    expires  = created + datetime.timedelta(days=lifetime_days)
    registry[username] = {
        "key_type"  : key_type,
        "created"   : created.isoformat(),
        "expires"   : expires.isoformat(),
        "status"    : "active",
        "rotations" : 0
    }
    save_key_registry(registry)
    print(f"  [Registry] Key registered for '{username}', expires {expires.date()}")

def revoke_key_in_registry(username: str):
    """Mark a key as revoked in the registry (does NOT delete PEM files)."""
    registry = load_key_registry()
    if username in registry:
        registry[username]["status"] = "revoked"
        registry[username]["revoked_at"] = datetime.datetime.now().isoformat()
        save_key_registry(registry)
        print(f"  [Registry] Key for '{username}' marked as REVOKED")

def is_key_valid(username: str) -> bool:
    """
    Check: key exists, is active, and has not expired.
    Returns False if any check fails.
    """
    registry = load_key_registry()
    if username not in registry:
        print(f"  [Registry] No key registered for '{username}'")
        return False
    entry = registry[username]
    if entry["status"] != "active":
        print(f"  [Registry] Key for '{username}' is '{entry['status']}'")
        return False
    expiry = datetime.datetime.fromisoformat(entry["expires"])
    if datetime.datetime.now() > expiry:
        print(f"  [Registry] Key for '{username}' EXPIRED on {expiry.date()}")
        return False
    return True

def rotate_key(username: str, bits: int = 2048):
    """
    Full key rotation:
      1. Generate new keys (overwrites old PEM files)
      2. Update registry metadata
    CHANGE: call this automatically every N days using a scheduler.
    """
    revoke_and_replace_key(username, bits)
    registry = load_key_registry()
    if username in registry:
        created = datetime.datetime.now()
        expires = created + datetime.timedelta(days=365)
        registry[username].update({
            "status"    : "active",
            "created"   : created.isoformat(),
            "expires"   : expires.isoformat(),
            "rotations" : registry[username].get("rotations", 0) + 1
        })
        save_key_registry(registry)
    print(f"  [Rotate] Key rotation complete for '{username}'")


# ══════════════════════════════════════════════════════════════════
#  SECTION 7 – BASE64  (how binary → storable string)
# ══════════════════════════════════════════════════════════════════
# Ciphertext and signatures are raw bytes.
# JSON and text files cannot store raw bytes directly.
# Base64 encodes bytes → ASCII string (safe to store anywhere).
#
# RULE: encode when storing, decode when using.

import base64

def bytes_to_b64(data: bytes) -> str:
    """Convert raw bytes → Base64 string for storage in JSON/text."""
    return base64.b64encode(data).decode('utf-8')

def b64_to_bytes(b64_str: str) -> bytes:
    """Convert Base64 string back → raw bytes for decryption/verification."""
    return base64.b64decode(b64_str)

# ── WORKED EXAMPLE (mirrors edusecure.py exactly) ─────────────────
#
#   ENCRYPTION SIDE:
#     cipher    = DES.new(key, DES.MODE_ECB)
#     raw_ct    = cipher.encrypt(pad(plaintext.encode(), 8))  ← bytes
#     stored_ct = base64.b64encode(raw_ct).decode()           ← str → JSON
#
#   DECRYPTION SIDE:
#     raw_ct    = base64.b64decode(stored_ct)                 ← str → bytes
#     cipher    = DES.new(key, DES.MODE_ECB)
#     plaintext = unpad(cipher.decrypt(raw_ct), 8).decode()   ← str


# ══════════════════════════════════════════════════════════════════
#  SECTION 8 – AUDIT LOGGING
# ══════════════════════════════════════════════════════════════════
# Exams (especially Lab 4 HealthCare/DRM questions) ask for
# "detailed logs of all key management operations".

LOG_FILE = "audit.log"   # ← change filename if exam specifies

def setup_logger(log_file: str = LOG_FILE):
    """
    Configure Python's built-in logging module.
    All log() calls below will write to both the file and the console.
    Level INFO means: INFO, WARNING, ERROR all get logged.
    DEBUG does not appear unless you change level to DEBUG.
    """
    logging.basicConfig(
        level    = logging.INFO,
        format   = "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt  = "%Y-%m-%d %H:%M:%S",
        handlers = [
            logging.FileHandler(log_file),    # write to file
            logging.StreamHandler()           # also print to screen
        ]
    )

def log_event(action: str, username: str, details: str = ""):
    """
    Log one event. Automatically includes timestamp.
    action  : what happened, e.g. 'KEY_GENERATED', 'ENCRYPT', 'LOGIN'
    username: who did it
    details : extra info (optional)
    """
    logging.info(f"ACTION={action:<20} USER={username:<15} {details}")

# ── USAGE EXAMPLES ────────────────────────────────────────────────
# setup_logger()
# log_event("LOGIN",           "alice",   "role=student")
# log_event("KEY_GENERATED",   "alice",   "type=RSA-2048")
# log_event("ENCRYPT",         "alice",   "record=ISL-5CCE-A2.txt")
# log_event("DECRYPT",         "prof_bob","record=ISL-5CCE-A2.txt, owner=alice")
# log_event("KEY_REVOKED",     "alice",   "reason=compromise")
# log_event("KEY_ROTATED",     "alice",   "new_expiry=2025-01-01")

# ── MANUAL LOG (append to plain text file) ─────────────────────────
def manual_log(message: str, logfile: str = "manual_audit.log"):
    """Simple alternative: just append timestamped lines to a text file."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(logfile, 'a') as f:
        f.write(f"[{ts}] {message}\n")


# ══════════════════════════════════════════════════════════════════
#  SECTION 9 – COMMON PATTERNS FROM edusecure.py EXPLAINED
# ══════════════════════════════════════════════════════════════════

# ── PATTERN 1: Safe file read with fallback ───────────────────────
def safe_json_load(filepath: str, default=None):
    """
    Try to load JSON. Return default (e.g. {}) if file missing or corrupt.
    This is exactly what load_records() does.
    """
    if default is None:
        default = {}
    if not os.path.exists(filepath):
        return default
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"  [Warning] Corrupt JSON in {filepath}. Returning default.")
        return default

# ── PATTERN 2: Ensure directory exists before writing ────────────
# Always do this before writing to a sub-directory:
#   os.makedirs("keys", exist_ok=True)
# Without this, open("keys/alice.pem", "wb") fails if keys/ doesn't exist.

# ── PATTERN 3: Build a file path safely ──────────────────────────
# NEVER do:  path = "keys/" + username + "_private.pem"  (breaks on Windows)
# ALWAYS do: path = os.path.join("keys", f"{username}_private.pem")

# ── PATTERN 4: Check before deleting ─────────────────────────────
def safe_delete(path: str):
    """Delete only if the file exists. No error if it doesn't."""
    if os.path.exists(path):
        os.remove(path)

# ── PATTERN 5: Write then confirm ────────────────────────────────
def write_and_confirm(filepath: str, content: str) -> bool:
    """
    Write content to file, then read it back to confirm.
    Returns True if the written content matches.
    """
    with open(filepath, 'w') as f:
        f.write(content)
    with open(filepath, 'r') as f:
        written = f.read()
    return written == content

# ── PATTERN 6: Timestamp string (used everywhere in edusecure.py) ─
def get_timestamp() -> str:
    """Standard timestamp string for record-keeping."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── PATTERN 7: User input with validation ────────────────────────
def get_valid_input(prompt: str, valid_options: list) -> str:
    """
    Keep asking until user gives a valid option.
    Example: role = get_valid_input("Role: ", ["student","faculty","hod"])
    """
    while True:
        value = input(prompt).strip().lower()
        if value in valid_options:
            return value
        print(f"  [Error] Choose from: {valid_options}")

# ── PATTERN 8: Number input with error handling ───────────────────
def get_int_input(prompt: str, min_val: int, max_val: int) -> int:
    """
    Safely get an integer from the user.
    Re-prompts on invalid input.
    """
    while True:
        try:
            val = int(input(prompt).strip())
            if min_val <= val <= max_val:
                return val
            print(f"  [Error] Enter a number between {min_val} and {max_val}")
        except ValueError:
            print("  [Error] Please enter a valid integer")


# ══════════════════════════════════════════════════════════════════
#  SECTION 10 – COMPLETE WORKED SCENARIO
# ══════════════════════════════════════════════════════════════════
# Shows the full file I/O flow for a student uploading a record.

def demo_full_flow():
    """
    Demonstrates the complete data flow:
      1. Student provides plaintext
      2. Encrypt → Base64 string
      3. Hash the ciphertext → hex string
      4. Save everything to JSON
      5. Save a human-readable output to .txt
      6. Log the event
      7. Reload from JSON and verify
    """
    # ── Setup ─────────────────────────────────────────────────────
    setup_logger()
    import hashlib
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import pad, unpad

    KEY = b"EduSec8B"
    username = "alice"
    plaintext = "Score: 95/100 in IS Lab"
    record_name = "ISL-5CCE-A2.txt"

    print("\n[DEMO] Starting full file I/O flow\n")

    # ── Step 1: Encrypt ───────────────────────────────────────────
    cipher = DES.new(KEY, DES.MODE_ECB)
    raw_ct = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
    ct_b64 = base64.b64encode(raw_ct).decode()     # bytes → storable string
    print(f"  Ciphertext (B64): {ct_b64[:40]}…")

    # ── Step 2: Hash ──────────────────────────────────────────────
    record_hash = hashlib.sha256(ct_b64.encode()).hexdigest()
    print(f"  SHA-256 hash: {record_hash[:32]}…")

    # ── Step 3: Save to JSON DB ───────────────────────────────────
    record = {
        "record_name": record_name,
        "encrypted"  : ct_b64,
        "hash"       : record_hash,
        "timestamp"  : get_timestamp(),
        "owner"      : username
    }
    add_record(username, record)
    log_event("UPLOAD", username, f"record={record_name}")

    # ── Step 4: Save human-readable .txt output ───────────────────
    save_encrypted_to_txt(f"{username}_{record_name}", plaintext, ct_b64, record_hash)

    # ── Step 5: Reload and verify ─────────────────────────────────
    records = load_records()
    saved   = records[username][-1]   # last record for this user
    assert saved["hash"] == record_hash, "Hash mismatch after reload!"
    print(f"  Reload and verify: OK ✓")

    # ── Step 6: Decrypt from JSON ─────────────────────────────────
    raw_ct2    = base64.b64decode(saved["encrypted"])   # str → bytes
    cipher2    = DES.new(KEY, DES.MODE_ECB)
    decrypted  = unpad(cipher2.decrypt(raw_ct2), DES.block_size).decode()
    assert decrypted == plaintext, "Decryption mismatch!"
    print(f"  Decrypted: {decrypted}")
    print("\n[DEMO] Complete ✓")


if __name__ == "__main__":
    demo_full_flow()
