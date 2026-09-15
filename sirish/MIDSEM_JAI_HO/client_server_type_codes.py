"""
╔══════════════════════════════════════════════════════════════════╗
║   IS LAB – SECURE CLIENT-SERVER FRAMEWORK                        ║
║   Labs 5 & 6 Master Template                                     ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  WHAT THIS COVERS (all in one file for exam convenience)         ║
║  ─────────────────────────────────────────────────────────────   ║
║  • Socket-based client ↔ server communication (Lab 5 Ex 2+3)    ║
║  • AES-256-CBC encryption of every message  (Lab 2)             ║
║  • SHA-256 integrity hash on every message  (Lab 5)             ║
║  • RSA digital signature per message        (Lab 6)             ║
║  • RBAC access control on the server side   (Lab 4)             ║
║  • Audit log of every event                 (Lab 4)             ║
║  • Multi-part message reassembly            (Lab 5 Additional)  ║
║                                                                  ║
║  HOW TO RUN                                                      ║
║  ─────────────────────────────────────────────────────────────   ║
║  Terminal 1:  python3 secure_client_server.py server             ║
║  Terminal 2:  python3 secure_client_server.py client             ║
║  (or) Auto:   python3 secure_client_server.py demo              ║
║                                                                  ║
║  HOW TO ADAPT FOR THE EXAM                                       ║
║  ─────────────────────────────────────────────────────────────   ║
║  1. Cipher    → replace AES block (search # ── ENCRYPT MSG)      ║
║  2. Hash      → replace hashlib.sha256 in hash_message()         ║
║  3. Signature → replace RSA sign/verify in sign_message()        ║
║  4. Roles     → edit ROLES dict and handle_request()             ║
║  5. Protocol  → add/remove fields in build_packet() / parse_p()  ║
╚══════════════════════════════════════════════════════════════════╝

PROTOCOL DESIGN  (what travels over the socket)
─────────────────────────────────────────────────
Every message is a JSON "packet" with these fields:
  {
    "type"      : "UPLOAD" | "DOWNLOAD" | "VERIFY" | "HASH_CHECK"
                   | "KEY_EXCHANGE" | "PING" | "PART" | "REASSEMBLE",
    "sender"    : "alice",
    "role"      : "student",
    "encrypted" : "<AES-256-CBC ciphertext, Base64>",
    "hash"      : "<SHA-256 of the encrypted field, hex>",
    "signature" : "<RSA signature of hash, Base64>",
    "part_no"   : 1,       # only for multi-part messages
    "total_parts": 3,      # only for multi-part messages
    "timestamp" : "2024-..."
  }

WHY EACH FIELD
──────────────
  encrypted  → CONFIDENTIALITY  (only server with AES key can read)
  hash       → INTEGRITY        (any bit-flip changes the hash)
  signature  → AUTHENTICITY     (only sender's private key can produce it)

This directly maps to the CIA triad from Lab 6.
"""

import os
import sys
import json
import socket
import hashlib
import base64
import logging
import datetime
import threading
import time

# ── pycryptodome ──────────────────────────────────────────────────
from Crypto.Cipher    import AES, DES, DES3         # ← CHANGE cipher here
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash      import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random    import get_random_bytes


# ══════════════════════════════════════════════════════════════════
#  CONFIGURATION  ← CHANGE THESE FOR THE EXAM
# ══════════════════════════════════════════════════════════════════

SERVER_HOST = "127.0.0.1"   # localhost
SERVER_PORT = 9999           # ← change port if asked

# AES shared key (in real systems this is exchanged via DH/RSA)
# ← CHANGE to whatever key the exam specifies
# Must be exactly 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"   # 32 bytes = AES-256

KEYS_DIR     = "keys"
LOG_FILE     = "server_audit.log"
RECORDS_FILE = "server_records.json"

# ── RBAC: roles and their allowed request types ────────────────────
# ← CHANGE roles and permissions to match exam scenario
ROLES = {
    # ← CHANGE roles and allowed operations to match the exam scenario
    "student": {"UPLOAD", "PING", "HASH_CHECK", "PART"},   # PART = send multi-part msgs
    "faculty": {"DOWNLOAD", "VERIFY", "PING", "HASH_CHECK", "PART"},
    "hod"    : {"VERIFY", "PING"},
}


# ══════════════════════════════════════════════════════════════════
#  LOGGING SETUP
# ══════════════════════════════════════════════════════════════════

def setup_logging():
    """Configure logging to both file and console."""
    logging.basicConfig(
        level    = logging.INFO,
        format   = "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt  = "%H:%M:%S",
        handlers = [
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )

def log(action: str, user: str = "-", detail: str = ""):
    """Write one audit log line."""
    logging.info(f"[{action:<16}] user={user:<12} {detail}")


# ══════════════════════════════════════════════════════════════════
#  KEY MANAGEMENT  (RSA keys for signatures)
# ══════════════════════════════════════════════════════════════════

def ensure_keys_dir():
    os.makedirs(KEYS_DIR, exist_ok=True)

def key_path(username: str, kind: str) -> str:
    """Returns e.g. 'keys/alice_private.pem'"""
    return os.path.join(KEYS_DIR, f"{username}_{kind}.pem")

def generate_keys(username: str, bits: int = 2048):
    """
    Generate RSA key pair if not already present.
    bits: 2048 standard. ← CHANGE if exam asks for 1024 or 4096.
    Saves two PEM files: {username}_private.pem and {username}_public.pem
    """
    ensure_keys_dir()
    priv = key_path(username, "private")
    pub  = key_path(username, "public")
    if os.path.exists(priv):
        return   # already generated; don't overwrite
    k = RSA.generate(bits)
    with open(priv, "wb") as f: f.write(k.export_key())
    with open(pub,  "wb") as f: f.write(k.publickey().export_key())
    log("KEY_GEN", username, f"RSA-{bits} key pair saved")

def load_private(username: str):
    """Load RSA private key object from PEM file."""
    with open(key_path(username, "private"), "rb") as f:
        return RSA.import_key(f.read())

def load_public(username: str):
    """Load RSA public key object from PEM file."""
    with open(key_path(username, "public"), "rb") as f:
        return RSA.import_key(f.read())

def get_public_key_pem(username: str) -> str:
    """Return the public key as a PEM string (for sending over socket)."""
    with open(key_path(username, "public"), "rb") as f:
        return f.read().decode()


# ══════════════════════════════════════════════════════════════════
#  CRYPTO PRIMITIVES
# ══════════════════════════════════════════════════════════════════

# ── ENCRYPT MSG ──────────────────────────────────────────────────
# To swap cipher: replace ONLY this function.
# AES-256-CBC is used here.
# For DES: see notes inside the function.

def encrypt_message(plaintext: str, key: bytes = AES_KEY) -> str:
    """
    Encrypt plaintext string with AES-256 CBC.
    IV (16 bytes) is randomly generated and prepended to ciphertext.
    Returns Base64 string.

    ── TO SWAP TO DES ────────────────────────────────────────────
    from Crypto.Cipher import DES
    DES_KEY = b"EduSec8B"   # 8 bytes
    def encrypt_message(plaintext, key=DES_KEY):
        iv = get_random_bytes(8)                        # DES block = 8
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext.encode(), 8))
        return base64.b64encode(iv + ct).decode()
    ──────────────────────────────────────────────────────────────
    """
    iv     = get_random_bytes(16)                       # fresh IV per message
    cipher = AES.new(key, AES.MODE_CBC, iv)             # AES-256-CBC cipher
    ct     = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    # Store as: Base64(IV + ciphertext)
    return base64.b64encode(iv + ct).decode()

def decrypt_message(ct_b64: str, key: bytes = AES_KEY) -> str:
    """
    Decrypt AES-256-CBC ciphertext.
    Splits off the first 16 bytes as IV, then decrypts the rest.
    """
    raw    = base64.b64decode(ct_b64)
    iv, ct = raw[:16], raw[16:]                         # unpack IV + ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# ── HASH ──────────────────────────────────────────────────────────
# To swap: replace hashlib.sha256 with hashlib.md5 / sha1 / sha512

def hash_message(data: str) -> str:
    """
    SHA-256 hash of a string. Returns hex digest (64 chars).
    ← CHANGE: hashlib.sha256 → hashlib.md5 / sha1 / sha512
    """
    return hashlib.sha256(data.encode()).hexdigest()

# ── SIGN ──────────────────────────────────────────────────────────
# To swap: replace pkcs1_15 with pss, or use DSA/ECC

def sign_message(data: str, username: str) -> str:
    """
    RSA-PKCS#1-v1.5 digital signature.
    Steps:
      1. Compute SHA-256 of data using pycryptodome's Hash object
         (needed by pkcs1_15 – different from hashlib above)
      2. Sign the hash object with the private key
      3. Return Base64 signature string

    ← SWAP TO RSA-PSS:
        from Crypto.Signature import pss
        sig = pss.new(key).sign(SHA256.new(data.encode()))
    ← SWAP TO ECDSA:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        key = ECC.import_key(open(...).read())
        sig = DSS.new(key, 'fips-186-3').sign(SHA256.new(data.encode()))
    """
    key = load_private(username)
    h   = SHA256.new(data.encode())                     # hash object for RSA
    sig = pkcs1_15.new(key).sign(h)                    # PKCS#1 v1.5 sign
    return base64.b64encode(sig).decode()

def verify_signature(data: str, sig_b64: str, username: str) -> bool:
    """
    Verify RSA signature. Returns True if valid, False otherwise.
    The verifier uses the SENDER's public key.
    """
    try:
        key = load_public(username)
        h   = SHA256.new(data.encode())
        pkcs1_15.new(key).verify(h, base64.b64decode(sig_b64))
        return True
    except (ValueError, TypeError):
        return False


# ══════════════════════════════════════════════════════════════════
#  PACKET BUILDER / PARSER
# ══════════════════════════════════════════════════════════════════
# Every message between client and server is a JSON "packet".
# This section builds and parses those packets.

def build_packet(msg_type: str, sender: str, role: str,
                 payload: str,
                 part_no: int = 0, total_parts: int = 0) -> str:
    """
    Create a secure packet:
      1. Encrypt the payload with AES-256-CBC
      2. Hash the encrypted field (integrity seal)
      3. Sign the hash with sender's RSA private key (authenticity)
      4. Bundle everything into a JSON string

    Arguments:
      msg_type    : e.g. "UPLOAD", "DOWNLOAD", "VERIFY"
      sender      : username (must have RSA keys in keys/)
      role        : "student", "faculty", or "hod"
      payload     : plaintext string to send securely
      part_no     : for multi-part messages (0 = single message)
      total_parts : total number of parts (0 = single message)

    Returns: JSON string safe to send over socket.
    """
    # Step 1: AES-encrypt the payload
    encrypted = encrypt_message(payload)

    # Step 2: SHA-256 hash of the encrypted text (not plaintext!)
    # Hashing the ciphertext: detects any tampering of the ciphertext in transit
    msg_hash  = hash_message(encrypted)

    # Step 3: RSA sign the hash
    # This proves the packet came from 'sender' (who has the private key)
    signature = sign_message(msg_hash, sender)

    packet = {
        "type"        : msg_type,
        "sender"      : sender,
        "role"        : role,
        "encrypted"   : encrypted,    # AES-256-CBC ciphertext (Base64)
        "hash"        : msg_hash,     # SHA-256 of 'encrypted' field (hex)
        "signature"   : signature,    # RSA sig of 'hash' field (Base64)
        "part_no"     : part_no,
        "total_parts" : total_parts,
        "timestamp"   : datetime.datetime.now().isoformat(),
    }
    return json.dumps(packet)

def parse_packet(raw: str) -> dict:
    """
    Parse a JSON packet string back into a Python dict.
    Returns the dict, or None if the JSON is invalid.
    """
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None

def verify_packet(packet: dict) -> tuple:
    """
    Verify the integrity and authenticity of a received packet.
    Steps:
      1. Check hash: recompute SHA-256(encrypted) and compare with stored hash
         → detects any bit-flip or tampering of the ciphertext in transit
      2. Check signature: verify RSA sig of the hash using sender's public key
         → proves the packet was created by the stated sender

    Returns: (hash_ok: bool, sig_ok: bool)
    If BOTH are True, the packet is trustworthy.
    If hash_ok is False → packet was modified in transit (integrity breach).
    If sig_ok is False  → packet did not come from the stated sender (auth breach).
    """
    # Step 1: Integrity check
    recomputed_hash = hash_message(packet["encrypted"])
    hash_ok = (recomputed_hash == packet["hash"])

    # Step 2: Authenticity check (RSA signature on the hash)
    sig_ok = verify_signature(packet["hash"], packet["signature"], packet["sender"])

    return hash_ok, sig_ok

def decrypt_packet(packet: dict) -> str:
    """
    Decrypt the payload inside a verified packet.
    Call verify_packet() first; only decrypt if both checks pass.
    Returns plaintext string.
    """
    return decrypt_message(packet["encrypted"])


# ══════════════════════════════════════════════════════════════════
#  SOCKET HELPERS
# ══════════════════════════════════════════════════════════════════
# Sockets send raw bytes. JSON can be long.
# We use a length-prefix protocol to handle arbitrary message sizes:
#   [4-byte length as big-endian uint32] [JSON bytes]
# This avoids TCP stream fragmentation issues.

MSG_LEN_BYTES = 4   # number of bytes used to encode message length

def send_packet(sock: socket.socket, packet_str: str):
    """
    Send a packet string over a socket with a 4-byte length prefix.
    Encoding:
      bytes 0-3 : big-endian uint32 = length of the JSON string in bytes
      bytes 4+  : the JSON string encoded as UTF-8
    """
    data   = packet_str.encode('utf-8')
    length = len(data)
    # '!I' = network byte order (big-endian) unsigned int (4 bytes)
    header = length.to_bytes(MSG_LEN_BYTES, byteorder='big')
    sock.sendall(header + data)

def recv_packet(sock: socket.socket) -> str:
    """
    Receive a length-prefixed packet from a socket.
    Steps:
      1. Read exactly 4 bytes → decode as message length N
      2. Read exactly N bytes → decode as JSON string
    Returns the JSON string, or None if connection closed.
    """
    # Read the 4-byte header
    header = _recv_exactly(sock, MSG_LEN_BYTES)
    if not header:
        return None
    length = int.from_bytes(header, byteorder='big')
    # Read the full JSON payload
    data = _recv_exactly(sock, length)
    if not data:
        return None
    return data.decode('utf-8')

def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Internal helper: receive exactly n bytes from socket.
    TCP can deliver data in chunks, so we loop until we have all n bytes.
    Returns None if connection is closed before n bytes arrive.
    """
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None          # connection closed
        buf += chunk
    return buf


# ══════════════════════════════════════════════════════════════════
#  SERVER RECORDS DATABASE
# ══════════════════════════════════════════════════════════════════

def load_db() -> dict:
    """Load server-side records from JSON file."""
    if os.path.exists(RECORDS_FILE):
        with open(RECORDS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_db(db: dict):
    """Save records back to JSON file."""
    with open(RECORDS_FILE, 'w') as f:
        json.dump(db, f, indent=2)


# ══════════════════════════════════════════════════════════════════
#  SERVER: REQUEST HANDLER
# ══════════════════════════════════════════════════════════════════

# Buffer for reassembling multi-part messages.
# Key: (sender, total_parts_expected), Value: list of (part_no, payload) tuples
_part_buffer = {}
_part_lock   = threading.Lock()

def handle_request(packet: dict, db: dict) -> str:
    """
    Main server-side request dispatcher.
    Called once per verified, decrypted packet.

    Arguments:
      packet : the full parsed packet dict (already verified and decrypted)
      db     : the in-memory records database

    Returns: plaintext response string to send back to client.

    ── HOW TO ADD A NEW OPERATION ─────────────────────────────────
    Add an elif branch:
      elif msg_type == "NEW_OP":
          if not rbac_check(role, "NEW_OP"):
              return "DENIED: insufficient role"
          # ... your logic ...
          return "result string"
    ───────────────────────────────────────────────────────────────
    """
    sender   = packet["sender"]
    role     = packet["role"]
    msg_type = packet["type"]
    payload  = packet.get("_decrypted", "")   # set by server_loop after decrypt

    log("REQUEST", sender, f"type={msg_type} role={role}")

    # ── RBAC check: does this role allow this operation? ──────────
    if not rbac_check(role, msg_type):
        log("DENIED", sender, f"{role} cannot {msg_type}")
        return f"ERROR: Role '{role}' is not permitted to '{msg_type}'"

    # ── Dispatch ──────────────────────────────────────────────────

    if msg_type == "PING":
        # Simplest possible operation – used to test connectivity
        return f"PONG from server at {datetime.datetime.now().isoformat()}"

    elif msg_type == "UPLOAD":
        # Student uploads an encrypted record.
        # payload = the plaintext record content
        rec_id = f"{sender}_{datetime.datetime.now().strftime('%H%M%S')}"
        if sender not in db:
            db[sender] = []
        db[sender].append({
            "id"        : rec_id,
            "content"   : payload,              # store decrypted on server
            "encrypted" : packet["encrypted"],  # also keep ciphertext
            "hash"      : packet["hash"],
            "timestamp" : packet["timestamp"],
        })
        save_db(db)
        log("STORED", sender, f"record_id={rec_id}")
        return f"OK: Record stored with id={rec_id}"

    elif msg_type == "DOWNLOAD":
        # Faculty downloads all records for a target user.
        # payload = the username whose records to fetch
        target = payload.strip()
        records = db.get(target, [])
        if not records:
            return f"NO_RECORDS for '{target}'"
        # Return record IDs and content summaries
        summary = "\n".join(
            f"  [{r['id']}] {r['content'][:40]}… [{r['timestamp']}]"
            for r in records
        )
        log("DOWNLOAD", sender, f"target={target} count={len(records)}")
        return f"RECORDS for '{target}':\n{summary}"

    elif msg_type == "VERIFY":
        # Faculty/HoD verifies integrity of a stored record.
        # payload = record_id to verify
        rec_id = payload.strip()
        for user_recs in db.values():
            for r in user_recs:
                if r["id"] == rec_id:
                    # Recompute hash of the stored ciphertext
                    recomputed = hash_message(r["encrypted"])
                    match = (recomputed == r["hash"])
                    log("VERIFY", sender, f"id={rec_id} intact={match}")
                    status = "INTACT ✓" if match else "TAMPERED ✗"
                    return f"VERIFY {rec_id}: {status}\n  Stored  : {r['hash'][:32]}…\n  Computed: {recomputed[:32]}…"
        return f"ERROR: Record '{rec_id}' not found"

    elif msg_type == "HASH_CHECK":
        # Client sends data; server returns its SHA-256 hash.
        # This is Lab 5, Exercise 2 exactly.
        h = hash_message(payload)
        log("HASH_COMPUTED", sender, f"hash={h[:16]}…")
        return f"HASH:{h}"

    elif msg_type == "PART":
        # Multi-part message. Collect all parts, then reassemble.
        # Lab 5 Additional Exercise.
        return _handle_part(packet, payload, db)

    else:
        return f"ERROR: Unknown request type '{msg_type}'"


def _handle_part(packet: dict, payload: str, db: dict) -> str:
    """
    Handle one part of a multi-part message.
    Stores each part in _part_buffer until all parts arrive,
    then reassembles and processes as a single UPLOAD.

    Protocol:
      part_no     : 1-based index of this part (1, 2, 3, ...)
      total_parts : how many parts to expect in total
    """
    sender      = packet["sender"]
    part_no     = packet.get("part_no", 1)
    total_parts = packet.get("total_parts", 1)
    buf_key     = (sender, total_parts)

    with _part_lock:
        if buf_key not in _part_buffer:
            _part_buffer[buf_key] = []
        _part_buffer[buf_key].append((part_no, payload))
        received = len(_part_buffer[buf_key])

    log("PART_RCV", sender, f"part={part_no}/{total_parts}")

    if received < total_parts:
        return f"PART {part_no}/{total_parts} received. Waiting for more."

    # All parts received — reassemble in order
    with _part_lock:
        parts   = sorted(_part_buffer.pop(buf_key), key=lambda x: x[0])
        full_msg = "".join(p[1] for p in parts)

    # Hash the reassembled message (Lab 5 Additional Exercise)
    full_hash = hash_message(full_msg)
    log("REASSEMBLED", sender, f"total_chars={len(full_msg)} hash={full_hash[:16]}…")

    # Store reassembled message as a record
    rec_id = f"{sender}_multipart_{datetime.datetime.now().strftime('%H%M%S')}"
    if sender not in db:
        db[sender] = []
    db[sender].append({
        "id"       : rec_id,
        "content"  : full_msg,
        "hash"     : full_hash,
        "timestamp": packet["timestamp"],
    })
    save_db(db)

    return f"REASSEMBLED {total_parts} parts. HASH:{full_hash}"


# ══════════════════════════════════════════════════════════════════
#  RBAC CHECK  (server-side access control)
# ══════════════════════════════════════════════════════════════════

def rbac_check(role: str, operation: str) -> bool:
    """
    Return True if the role is permitted to perform this operation.
    ROLES dict at the top of the file defines the policy.
    ← CHANGE: edit ROLES dict to match exam requirements.
    """
    return operation in ROLES.get(role, set())


# ══════════════════════════════════════════════════════════════════
#  SERVER: MAIN LOOP
# ══════════════════════════════════════════════════════════════════

def server_loop():
    """
    Main server loop.
    Listens on SERVER_HOST:SERVER_PORT.
    Spawns a new thread for each client connection.
    """
    setup_logging()
    db = load_db()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # SO_REUSEADDR: lets us restart quickly without "Address already in use"
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((SERVER_HOST, SERVER_PORT))
    srv.listen(5)           # queue up to 5 connection requests
    log("SERVER_START", "-", f"Listening on {SERVER_HOST}:{SERVER_PORT}")
    print(f"\n  [Server] Ready on {SERVER_HOST}:{SERVER_PORT}. Waiting for clients...\n")

    while True:
        try:
            conn, addr = srv.accept()
            log("CONNECT", "-", f"client={addr}")
            # Handle each client in its own thread so server stays responsive
            t = threading.Thread(target=handle_client, args=(conn, addr, db), daemon=True)
            t.start()
        except KeyboardInterrupt:
            log("SERVER_STOP", "-", "Keyboard interrupt")
            break

    srv.close()

def handle_client(conn: socket.socket, addr, db: dict):
    """
    Handle one client connection.
    Loop: receive packet → verify → decrypt → dispatch → send response.
    """
    log("SESSION_START", "-", f"addr={addr}")
    try:
        while True:
            # ── Receive ───────────────────────────────────────────
            raw = recv_packet(conn)
            if raw is None:
                break   # client disconnected

            packet = parse_packet(raw)
            if packet is None:
                send_packet(conn, "ERROR: Malformed packet")
                continue

            sender = packet.get("sender", "unknown")

            # ── Verify integrity and authenticity ─────────────────
            # This is the core of Lab 5+6: hash + signature check
            try:
                hash_ok, sig_ok = verify_packet(packet)
            except Exception as e:
                # Missing key file, corrupted signature, etc.
                send_packet(conn, f"ERROR: Verification failed ({e})")
                log("VERIFY_ERROR", sender, str(e))
                continue

            if not hash_ok:
                # Ciphertext was modified in transit → INTEGRITY BREACH
                log("INTEGRITY_FAIL", sender, "Hash mismatch – packet tampered!")
                send_packet(conn, "ERROR: Integrity check failed – packet may be tampered")
                continue

            if not sig_ok:
                # Signature invalid → AUTHENTICITY BREACH
                log("AUTH_FAIL", sender, "Signature invalid – wrong sender?")
                send_packet(conn, "ERROR: Signature verification failed – invalid sender")
                continue

            log("VERIFIED", sender, f"hash=OK sig=OK type={packet['type']}")

            # ── Decrypt ───────────────────────────────────────────
            try:
                plaintext = decrypt_packet(packet)
                packet["_decrypted"] = plaintext   # attach for handler
            except Exception as e:
                send_packet(conn, f"ERROR: Decryption failed ({e})")
                log("DECRYPT_FAIL", sender, str(e))
                continue

            # ── Dispatch to handler ───────────────────────────────
            response = handle_request(packet, db)

            # ── Send response (also encrypted for confidentiality) ─
            # We sign the response with the server's own key.
            # The server needs its own RSA key pair for this.
            # For simplicity, the server signs as "server".
            generate_keys("server")             # idempotent – skips if exists
            resp_packet = build_packet(
                msg_type = "RESPONSE",
                sender   = "server",
                role     = "server",
                payload  = response
            )
            send_packet(conn, resp_packet)

    except ConnectionResetError:
        log("DISCONNECT", "-", f"addr={addr} reset by peer")
    finally:
        conn.close()
        log("SESSION_END", "-", f"addr={addr}")


# ══════════════════════════════════════════════════════════════════
#  CLIENT
# ══════════════════════════════════════════════════════════════════

class SecureClient:
    """
    Client that communicates securely with the server.
    Usage:
        client = SecureClient("alice", "student")
        client.connect()
        response = client.send("UPLOAD", "my secret data")
        client.disconnect()
    """

    def __init__(self, username: str, role: str):
        self.username = username
        self.role     = role
        self.sock     = None
        # Generate RSA keys for this user on first use
        generate_keys(username)

    def connect(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        """Open TCP connection to the server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        print(f"  [Client] Connected to {host}:{port} as '{self.username}' ({self.role})")

    def disconnect(self):
        """Close the TCP connection."""
        if self.sock:
            self.sock.close()
            self.sock = None
            print(f"  [Client] Disconnected")

    def send(self, msg_type: str, payload: str,
             part_no: int = 0, total_parts: int = 0) -> str:
        """
        Build a secure packet, send it, receive and verify the response.
        Returns the decrypted response string.
        """
        # Build packet: encrypt payload + hash + sign
        packet_str = build_packet(
            msg_type    = msg_type,
            sender      = self.username,
            role        = self.role,
            payload     = payload,
            part_no     = part_no,
            total_parts = total_parts,
        )
        send_packet(self.sock, packet_str)

        # Receive server response
        raw_resp = recv_packet(self.sock)
        if raw_resp is None:
            return "ERROR: Server disconnected"

        resp_packet = parse_packet(raw_resp)
        if resp_packet is None:
            return f"ERROR: Bad response packet"

        # Verify server's response (server signs with its own key)
        try:
            hash_ok, sig_ok = verify_packet(resp_packet)
        except Exception as e:
            return f"ERROR: Could not verify server response ({e})"

        if not hash_ok:
            return "WARNING: Server response hash mismatch!"
        if not sig_ok:
            return "WARNING: Server response signature invalid!"

        return decrypt_packet(resp_packet)

    def send_multipart(self, full_message: str, num_parts: int = 3):
        """
        Split a long message into num_parts parts and send each separately.
        Lab 5 Additional Exercise: server reassembles and hashes them.
        """
        # Split message into exactly num_parts pieces.
        # Strategy: compute start index for each part using integer division
        # so every character ends up in exactly one part.
        L     = len(full_message)
        parts = [
            full_message[L * i // num_parts : L * (i+1) // num_parts]
            for i in range(num_parts)
        ]
        # Drop any empty trailing parts (can happen if message < num_parts chars)
        parts = [p for p in parts if p]

        print(f"  [Client] Sending {len(parts)}-part message…")
        last_response = ""
        for idx, part in enumerate(parts, 1):
            print(f"    Part {idx}/{len(parts)}: {part[:20]}…")
            last_response = self.send("PART", part,
                                      part_no=idx, total_parts=len(parts))
            print(f"    Server: {last_response}")

        # Client independently computes hash of full message to verify
        client_hash = hash_message(full_message)
        print(f"\n  [Client] Expected hash: {client_hash}")

        # Extract hash from last server response
        if "HASH:" in last_response:
            server_hash = last_response.split("HASH:")[1].strip()
            print(f"  [Client] Server hash  : {server_hash}")
            if client_hash == server_hash:
                print("  [Client] ✓ Integrity verified – hashes match")
            else:
                print("  [Client] ✗ Integrity FAIL – hashes do not match!")
        return last_response

    def interactive_menu(self):
        """Interactive menu for exam demo."""
        print(f"""
╔══════════════════════════════════════╗
║  Secure Client  [{self.username} / {self.role}]
╚══════════════════════════════════════╝
  1. PING server
  2. UPLOAD record
  3. DOWNLOAD records (faculty/hod only)
  4. VERIFY record integrity
  5. HASH_CHECK (send data, get SHA-256)
  6. Send multi-part message
  7. Disconnect
""")
        while True:
            choice = input("  Select: ").strip()
            if choice == "1":
                print(f"  Server: {self.send('PING', 'hello')}")
            elif choice == "2":
                data = input("  Record content: ")
                print(f"  Server: {self.send('UPLOAD', data)}")
            elif choice == "3":
                target = input("  Fetch records for user: ")
                print(f"  Server:\n{self.send('DOWNLOAD', target)}")
            elif choice == "4":
                rec_id = input("  Record ID to verify: ")
                print(f"  Server: {self.send('VERIFY', rec_id)}")
            elif choice == "5":
                data = input("  Data to hash: ")
                resp = self.send("HASH_CHECK", data)
                server_hash = resp.split("HASH:")[1] if "HASH:" in resp else "N/A"
                client_hash = hash_message(data)
                print(f"  Server hash : {server_hash}")
                print(f"  Client hash : {client_hash}")
                print(f"  Match: {server_hash == client_hash}")
            elif choice == "6":
                msg = input("  Full message to send in parts: ")
                n   = int(input("  Number of parts: ") or "3")
                self.send_multipart(msg, n)
            elif choice == "7":
                self.disconnect()
                break
            else:
                print("  Invalid option")


# ══════════════════════════════════════════════════════════════════
#  AUTOMATED DEMO  (no human input required)
# ══════════════════════════════════════════════════════════════════

def run_demo():
    """
    Automated demo that runs server + client in the same process.
    Each operation shows the crypto steps clearly.
    Useful for the exam: run this to prove everything works.
    """
    setup_logging()
    print("\n" + "═"*60)
    print("  AUTOMATED DEMO: Secure Client-Server System")
    print("═"*60)

    # ── Pre-generate keys for all users ──────────────────────────
    for user in ["alice", "prof_bob", "server"]:
        generate_keys(user)

    # ── Start server in a background thread ──────────────────────
    db = load_db()
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind((SERVER_HOST, SERVER_PORT))
    srv_sock.listen(5)

    def _srv():
        while True:
            try:
                conn, addr = srv_sock.accept()
                t = threading.Thread(target=handle_client, args=(conn, addr, db), daemon=True)
                t.start()
            except OSError:
                break

    threading.Thread(target=_srv, daemon=True).start()
    time.sleep(0.3)   # give server a moment to start

    # ── Demo operations ───────────────────────────────────────────
    print("\n── STEP 1: Student Alice uploads a record ──────────────────")
    alice = SecureClient("alice", "student")
    alice.connect()
    r = alice.send("UPLOAD", "IS Lab Score: 95/100. Submitted by Alice.")
    print(f"  Response: {r}")
    rec_id = r.split("id=")[-1].strip() if "id=" in r else ""

    print("\n── STEP 2: Alice pings the server ──────────────────────────")
    r = alice.send("PING", "hello")
    print(f"  Response: {r}")

    print("\n── STEP 3: Alice sends data for hash-check (Lab 5 Ex 2) ────")
    test_data   = "Secure Transmission Test"
    r           = alice.send("HASH_CHECK", test_data)
    server_hash = r.split("HASH:")[1] if "HASH:" in r else ""
    client_hash = hash_message(test_data)
    print(f"  Server hash  : {server_hash}")
    print(f"  Client hash  : {client_hash}")
    print(f"  Integrity OK : {server_hash == client_hash}")

    print("\n── STEP 4: Alice sends a multi-part message (Lab 5 Add.) ───")
    full_msg = "This is a long message split across multiple TCP packets for integrity testing."
    alice.send_multipart(full_msg, num_parts=3)
    alice.disconnect()

    print("\n── STEP 5: Faculty Bob downloads Alice's records ────────────")
    bob = SecureClient("prof_bob", "faculty")
    bob.connect()
    r = bob.send("DOWNLOAD", "alice")
    print(f"  Response:\n{r}")

    print("\n── STEP 6: Faculty Bob verifies record integrity ────────────")
    if rec_id:
        r = bob.send("VERIFY", rec_id)
        print(f"  Response: {r}")

    print("\n── STEP 7: Faculty Bob tries HASH_CHECK (faculty allowed) ──")
    r = bob.send("HASH_CHECK", "Faculty data integrity test")
    print(f"  Response: {r}")
    bob.disconnect()

    print("\n── STEP 8: Student tries DOWNLOAD (should be DENIED) ───────")
    alice2 = SecureClient("alice", "student")
    alice2.connect()
    r = alice2.send("DOWNLOAD", "alice")   # students not allowed
    print(f"  Response: {r}")
    alice2.disconnect()

    print("\n── STEP 9: Tamper detection demo ────────────────────────────")
    # Build a valid packet, then manually corrupt the ciphertext
    import json as _json
    pkt_str = build_packet("HASH_CHECK", "alice", "student", "tamper test")
    pkt     = _json.loads(pkt_str)
    # Flip the last character of the encrypted field → simulates bit flip in transit
    pkt["encrypted"] = pkt["encrypted"][:-1] + ("A" if pkt["encrypted"][-1] != "A" else "B")
    hash_ok, sig_ok = verify_packet(pkt)
    print(f"  After tampering: hash_ok={hash_ok}  sig_ok={sig_ok}")
    print(f"  → Tamper {'DETECTED ✓' if not hash_ok else 'not detected ✗'}")

    srv_sock.close()
    print("\n" + "═"*60)
    print("  DEMO COMPLETE")
    print("═"*60 + "\n")


# ══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    Usage:
      python3 secure_client_server.py server          ← start server
      python3 secure_client_server.py client alice student  ← start client
      python3 secure_client_server.py demo            ← automated demo
    """
    mode = sys.argv[1] if len(sys.argv) > 1 else "demo"

    if mode == "server":
        server_loop()

    elif mode == "client":
        # Usage: python3 secure_client_server.py client <username> <role>
        username = sys.argv[2] if len(sys.argv) > 2 else "alice"
        role     = sys.argv[3] if len(sys.argv) > 3 else "student"
        c = SecureClient(username, role)
        c.connect()
        c.interactive_menu()

    elif mode == "demo":
        run_demo()

    else:
        print("Usage: python3 secure_client_server.py [server | client <user> <role> | demo]")
