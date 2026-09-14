from Crypto.Util.number import getPrime, inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime, timedelta
import time

KEY_SIZE = 1024
keys = {}
logs = []

def log(msg):
    logs.append(f"{datetime.now()} : {msg}")
    print("[LOG]", msg)

# ---------- Rabin Key Generation ----------

def generate_keys(name):
    start = time.perf_counter()

    p = getPrime(KEY_SIZE // 2)
    while p % 4 != 3:
        p = getPrime(KEY_SIZE // 2)

    q = getPrime(KEY_SIZE // 2)
    while q % 4 != 3 or q == p:
        q = getPrime(KEY_SIZE // 2)

    n = p * q

    keys[name] = {
        "public": n,
        "private": (p, q),
        "expiry": datetime.now() + timedelta(days=365),
        "revoked": False
    }

    t = time.perf_counter() - start
    log(f"Keys generated for {name}")

    print(f"\n{name}")
    print("Public Key (n):", n)
    print("Private Key p:", p)
    print("Private Key q:", q)
    print(f"Generation Time: {t:.6f}s")

# ---------- Key Distribution / Access ----------

def get_public(name):
    if name not in keys or keys[name]["revoked"]:
        print("Public key unavailable!")
        return None

    log(f"Public key distributed to {name}")
    return keys[name]["public"]

def get_private(name, authorized=True):
    if not authorized or name not in keys or keys[name]["revoked"]:
        log(f"Private key access denied for {name}")
        print("Access Denied!")
        return None

    log(f"Authorized private key access for {name}")
    return keys[name]["private"]

# ---------- Rabin Encryption ----------

def encrypt(message, n):
    start = time.perf_counter()

    m = int.from_bytes(message.encode(), "big")
    if m >= n:
        raise ValueError("Message too large for key size")

    c = pow(m, 2, n)

    return c, time.perf_counter() - start

# ---------- Rabin Decryption ----------

def decrypt(c, p, q):
    start = time.perf_counter()

    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    yp = inverse(p, q)
    yq = inverse(q, p)

    r1 = (yp*p*mq + yq*q*mp) % n
    r2 = n - r1
    r3 = (yp*p*mq - yq*q*mp) % n
    r4 = n - r3

    return [r1, r2, r3, r4], time.perf_counter() - start

# ---------- Revocation ----------

def revoke(name):
    keys[name]["revoked"] = True
    log(f"Key revoked for {name}")

# ---------- Renewal ----------

def renew(name):
    log(f"Renewing key for {name}")
    generate_keys(name)

# ---------- Register Facilities ----------

generate_keys("Hospital A")
generate_keys("Clinic B")

# ---------- Rabin Demonstration ----------

message = "Patient Record 123"
print("\nPlaintext:", message)

n = get_public("Hospital A")
private = get_private("Hospital A")

p, q = private

ciphertext, enc_time = encrypt(message, n)

print("\nRabin Ciphertext:", ciphertext)
print(f"Encryption Time: {enc_time:.6f}s")

roots, dec_time = decrypt(ciphertext, p, q)

print("\nFour Possible Roots:")
for r in roots:
    print(r)

original = int.from_bytes(message.encode(), "big")

if original in roots:
    print("\nDecrypted Text:", message)
else:
    print("\nOriginal plaintext not identified")

print(f"Decryption Time: {dec_time:.6f}s")

# ---------- Revocation ----------

print("\n--- Revocation ---")
revoke("Clinic B")

# ---------- Renewal ----------

print("\n--- Key Renewal ---")
renew("Hospital A")

# ---------- Expiry Check ----------

print("\n--- Expiry Check ---")
for name in keys:
    if datetime.now() >= keys[name]["expiry"]:
        renew(name)
    else:
        print(name, "key is valid until", keys[name]["expiry"])

# ---------- Audit Log ----------

print("\n--- Audit Log ---")
for x in logs:
    print(x)

# ---------- RSA Comparison ----------

print("\n--- RSA Comparison ---")

start = time.perf_counter()
rsa_key = RSA.generate(KEY_SIZE)
rsa_key_time = time.perf_counter() - start

cipher = PKCS1_OAEP.new(rsa_key.publickey())

start = time.perf_counter()
rsa_cipher = cipher.encrypt(message.encode())
rsa_enc_time = time.perf_counter() - start

cipher = PKCS1_OAEP.new(rsa_key)

start = time.perf_counter()
rsa_plain = cipher.decrypt(rsa_cipher).decode()
rsa_dec_time = time.perf_counter() - start

print(f"RSA Key Generation: {rsa_key_time:.6f}s")
print(f"RSA Encryption:     {rsa_enc_time:.6f}s")
print(f"RSA Decryption:     {rsa_dec_time:.6f}s")
print("RSA Decrypted Text:", rsa_plain)