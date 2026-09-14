import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

message = "Performance Testing of Encryption Algorithms"

des_key = b"A1B2C3D4"

des = DES.new(des_key, DES.MODE_ECB)

# Encryption Time
start = time.perf_counter()

des_cipher = des.encrypt(pad(message.encode(), DES.block_size))

des_encrypt_time = time.perf_counter() - start

# Decryption Time
start = time.perf_counter()

des_plain = unpad(des.decrypt(des_cipher), DES.block_size)

des_decrypt_time = time.perf_counter() - start

# ---------------- AES-256 ----------------

aes_key = b"0123456789ABCDEF0123456789ABCDEF"

aes = AES.new(aes_key, AES.MODE_ECB)

# Encryption Time
start = time.perf_counter()

aes_cipher = aes.encrypt(pad(message.encode(), AES.block_size))

aes_encrypt_time = time.perf_counter() - start

# Decryption Time
start = time.perf_counter()

aes_plain = unpad(aes.decrypt(aes_cipher), AES.block_size)

aes_decrypt_time = time.perf_counter() - start

# ---------------- Results ----------------

print("DES Encryption Time :", des_encrypt_time, "seconds")
print("DES Decryption Time :", des_decrypt_time, "seconds")

print()

print("AES-256 Encryption Time :", aes_encrypt_time, "seconds")
print("AES-256 Decryption Time :", aes_decrypt_time, "seconds")

print()

if aes_encrypt_time < des_encrypt_time:
    print("AES-256 encryption is faster.")
else:
    print("DES encryption is faster.")

if aes_decrypt_time < des_decrypt_time:
    print("AES-256 decryption is faster.")
else:
    print("DES decryption is faster.")