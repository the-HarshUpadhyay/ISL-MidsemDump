from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

message = "Top Secret Data"

key = b"FEDCBA9876543210FEDCBA98"

cipher = AES.new(key, AES.MODE_ECB)

ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

print("Encrypted (Hex):", ciphertext.hex())

plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("Decrypted:", plaintext.decode())