from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

message = "Confidential Data"
key = b"A1B2C3D4"          # 8-byte key

cipher = DES.new(key, DES.MODE_ECB)

ciphertext = cipher.encrypt(pad(message.encode(), DES.block_size))

print("Encrypted (Hex):", ciphertext.hex())

decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)

print("Decrypted:", decrypted.decode())