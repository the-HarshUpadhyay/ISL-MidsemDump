from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

message = "Sensitive Information"

key = b"0123456789ABCDEF"

cipher = AES.new(key, AES.MODE_ECB)

ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

print("Encrypted (Hex):", ciphertext.hex())

plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("Decrypted:", plaintext.decode())