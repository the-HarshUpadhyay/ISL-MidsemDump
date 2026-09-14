from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

message = "Classified Text"

key = b"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"

# Triple DES uses only the first 24 bytes
key = DES3.adjust_key_parity(key[:24])

cipher = DES3.new(key, DES3.MODE_ECB)

ciphertext = cipher.encrypt(pad(message.encode(), DES3.block_size))

print("Encrypted (Hex):", ciphertext.hex())

plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)

print("Decrypted:", plaintext.decode())