"""
LAB 2 - QUESTION 1: DES ENCRYPTION

Question:
Encrypt "Confidential Data" using DES with key "A1B2C3D4".
Decrypt the ciphertext and verify the original message.

Note:
DES requires an 8-byte key. The given ASCII key has exactly 8 bytes.
DES is obsolete for real security; use AES today.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def encrypt_message(message, key_text):
    key = key_text.encode("utf-8")
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(message.encode("utf-8"), DES.block_size))


def decrypt_message(ciphertext, key_text):
    key = key_text.encode("utf-8")
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode("utf-8")


def main():
    message = "Confidential Data"
    key = "A1B2C3D4"

    ciphertext = encrypt_message(message, key)
    plaintext = decrypt_message(ciphertext, key)

    print("Ciphertext:", ciphertext.hex())
    print("Decrypted:", plaintext)
    print("Verification:", plaintext == message)


if __name__ == "__main__":
    main()
