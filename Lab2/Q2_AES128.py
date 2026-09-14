"""
LAB 2 - QUESTION 2: AES-128 ENCRYPTION

Question:
Encrypt "Sensitive Information" using AES-128 with:
    0123456789ABCDEF0123456789ABCDEF

Decrypt and verify the original message.

The supplied key is hexadecimal, so bytes.fromhex() is used.
AES-GCM is recommended in real applications; ECB is used here only
because the exercise asks for a basic block-cipher demonstration.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt_message(message, hex_key):
    key = bytes.fromhex(hex_key)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), AES.block_size))


def decrypt_message(ciphertext, hex_key):
    key = bytes.fromhex(hex_key)
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


def main():
    message = "Sensitive Information"
    key = "0123456789ABCDEF0123456789ABCDEF"

    ciphertext = encrypt_message(message, key)
    plaintext = decrypt_message(ciphertext, key)

    print("Ciphertext:", ciphertext.hex())
    print("Decrypted:", plaintext)
    print("Verification:", plaintext == message)


if __name__ == "__main__":
    main()
