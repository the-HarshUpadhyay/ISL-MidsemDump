"""
LAB 2 - QUESTION 4: TRIPLE DES

Question:
Encrypt "Classified Text" using Triple DES with:
    1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF

Decrypt and verify the original message.

The given key is 24 bytes in ASCII, suitable for 3-key Triple DES.
"""

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def encrypt_message(message, key_text):
    key = bytes.fromhex(key_text)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), DES3.block_size))


def decrypt_message(ciphertext, key_text):
    key = bytes.fromhex(key_text)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size).decode()


def main():
    message = "Classified Text"
    key = (
        "1234567890ABCDEF"
        "1234567890ABCDEF"
        "1234567890ABCDEF"
    )

    ciphertext = encrypt_message(message, key)
    plaintext = decrypt_message(ciphertext, key)

    print("Ciphertext:", ciphertext.hex())
    print("Decrypted:", plaintext)
    print("Verification:", plaintext == message)


if __name__ == "__main__":
    main()
