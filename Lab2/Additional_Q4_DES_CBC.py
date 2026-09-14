"""
LAB 2 - ADDITIONAL QUESTION 4: DES CBC MODE

Question:
Encrypt "Secure Communication" using DES-CBC with:
    Key: A1B2C3D4
    IV:  12345678

Print ciphertext and decrypt it.

The key and IV are ASCII strings of 8 bytes.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def encrypt_message(message, key_text, iv_text):
    cipher = DES.new(
        key_text.encode(),
        DES.MODE_CBC,
        iv=iv_text.encode()
    )
    return cipher.encrypt(pad(message.encode(), DES.block_size))


def decrypt_message(ciphertext, key_text, iv_text):
    cipher = DES.new(
        key_text.encode(),
        DES.MODE_CBC,
        iv=iv_text.encode()
    )
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()


def main():
    message = "Secure Communication"
    key = "A1B2C3D4"
    iv = "12345678"

    ciphertext = encrypt_message(message, key, iv)
    plaintext = decrypt_message(ciphertext, key, iv)

    print("Ciphertext:", ciphertext.hex())
    print("Decrypted:", plaintext)
    print("Verification:", plaintext == message)


if __name__ == "__main__":
    main()
