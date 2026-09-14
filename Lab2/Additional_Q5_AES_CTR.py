"""
LAB 2 - ADDITIONAL QUESTION 5: AES CTR MODE

Question:
Encrypt "Cryptography Lab Exercise" using AES-CTR with:
    Key:   0123456789ABCDEF0123456789ABCDEF
    Nonce: 0000000000000000

Print ciphertext and decrypt it.

The key is hexadecimal. The nonce is also hexadecimal and is converted
to 8 bytes. PyCryptodome generates the counter after the nonce.
"""

from Crypto.Cipher import AES


def encrypt_message(message, hex_key, hex_nonce):
    key = bytes.fromhex(hex_key)
    nonce = bytes.fromhex(hex_nonce)

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(message.encode())


def decrypt_message(ciphertext, hex_key, hex_nonce):
    key = bytes.fromhex(hex_key)
    nonce = bytes.fromhex(hex_nonce)

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()


def main():
    message = "Cryptography Lab Exercise"
    key = "0123456789ABCDEF0123456789ABCDEF"
    nonce = "0000000000000000"

    ciphertext = encrypt_message(message, key, nonce)
    plaintext = decrypt_message(ciphertext, key, nonce)

    print("Ciphertext:", ciphertext.hex())
    print("Decrypted:", plaintext)
    print("Verification:", plaintext == message)


if __name__ == "__main__":
    main()
