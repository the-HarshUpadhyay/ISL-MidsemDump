"""
LAB 2 - ADDITIONAL QUESTION 2: DES HEX BLOCKS

Question:
Encrypt the following data using DES with key:
    A1B2C3D4E5F60708

Block 1:
    54686973206973206120636f6e666964656e7469616c206d657373616765

Block 2:
    416e64207468697320697320746865207365636f6e6420626c6f636b

Print ciphertext for each block and decrypt them.

The key is hexadecimal and represents 8 bytes.
Each block is encrypted independently using ECB.
"""

from Crypto.Cipher import DES


def encrypt_block(hex_block, hex_key):
    key = bytes.fromhex(hex_key)
    block = bytes.fromhex(hex_block)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(block)


def decrypt_block(ciphertext, hex_key):
    key = bytes.fromhex(hex_key)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def main():
    key = "A1B2C3D4E5F60708"

    blocks = [
        "54686973206973206120636f6e666964656e7469616c206d657373616765",
        "416e64207468697320697320746865207365636f6e6420626c6f636b"
    ]

    for number, block in enumerate(blocks, start=1):
        ciphertext = encrypt_block(block, key)
        plaintext = decrypt_block(ciphertext, key)

        print(f"Block {number} ciphertext:", ciphertext.hex())
        print(f"Block {number} plaintext:", plaintext.decode())
        print()


if __name__ == "__main__":
    main()
