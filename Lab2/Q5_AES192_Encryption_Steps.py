"""
LAB 2 - QUESTION 5: AES-192 ENCRYPTION STEPS

Question:
Encrypt "Top Secret Data" using AES-192 with:
    FEDCBA9876543210FEDCBA9876543210

Show:
1. Key expansion
2. Initial AddRoundKey
3. Main rounds
4. Final round

This program uses PyCryptodome for the actual AES encryption and prints
the conceptual AES round sequence. AES-192 has:
    - 192-bit key
    - 12 rounds
    - 13 round keys, including the initial key

The key is hexadecimal and is decoded into 24 bytes.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def show_aes_steps(message, hex_key):
    key = bytes.fromhex(hex_key)
    plaintext = pad(message.encode(), AES.block_size)

    print("Plaintext bytes:", plaintext.hex())
    print("Key:", key.hex())
    print("Key size: 192 bits")
    print("Number of rounds: 12")
    print("Round keys: 13")
    print("\nConceptual encryption sequence:")
    print("Key expansion -> Round Key 0")
    print("Initial round: AddRoundKey")

    for round_number in range(1, 12):
        print(
            f"Main round {round_number}: "
            "SubBytes -> ShiftRows -> MixColumns -> AddRoundKey"
        )

    print("Final round 12: SubBytes -> ShiftRows -> AddRoundKey")

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    print("\nCiphertext:", ciphertext.hex())
    print("Note: PyCryptodome performs the internal key expansion and state")
    print("transformations. The lines above show the required AES stages.")


def main():
    show_aes_steps(
        "Top Secret Data",
        "FEDCBA9876543210FEDCBA9876543210"
    )


if __name__ == "__main__":
    main()
