"""
============================================================
LAB 3 - QUESTION 1: RSA ENCRYPTION AND DECRYPTION
============================================================

QUESTION:
Using RSA, encrypt the message "Asymmetric Encryption" with
the public key (n, e). Then decrypt the ciphertext with the
private key (n, d) to verify the original message.

CONTEXT:
RSA is an asymmetric encryption algorithm based on the
difficulty of factoring a large composite number into its
prime factors.

RSA KEY GENERATION:
1. Choose two distinct prime numbers p and q.
2. Calculate n = p * q.
3. Calculate phi(n) = (p - 1) * (q - 1).
4. Choose e such that gcd(e, phi(n)) = 1.
5. Calculate d such that:
       (d * e) mod phi(n) = 1

PUBLIC KEY  = (n, e)
PRIVATE KEY = (n, d)

ENCRYPTION:
       c = m^e mod n

DECRYPTION:
       m = c^d mod n

LIBRARY:
    pip install pycryptodome

NOTE:
This program uses RSA-2048 and OAEP padding, which is the
appropriate practical approach for encrypting short messages.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_keys(key_size=2048):
    """Generate and return an RSA private key and public key."""
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()
    return private_key, public_key


def encrypt_message(message, public_key):
    """Encrypt a string using RSA-OAEP and the public key."""
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode("utf-8"))
    return ciphertext


def decrypt_message(ciphertext, private_key):
    """Decrypt RSA-OAEP ciphertext using the private key."""
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode("utf-8")


def main():
    print("===== RSA ENCRYPTION AND DECRYPTION =====")

    # Original message from the lab question
    message = "Asymmetric Encryption"

    # Step 1: Generate public and private keys
    private_key, public_key = generate_rsa_keys()

    # Step 2: Encrypt using the public key
    ciphertext = encrypt_message(message, public_key)

    print("\nOriginal message:", message)
    print("Ciphertext:", ciphertext.hex())

    # Step 3: Decrypt using the private key
    decrypted_message = decrypt_message(ciphertext, private_key)

    print("Decrypted message:", decrypted_message)

    # Step 4: Verify that decryption recovered the message
    print("Verification:", message == decrypted_message)


if __name__ == "__main__":
    main()
