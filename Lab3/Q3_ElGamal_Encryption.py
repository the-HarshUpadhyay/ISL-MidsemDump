"""
============================================================
LAB 3 - QUESTION 3: ELGAMAL ENCRYPTION AND DECRYPTION
============================================================

QUESTION:
Given an ElGamal encryption scheme with a public key
(p, g, h) and a private key x, encrypt the message
"Confidential Data". Then decrypt the ciphertext to
retrieve the original message.

CONTEXT:
ElGamal is an asymmetric encryption algorithm based on the
Diffie-Hellman key exchange and the discrete logarithm problem.

KEY GENERATION:
1. Choose a large prime p.
2. Choose a generator g.
3. Choose private key x.
4. Calculate:
       y = g^x mod p

PUBLIC KEY  = (p, g, y)
PRIVATE KEY = x

ENCRYPTION:
Choose a fresh random value k.

       c1 = g^k mod p
       c2 = m * y^k mod p

CIPHERTEXT = (c1, c2)

DECRYPTION:
       s = c1^x mod p
       m = c2 * inverse(s) mod p

LIBRARY:
    pip install pycryptodome

NOTE:
This is an educational textbook ElGamal implementation.
The message integer must be smaller than p.
"""

from Crypto.Util.number import getPrime
from secrets import randbelow


def generate_elgamal_keys(prime_bits=256):
    """
    Generate ElGamal public and private keys.

    Public key  = (p, g, y)
    Private key = x
    """
    p = getPrime(prime_bits)
    g = 2

    # Private key: 1 <= x <= p - 2
    x = randbelow(p - 2) + 1

    # Public key component: y = g^x mod p
    y = pow(g, x, p)

    public_key = (p, g, y)
    private_key = x

    return public_key, private_key


def text_to_integer(message):
    """Convert a string into an integer."""
    return int.from_bytes(
        message.encode("utf-8"),
        byteorder="big"
    )


def integer_to_text(number):
    """Convert an integer back into a string."""
    if number == 0:
        return ""

    byte_length = (number.bit_length() + 7) // 8

    return number.to_bytes(
        byte_length,
        byteorder="big"
    ).decode("utf-8")


def encrypt_message(message, public_key):
    """
    Encrypt using textbook ElGamal.

    c1 = g^k mod p
    c2 = m * y^k mod p
    """
    p, g, y = public_key
    message_integer = text_to_integer(message)

    if message_integer >= p:
        raise ValueError(
            "Message is too large for the selected modulus."
        )

    # Fresh random ephemeral key for every encryption
    k = randbelow(p - 2) + 1

    c1 = pow(g, k, p)
    shared_secret = pow(y, k, p)
    c2 = (message_integer * shared_secret) % p

    return c1, c2


def decrypt_message(ciphertext, private_key, public_key):
    """
    Decrypt ElGamal ciphertext.

    s = c1^x mod p
    m = c2 * inverse(s) mod p
    """
    c1, c2 = ciphertext
    p, _, _ = public_key
    x = private_key

    shared_secret = pow(c1, x, p)

    # Calculate modular multiplicative inverse
    inverse_secret = pow(shared_secret, -1, p)

    message_integer = (
        c2 * inverse_secret
    ) % p

    return integer_to_text(message_integer)


def main():
    print("===== ELGAMAL ENCRYPTION AND DECRYPTION =====")

    # Original message from the lab question
    message = "Confidential Data"

    # Step 1: Generate keys
    public_key, private_key = generate_elgamal_keys()

    # Step 2: Encrypt using the public key
    ciphertext = encrypt_message(
        message,
        public_key
    )

    print("\nOriginal message:", message)
    print("Ciphertext:", ciphertext)

    # Step 3: Decrypt using the private key
    decrypted_message = decrypt_message(
        ciphertext,
        private_key,
        public_key
    )

    print("Decrypted message:", decrypted_message)
    print("Verification:", message == decrypted_message)


if __name__ == "__main__":
    main()
