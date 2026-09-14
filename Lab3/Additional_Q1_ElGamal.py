"""
ADDITIONAL EXERCISE 1: ELGAMAL ENCRYPTION

Question:
Given the ElGamal public key parameters:
    p = 7919
    g = 2
    h = 6465

and the private key:
    x = 2999

Encrypt the message:
    "Asymmetric Algorithms"

Then decrypt the ciphertext and verify that the original message is recovered.

Context:
ElGamal is a public-key encryption algorithm based on the difficulty of
the discrete logarithm problem.

Key generation:
    y = g^x mod p

Encryption:
    Choose random ephemeral key k.
    c1 = g^k mod p
    c2 = m * y^k mod p

Decryption:
    s = c1^x mod p
    m = c2 * inverse(s) mod p

Note:
This is a textbook educational implementation. Real systems should use
standardized, authenticated and properly padded cryptographic schemes.
The message must be converted into an integer smaller than p.
"""

from secrets import randbelow


# Convert a text message into an integer.
def text_to_integer(message):
    return int.from_bytes(message.encode("utf-8"), byteorder="big")


# Convert an integer back into a text message.
def integer_to_text(number):
    byte_length = max(1, (number.bit_length() + 7) // 8)
    return number.to_bytes(byte_length, byteorder="big").decode("utf-8")


# Encrypt a message using ElGamal.
def encrypt_message(message, p, g, h):
    message_integer = text_to_integer(message)

    if message_integer >= p:
        raise ValueError(
            "Message is too large for the given prime p. "
            "Use a larger prime or split the message."
        )

    # The ephemeral key must be in the range 1 to p-2.
    k = randbelow(p - 2) + 1

    c1 = pow(g, k, p)
    shared_secret = pow(h, k, p)
    c2 = (message_integer * shared_secret) % p

    return c1, c2


# Decrypt an ElGamal ciphertext.
def decrypt_message(c1, c2, p, private_key):
    shared_secret = pow(c1, private_key, p)

    # Modular inverse of the shared secret.
    inverse_secret = pow(shared_secret, -1, p)

    message_integer = (c2 * inverse_secret) % p

    return integer_to_text(message_integer)


def main():
    # Given public and private key values.
    p = 7919
    g = 2
    h = 6465
    private_key = 2999

    message = "Asymmetric Algorithms"

    print("Original message:", message)

    ciphertext = encrypt_message(message, p, g, h)
    print("Ciphertext (c1, c2):", ciphertext)

    decrypted_message = decrypt_message(
        ciphertext[0],
        ciphertext[1],
        p,
        private_key
    )

    print("Decrypted message:", decrypted_message)
    print("Verification:", decrypted_message == message)


if __name__ == "__main__":
    main()
