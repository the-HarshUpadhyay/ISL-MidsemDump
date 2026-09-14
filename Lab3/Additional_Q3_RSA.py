"""
ADDITIONAL EXERCISE 3: RSA ENCRYPTION AND DECRYPTION

Question:
Given:
    n = 323
    e = 5
    d = 173

Encrypt the message:
    "Cryptographic Protocols"

Then decrypt the ciphertext and verify the original message.

Context:
RSA encryption uses:
    c = m^e mod n

RSA decryption uses:
    m = c^d mod n

Important:
The supplied values are small educational RSA parameters. In real
applications, RSA uses large keys such as 2048 bits and secure padding
such as OAEP.

Because n = 323 is small, this program encrypts the message one character
at a time. Each character is converted to its Unicode code point.
"""

# Convert a text message into a list of integer character codes.
def text_to_integer_list(message):
    return [ord(character) for character in message]


# Convert a list of integer character codes into text.
def integer_list_to_text(numbers):
    return "".join(chr(number) for number in numbers)


# Encrypt each character using the given RSA public key.
def encrypt_message(message, n, e):
    plaintext_numbers = text_to_integer_list(message)

    ciphertext = [
        pow(number, e, n)
        for number in plaintext_numbers
    ]

    return ciphertext


# Decrypt each ciphertext number using the RSA private key.
def decrypt_message(ciphertext, n, d):
    plaintext_numbers = [
        pow(number, d, n)
        for number in ciphertext
    ]

    return integer_list_to_text(plaintext_numbers)


def main():
    # Given RSA parameters.
    n = 323
    e = 5
    d = 173

    message = "Cryptographic Protocols"

    print("Original message:", message)

    ciphertext = encrypt_message(message, n, e)
    print("Ciphertext:", ciphertext)

    decrypted_message = decrypt_message(
        ciphertext,
        n,
        d
    )

    print("Decrypted message:", decrypted_message)
    print("Verification:", decrypted_message == message)


if __name__ == "__main__":
    main()
