from math import gcd

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i

def encrypt(text, key):
    text = text.replace(" ", "").lower()
    cipher = ""

    for ch in text:
        x = ord(ch) - ord('a')
        cipher += chr((key * x) % 26 + ord('a'))

    return cipher

def decrypt(cipher, key):
    inv = mod_inverse(key, 26)
    plain = ""

    for ch in cipher:
        y = ord(ch) - ord('a')
        plain += chr((inv * y) % 26 + ord('a'))

    return plain

text = "I am learning information security"
key = 15

cipher = encrypt(text, key)
plain = decrypt(cipher, key)

print("Ciphertext:", cipher)
print("Decrypted:", plain)