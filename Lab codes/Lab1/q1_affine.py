def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i

def encrypt(text, a, b):
    text = text.replace(" ", "").lower()
    cipher = ""

    for ch in text:
        x = ord(ch) - ord('a')
        cipher += chr((a * x + b) % 26 + ord('a'))

    return cipher

def decrypt(cipher, a, b):
    inv = mod_inverse(a, 26)
    plain = ""

    for ch in cipher:
        y = ord(ch) - ord('a')
        plain += chr((inv * (y - b)) % 26 + ord('a'))

    return plain

text = "I am learning information security"

cipher = encrypt(text, 15, 20)
plain = decrypt(cipher, 15, 20)

print("Ciphertext:", cipher)
print("Decrypted:", plain)