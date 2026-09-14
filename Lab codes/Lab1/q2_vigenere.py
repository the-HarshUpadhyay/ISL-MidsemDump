def generate_key(text, key):
    key = key.lower()
    text = text.replace(" ", "").lower()

    while len(key) < len(text):
        key += key

    return key[:len(text)]

def encrypt(text, key):
    text = text.replace(" ", "").lower()
    key = generate_key(text, key)

    cipher = ""

    for t, k in zip(text, key):
        cipher += chr((ord(t)-97 + ord(k)-97) % 26 + 97)

    return cipher

def decrypt(cipher, key):
    key = generate_key(cipher, key)

    plain = ""

    for c, k in zip(cipher, key):
        plain += chr((ord(c)-97 - (ord(k)-97)) % 26 + 97)

    return plain

text = "the house is being sold tonight"

cipher = encrypt(text, "dollars")
plain = decrypt(cipher, "dollars")

print(cipher)
print(plain)