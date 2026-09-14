def encrypt(text, key):
    text = text.replace(" ", "").lower()

    key_stream = [key]

    for ch in text[:-1]:
        key_stream.append(ord(ch) - 97)

    cipher = ""

    for i in range(len(text)):
        p = ord(text[i]) - 97
        cipher += chr((p + key_stream[i]) % 26 + 97)

    return cipher

def decrypt(cipher, key):
    plain = ""
    key_stream = [key]

    for i in range(len(cipher)):
        c = ord(cipher[i]) - 97
        p = (c - key_stream[i]) % 26
        plain += chr(p + 97)
        key_stream.append(p)

    return plain

text = "the house is being sold tonight"

cipher = encrypt(text, 7)
plain = decrypt(cipher, 7)

print(cipher)
print(plain)