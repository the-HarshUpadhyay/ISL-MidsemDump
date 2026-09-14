def encrypt(text, key):
    result = ""
    text = text.replace(" ", "").lower()

    for ch in text:
        if ch.isalpha():
            result += chr((ord(ch) - ord('a') + key) % 26 + ord('a'))
    return result

def decrypt(cipher, key):
    result = ""
    for ch in cipher:
        result += chr((ord(ch) - ord('a') - key) % 26 + ord('a'))
    return result

text = "I am learning information security"
key = 20

cipher = encrypt(text, key)
plain = decrypt(cipher, key)

print("Ciphertext:", cipher)
print("Decrypted:", plain)