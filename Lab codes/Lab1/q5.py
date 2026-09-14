cipher = "CIW"
plain = "YES"

key = (ord(cipher[0]) - ord(plain[0])) % 26

print("Shift Key =", key)

cipher2 = "XVIEWYWI"

plaintext = ""

for ch in cipher2:
    plaintext += chr((ord(ch)-65-key)%26 + 65)

print("Recovered Plaintext:", plaintext)
print("Attack Type: Known Plaintext Attack")