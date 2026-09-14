# ============================================================
# LAB 1 - QUESTION 1: ADDITIVE, MULTIPLICATIVE AND AFFINE CIPHER
# ============================================================
# QUESTION / CONTEXT:
# Implement the following classical substitution ciphers:
# 1. Additive (Caesar) cipher
# 2. Multiplicative cipher
# 3. Affine cipher
#
# THEORY:
# We represent A=0, B=1, ..., Z=25.
#
# Additive encryption:      C = (P + k) mod 26
# Additive decryption:      P = (C - k) mod 26
#
# Multiplicative encryption: C = (P * k) mod 26
# Multiplicative decryption: P = (C * k_inverse) mod 26
# The key k must satisfy gcd(k,26)=1.
#
# Affine encryption:         C = (aP + b) mod 26
# Affine decryption:         P = a_inverse(C-b) mod 26
# Here gcd(a,26)=1.
#
# IMPORTANT:
# This implementation uses uppercase English letters and removes spaces.
# For a larger alphabet such as a-zA-Z0-9, replace 26 with the alphabet
# length and create a matching index-to-character mapping.
# ============================================================

"""
LAB 1: BASIC SYMMETRIC KEY CIPHERS
This file contains an exam-friendly solution. Classical ciphers use A-Z
with A=0,...,Z=25; spaces are ignored unless stated otherwise.
"""


from math import gcd
A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def inverse(k, m=26):
    for x in range(1, m):
        if k*x % m == 1: return x
    raise ValueError("No modular inverse")

def additive_encrypt(text, key):
    return "".join(A[(A.index(c)+key)%26] if c in A else c
                   for c in text.upper() if not c.isspace())

def additive_decrypt(text, key):
    return additive_encrypt(text, -key)

def multiplicative_encrypt(text, key):
    if gcd(key,26) != 1: raise ValueError("Invalid multiplicative key")
    return "".join(A[(A.index(c)*key)%26] if c in A else c
                   for c in text.upper() if not c.isspace())

def multiplicative_decrypt(text, key):
    return multiplicative_encrypt(text, inverse(key))

def affine_encrypt(text, a, b):
    if gcd(a,26) != 1: raise ValueError("Invalid affine multiplier")
    return "".join(A[(a*A.index(c)+b)%26] if c in A else c
                   for c in text.upper() if not c.isspace())

def affine_decrypt(text, a, b):
    ai = inverse(a)
    return "".join(A[(ai*(A.index(c)-b))%26] if c in A else c
                   for c in text)

def main():
    msg = "I am learning information security"
    for name, enc, dec in [
        ("Additive", additive_encrypt(msg,20), None),
        ("Multiplicative", multiplicative_encrypt(msg,15), None),
        ("Affine", affine_encrypt(msg,15,20), None)]:
        if name=="Additive": plain=additive_decrypt(enc,20)
        elif name=="Multiplicative": plain=multiplicative_decrypt(enc,15)
        else: plain=affine_decrypt(enc,15,20)
        print(name, "ciphertext:", enc, "| decrypted:", plain)
if __name__=="__main__": main()
