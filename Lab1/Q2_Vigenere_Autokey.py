# ============================================================
# LAB 1 - QUESTION 2: VIGENERE AND AUTOKEY CIPHER
# ============================================================
# QUESTION / CONTEXT:
# Implement the Vigenere cipher and the Autokey cipher.
#
# THEORY:
# Vigenere is a polyalphabetic substitution cipher.
# Each plaintext letter is shifted by the corresponding key letter.
#
# Encryption: C_i = (P_i + K_i) mod 26
# Decryption: P_i = (C_i - K_i) mod 26
#
# In ordinary Vigenere, the keyword repeats:
#     KEYKEYKEYKEY...
#
# In Autokey, the keyword is followed by plaintext letters:
#     KEY + plaintext
# This makes the keystream less repetitive than ordinary Vigenere.
#
# This program uses A-Z, maps A=0 through Z=25, and removes spaces.
# ============================================================

"""
LAB 1: BASIC SYMMETRIC KEY CIPHERS
This file contains an exam-friendly solution. Classical ciphers use A-Z
with A=0,...,Z=25; spaces are ignored unless stated otherwise.
"""


A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def clean(s): return "".join(c.upper() for c in s if c.isalpha())

def vigenere_encrypt(text, key):
    p, k = clean(text), clean(key)
    return "".join(A[(A.index(c)+A.index(k[i%len(k)]))%26]
                   for i,c in enumerate(p))

def vigenere_decrypt(text, key):
    k=clean(key)
    return "".join(A[(A.index(c)-A.index(k[i%len(k)]))%26]
                   for i,c in enumerate(text))

def autokey_encrypt(text, initial_key):
    p=clean(text); stream=[initial_key]+[A.index(c) for c in p]
    return "".join(A[(A.index(c)+stream[i])%26] for i,c in enumerate(p))

def autokey_decrypt(text, initial_key):
    p=""
    for i,c in enumerate(text):
        k=initial_key if i==0 else A.index(p[i-1])
        p += A[(A.index(c)-k)%26]
    return p

def main():
    msg="the house is being sold tonight"
    c=vigenere_encrypt(msg,"dollars")
    print("Vigenere:",c,"->",vigenere_decrypt(c,"dollars"))
    c=autokey_encrypt(msg,7)
    print("Autokey:",c,"->",autokey_decrypt(c,7))
if __name__=="__main__": main()
