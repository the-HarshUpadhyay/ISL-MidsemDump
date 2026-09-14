# ============================================================
# ADDITIONAL EXERCISE 3: VIGENERE WITH KEY HEALTH
# ============================================================
# QUESTION / CONTEXT:
# Encrypt and decrypt a message using the Vigenere keyword HEALTH.
#
# THEORY:
# Convert A-Z to 0-25 and repeat the keyword as needed.
#
# Encryption: C_i = (P_i + K_i) mod 26
# Decryption: P_i = (C_i - K_i) mod 26
#
# The same keyword must be used for decryption.
# ============================================================

"""
LAB 1: BASIC SYMMETRIC KEY CIPHERS
This file contains an exam-friendly solution. Classical ciphers use A-Z
with A=0,...,Z=25; spaces are ignored unless stated otherwise.
"""


A="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def clean(s):return "".join(c.upper() for c in s if c.isalpha())
def enc(text,key):
    p,k=clean(text),clean(key)
    return "".join(A[(A.index(c)+A.index(k[i%len(k)]))%26] for i,c in enumerate(p))
def main(): print(enc("Life is full of surprises","HEALTH"))
if __name__=="__main__":main()
