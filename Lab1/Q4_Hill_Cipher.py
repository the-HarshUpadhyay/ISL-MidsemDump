# ============================================================
# LAB 1 - QUESTION 4: HILL CIPHER
# ============================================================
# QUESTION / CONTEXT:
# Implement the Hill cipher using matrix multiplication for encryption
# and the inverse key matrix for decryption.
#
# THEORY:
# Convert letters to numbers using A=0,...,Z=25.
# For a 2x2 key matrix K and plaintext vector P:
#
#                 C = K P mod 26
#
# Decryption uses:
#
#                 P = K^(-1) C mod 26
#
# The key matrix must be invertible modulo 26. Therefore:
# gcd(det(K),26)=1.
#
# This program uses K = [[3,3],[2,7]].
# ============================================================

"""
LAB 1: BASIC SYMMETRIC KEY CIPHERS
This file contains an exam-friendly solution. Classical ciphers use A-Z
with A=0,...,Z=25; spaces are ignored unless stated otherwise.
"""


from math import gcd
A="ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def inv(k):
    for x in range(26):
        if k*x%26==1:return x
    raise ValueError("No inverse")

def clean(s): return "".join(c.upper() for c in s if c.isalpha())

def hill_encrypt(text,K):
    p=clean(text)
    if len(p)%2:p+="X"
    out=""
    for i in range(0,len(p),2):
        x,y=A.index(p[i]),A.index(p[i+1])
        out+=A[(K[0][0]*x+K[0][1]*y)%26]
        out+=A[(K[1][0]*x+K[1][1]*y)%26]
    return out

def hill_decrypt(text,K):
    det=(K[0][0]*K[1][1]-K[0][1]*K[1][0])%26
    if gcd(det,26)!=1: raise ValueError("Key not invertible")
    d=inv(det)
    I=[[K[1][1]*d,-K[0][1]*d],[-K[1][0]*d,K[0][0]*d]]
    return hill_encrypt(text,I)  # multiplication routine works modulo 26

def main():
    K=[[3,3],[2,7]]
    c=hill_encrypt("We live in an insecure world",K)
    print("Ciphertext:",c)
    print("Decrypted:",hill_decrypt(c,K))
if __name__=="__main__":main()
