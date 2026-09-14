# ============================================================
# LAB 1 - QUESTION 6: AFFINE CIPHER BRUTE-FORCE ATTACK
# ============================================================
# QUESTION / CONTEXT:
# Recover an affine cipher key by trying every valid affine key.
#
# THEORY:
# Affine encryption is:
#
#                 C = (aP + b) mod 26
#
# Only values of a with gcd(a,26)=1 are valid because a must have a
# modular inverse. The possible multiplicative keys are:
# 1,3,5,7,9,11,15,17,19,21,23,25.
#
# A brute-force attack tests all valid (a,b) combinations and checks
# whether the known plaintext maps to the known ciphertext.
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
def enc(s,a,b): return "".join(A[(a*A.index(c)+b)%26] for c in s)
def dec(s,a,b):
    ai=inv(a)
    return "".join(A[(ai*(A.index(c)-b))%26] for c in s)
def main():
    c="XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    for a in range(26):
        if gcd(a,26)!=1: continue
        for b in range(26):
            if enc("AB",a,b)=="GL":
                print("Key:",(a,b),"Plaintext:",dec(c,a,b))
if __name__=="__main__":main()
