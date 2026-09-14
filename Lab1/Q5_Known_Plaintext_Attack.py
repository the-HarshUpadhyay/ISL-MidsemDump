# ============================================================
# LAB 1 - QUESTION 5: KNOWN-PLAINTEXT ATTACK
# ============================================================
# QUESTION / CONTEXT:
# A plaintext-ciphertext pair is known. Use it to recover the key of
# an additive cipher and decrypt another ciphertext.
#
# THEORY:
# For an additive cipher:
#
#                 C = (P + k) mod 26
#
# If P and C are known, then:
#
#                 k = (C - P) mod 26
#
# Example:
# Plaintext  = YES
# Ciphertext = CIW
# Y(24) -> C(2), so k=(2-24) mod 26 = 4.
#
# Once the key is recovered, apply the same shift to the target message.
# ============================================================

"""
LAB 1: BASIC SYMMETRIC KEY CIPHERS
This file contains an exam-friendly solution. Classical ciphers use A-Z
with A=0,...,Z=25; spaces are ignored unless stated otherwise.
"""


# Attack: known-plaintext attack. YES -> CIW gives shift = 4.
A="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def decrypt(text,key):
    return "".join(A[(A.index(c)-key)%26] if c in A else c
                   for c in text.upper())
def main():
    known_plain="YES"; known_cipher="CIW"
    key=(A.index(known_cipher[0])-A.index(known_plain[0]))%26
    print("Attack: known-plaintext attack")
    print("Shift key:",key)
    print("Plaintext:",decrypt("XVIEWYWI",key)) # TREASURE
if __name__=="__main__":main()
