# ============================================================
# ADDITIONAL EXERCISE 1: ADDITIVE CIPHER BRUTE FORCE
# ============================================================
# QUESTION / CONTEXT:
# Given an additive-cipher ciphertext, try every possible shift key.
# Rank or inspect the results to identify the meaningful plaintext.
#
# THEORY:
# For each key k from 0 to 25:
#                 P = (C - k) mod 26
#
# Since there are only 26 possible keys, exhaustive search is practical.
# ============================================================

"""
LAB 1: BASIC SYMMETRIC KEY CIPHERS
This file contains an exam-friendly solution. Classical ciphers use A-Z
with A=0,...,Z=25; spaces are ignored unless stated otherwise.
"""


A="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def dec(s,k): return "".join(A[(A.index(c)-k)%26] if c in A else c for c in s)
def main():
    c="NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"
    print("Try keys near birthday 13 first:")
    for k in sorted(range(26),key=lambda x:(abs(x-13),x)):
        print(k,dec(c,k))
if __name__=="__main__":main()
