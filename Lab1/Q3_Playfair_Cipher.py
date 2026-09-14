# ============================================================
# LAB 1 - QUESTION 3: PLAYFAIR CIPHER
# ============================================================
# QUESTION / CONTEXT:
# Implement encryption using the Playfair digraph substitution cipher.
#
# THEORY:
# 1. Construct a 5x5 key matrix from a keyword.
# 2. Combine I and J so that 25 cells are available.
# 3. Split plaintext into pairs.
# 4. If a pair contains repeated letters, insert X between them.
# 5. If one letter remains at the end, append X.
#
# Encryption rules for a pair:
# - Same row: replace each letter with the letter to its right.
# - Same column: replace each letter with the letter below it.
# - Rectangle: replace each letter with the letter in the same row but
#   in the other letter's column.
#
# This implementation uses X as the filler character and combines I/J.
# ============================================================

"""
LAB 1: BASIC SYMMETRIC KEY CIPHERS
This file contains an exam-friendly solution. Classical ciphers use A-Z
with A=0,...,Z=25; spaces are ignored unless stated otherwise.
"""


# Playfair key: GUIDANCE. I/J share one cell. X is the filler character.
ALPHABET="ABCDEFGHIKLMNOPQRSTUVWXYZ"

def matrix(key):
    s=""
    for c in (key.upper()+ALPHABET):
        c="I" if c=="J" else c
        if c in ALPHABET and c not in s: s+=c
    return [s[i:i+5] for i in range(0,25,5)]

def pos(m,c):
    c="I" if c=="J" else c
    for r in range(5):
        for col in range(5):
            if m[r][col]==c:return r,col

def prepare(text):
    t="".join(c.upper() for c in text if c.isalpha()).replace("J","I")
    out=[]; i=0
    while i<len(t):
        a=t[i]
        if i+1==len(t): out.append(a+"X"); i+=1
        elif t[i]==t[i+1]: out.append(a+"X"); i+=1
        else: out.append(a+t[i+1]); i+=2
    return out

def playfair_encrypt(text,key):
    m=matrix(key); out=""
    for a,b in prepare(text):
        r1,c1=pos(m,a); r2,c2=pos(m,b)
        if r1==r2: out+=m[r1][(c1+1)%5]+m[r2][(c2+1)%5]
        elif c1==c2: out+=m[(r1+1)%5][c1]+m[(r2+1)%5][c2]
        else: out+=m[r1][c2]+m[r2][c1]
    return out

def main():
    m=matrix("GUIDANCE")
    print("Matrix:")
    for row in m: print(" ".join(row))
    print("Ciphertext:",playfair_encrypt(
        "The key is hidden under the door pad","GUIDANCE"))
if __name__=="__main__":main()
