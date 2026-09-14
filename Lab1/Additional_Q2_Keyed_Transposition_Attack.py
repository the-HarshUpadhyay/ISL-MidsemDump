# ============================================================
# ADDITIONAL EXERCISE 2: KEYED TRANSPOSITION ATTACK
# ============================================================
# QUESTION / CONTEXT:
# Explore a small keyed transposition cipher by trying candidate
# permutation keys and comparing the resulting plaintexts.
#
# THEORY:
# A transposition cipher changes the order of characters rather than
# replacing the characters. For a small block size, all permutations can
# be tested. The number of permutations grows as n!, so brute force is
# practical only for small n.
#
# NOTE:
# The supplied exercise data should use a consistent character set.
# If the ciphertext contains a character absent from the plaintext,
# inspect the question data for a possible typo before interpreting
# the result.
# ============================================================

"""
LAB 1: BASIC SYMMETRIC KEY CIPHERS
This file contains an exam-friendly solution. Classical ciphers use A-Z
with A=0,...,Z=25; spaces are ignored unless stated otherwise.
"""


# a) Known-plaintext attack. b) Permutation key size = 9.
# Note: ciphertext contains L although plaintext contains only a-i;
# this inconsistency prevents exact permutation recovery.
def main():
    p="abcdefghi"; c="CABDEHFGL"
    print("Attack: known-plaintext attack")
    print("Permutation key size:",len(p))
    print("Warning:",set(c.lower())-set(p),"is not in the plaintext alphabet")
if __name__=="__main__":main()
