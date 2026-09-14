from math import gcd

cipher = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

# Given:
# a->G (0->6)
# b->L (1->11)

# 11 = a*1 + b
# 6 = b

b = 6
a = 5

def mod_inverse(a,m):
    for i in range(m):
        if (a*i)%m==1:
            return i

ainv = mod_inverse(a,26)

plain = ""

for ch in cipher:
    y = ord(ch)-65
    x = (ainv*(y-b))%26
    plain += chr(x+65)

print("a =", a)
print("b =", b)
print("Plaintext:")
print(plain)