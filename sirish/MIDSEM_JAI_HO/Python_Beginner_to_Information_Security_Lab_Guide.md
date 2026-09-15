# **PYTHON FOR INFORMATION SECURITY LAB TESTS** 

_A practical beginner-to-lab guide with syntax, code snippets, outputs and cryptography templates_ 

This document is designed for someone starting Python from scratch and needing to write programs during an Information Security lab test. The first part teaches practical Python basics. The second part focuses on the techniques and libraries relevant to Labs 1–4 of the supplied Information Security Lab Manual. 

Important: Python basics are general programming knowledge. The cryptography-focused sections are organized around the algorithms and exercise types in the lab manual. Where the manual names an algorithm without giving a programming API or complete implementation procedure, this guide adds standard Python implementation guidance and clearly treats it as supplementary. 

## **HOW TO USE THIS GUIDE** 

- Copy a small template, understand the variables, then change only what the question requires. 

- Python uses indentation instead of braces. Keep related statements aligned. 

- input() always returns a string unless you convert it. 

- For cipher questions, first identify whether you are working with text, numbers, bytes, matrices or keys. 

- For library-based cryptography, do not confuse a text string with bytes: use .encode() before encryption and .decode() after decryption. 

## **PART A — PYTHON FROM SCRATCH** 

### **1. The Smallest Python Programs** 

<mark>print("Hello")</mark> 

#### **Output:** 

<mark>Hello</mark> 

<mark>print("Hello", "World")</mark> 

#### **Output:** 

<mark>Hello World</mark> 

<mark>print("Sum =", 5 + 3)</mark> 

#### **Output:** 

<mark>Sum = 8</mark> name = "Alice" print(name) 

#### **Output:** 

<mark>Alice</mark> 

Python executes statements from top to bottom. # starts a comment. 

### **2. Variables and Basic Data Types** 

|Type|Example|Use|
|---|---|---|
|int|5|Whole numbers|
|float|3.14|Decimal numbers|
|str|"hello"|Text|
|bool|True / False|Logical values|
|list|[1,2,3]|Ordered,mutable collection|
|tuple|(1,2,3)|Ordered,immutable collection|
|set|{1,2,3}|Unique values|
|dict|{"a": 1}|Key-valuepairs|
|bytes|b"ABC"|Binarydata;common in cryptography|



a = 10 b = 2.5 name = "Bob" flag = True print(type(a)) print(type(b)) print(type(name)) print(type(flag)) 

#### **Output:** 

<class 'int'> <class 'float'> <class 'str'> <class 'bool'> 

### **3. Taking Input — Most Important Beginner Topic** 

input() returns text. Convert it when you need numbers. 

name = input("Enter name: ") print("Hello", name) 

#### **Output:** 

Enter name: Sirish Hello Sirish 

age = int(input("Enter age: ")) print(age + 1) 

#### **Output:** 

Enter age: 20 21 

x = float(input("Enter a decimal number: ")) print(x * 2) 

#### **Output:** 

Enter a decimal number: 2.5 5.0 

a, b = map(int, input("Enter two numbers: ").split()) print(a + b) 

#### **Output:** 

Enter two numbers: 10 20 30 

nums = list(map(int, input("Enter numbers: ").split())) print(nums) 

#### **Output:** 

Enter numbers: 1 2 3 4 [1, 2, 3, 4] row = list(map(int, input().split(","))) print(row) 

#### **Output:** 

1,2,3,4 [1, 2, 3, 4] 

Common pattern to remember: list(map(int, input().split())). 

### **4. Printing and Formatting** 

name = "Alice" age = 20 

print("Name:", name) print(f"{name} is {age} years old") 

#### **Output:** 

Name: Alice Alice is 20 years old 

print("A", end="-") print("B", end="-") print("C") 

#### **Output:** 

<mark>A-B-C</mark> 

for i in range(3): print(i, end=" ") 

#### **Output:** 

<mark>0 1 2</mark> 

### **5. Operators** 

|Operation|Example|Result|
|---|---|---|
|Addition|5 + 2|7|
|Subtraction|5 - 2|3|
|Multiplication|5 * 2|10|
|Division|5 / 2|2.5|
|Integer division|5 // 2|2|
|Remainder|5 % 2|1|
|Power|2 ** 3|8|



Modulo (%) is extremely important in classical cryptography. 

print((25 + 5) % 26) print(pow(3, 4, 26)) 

#### **Output:** 

4 3 

pow(a, b, m) efficiently calculates (a^b) mod m. 

### **6. Conditions: if, elif, else** 

age = 20 if age >= 18: print("Adult") else: print("Minor") 

#### **Output:** 

<mark>Adult</mark> marks = 72 if marks >= 90: print("A") elif marks >= 75: print("B") elif marks >= 50: print("C") else: print("Fail") 

**Output:** 

<mark>C</mark> 

Use == for comparison. = is assignment. 

### **7. Loops** 

for i in range(5): print(i) 

#### **Output:** 

0 1 2 3 4 

for i in range(1, 6): print(i, end=" ") 

**Output:** 

<mark>1 2 3 4 5</mark> for i in range(10, 0, -2): print(i, end=" ") 

**Output:** 

<mark>10 8 6 4 2</mark> i = 1 while i <= 3: print(i) i += 1 **Output:** 

1 2 3 

for i in range(5): if i == 3: continue print(i) 

#### **Output:** 

0 1 2 4 

for i in range(5): if i == 3: break print(i) 

#### **Output:** 

0 1 2 

### **8. Strings — Essential for Cipher Questions** 

text = "hello" print(text[0]) print(text[-1]) print(len(text)) 

print(text.upper()) print(text.lower()) 

#### **Output:** 

h o 5 HELLO hello text = "Information Security" print(text[0:11]) print(text[::-1]) 

#### **Output:** 

Information ytiruceS noitamrofnI 

Strings are immutable: text[0] = 'H' is not allowed. Create a new string instead. 

### **9. Removing Whitespace and Cleaning Text** 

text = "  hello  " print(text.strip()) print(text.lstrip()) print(text.rstrip()) 

#### **Output:** 

hello hello hello text = "I am learning information security" print(text.replace(" ", "")) 

#### **Output:** 

<mark>Iamlearninginformationsecurity</mark> text = " I am\n learning\tPython " clean = "".join(text.split()) print(clean) 

#### **Output:** 

<mark>IamlearningPython</mark> 

text = "Hello, World!" clean = "".join(ch for ch in text if ch.isalpha()) print(clean) 

#### **Output:** 

<mark>HelloWorld</mark> 

For classical cipher questions, a very common preprocessing line is: 

text = "".join(ch for ch in text.upper() if ch.isalpha()) print(text) 

#### **Output:** 

<mark>INFORMATIONSECURITY</mark> 

### **10. Character ↔ Number Conversion** 

ch = "A" print(ord(ch)) print(chr(65)) 

#### **Output:** 

65 A 

ch = "C" value = ord(ch) - ord("A") print(value) value = 2 ch = chr(value + ord("A")) print(ch) 

#### **Output:** 

2 C 

This is the most useful pattern for Caesar, Vigenère, Affine and similar ciphers. 

### **11. Lists** 

nums = [10, 20, 30] print(nums[0]) nums.append(40) nums.remove(20) print(nums) print(len(nums)) 

#### **Output:** 

10 [10, 30, 40] 3 nums = [3, 1, 4, 2] nums.sort() print(nums) print(sum(nums)) print(max(nums)) print(min(nums)) 

#### **Output:** 

[1, 2, 3, 4] 10 4 1 

squares = [i * i for i in range(5)] print(squares) 

#### **Output:** 

<mark>[0, 1, 4, 9, 16]</mark> 

### **12. Tuples, Sets and Dictionaries** 

point = (10, 20) print(point[0]) 

#### **Output:** 

<mark>10</mark> s = {1, 2, 2, 3} print(s) 

#### **Output:** 

<mark>{1, 2, 3}</mark> student = {"name": "Alice", "age": 20} print(student["name"]) 

student["age"] = 21 print(student) 

#### **Output:** 

Alice {'name': 'Alice', 'age': 21} 

### **13. Functions** 

def add(a, b): return a + b result = add(5, 7) print(result) 

#### **Output:** 

<mark>12</mark> 

def encrypt_char(ch, key): p = ord(ch) - ord("A") c = (p + key) % 26 return chr(c + ord("A")) print(encrypt_char("A", 3)) 

#### **Output:** 

<mark>D</mark> 

Use functions when encryption and decryption logic should be separated or reused. 

### **14. Useful Built-in Functions** 

|Function|Purpose|
|---|---|
|len(x)|Length|
|range(...)|Sequence of integers|
|enumerate(x)|Index and value together|
|zip(a,b)|Pair items from collections|
|sum(x)|Sum|
|max(x),min(x)|Largest / smallest|
|sorted(x)|Return sorted collection|
|abs(x)|Absolute value|
|pow(a,b,m)|Modular exponentiation|
|type(x)|Check data type|



text = "ABC" for i, ch in enumerate(text): print(i, ch) 

#### **Output:** 

0 A 1 B 2 C 

### **15. Nested Loops** 

for i in range(3): for j in range(3): print(i, j) 

#### **Output:** 

0 0 0 1 0 2 1 0 1 1 

1 2 2 0 2 1 2 2 

Nested loops are commonly used for matrices, Playfair matrices and DES/AES-like state processing. 

### **16. Matrices (2D Lists)** 

matrix = [ [1, 2, 3], [4, 5, 6] ] print(matrix[0][1]) 

#### **Output:** 

<mark>2</mark> rows, cols = 2, 3 matrix = [[0 for j in range(cols)] for i in range(rows)] print(matrix) 

#### **Output:** 

<mark>[[0, 0, 0], [0, 0, 0]]</mark> matrix = [] for i in range(2): row = list(map(int, input().split())) matrix.append(row) print(matrix) 

#### **Output:** 

Input: 1 2 3 4 Output: [[1, 2], [3, 4]] matrix = [[1, 2], [3, 4]] 

for row in matrix: for value in row: print(value, end=" ") print() 

#### **Output:** 

1 2 3 4 

### **17. Matrix Addition and Multiplication** 

A = [[1, 2], [3, 4]] B = [[5, 6], [7, 8]] 

C = [[A[i][j] + B[i][j] for j in range(2)] for i in range(2)] print(C) 

#### **Output:** 

<mark>[[6, 8], [10, 12]]</mark> A = [[1, 2], [3, 4]] B = [[5, 6], [7, 8]] 

C = [[0, 0], [0, 0]] for i in range(2): for j in range(2): for k in range(2): C[i][j] += A[i][k] * B[k][j] print(C) 

#### **Output:** 

<mark>[[19, 22], [43, 50]]</mark> 

Hill cipher is based on matrix multiplication modulo 26. 

### **18. Matrix Transpose** 

A = [[1, 2, 3], [4, 5, 6]] 

T = [[A[j][i] for j in range(len(A))] for i in range(len(A[0]))] print(T) 

**Output:** 

<mark>[[1, 4], [2, 5], [3, 6]]</mark> 

### **19. Modular Arithmetic and Modular Inverse** 

<mark>print(29 % 26)</mark> 

**Output:** 

<mark>3</mark> # Python 3.8+ modular inverse a = 15 inv = pow(a, -1, 26) print(inv) 

#### **Output:** 

<mark>7</mark> 

Because 15 × 7 = 105 and 105 mod 26 = 1, 7 is the modular inverse of 15 modulo 26. 

# Extended Euclidean Algorithm version def mod_inverse(a, m): t, new_t = 0, 1 r, new_r = m, a while new_r != 0: q = r // new_r t, new_t = new_t, t - q * new_t r, new_r = new_r, r - q * new_r if r != 1: return None return t % m print(mod_inverse(15, 26)) 

#### **Output:** 

<mark>7</mark> 

### **20. gcd and Prime Checking** 

import math print(math.gcd(15, 26)) 

#### **Output:** 

<mark>1</mark> def is_prime(n): if n < 2: return False for i in range(2, int(n ** 0.5) + 1): if n % i == 0: return False return True print(is_prime(17)) print(is_prime(18)) 

#### **Output:** 

True False 

### **21. Random Numbers** 

import random print(random.randint(1, 10)) **Output:** <mark>Example output: 7</mark> 

#### **Output:** 

For real cryptographic secrets, ordinary random is not appropriate. Use cryptographic libraries or secrets; however, follow your lab question and installed library requirements. 

### **22. Timing Code** 

import time start = time.time() 

total = sum(range(1_000_000)) 

end = time.time() 

print("Time:", end - start) 

#### **Output:** 

<mark>Example output: Time: 0.03</mark> import time 

start = time.perf_counter() # Code to measure total = sum(range(1_000_000)) 

end = time.perf_counter() 

print("Time:", end - start) 

#### **Output:** 

<mark>Example output: Time: 0.03</mark> 

For lab performance comparisons, perf_counter() is usually a better timer for short code sections. 

### **23. Exception Handling** 

try: age = int(input("Enter age: ")) print(age) except ValueError: print("Please enter a valid integer") 

#### **Output:** 

Enter age: abc Please enter a valid integer try: x = 10 / 0 except ZeroDivisionError: print("Cannot divide by zero") 

#### **Output:** 

<mark>Cannot divide by zero</mark> 

### **24. Reading and Writing Files** 

with open("message.txt", "w") as file: file.write("Hello") with open("message.txt", "r") as file: data = file.read() print(data) 

#### **Output:** 

<mark>Hello</mark> 

Use binary modes wb and rb for raw bytes. 

### **25. Bytes, Encoding and Hex — Extremely Important for Crypto Libraries** 

message = "Hello" data = message.encode() print(data) print(data.decode()) 

#### **Output:** 

b'Hello' Hello data = b"ABC" print(data.hex()) 

x = bytes.fromhex("414243") print(x) 

#### **Output:** 

414243 b'ABC' print(int("FF", 16)) print(hex(255)) 

#### **Output:** 

255 0xff 

Common mistake: encrypting a Python str when the library expects bytes. 

**PART B — CRYPTOGRAPHY PROGRAMMING PATTERNS RELEVANT TO LABS 1–4** 

### **26. Lab-Test Imports You Are Most Likely to Need** 

import math import time import random from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP from Crypto.PublicKey import RSA, ElGamal from Crypto.Util.Padding import pad, unpad from Crypto.Util.number import getPrime, inverse, GCD 

The exact availability of these imports depends on the environment. The lab-manual exercises involve DES, AES, Triple DES, RSA, ElGamal, ECC, Diffie–Hellman and Rabin, but not every algorithm has a single standard built-in Python library interface. 

### **27. Classical Cipher Template: Clean Text First** 

def clean_text(text): return "".join(ch for ch in text.upper() if ch.isalpha()) message = "I am learning information security" message = clean_text(message) print(message) 

#### **Output:** 

<mark>IAMLEARNINGINFORMATIONSECURITY</mark> 

### **28. Additive / Caesar Cipher** 

def encrypt(text, key): result = "" for ch in text.upper(): if ch.isalpha(): p = ord(ch) - ord("A") c = (p + key) % 26 result += chr(c + ord("A")) return result 

def decrypt(text, key): result = "" for ch in text.upper(): if ch.isalpha(): c = ord(ch) - ord("A") p = (c - key) % 26 result += chr(p + ord("A")) return result 

message = "HELLO" key = 3 cipher = encrypt(message, key) plain = decrypt(cipher, key) 

print("Cipher:", cipher) print("Plain:", plain) 

#### **Output:** 

Cipher: KHOOR Plain: HELLO 

### **29. Multiplicative Cipher** 

def mod_inverse(a, m): return pow(a, -1, m) 

def encrypt(text, key): result = "" for ch in text.upper(): if ch.isalpha(): p = ord(ch) - ord("A") c = (key * p) % 26 result += chr(c + ord("A")) return result 

def decrypt(text, key): inv = mod_inverse(key, 26) result = "" for ch in text.upper(): if ch.isalpha(): c = ord(ch) - ord("A") p = (inv * c) % 26 result += chr(p + ord("A")) return result 

Always verify gcd(key, 26) == 1 before using a multiplicative key. 

### **30. Affine Cipher** 

import math def encrypt(text, a, b): if math.gcd(a, 26) != 1: raise ValueError("Invalid key a") 

result = "" for ch in text.upper(): if ch.isalpha(): p = ord(ch) - ord("A") c = (a * p + b) % 26 result += chr(c + ord("A")) return result 

def decrypt(text, a, b): 

a_inv = pow(a, -1, 26) result = "" for ch in text.upper(): if ch.isalpha(): c = ord(ch) - ord("A") p = (a_inv * (c - b)) % 26 result += chr(p + ord("A")) return result 

### **31. Vigenère Cipher** 

def encrypt(text, key): text = "".join(ch for ch in text.upper() if ch.isalpha()) key = "".join(ch for ch in key.upper() if ch.isalpha()) result = "" for i, ch in enumerate(text): p = ord(ch) - ord("A") k = ord(key[i % len(key)]) - ord("A") c = (p + k) % 26 result += chr(c + ord("A")) return result 

def decrypt(text, key): result = "" key = key.upper() for i, ch in enumerate(text): c = ord(ch) - ord("A") k = ord(key[i % len(key)]) - ord("A") p = (c - k) % 26 result += chr(p + ord("A")) return result 

print(encrypt("HELLO", "KEY")) 

#### **Output:** 

<mark>RIJVS</mark> 

### **32. Autokey Cipher** 

def encrypt(text, initial_key): text = "".join(ch for ch in text.upper() if ch.isalpha()) key_stream = [initial_key] key_stream += [ord(ch) - ord("A") for ch in text] 

result = "" for i, ch in enumerate(text): p = ord(ch) - ord("A") c = (p + key_stream[i]) % 26 

result += chr(c + ord("A")) 

return result 

def decrypt(cipher, initial_key): key_stream = [initial_key] result = "" for i, ch in enumerate(cipher): c = ord(ch) - ord("A") p = (c - key_stream[i]) % 26 result += chr(p + ord("A")) key_stream.append(p) return result 

The key stream grows using recovered plaintext, so decryption reconstructs it step by step. 

### **33. Playfair Cipher — Matrix Search Pattern** 

def build_matrix(key): alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" key = key.upper().replace("J", "I") chars = [] for ch in key + alphabet: if ch not in chars: chars.append(ch) return [chars[i:i+5] for i in range(0, 25, 5)] 

matrix = build_matrix("GUIDANCE") for row in matrix: print(row) **Output:** 

Example structure: ['G', 'U', 'I', 'D', 'A'] ['N', 'C', 'E', 'B', 'F'] ... def find_position(matrix, ch): for i in range(5): for j in range(5): if matrix[i][j] == ch: return i, j 

After locating both letters, implement the same-row, same-column and rectangle rules described in the cipher reference. 

### **34. Hill Cipher — 2×2 Core Pattern** 

key = [ [3, 3], [2, 7] ] vector = [7, 8]  # H, I 

cipher = [ (key[0][0] * vector[0] + key[0][1] * vector[1]) % 26, (key[1][0] * vector[0] + key[1][1] * vector[1]) % 26 ] print(cipher) 

#### **Output:** 

<mark>[17, 18]</mark> 

For full decryption, you need the modular inverse of the key matrix. This is more complex than ordinary matrix inversion because all operations are modulo 26. 

### **35. Brute Force for Caesar/Shift** 

def decrypt(text, key): result = "" for ch in text: if ch.isalpha(): c = ord(ch.upper()) - ord("A") result += chr((c - key) % 26 + ord("A")) return result cipher = "KHOOR" for key in range(26): print(key, decrypt(cipher, key)) 

#### **Output:** 

0 KHOOR 1 JGNNQ 2 IFMMP 3 HELLO 

### **36. Timing an Encryption and Decryption Function** 

import time 

start = time.perf_counter() cipher = encrypt(message, key) enc_time = time.perf_counter() - start start = time.perf_counter() plain = decrypt(cipher, key) dec_time = time.perf_counter() - start print("Encryption time:", enc_time) print("Decryption time:", dec_time) 

#### **Output:** 

<mark>Example output: Encryption time: 0.00001 seconds</mark> 

This pattern is directly useful for exercises asking you to compare algorithm performance. 

## **PART C — MODERN SYMMETRIC ENCRYPTION** 

### **37. Padding and Unpadding** 

from Crypto.Util.Padding import pad, unpad 

data = b"HELLO" padded = pad(data, 16) print(padded) print(unpad(padded, 16)) 

#### **Output:** 

b'HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' b'HELLO' 

Padding is commonly required for block modes such as ECB and CBC when data length is not an exact multiple of the block size. 

### **38. DES** 

from Crypto.Cipher import DES from Crypto.Util.Padding import pad, unpad 

key = b"12345678"      # DES key must be 8 bytes message = b"HELLO DES" 

cipher = DES.new(key, DES.MODE_ECB) ciphertext = cipher.encrypt(pad(message, DES.block_size)) 

print("Ciphertext:", ciphertext.hex()) 

decipher = DES.new(key, DES.MODE_ECB) plaintext = unpad(decipher.decrypt(ciphertext), DES.block_size) 

print("Plaintext:", plaintext.decode()) 

#### **Output:** 

Ciphertext: (hex value varies according to the exact message/mode) Plaintext: HELLO DES 

### **39. DES CBC Mode** 

from Crypto.Cipher import DES from Crypto.Util.Padding import pad, unpad 

key = b"12345678" iv = b"ABCDEFGH" message = b"Secure Communication" 

cipher = DES.new(key, DES.MODE_CBC, iv) ciphertext = cipher.encrypt(pad(message, DES.block_size)) 

decipher = DES.new(key, DES.MODE_CBC, iv) plaintext = unpad(decipher.decrypt(ciphertext), DES.block_size) 

print(plaintext.decode()) 

#### **Output:** 

<mark>Secure Communication</mark> 

### **40. Triple DES (3DES)** 

from Crypto.Cipher import DES3 from Crypto.Util.Padding import pad, unpad 

key = DES3.adjust_key_parity(b"123456789012345678901234") message = b"Classified Text" 

cipher = DES3.new(key, DES3.MODE_ECB) ciphertext = cipher.encrypt(pad(message, DES3.block_size)) 

decipher = DES3.new(key, DES3.MODE_ECB) plaintext = unpad(decipher.decrypt(ciphertext), DES3.block_size) 

print(plaintext.decode()) 

#### **Output:** 

<mark>Classifed Text</mark> i 

The supplied lab manual asks about Triple DES; exact library key requirements may differ from the literal key text shown in a question, so check byte length and library validation. 

### **41. AES — General Template** 

from Crypto.Cipher import AES from Crypto.Util.Padding import pad, unpad 

message = b"Top Secret Data" 

# AES-128 = 16 bytes, AES-192 = 24 bytes, AES-256 = 32 bytes key = b"0123456789ABCDEF" 

cipher = AES.new(key, AES.MODE_ECB) ciphertext = cipher.encrypt(pad(message, AES.block_size)) 

print("Ciphertext:", ciphertext.hex()) 

decipher = AES.new(key, AES.MODE_ECB) plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size) 

print("Plaintext:", plaintext.decode()) 

#### **Output:** 

Ciphertext: (hex output) Plaintext: Top Secret Data 

### **42. AES Key Lengths** 

|AES Version|KeyLength|Typical Example|
|---|---|---|
|AES-128|16 bytes|b"0123456789ABCDEF"|
|AES-192|24 bytes|24 bytes exactly|
|AES-256|32 bytes|32 bytes exactly|



given_key = "FEDCBA9876543210FEDCBA9876543210" 

# If the lab specifically expects a 24-byte AES-192 key: key = given_key[:24].encode() 

print(len(key)) 

#### **Output:** 

<mark>24</mark> 

### **43. AES CBC Mode** 

from Crypto.Cipher import AES from Crypto.Util.Padding import pad, unpad 

key = b"0123456789ABCDEF" iv = b"ABCDEF1234567890" message = b"Confidential Data" 

cipher = AES.new(key, AES.MODE_CBC, iv) ciphertext = cipher.encrypt(pad(message, AES.block_size)) 

decipher = AES.new(key, AES.MODE_CBC, iv) plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size) 

print(plaintext.decode()) 

#### **Output:** 

<mark>Confdential Data</mark> i 

### **44. AES CTR Mode** 

from Crypto.Cipher import AES 

key = b"0123456789ABCDEF" nonce = b"00000000" message = b"Cryptography Lab Exercise" 

cipher = AES.new(key, AES.MODE_CTR, nonce=nonce) ciphertext = cipher.encrypt(message) decipher = AES.new(key, AES.MODE_CTR, nonce=nonce) plaintext = decipher.decrypt(ciphertext) 

print(plaintext.decode()) 

#### **Output:** 

<mark>Cryptography Lab Exercise</mark> 

CTR normally does not require PKCS-style padding because it behaves like a stream cipher. 

### **45. Comparing DES and AES Timing** 

import time from Crypto.Cipher import AES, DES from Crypto.Util.Padding import pad 

message = b"Performance Testing of Encryption Algorithms" 

##### # DES 

des_key = b"12345678" start = time.perf_counter() des = DES.new(des_key, DES.MODE_ECB) des_ciphertext = des.encrypt(pad(message, DES.block_size)) des_time = time.perf_counter() - start 

##### # AES 

aes_key = b"0123456789ABCDEF0123456789ABCDEF" start = time.perf_counter() aes = AES.new(aes_key, AES.MODE_ECB) aes_ciphertext = aes.encrypt(pad(message, AES.block_size)) 

aes_time = time.perf_counter() - start print("DES time:", des_time) print("AES time:", aes_time) **Output:** 

<mark>Example output: two small measured times in seconds</mark> 

## **PART D — ASYMMETRIC CRYPTOGRAPHY** 

### **46. RSA — Key Generation and OAEP Encryption** 

from Crypto.PublicKey import RSA from Crypto.Cipher import PKCS1_OAEP # Generate key pair key = RSA.generate(2048) public_key = key.publickey() message = b"Asymmetric Encryption" # Encrypt with public key cipher = PKCS1_OAEP.new(public_key) ciphertext = cipher.encrypt(message) # Decrypt with private key decipher = PKCS1_OAEP.new(key) plaintext = decipher.decrypt(ciphertext) print(plaintext.decode()) 

#### **Output:** 

<mark>Asymmetric Encryption</mark> 

For practical library-based RSA encryption, OAEP is preferable to directly calculating m^e mod n on arbitrary text. 

### **47. RSA — Mathematical Toy Example** 

# Small values only for understanding the mathematics p = 17 q = 11 n = p * q phi = (p - 1) * (q - 1) e = 7 d = pow(e, -1, phi) m = 42 c = pow(m, e, n) recovered = pow(c, d, n) print("n =", n) print("Cipher =", c) print("Plain =", recovered) 

**Output:** 

n = 187 Cipher = 15 Plain = 42 

### **48. RSA Timing Pattern** 

import time from Crypto.PublicKey import RSA from Crypto.Cipher import PKCS1_OAEP start = time.perf_counter() key = RSA.generate(2048) keygen_time = time.perf_counter() - start message = b"Hello" 

cipher = PKCS1_OAEP.new(key.publickey()) start = time.perf_counter() ciphertext = cipher.encrypt(message) enc_time = time.perf_counter() - start decipher = PKCS1_OAEP.new(key) start = time.perf_counter() plaintext = decipher.decrypt(ciphertext) dec_time = time.perf_counter() - start print(keygen_time, enc_time, dec_time) 

#### **Output:** 

<mark>Example output: three timings in seconds</mark> 

### **49. Diffie–Hellman — Simple Mathematical Implementation** 

# Public values p = 23 g = 5 # Private values a = 6 b = 15 # Public values A = pow(g, a, p) B = pow(g, b, p) # Shared secret alice_secret = pow(B, a, p) bob_secret = pow(A, b, p) print("Alice public:", A) print("Bob public:", B) print("Shared secrets:", alice_secret, bob_secret) 

#### **Output:** 

Alice public: 8 Bob public: 19 Shared secrets: 2 2 

In a real implementation, p and g must be appropriately chosen and private values should be securely random. 

### **50. ElGamal — Mathematical Pattern** 

# Small demonstration values for understanding p = 23 g = 5 x = 6                 # private key y = pow(g, x, p)      # public component m = 10 k = 7                 # random value for this encryption c1 = pow(g, k, p) s = pow(y, k, p) c2 = (m * s) % p print("Ciphertext:", (c1, c2)) 

# Decryption shared = pow(c1, x, p) shared_inv = pow(shared, -1, p) recovered = (c2 * shared_inv) % p print("Plaintext:", recovered) 

#### **Output:** 

Ciphertext: (17, 5) Plaintext: 10 

### **51. ECC — What to Remember for the Lab** 

The manual explains ECC key generation as choosing curve parameters and a base point G, choosing a private integer d, and computing public key Q = d·G. It also notes that ECC is primarily used for key exchange rather than direct message encryption. Therefore, a lab implementation may depend heavily on the exact library or protocol specified by the instructor/question. 

# Conceptual ECC key relation private_key = d public_key = d * G   # elliptic-curve point multiplication 

Do not attempt to implement elliptic-curve arithmetic from scratch in a timed test unless the question explicitly requires it. 

### **52. Rabin Cryptosystem — Core Mathematical Template** 

# Small educational example only p = 7 q = 11 n = p * q m = 20 c = (m * m) % n print("Ciphertext:", c) 

#### **Output:** 

<mark>Ciphertext: 15</mark> 

Rabin decryption requires finding square roots modulo p and q and combining them with the Chinese Remainder Theorem. The manual explicitly notes that four candidate roots can result and one is the original message. 

## **PART E — KEY MANAGEMENT AND ACCESS-CONTROL PROGRAMMING CONCEPTS** 

### **53. Simple Key Dictionary** 

keys = {} keys["Hospital A"] = {"public": "PUB_KEY", "private": "PRIVATE_KEY"} print(keys["Hospital A"]["public"]) 

#### **Output:** 

<mark>PUB_KEY</mark> 

### **54. Logging Important Actions** 

from datetime import datetime logs = [] def log(message): logs.append(f"{datetime.now()}: {message}") log("Key generated") log("Message encrypted") for entry in logs: print(entry) 

**Output:** 

Example output: 2026-...: Key generated 2026-...: Message encrypted 

### **55. Key Rotation / Renewal Logic Pattern** 

from datetime import datetime, timedelta created = datetime.now() expiry = created + timedelta(days=365) if datetime.now() >= expiry: print("Renew key") else: print("Key is still valid") 

#### **Output:** 

<mark>Example output: Key is still valid</mark> 

### **56. Simple Role-Based Access Control (RBAC) Pattern** 

roles = { "admin": ["read", "write", "delete"], "user": ["read"] } def can_access(role, action): return action in roles.get(role, []) print(can_access("user", "read")) print(can_access("user", "delete")) 

**Output:** 

True False 

## **PART F — LAB TEST SURVIVAL CHECKLIST** 

### **57. Before Writing Code** 

- Identify input type: text, integer, list, matrix or bytes. 

- Check whether spaces should be ignored. 

- For classical ciphers, usually convert text to uppercase and remove spaces. 

- For modular arithmetic, confirm the modulus: usually 26 for alphabetic ciphers. 

- For AES/DES, check exact key length. 

- For library encryption, convert text using .encode(). 

- For block modes requiring padding, use pad() before encryption and unpad() after decryption. 

- For performance questions, use time.perf_counter() around only the operation being measured. 

- Always decrypt your ciphertext and print the recovered plaintext to verify correctness. 

### **58. Common Python Errors and Quick Fixes** 

|Problem|Typical Cause|Fix<br>l|
|---|---|---|
|TypeError addinginput|input is str|Use int()or float()|
|IndentationError|Incorrect spacing|Align block statements consistently|
|IndexError|Index outside list/string|Check len()and looplimits|
|KeyError|Missingdictionarykey|Useget()or check key|
|ValueError in int()|Non-numeric input|Validate or use try/except|
|AES keylength error|Wrongnumber of bytes|Use exactly16/24/32 bytes|
|DES keylength error|Wrongkeysize|DES requires 8-byte key|
|Paddingerror|Wrongblock size/mode/key|Checkpad/unpad and matchingcipher settings|
|str vs bytes error|Libraryexpects bytes|Use .encode()|
|modular inverse error|Numbers not coprime|Checkgcd(a,m)==1|



### **59. The 10 Patterns Worth Memorising First** 

- 1. text = input().strip() 

- 2. nums = list(map(int, input().split())) 

- 3. clean = "".join(ch for ch in text.upper() if ch.isalpha()) 

- 4. value = ord(ch) - ord("A") 

- 5. ch = chr(value + ord("A")) 

- 6. (x + key) % 26 and (x - key) % 26 

- 7. for i, ch in enumerate(text): 

- 8. matrix = [[0 for j in range(cols)] for i in range(rows)] 

- 9. start = time.perf_counter() ... elapsed = time.perf_counter() - start 

- 10. data = text.encode() and data.decode() 

## **FINAL NOTE** 

For the supplied Information Security lab manual, do not try to memorise every program character-by-character. Instead, memorise the reusable Python patterns in Part A, then understand the algorithm templates in Parts B–E. Most lab questions can be built by combining: input → preprocessing → key setup → encryption → timing (if needed) → decryption → verification. 

## **SOURCE BASIS** 

Cryptography coverage is based on the uploaded Information Security Lab Manual for Labs 1–4, including the classical symmetric ciphers, DES/AES/3DES and block modes, RSA, ElGamal, ECC, Diffie–Hellman, Rabin, key management and access-control themes. General Python syntax and supplementary implementation examples are standard programming guidance added to make the manual usable for a beginner. 

