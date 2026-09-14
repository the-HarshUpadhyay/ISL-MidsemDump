"""\n================================================================================
SECTION 1 — FULL LAB QUESTION
================================================================================
Lab No. 5: Hashing

Objectives
1. To implement user defined hashing function.
2. To demonstrate the application of hash function.

Introduction
A hash function H takes an input data block M of variable length and generates a fixed-size
hash value h=H(M). An effective hash function ensures that applying it to a large set of
inputs yields outputs that are evenly distributed and seemingly random. The primary goal
of a hash function is to maintain data integrity, such that any change in the input M, even
by a single bit, will likely result in a different hash value.

For security purposes, a special type of hash function, known as a cryptographic hash
function, is used. This algorithm has two key properties:
- The one-way property, which makes it computationally infeasible to find a data object
  that matches a pre-specified hash result.
- The collision-free property, which makes it computationally infeasible to find two
  distinct data objects that produce the same hash result.

Due to these properties, cryptographic hash functions are commonly employed to verify
whether data has been altered.

Lab Exercises

Implement the hash function in Python. Your function should start with an initial hash
value of 5381 and for each character in the input string, multiply the current hash value
by 33, add the ASCII value of the character, and use bitwise operations to ensure thorough
mixing of the bits. Finally, ensure the hash value is kept within a 32-bit range by applying
an appropriate mask.

1) Using socket programming in Python, demonstrate the application of hash functions for
ensuring data integrity during transmission over a network. Write server and client scripts
where the server computes the hash of received data and sends it back to the client, which
then verifies the integrity of the data by comparing the received hash with the locally
computed hash. Show how the hash verification detects data corruption or tampering during
transmission.


================================================================================
SECTION 2 — QUESTION / CONTEXT EXPLANATION
================================================================================
This program is the implementation for the question stated below. Hashing maps variable-
length input data to a fixed-size value. In this lab the custom hash is used for learning,
while MD5, SHA-1, and SHA-256 are compared using Python's hashlib.

A hash value is useful for integrity checking because the receiver can recompute the digest
and compare it with an expected digest. A plain hash is not encryption and does not provide
confidentiality. Also, if an attacker can modify both a message and its unauthenticated hash,
the comparison alone is not a secure authentication mechanism.

================================================================================
SECTION 3 — THEORY AND FORMULAS
================================================================================
General hash:
    h = H(M)

Custom hash requested by the lab:
    h0 = 5381
    hi = 33 * h(i-1) + ord(c_i)
    apply bitwise mixing
    hfinal = h & 0xFFFFFFFF

Bitwise identity used in the code:
    h * 33 = (h << 5) + h

32-bit mask:
    0xFFFFFFFF = 2^32 - 1

Collision:
    H(M1) = H(M2), where M1 != M2

Digest comparison:
    integrity_ok = (local_hash == received_hash)

Timing:
    elapsed_time = end_time - start_time

For an ideal n-bit cryptographic hash, generic collision search has a birthday-bound
order of about 2^(n/2), while preimage search is on the order of 2^n.

================================================================================
SECTION 4 — DETAILED COMMENTS
================================================================================
The original program logic is retained. Comments explain:
- initialization and per-character processing;
- the 33x update and bitwise mixing;
- 32-bit masking;
- UTF-8 conversion for socket and cryptographic hashing;
- socket connection and message transfer;
- timing and collision counting;
- multipart framing and reassembly.

For TCP programs, recv() may return fewer bytes than requested. The multipart server therefore
uses an exact-length receive helper and explicit length prefixes for reliable educational
framing.

================================================================================
SECTION 5 — HASHING AND VERIFICATION LOGIC
================================================================================
Hashing flow:
    1. Obtain or receive the message.
    2. Compute H(message).
    3. Return/store/transmit the digest.
    4. Recompute H(message) at the other side.
    5. Compare the two values.
    6. Matching digests indicate that the compared data produced the same hash.

There is no encryption or digital-signature operation in this lab. The relevant operation is
hash computation and integrity verification.

================================================================================
SECTION 6 — BRUTE-FORCE AND ATTACK EXERCISES
================================================================================
1. Change one character and compare the custom hash.
2. Try empty strings, repeated characters, and long strings.
3. Search a small input space for two different messages with the same custom 32-bit hash.
4. Explain why a 32-bit hash has many fewer possible outputs than SHA-256.
5. Modify the client message and demonstrate integrity failure.
6. Explain how replacing both data and an unauthenticated hash defeats a naive integrity check.
7. Compare the security implications of MD5, SHA-1, and SHA-256.
8. Explain why replay, tampering, and impersonation require stronger authentication mechanisms
   such as HMAC or digital signatures.

================================================================================
SECTION 7 — CHARACTER MAPPING AND ASSUMPTIONS
================================================================================
- The custom hash uses ord(character). For ordinary English characters, this corresponds
  to the ASCII value requested by the lab.
- Python strings may contain Unicode; cryptographic examples encode them using UTF-8.
- & 0xFFFFFFFF restricts the custom hash result to an unsigned 32-bit value.
- Hexadecimal digest strings are display representations, not the underlying binary digest.
- The performance experiment uses random alphanumeric strings and a dataset of 50–100 entries.
- Finding no collision in a small dataset does not prove collision resistance.
- Socket demonstrations use localhost and educational framing; production protocols need
  proper authentication, framing, error handling, and cryptographic integrity protection.

================================================================================
ACTUAL QUESTION FOR THIS FILE
================================================================================
QUESTION 1 — USER-DEFINED HASH FUNCTION
Implement the hash function in Python. Your function should start with an initial hash value
of 5381 and for each character in the input string, multiply the current hash value by 33,
add the ASCII value of the character, and use bitwise operations to ensure thorough mixing
of the bits. Finally, ensure the hash value is kept within a 32-bit range by applying an
appropriate mask.
"""

def user_defined_hash(message):
    hash_value = 5381
    mask_32_bit = 0xFFFFFFFF

    for character in message:
        hash_value = ((hash_value << 5) + hash_value) + ord(character)
        hash_value ^= (hash_value << 16)
        hash_value &= mask_32_bit

    return hash_value


if __name__ == "__main__":
    message = input("Enter a message: ")

    result = user_defined_hash(message)

    print("Message:", message)
    print("32-bit hash:", result)
    print("Hash in hexadecimal:", hex(result))
