'''
================================================================================
SECTION 1 — FULL QUESTION
================================================================================
Lab No. 5: Hashing

Objectives
1. To implement user defined hashing function.
2. To demonstrate the application of hash function.

Introduction
A hash function H takes an input data block M of variable length and generates a fixed-size
hash value h = H(M). An effective hash function ensures that applying it to a large set of
inputs yields outputs that are evenly distributed and seemingly random. The primary goal of
a hash function is to maintain data integrity, such that any change in the input M, even by a
single bit, will likely result in a different hash value.

For security purposes, a special type of hash function, known as a cryptographic hash function,
is used. This algorithm has two key properties:
- The one-way property, which makes it computationally infeasible to find a data object that
  matches a pre-specified hash result.
- The collision-free property, which makes it computationally infeasible to find two distinct
  data objects that produce the same hash result.

Due to these properties, cryptographic hash functions are commonly employed to verify whether
data has been altered.

Lab Exercises
2. Using socket programming in Python, demonstrate the application of hash functions for
   ensuring data integrity during transmission over a network. Write server and client scripts
   where the server computes the hash of received data and sends it back to the client, which
   then verifies the integrity of the data by comparing the received hash with the locally
   computed hash. Show how the hash verification detects data corruption or tampering during
   transmission.

================================================================================
SECTION 2 — QUESTION / CONTEXT EXPLANATION
================================================================================
This lab studies hashing as a way to map variable-length input data to a fixed-size
digest. The first program builds a simple user-defined hash function. The socket
program demonstrates integrity checking over a network. The performance program
compares MD5, SHA-1, and SHA-256 using random strings and checks whether two inputs
produce the same digest. The additional exercise extends the network example by
transmitting one message in multiple parts and hashing the reassembled message.

Important distinction:
- A general-purpose hash is useful for tables, indexing, and demonstrations.
- A cryptographic hash is designed for security properties such as preimage resistance,
  second-preimage resistance, and collision resistance.
- A hash alone does not authenticate the sender. An attacker who can modify both the
  message and its hash can bypass a plain integrity check. Use a MAC or digital
  signature for authenticity.

================================================================================
SECTION 3 — THEORY AND FORMULAS
================================================================================
1. Hash function:
       h = H(M)

2. User-defined hash requested in Exercise 1:
       h_0 = 5381
       h_i = (33 * h_(i-1) + value(c_i)) with mixing operations
       h_final = h & 0xFFFFFFFF

   Here value(c_i) is the character's ordinal value, normally obtained using ord(c_i).
   The mask 0xFFFFFFFF keeps the result in the unsigned 32-bit range.

3. Cryptographic digest:
       digest = H(message)

   A one-bit or one-character change should normally produce a different digest,
   although no finite hash function can guarantee a unique output for every input.

4. Collision:
       H(M1) = H(M2), where M1 != M2

5. Birthday-bound intuition:
   For an n-bit digest, generic collision searching becomes feasible around 2^(n/2)
   work in the idealized setting. This is why short digests are unsuitable for modern
   collision-resistant security applications.

6. Network integrity check:
       local_hash = H(original_message)
       received_hash = server_hash(received_message)
       integrity_ok = (local_hash == received_hash)

   This detects accidental corruption when the expected hash is trusted. For hostile
   tampering, use HMAC or a digital signature.

7. Performance measurement:
       elapsed_time = end_time - start_time

   Collision detection can be implemented with a set:
       if digest in seen: collision detected
       else: add digest to seen

================================================================================
SECTION 4 — DETAILED COMMENTS / IMPLEMENTATION GUIDE
================================================================================
- Use UTF-8 when converting Python strings to bytes for cryptographic algorithms.
- Use hashlib.md5, hashlib.sha1, and hashlib.sha256 for the comparison experiment.
- Use time.perf_counter() for high-resolution timing.
- Use secrets or random.SystemRandom for unpredictable test data when appropriate.
- Socket send() and recv() may transfer partial data; production code should frame
  messages or use sendall() and a length-prefix protocol.
- Bind local demonstrations to 127.0.0.1 unless remote networking is specifically required.
- Always close sockets using context managers or finally blocks.
- Compare digests using hmac.compare_digest() when comparing security-sensitive values.
- The examples are educational. MD5 and SHA-1 are included for comparison only and
  should not be selected for new security designs.

================================================================================
SECTION 5 — HASHING / VERIFICATION LOGIC
================================================================================
The programs do not perform encryption. Their core operation is:
1. Read or generate a message.
2. Compute a digest.
3. Transmit or store the digest.
4. Recompute the digest from the received or later-retrieved message.
5. Compare the two values.
6. Report whether the message appears unchanged.

For the multipart exercise:
1. Split the original message into chunks.
2. Send each chunk with a clear framing rule.
3. Reassemble chunks in the server in the correct order.
4. Hash the complete reassembled message.
5. Return the digest.
6. Compare it with the client's digest of the original message.

================================================================================
SECTION 6 — BRUTE-FORCE AND ATTACK EXERCISES
================================================================================
Suggested experiments:
1. Brute-force a small user-defined hash domain and look for collisions.
2. Change one character in a message and compare the resulting digest.
3. Try an empty string, repeated characters, Unicode text, and long input.
4. Demonstrate that a plain hash is vulnerable if an attacker can replace both
   the message and the transmitted hash.
5. Demonstrate a length/framing error in socket communication and explain why
   message framing is necessary.
6. Compare the practical meaning of collisions in a small 32-bit custom hash with
   the much larger digest spaces of SHA-256.
7. Explain why MD5 and SHA-1 should not be used for new collision-resistant designs.
8. For a stronger network experiment, replace the plain hash with HMAC-SHA256
   using a shared secret and compare the security properties.

================================================================================
SECTION 7 — CHARACTER MAPPING AND ASSUMPTIONS
================================================================================
- The custom function processes Python characters and uses ord(character), which
  returns the Unicode code point. For ordinary English input this matches ASCII.
- Cryptographic examples encode strings as UTF-8 bytes before hashing.
- The custom function returns an unsigned 32-bit integer because of & 0xFFFFFFFF.
- Hexadecimal digests are display representations of binary digest bytes.
- Random-string experiments use printable ASCII unless the source code says otherwise.
- Collision absence in a dataset of 50–100 strings does not prove collision resistance.
- The socket examples assume localhost connectivity and a trusted expected digest.
- Hashing provides integrity evidence, not confidentiality; it does not hide the message.
'''

"""
LAB 5 - HASHING
QUESTION 2 - CLIENT

The client:
1. Sends a message to the server.
2. Computes the local hash.
3. Receives the server's hash.
4. Compares both hashes.
5. Demonstrates detection of local data corruption.

Run:
    Terminal 1: python Q2_Hash_Integrity_Server.py
    Terminal 2: python Q2_Hash_Integrity_Client.py
"""

import socket


def user_defined_hash(message):
    hash_value = 5381
    mask_32_bit = 0xFFFFFFFF

    for character in message:
        hash_value = ((hash_value << 5) + hash_value) + ord(character)
        hash_value ^= (hash_value << 16)
        hash_value &= mask_32_bit

    return hash_value


HOST = "127.0.0.1"
PORT = 5000

message = input("Enter message to send: ")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))
    client_socket.sendall(message.encode("utf-8"))

    server_hash = int(client_socket.recv(4096).decode("utf-8"))

local_hash = user_defined_hash(message)

print("Original message:", message)
print("Local hash:", local_hash)
print("Server hash:", server_hash)

if local_hash == server_hash:
    print("Integrity verification successful: data is unchanged.")
else:
    print("Integrity verification failed: data may be corrupted or tampered.")

# Demonstration of corruption detection:
corrupted_message = message + "X"
corrupted_hash = user_defined_hash(corrupted_message)

print("\nCorruption demonstration")
print("Corrupted message:", corrupted_message)
print("Corrupted hash:", corrupted_hash)

if corrupted_hash != server_hash:
    print("Corruption detected successfully.")
else:
    print("Corruption was not detected.")
