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

3. Design a Python-based experiment to analyze the performance of MD5, SHA-1, and SHA-256
   hashing techniques in terms of computation time and collision resistance. Generate a dataset
   of random strings ranging from 50 to 100 strings, compute the hash values using each hashing
   technique, and measure the time taken for hash computation. Implement collision detection
   algorithms to identify any collisions within the hashed dataset.

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
QUESTION 3

Analyze MD5, SHA-1, and SHA-256 in terms of:
- Computation time.
- Collision detection in a dataset of random strings.
- Digest size.

The experiment generates 50-100 random strings. The default is 100.

Important:
- Finding no collision in a small random sample does NOT prove collision
  resistance.
- MD5 and SHA-1 are cryptographically broken for collision resistance.
- SHA-256 is recommended for modern integrity applications.
"""

import hashlib
import random
import string
import time


def generate_random_string(length=20):
    characters = string.ascii_letters + string.digits
    return "".join(random.choices(characters, k=length))


def generate_dataset(size=100):
    return [generate_random_string() for _ in range(size)]


def analyze_hash_algorithm(algorithm_name, dataset):
    hash_values = []
    start_time = time.perf_counter()

    for message in dataset:
        digest = hashlib.new(
            algorithm_name,
            message.encode("utf-8")
        ).hexdigest()
        hash_values.append(digest)

    elapsed_time = time.perf_counter() - start_time
    collision_count = len(hash_values) - len(set(hash_values))

    return {
        "algorithm": algorithm_name,
        "time_seconds": elapsed_time,
        "digest_size_bits": hashlib.new(algorithm_name).digest_size * 8,
        "collision_count": collision_count,
        "hash_values": hash_values,
    }


if __name__ == "__main__":
    dataset_size = 100
    dataset = generate_dataset(dataset_size)

    print(f"Dataset size: {dataset_size} random strings\n")

    for algorithm in ["md5", "sha1", "sha256"]:
        result = analyze_hash_algorithm(algorithm, dataset)

        print("Algorithm:", result["algorithm"].upper())
        print("Digest size:", result["digest_size_bits"], "bits")
        print("Computation time:",
              f'{result["time_seconds"]:.10f}', "seconds")
        print("Collisions found:", result["collision_count"])
        print("-" * 45)

    print("\nConclusion:")
    print("- MD5 is fast but unsuitable for collision-resistant security.")
    print("- SHA-1 is unsuitable for collision-resistant security.")
    print("- SHA-256 provides a stronger modern security margin.")
