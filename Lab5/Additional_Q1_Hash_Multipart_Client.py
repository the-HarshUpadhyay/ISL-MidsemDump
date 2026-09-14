"""\n
============================================================
FULL LAB QUESTION
============================================================
Lab No. 5: Hashing

Objectives:
1. To implement user defined hashing function.
2. To demonstrate the application of hash function.

Introduction:
A hash function H takes an input data block M of variable length and generates
a fixed-size hash value h = H(M). A useful hash function distributes outputs
well and helps detect changes in data. Cryptographic hash functions additionally
aim to provide one-way and collision-resistant behavior.

============================================================
QUESTION / CONTEXT EXPLANATION
============================================================
This program is one part of the Hashing laboratory. It is intended for an
educational demonstration of hashing, integrity checking, performance testing,
or multipart network transmission.

============================================================
THEORY AND FORMULAS
============================================================
Hash function:
    h = H(M)

Custom hash:
    h0 = 5381
    hi = 33 * h(i-1) + ord(character)
    hfinal = h & 0xFFFFFFFF

Collision:
    H(M1) = H(M2), where M1 != M2

Integrity comparison:
    local_hash == received_hash

Timing:
    elapsed_time = end_time - start_time

============================================================
DETAILED COMMENTS / LOGIC
============================================================
The code below includes comments explaining the input, processing, output,
socket protocol where applicable, and verification steps.

============================================================
HASHING / VERIFICATION LOGIC
============================================================
Hashing is not encryption. It does not hide the message. It creates a digest
that can be recomputed and compared. A plain hash does not authenticate the
sender; HMAC or digital signatures are needed against an active attacker.

============================================================
BRUTE-FORCE AND ATTACK EXERCISES
============================================================
1. Try empty input, repeated characters, long input, and Unicode input.
2. Change one character and compare the digest.
3. Search a small input space for custom-hash collisions.
4. Explain why a 32-bit custom hash has a limited output space.
5. Explain why replacing both a message and its plain hash defeats a naive check.
6. Explain TCP fragmentation and why length-prefix framing is useful.
7. Explain why MD5 and SHA-1 are unsuitable for new collision-resistant designs.

============================================================
CHARACTER MAPPING AND ASSUMPTIONS
============================================================
- ord(character) returns a Unicode code point; for English characters it matches ASCII.
- Cryptographic hashing normally uses UTF-8 encoded bytes.
- 0xFFFFFFFF limits the custom hash to an unsigned 32-bit value.
- Hexadecimal digests are printable representations of binary digest bytes.
- The socket examples use localhost and educational framing assumptions.
- No collision in a small dataset does not prove collision resistance.

ADDITIONAL QUESTION 1 — MULTIPART MESSAGE HASHING

Write a client and server program in Python where the client sends a message
to the server in multiple parts.

The client must:
1. Read an original message.
2. Divide the message into multiple parts.
3. Send the parts to the server using a clearly defined protocol.
4. Compute the hash of the complete original message locally.
5. Receive the hash computed by the server.
6. Compare both hashes.
7. Display whether the reassembled message passed integrity verification.

"""
import socket
import struct


def user_defined_hash(message):
    hash_value = 5381
    mask_32_bit = 0xFFFFFFFF

    for character in message:
        hash_value = ((hash_value << 5) + hash_value) + ord(character)
        hash_value ^= (hash_value << 16)
        hash_value &= mask_32_bit

    return hash_value


HOST = "127.0.0.1"
PORT = 5001

message = input("Enter message: ")
encoded_message = message.encode("utf-8")

# Split the message into three parts.
part_size = max(1, len(encoded_message) // 3)
parts = [
    encoded_message[index:index + part_size]
    for index in range(0, len(encoded_message), part_size)
]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))

    # Send number of parts as a fixed 4-byte field.
    client_socket.sendall(
        f"{len(parts):04d}".encode("utf-8")
    )

    for part in parts:
        client_socket.sendall(struct.pack("!I", len(part)))
        client_socket.sendall(part)

    server_hash = int(client_socket.recv(4096).decode("utf-8"))

local_hash = user_defined_hash(message)

print("Original message:", message)
print("Number of parts:", len(parts))
print("Local hash:", local_hash)
print("Server hash:", server_hash)

if local_hash == server_hash:
    print("Integrity verification successful.")
else:
    print("Integrity verification failed.")
