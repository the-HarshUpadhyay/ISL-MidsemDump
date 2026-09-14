
# ======================================================================
# FULL QUESTION / CLIENT ROLE
# ======================================================================
# Implement the client side of a client-server digital-signature scenario.
# The client creates a message, signs it with its private key, and sends
# the message and signature to the server for verification.
#
# The client must demonstrate message creation, signing, transmission,
# and handling of the server's verification response.
# ======================================================================

"""LAB 6 - QUESTION 3 - DIGITAL SIGNATURE CLIENT"""

import socket
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

HOST = "127.0.0.1"
PORT = 5002

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

document = input("Enter document to sign: ").encode("utf-8")

signature = private_key.sign(
    document,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)

public_key_bytes = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

payload = (
    document
    + b"\n---SIGNATURE---\n"
    + signature
    + b"\n---PUBLIC KEY---\n"
    + public_key_bytes
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    client.sendall(payload)
    print("Server result:", client.recv(4096).decode())
