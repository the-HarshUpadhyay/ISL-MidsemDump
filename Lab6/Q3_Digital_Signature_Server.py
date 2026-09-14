
# ======================================================================
# FULL QUESTION / SERVER ROLE
# ======================================================================
# Implement the server side of a client-server digital-signature scenario.
# The server receives a message and signature from the client, verifies
# the signature using the client's public key, and reports whether the
# message is authentic and unmodified.
#
# The server must reject modified messages or invalid signatures.
# ======================================================================

"""LAB 6 - QUESTION 3 - DIGITAL SIGNATURE SERVER"""

import socket
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

HOST = "127.0.0.1"
PORT = 5002


def receive_message(connection):
    data = b""
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Server listening on {HOST}:{PORT}")

    connection, address = server.accept()
    with connection:
        print("Connected by:", address)
        payload = receive_message(connection)

        document, signature, public_key_bytes = payload.split(
            b"\n---SIGNATURE---\n", 1
        )
        signature, public_key_bytes = signature.split(
            b"\n---PUBLIC KEY---\n", 1
        )

        public_key = serialization.load_pem_public_key(
            public_key_bytes
        )

        try:
            public_key.verify(
                signature,
                document,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            print("Signature verification successful.")
            print("Document:", document.decode())
            connection.sendall(b"VALID")
        except InvalidSignature:
            print("Signature verification failed.")
            connection.sendall(b"INVALID")
