"""
============================================================
LAB 3 - QUESTION 4: SECURE FILE TRANSFER SYSTEM
============================================================

QUESTION:
Design and implement a secure file transfer system using
RSA (2048-bit) and ECC (secp256r1 curve) public key algorithms.
Generate and exchange keys, then encrypt and decrypt files of
varying sizes, such as 1 MB and 10 MB, using both algorithms.

Measure and compare:
1. Key generation time
2. Encryption time
3. Decryption time
4. Computational overhead

Evaluate:
1. Security and efficiency
2. Key size
3. Storage requirements
4. Resistance to known attacks
5. Strengths and weaknesses of RSA and ECC

CONTEXT:
Public-key algorithms are not normally used to encrypt large
files directly. A hybrid encryption system is used:

    RSA/ECC -> protect or derive an AES key
    AES-GCM -> encrypt the complete file

RSA SYSTEM:
    RSA-2048 + RSA-OAEP + AES-GCM

ECC SYSTEM:
    ECDH secp256r1 + HKDF + AES-GCM

LIBRARIES:
    pip install pycryptodome cryptography
"""

import os
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# RSA FUNCTIONS
# ============================================================

def generate_rsa_keys():
    """Generate a 2048-bit RSA key pair."""
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key


def rsa_encrypt_aes_key(aes_key, public_key):
    """Encrypt the AES key using RSA-OAEP."""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(aes_key)


def rsa_decrypt_aes_key(encrypted_key, private_key):
    """Decrypt the AES key using RSA-OAEP."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_key)


def encrypt_file_using_rsa(input_file, output_file, public_key):
    """
    Encrypt the complete file using AES-GCM.
    Encrypt only the AES key using RSA-OAEP.
    """
    aes_key = get_random_bytes(32)
    encrypted_aes_key = rsa_encrypt_aes_key(
        aes_key,
        public_key
    )

    nonce = get_random_bytes(12)

    with open(input_file, "rb") as file:
        plaintext = file.read()

    cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(output_file, "wb") as file:
        # Store metadata followed by encrypted content
        file.write(len(encrypted_aes_key).to_bytes(4, "big"))
        file.write(encrypted_aes_key)
        file.write(nonce)
        file.write(tag)
        file.write(ciphertext)


def decrypt_file_using_rsa(input_file, output_file, private_key):
    """Decrypt a file encrypted by encrypt_file_using_rsa()."""
    with open(input_file, "rb") as file:
        key_length = int.from_bytes(
            file.read(4),
            "big"
        )

        encrypted_aes_key = file.read(key_length)
        nonce = file.read(12)
        tag = file.read(16)
        ciphertext = file.read()

    aes_key = rsa_decrypt_aes_key(
        encrypted_aes_key,
        private_key
    )

    cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    with open(output_file, "wb") as file:
        file.write(plaintext)


# ============================================================
# ECC FUNCTIONS
# ============================================================

def generate_ecc_keys():
    """Generate an ECC secp256r1 key pair."""
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def derive_ecc_aes_key(private_key, peer_public_key):
    """Derive a 256-bit AES key using ECDH and HKDF."""
    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Lab 3 Secure File Transfer"
    ).derive(shared_secret)


def encrypt_file_using_ecc(input_file, output_file,
                           sender_private_key,
                           receiver_public_key):
    """Encrypt a file using ECDH-derived AES-GCM key."""
    aes_key = derive_ecc_aes_key(
        sender_private_key,
        receiver_public_key
    )

    nonce = os.urandom(12)

    with open(input_file, "rb") as file:
        plaintext = file.read()

    cipher = AESGCM(aes_key)
    ciphertext = cipher.encrypt(
        nonce,
        plaintext,
        None
    )

    with open(output_file, "wb") as file:
        file.write(nonce)
        file.write(ciphertext)


def decrypt_file_using_ecc(input_file, output_file,
                           receiver_private_key,
                           sender_public_key):
    """Decrypt a file encrypted by encrypt_file_using_ecc()."""
    with open(input_file, "rb") as file:
        nonce = file.read(12)
        ciphertext = file.read()

    aes_key = derive_ecc_aes_key(
        receiver_private_key,
        sender_public_key
    )

    cipher = AESGCM(aes_key)
    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        None
    )

    with open(output_file, "wb") as file:
        file.write(plaintext)


# ============================================================
# UTILITY AND TIMING FUNCTIONS
# ============================================================

def create_sample_file(filename, size_in_mb=1):
    """Create a sample binary file of the requested size."""
    data = os.urandom(size_in_mb * 1024 * 1024)

    with open(filename, "wb") as file:
        file.write(data)


def measure_time(function, *args):
    """Run a function and return (result, elapsed_time)."""
    start_time = time.perf_counter()
    result = function(*args)
    end_time = time.perf_counter()

    return result, end_time - start_time


def verify_files_are_equal(file_one, file_two):
    """Return True if two files contain identical bytes."""
    with open(file_one, "rb") as first:
        with open(file_two, "rb") as second:
            return first.read() == second.read()


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():
    print("===== SECURE FILE TRANSFER =====")

    input_file = "sample_1MB.bin"

    if not os.path.exists(input_file):
        print("Creating sample 1 MB file...")
        create_sample_file(input_file, size_in_mb=1)

    # RSA key generation timing
    rsa_keys, rsa_keygen_time = measure_time(
        generate_rsa_keys
    )
    rsa_private, rsa_public = rsa_keys

    # ECC key generation timing
    ecc_sender_keys, ecc_keygen_time = measure_time(
        generate_ecc_keys
    )
    ecc_receiver_keys, _ = measure_time(
        generate_ecc_keys
    )

    ecc_sender_private, ecc_sender_public = ecc_sender_keys
    ecc_receiver_private, ecc_receiver_public = ecc_receiver_keys

    # RSA encryption and decryption timing
    _, rsa_encrypt_time = measure_time(
        encrypt_file_using_rsa,
        input_file,
        "rsa_encrypted.bin",
        rsa_public
    )

    _, rsa_decrypt_time = measure_time(
        decrypt_file_using_rsa,
        "rsa_encrypted.bin",
        "rsa_decrypted.bin",
        rsa_private
    )

    # ECC encryption and decryption timing
    _, ecc_encrypt_time = measure_time(
        encrypt_file_using_ecc,
        input_file,
        "ecc_encrypted.bin",
        ecc_sender_private,
        ecc_receiver_public
    )

    _, ecc_decrypt_time = measure_time(
        decrypt_file_using_ecc,
        "ecc_encrypted.bin",
        "ecc_decrypted.bin",
        ecc_receiver_private,
        ecc_sender_public
    )

    print("\n===== PERFORMANCE RESULTS =====")
    print(f"RSA-2048 key generation: {rsa_keygen_time:.6f} seconds")
    print(f"ECC key generation:      {ecc_keygen_time:.6f} seconds")

    print(f"\nRSA file encryption:     {rsa_encrypt_time:.6f} seconds")
    print(f"RSA file decryption:     {rsa_decrypt_time:.6f} seconds")

    print(f"\nECC file encryption:     {ecc_encrypt_time:.6f} seconds")
    print(f"ECC file decryption:     {ecc_decrypt_time:.6f} seconds")

    print("\n===== FILE VERIFICATION =====")
    print(
        "RSA verified:",
        verify_files_are_equal(input_file, "rsa_decrypted.bin")
    )
    print(
        "ECC verified:",
        verify_files_are_equal(input_file, "ecc_decrypted.bin")
    )


if __name__ == "__main__":
    main()
