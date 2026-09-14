"""
LAB 2 - QUESTION 3: PERFORMANCE COMPARISON

Question:
Compare encryption and decryption times for DES and AES-256 using:
    "Performance Testing of Encryption Algorithms"

This program measures multiple repetitions and reports average time.
ECB is used only for comparison with the basic lab exercise.
"""

import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad


def measure(function, repetitions=1000):
    start = time.perf_counter()
    for _ in range(repetitions):
        function()
    return (time.perf_counter() - start) / repetitions


def main():
    message = "Performance Testing of Encryption Algorithms"
    des_key = b"A1B2C3D4"
    aes_key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
        "0123456789ABCDEF0123456789ABCDEF"
    )

    des_plain = pad(message.encode(), DES.block_size)
    aes_plain = pad(message.encode(), AES.block_size)

    des_cipher = DES.new(des_key, DES.MODE_ECB)
    aes_cipher = AES.new(aes_key, AES.MODE_ECB)

    des_ct = des_cipher.encrypt(des_plain)
    aes_ct = aes_cipher.encrypt(aes_plain)

    des_enc_time = measure(lambda: DES.new(des_key, DES.MODE_ECB).encrypt(des_plain))
    des_dec_time = measure(lambda: DES.new(des_key, DES.MODE_ECB).decrypt(des_ct))
    aes_enc_time = measure(lambda: AES.new(aes_key, AES.MODE_ECB).encrypt(aes_plain))
    aes_dec_time = measure(lambda: AES.new(aes_key, AES.MODE_ECB).decrypt(aes_ct))

    print("Average time per operation:")
    print(f"DES encryption:    {des_enc_time:.9f} seconds")
    print(f"DES decryption:    {des_dec_time:.9f} seconds")
    print(f"AES-256 encryption:{aes_enc_time:.9f} seconds")
    print(f"AES-256 decryption:{aes_dec_time:.9f} seconds")
    print("\nFinding: timings depend on hardware, Python version and library.")
    print("AES is normally preferred because DES has only a 56-bit effective key.")


if __name__ == "__main__":
    main()
