"""
LAB 2 - ADDITIONAL QUESTION 1: DES/AES MODES AND PERFORMANCE

Question:
Using DES and AES with 128, 192 and 256-bit keys:
a) Encrypt five different messages using the same key.
b) Consider different modes of operation.
c) Plot execution time for each technique.
d) Compare the modes.

Modes tested:
    ECB, CBC, CFB, OFB, CTR

AES keys are hexadecimal. DES uses an 8-byte ASCII key.
CBC/CFB/OFB require an IV; CTR uses a nonce/counter.
"""

import time
import matplotlib.pyplot as plt
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad


MESSAGES = [
    "Message One",
    "Message Two",
    "Information Security",
    "Cryptography Lab",
    "Performance Testing"
]


def benchmark(cipher_name, key, mode, messages):
    total = 0.0
    for message in messages:
        data = message.encode()
        start = time.perf_counter()

        if cipher_name == "DES":
            block = DES.block_size
            if mode == "ECB":
                cipher = DES.new(key, DES.MODE_ECB)
            elif mode == "CBC":
                cipher = DES.new(key, DES.MODE_CBC, iv=b"12345678")
            elif mode == "CFB":
                cipher = DES.new(key, DES.MODE_CFB, iv=b"12345678")
            elif mode == "OFB":
                cipher = DES.new(key, DES.MODE_OFB, iv=b"12345678")
            else:
                cipher = DES.new(key, DES.MODE_CTR, nonce=b"123456")
        else:
            block = AES.block_size
            if mode == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
            elif mode == "CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv=b"1234567890123456")
            elif mode == "CFB":
                cipher = AES.new(key, AES.MODE_CFB, iv=b"1234567890123456")
            elif mode == "OFB":
                cipher = AES.new(key, AES.MODE_OFB, iv=b"1234567890123456")
            else:
                cipher = AES.new(key, AES.MODE_CTR, nonce=b"12345678")

        if mode in ("ECB", "CBC"):
            cipher.encrypt(pad(data, block))
        else:
            cipher.encrypt(data)

        total += time.perf_counter() - start

    return total / len(messages)


def main():
    keys = {
        "DES": b"A1B2C3D4",
        "AES-128": bytes.fromhex("0123456789ABCDEF0123456789ABCDEF"),
        "AES-192": bytes.fromhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
        "AES-256": bytes.fromhex(
            "0123456789ABCDEF0123456789ABCDEF"
            "0123456789ABCDEF0123456789ABCDEF"
        )
    }

    modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]
    labels, values = [], []

    for cipher_name, key in keys.items():
        for mode in modes:
            value = benchmark(cipher_name, key, mode, MESSAGES)
            label = f"{cipher_name}-{mode}"
            labels.append(label)
            values.append(value)
            print(f"{label:18s}: {value:.9f} seconds")

    plt.figure(figsize=(12, 6))
    plt.bar(labels, values)
    plt.xlabel("Algorithm and mode")
    plt.ylabel("Average execution time (seconds)")
    plt.title("DES/AES Mode Performance Comparison")
    plt.xticks(rotation=60, ha="right")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()
